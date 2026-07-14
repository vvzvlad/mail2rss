"""Async JMAP client for Fastmail (SPEC.md §6.1, §6.2, §8.1).

Read-only by construction: the Fastmail token is JMAP + "Read-only access" (F1),
so nothing here can mutate the mailbox even if it tried. The client does exactly
what the feed pipeline needs and nothing more:

- get_session()      -> resolve apiUrl / downloadUrl / accountId, cached in-process
- get_mailboxes()    -> Mailbox/get with ids: null (few folders, fetch all)
- query_emails()     -> ONE HTTP request, TWO method calls (Email/query + Email/get
                        via the #ids back-reference) — exactly the JSON of §6.2
- get_email()        -> single Email/get by id (used by the permalink)
- stream_blob()      -> stream a blob from downloadUrl with our Bearer (§8.1)

Errors are typed so the HTTP layer can tell §6.4's "serve stale cache or 503"
(a transient JmapError) from "the folder/email is gone" (JmapNotFound).

Throttle: jmap_rpc_bounded() puts the concurrency GATE OUTSIDE and the TIMEOUT
INSIDE, so queue backpressure never eats a request's own timeout budget. This
shape is copied deliberately from a sibling project's tg_throttle.py; inverting
it is a known bug class.

The bearer token is NEVER logged.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

import httpx
from loguru import logger

from src.models import BodyPart, Email, JmapSession, Mailbox

JMAP_CORE = "urn:ietf:params:jmap:core"
JMAP_MAIL = "urn:ietf:params:jmap:mail"

# Exactly the properties of §6.2.
_EMAIL_PROPERTIES = [
    "id", "blobId", "mailboxIds", "subject", "from", "sender",
    "receivedAt", "sentAt", "messageId", "preview", "hasAttachment",
    "htmlBody", "textBody", "bodyValues", "attachments",
    "header:List-Unsubscribe:asURLs", "header:List-Id:asText",
]
_BODY_PROPERTIES = ["partId", "blobId", "size", "name", "type", "charset", "disposition", "cid"]
_MAX_BODY_VALUE_BYTES = 1_000_000

# JMAP method-level error `type`s that mean "the thing is gone", not "try later".
_NOTFOUND_ERROR_TYPES = {"notFound", "anchorNotFound"}


class JmapError(Exception):
    """A JMAP call failed. `transient` marks network/5xx/429 failures — the ones
    §6.4 answers with stale cache or a 503 + Retry-After. Non-transient means a
    permanent protocol/auth failure that retrying will not fix."""

    def __init__(self, message: str, *, transient: bool = True) -> None:
        super().__init__(message)
        self.transient = transient


class JmapNotFound(Exception):
    """A referenced mailbox or email does not exist (§6.1). The HTTP layer turns
    this into a 410/explanation feed, not a retry."""


class JmapClient:
    def __init__(
        self,
        token: str,
        session_url: str,
        client: httpx.AsyncClient,
        *,
        max_concurrent: int = 4,
        rpc_timeout: float = 30.0,
    ) -> None:
        self._token = token
        self._session_url = session_url
        self._client = client
        self._rpc_timeout = rpc_timeout
        # Concurrency gate. Fastmail allows maxConcurrentRequests: 10; we stay
        # well under it and self-limit (§6.3).
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._session: JmapSession | None = None
        self._session_lock = asyncio.Lock()

    @property
    def _auth_headers(self) -> dict[str, str]:
        # The token never appears in a log line — only ever in this header.
        return {"Authorization": f"Bearer {self._token}"}

    # --- Throttle ------------------------------------------------------------

    @asynccontextmanager
    async def jmap_rpc_bounded(self, timeout: float) -> AsyncIterator[None]:
        """Gate OUTSIDE, timeout INSIDE (SPEC.md §14.1).

        Time spent waiting for the semaphore does NOT count against `timeout`;
        the timeout only starts once we hold the gate and are actually doing work.
        """
        async with self._semaphore:  # gate — may block on backpressure
            async with asyncio.timeout(timeout):  # budget — starts after the gate
                yield

    # --- Session -------------------------------------------------------------

    async def get_session(self) -> JmapSession:
        """Resolve and cache the JMAP session (§6.1). Concurrency-safe."""
        if self._session is not None:
            return self._session
        async with self._session_lock:
            if self._session is not None:
                return self._session
            async with self.jmap_rpc_bounded(self._rpc_timeout):
                try:
                    resp = await self._client.get(self._session_url, headers=self._auth_headers)
                except httpx.HTTPError as exc:
                    raise JmapError(f"session request failed: {exc!r}") from exc
                self._raise_for_status(resp)
                data = self._json(resp)
            try:
                account_id = data["primaryAccounts"][JMAP_MAIL]
                session = JmapSession(
                    api_url=data["apiUrl"],
                    download_url=data["downloadUrl"],
                    account_id=account_id,
                )
            except (KeyError, TypeError) as exc:
                raise JmapError(f"malformed JMAP session: missing {exc!r}", transient=False) from exc
            self._session = session
            logger.info(f"jmap_session_resolved: account_id {account_id}")
            return session

    # --- Mailboxes -----------------------------------------------------------

    async def get_mailboxes(self) -> list[Mailbox]:
        """Fetch the whole mailbox tree (§6.1): Mailbox/get with ids: null."""
        session = await self.get_session()
        responses = await self._request(
            [
                [
                    "Mailbox/get",
                    {"accountId": session.account_id, "ids": None},
                    "m",
                ]
            ]
        )
        result = self._result(responses, "m")
        mailboxes: list[Mailbox] = []
        for obj in result.get("list", []):
            mailboxes.append(
                Mailbox(
                    id=obj["id"],
                    name=obj.get("name") or "",
                    parent_id=obj.get("parentId"),
                    role=(obj.get("role") or None),
                    total_emails=int(obj.get("totalEmails") or 0),
                )
            )
        logger.info(f"jmap_mailboxes_fetched: count {len(mailboxes)}")
        return mailboxes

    # --- Emails --------------------------------------------------------------

    async def query_emails(self, mailbox_ids: Sequence[str], limit: int) -> list[Email]:
        """List a folder's newest emails (§6.2): ONE HTTP request, TWO method calls.

        Email/query yields the ids, Email/get resolves them via the `#ids`
        back-reference — so the ids never round-trip through us.
        """
        if not mailbox_ids:
            return []
        session = await self.get_session()

        if len(mailbox_ids) == 1:
            email_filter: dict[str, Any] = {"inMailbox": mailbox_ids[0]}
        else:
            email_filter = {
                "operator": "OR",
                "conditions": [{"inMailbox": mid} for mid in mailbox_ids],
            }

        method_calls = [
            [
                "Email/query",
                {
                    "accountId": session.account_id,
                    "filter": email_filter,
                    "sort": [{"property": "receivedAt", "isAscending": False}],
                    "limit": limit,
                    "calculateTotal": False,
                },
                "q",
            ],
            [
                "Email/get",
                {
                    "accountId": session.account_id,
                    "#ids": {"resultOf": "q", "name": "Email/query", "path": "/ids"},
                    "properties": _EMAIL_PROPERTIES,
                    "bodyProperties": _BODY_PROPERTIES,
                    "fetchHTMLBodyValues": True,
                    "fetchTextBodyValues": True,
                    "maxBodyValueBytes": _MAX_BODY_VALUE_BYTES,
                },
                "g",
            ],
        ]
        responses = await self._request(method_calls)
        # Surface a bad mailbox as JmapNotFound (the query call carries the filter).
        self._result(responses, "q")
        get_result = self._result(responses, "g")
        emails = [_parse_email(obj) for obj in get_result.get("list", [])]
        logger.info(
            f"jmap_query_emails: mailboxes {len(mailbox_ids)}, limit {limit}, returned {len(emails)}"
        )
        return emails

    async def get_email(self, email_id: str) -> Email | None:
        """Fetch one email by id (§9). Returns None if the email is gone — the
        permalink turns that into a 410."""
        session = await self.get_session()
        responses = await self._request(
            [
                [
                    "Email/get",
                    {
                        "accountId": session.account_id,
                        "ids": [email_id],
                        "properties": _EMAIL_PROPERTIES,
                        "bodyProperties": _BODY_PROPERTIES,
                        "fetchHTMLBodyValues": True,
                        "fetchTextBodyValues": True,
                        "maxBodyValueBytes": _MAX_BODY_VALUE_BYTES,
                    },
                    "g",
                ]
            ]
        )
        result = self._result(responses, "g")
        items = result.get("list", [])
        if not items:
            # Email id landed in `notFound` — gone or never existed.
            return None
        return _parse_email(items[0])

    # --- Blob streaming ------------------------------------------------------

    async def stream_blob(self, blob_id: str, name: str, type_: str) -> AsyncIterator[bytes]:
        """Stream a blob from Fastmail's download host (§8.1).

        The URL is built ONLY from the session's downloadUrl template with our own
        blob_id/name/type — never from anything in the email — so the host is
        fixed and there is no SSRF surface. The host is fastmailusercontent.com,
        deliberately different from the API host (F6).
        """
        session = await self.get_session()
        url = _expand_download_url(
            session.download_url,
            account_id=session.account_id,
            blob_id=blob_id,
            name=name,
            type_=type_,
        )
        try:
            async with self._client.stream("GET", url, headers=self._auth_headers) as resp:
                if resp.status_code == 404:
                    await resp.aclose()
                    raise JmapNotFound(f"blob not found: {blob_id}")
                self._raise_for_status(resp)
                async for chunk in resp.aiter_bytes():
                    yield chunk
        except httpx.HTTPError as exc:
            raise JmapError(f"blob stream failed: {exc!r}") from exc

    # --- Low-level RPC -------------------------------------------------------

    async def _request(self, method_calls: list[Any]) -> list[Any]:
        """POST one JMAP request and return its methodResponses list."""
        session = await self.get_session()
        payload = {"using": [JMAP_CORE, JMAP_MAIL], "methodCalls": method_calls}
        async with self.jmap_rpc_bounded(self._rpc_timeout):
            try:
                resp = await self._client.post(
                    session.api_url, headers=self._auth_headers, json=payload
                )
            except httpx.HTTPError as exc:
                raise JmapError(f"jmap request failed: {exc!r}") from exc
            self._raise_for_status(resp)
            data = self._json(resp)
        responses = data.get("methodResponses")
        if not isinstance(responses, list):
            raise JmapError("malformed JMAP response: no methodResponses", transient=False)
        return responses

    @staticmethod
    def _raise_for_status(resp: httpx.Response) -> None:
        code = resp.status_code
        if code < 400:
            return
        # Transient: rate limit and server errors — §6.4 serves stale or 503.
        transient = code == 429 or code >= 500
        raise JmapError(f"jmap http {code}", transient=transient)

    @staticmethod
    def _json(resp: httpx.Response) -> dict[str, Any]:
        try:
            data = resp.json()
        except ValueError as exc:
            raise JmapError(f"invalid JSON from JMAP: {exc!r}", transient=False) from exc
        if not isinstance(data, dict):
            raise JmapError("unexpected JMAP payload (not an object)", transient=False)
        return data

    @staticmethod
    def _result(responses: list[Any], call_id: str) -> dict[str, Any]:
        """Extract one method response by call id, mapping errors to exceptions.

        A JMAP method error arrives as ["error", {...}, callId]. A not-found type
        becomes JmapNotFound; anything else becomes a JmapError.
        """
        for entry in responses:
            if not (isinstance(entry, list) and len(entry) == 3 and entry[2] == call_id):
                continue
            name, args = entry[0], entry[1]
            if name == "error":
                err_type = (args or {}).get("type", "unknown")
                if err_type in _NOTFOUND_ERROR_TYPES:
                    raise JmapNotFound(f"jmap method error: {err_type}")
                # invalidArguments referencing a mailbox is the shape Fastmail
                # returns for a filter on a deleted folder — treat it as gone.
                if err_type == "invalidArguments":
                    raise JmapNotFound(f"jmap invalidArguments: {(args or {}).get('description', '')}")
                raise JmapError(f"jmap method error: {err_type}", transient=False)
            if not isinstance(args, dict):
                raise JmapError(f"malformed JMAP result for {call_id!r}", transient=False)
            return args
        raise JmapError(f"missing JMAP result for call {call_id!r}", transient=False)


# --- Parsing -----------------------------------------------------------------


def _parse_datetime(value: str) -> datetime:
    """Parse a JMAP UTCDate (RFC 3339) into a timezone-aware UTC datetime.

    JMAP always sends receivedAt, and it is always offset-qualified. We normalise
    to UTC and NEVER fall back to now() (SPEC.md §7.3, §14.2)."""
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        # JMAP dates are always aware; a naive one signals a broken payload.
        raise JmapError(f"naive datetime from JMAP: {value!r}", transient=False)
    return parsed.astimezone(timezone.utc)


def _parse_email(obj: dict[str, Any]) -> Email:
    from_list = obj.get("from") or []
    if from_list:
        from_name = from_list[0].get("name") or None
        from_email = from_list[0].get("email") or None
    else:
        from_name = None
        from_email = None

    received_raw = obj.get("receivedAt")
    if not received_raw:
        raise JmapError(f"email {obj.get('id')!r} has no receivedAt", transient=False)

    message_ids = obj.get("messageId") or []
    message_id = message_ids[0] if message_ids else None

    body_values: dict[str, Any] = obj.get("bodyValues") or {}
    html_body, html_truncated = _collect_body(obj.get("htmlBody"), body_values)
    text_body, _ = _collect_body(obj.get("textBody"), body_values)

    # mailboxIds is a map {id: true}; we only need the ids.
    mailbox_ids = tuple((obj.get("mailboxIds") or {}).keys())

    attachments = tuple(_parse_body_part(part) for part in (obj.get("attachments") or []))

    list_unsub = obj.get("header:List-Unsubscribe:asURLs") or []
    list_id = obj.get("header:List-Id:asText") or None

    return Email(
        id=obj["id"],
        message_id=message_id,
        subject=obj.get("subject") or "",
        from_name=from_name,
        from_email=from_email,
        received_at=_parse_datetime(received_raw),
        preview=obj.get("preview") or "",
        mailbox_ids=mailbox_ids,
        html_body=html_body,
        text_body=text_body,
        html_truncated=html_truncated,
        attachments=attachments,
        list_unsubscribe=tuple(list_unsub),
        list_id=list_id,
    )


def _collect_body(parts: Any, body_values: dict[str, Any]) -> tuple[str | None, bool]:
    """Concatenate bodyValues for the given body parts; report any truncation.

    Returns (body_or_None, truncated). None means there were no parts at all,
    distinct from "" (parts present but empty)."""
    if not parts:
        return None, False
    chunks: list[str] = []
    truncated = False
    for part in parts:
        part_id = part.get("partId")
        if part_id is None:
            continue
        value = body_values.get(part_id)
        if value is None:
            continue
        chunks.append(value.get("value") or "")
        if value.get("isTruncated"):
            truncated = True
    return "".join(chunks), truncated


def _parse_body_part(part: dict[str, Any]) -> BodyPart:
    return BodyPart(
        part_id=part.get("partId"),
        blob_id=part.get("blobId"),
        type=part.get("type") or "application/octet-stream",
        name=part.get("name"),
        disposition=part.get("disposition"),
        cid=part.get("cid"),
        size=int(part.get("size") or 0),
    )


# --- Download URL template ---------------------------------------------------


def _expand_download_url(
    template: str, *, account_id: str, blob_id: str, name: str, type_: str
) -> str:
    """RFC 6570 level-1 substitution into Fastmail's downloadUrl template.

    Each value is percent-encoded (level-1 simple string expansion). We do it by
    hand rather than pull in a URI-template library for four substitutions.
    """
    from urllib.parse import quote

    return (
        template.replace("{accountId}", quote(account_id, safe=""))
        .replace("{blobId}", quote(blob_id, safe=""))
        .replace("{name}", quote(name, safe=""))
        .replace("{type}", quote(type_, safe=""))
    )
