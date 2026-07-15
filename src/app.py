"""FastAPI app + routes (SPEC.md §5, §6, §9). The HTTP layer that ties the
foundation and render layers into a running service.

Routes (SPEC.md §5):
    GET  /f/{slug}/{mailbox_id}/{mac}/atom.xml        -> Atom feed (§5.1, §6)
    GET  /f/{slug}/{mailbox_id}/{mac}/e/{email_id}.html -> permalink (§9)
    GET  /f/{slug}/{mailbox_id}/{mac}/m/{blob_id}/{sig}/{name} -> media proxy (§8.1)
    GET  /                                            -> discovery form (§4.4)
    POST /                                            -> secret -> folder list / OPML
    GET  /health                                      -> liveness + last JMAP probe
    GET  /robots.txt                                  -> Disallow: /
    *                                                 -> 404

Capability-URL hygiene (SPEC.md §5.2): the ``mac`` never reaches a log line — the
access-log middleware records the mailbox_id and the first 6 chars of a hash of
the mac. A failed MAC check returns 404 (never 401/403 — we do not confirm a
folder exists) and never logs the expected value.

The CPU-heavy render pipeline and all SQLite work go through ``asyncio.to_thread``
so the event loop never blocks. gzip is applied by hand to the text responses (not
via middleware) so the media stream keeps its ``Content-Length`` and stays a
stream (SPEC.md §8.1).
"""

from __future__ import annotations

import asyncio
import gzip
import hashlib
import re
import time
import uuid
from html import escape
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime, parsedate_to_datetime
from urllib.parse import quote

import httpx
from fastapi import FastAPI, Request
from loguru import logger
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response

from src import discovery
from src.cache import Cache
from src.crypto import (
    canon_params,
    feed_url,
    media_sig,
    slugify,
    verify_feed_mac,
)
from src.discovery import RateLimiter, render_template
from src.feed import NS_MAIL2RSS, FeedEntry, build_atom, entry_id, error_feed
from src.jmap import JmapClient, JmapError, JmapNotFound
from src.mailbox_tree import MailboxTree
from src.media import MediaProxy
from src.models import DEFAULT_LIMIT, BodyPart, Email, FeedParams
from src.render import render_email, truncate_html
from src.settings import settings

# --- Constants ---------------------------------------------------------------

ATOM_CONTENT_TYPE = "application/atom+xml; charset=utf-8"
FEED_ROBOTS = "noindex, nofollow, noarchive"

# Size caps (SPEC.md §7.4). Each entry <= 200 KB; the whole feed ~1 MB (drop
# entries, do not cut content further); Miniflux will not fetch above 15 MiB.
MAX_ENTRY_BYTES = 200 * 1024
MAX_FEED_BYTES = 1_000_000
# Rough per-entry XML overhead (title, dates, links, author, category envelope).
_ENTRY_OVERHEAD = 1024

MAX_TITLE_LEN = 200
_TRUTHY = {"1", "true", "yes", "on"}
_GZIP_MIN_BYTES = 256

# First feed-level <updated> in a build_atom document (it precedes every entry).
_UPDATED_RE = re.compile(rb"<updated>([^<]+)</updated>")


# --- Health probe state ------------------------------------------------------


class HealthState:
    """Last known JMAP probe result. ``/health`` reports this — it never triggers
    a fresh Fastmail call (SPEC.md §10.4)."""

    def __init__(self) -> None:
        self.jmap_ok: bool | None = None
        self.jmap_checked_at: float | None = None
        self.jmap_error: str | None = None

    def record(self, ok: bool, error: str | None = None) -> None:
        self.jmap_ok = ok
        self.jmap_checked_at = time.time()
        self.jmap_error = None if ok else (error or "unknown")


# --- Lifespan ----------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Build the shared httpx client, JMAP client, cache, tree and media proxy."""
    client = httpx.AsyncClient(timeout=httpx.Timeout(30.0, connect=10.0))
    jmap = JmapClient(settings.fastmail_api_token, settings.jmap_session_url, client)
    cache = Cache.from_settings()
    await cache.init()
    tree = MailboxTree(jmap, settings.mailbox_tree_ttl, cache=cache)

    app.state.http = client
    app.state.jmap = jmap
    app.state.cache = cache
    app.state.tree = tree
    app.state.media = MediaProxy(cache, jmap)
    app.state.limiter = RateLimiter()
    app.state.health = HealthState()
    logger.info("app_started: base_url set")
    try:
        yield
    finally:
        await client.aclose()
        logger.info("app_stopped")


# no docs/openapi surface: there is no feed index anywhere (SPEC.md §5).
app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


# --- Access-log middleware (pure ASGI, never buffers the body) ---------------


class RequestLoggingMiddleware:
    """Pure-ASGI request logging. NOT BaseHTTPMiddleware — that buffers the body
    and would break the media stream (SPEC.md §14.1). The ``mac`` is never logged;
    only the mailbox_id and a 6-char hash of the mac (SPEC.md §5.2 p.5)."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        start = time.perf_counter()
        status = {"code": 0}

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                status["code"] = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            method = scope.get("method", "")
            fields = _scrub_path(scope.get("path", ""))
            logger.info(
                f"http_request: method {method}, {fields}, "
                f"status {status['code']}, ms {elapsed_ms:.1f}"
            )


def _scrub_path(path: str) -> str:
    """A log-safe description of the path with capability components hashed out.

    The mac is a capability token and must never appear in a log (SPEC.md §5.2
    p.5); the query string is dropped entirely so a stray secret cannot leak. On a
    media path (``/f/{slug}/{mailbox_id}/{mac}/m/{blob_id}/{sig}/{name}``) the
    ``sig`` (and ``blob_id``) are capability components too — hash them the same
    way as the mac so none of them reaches the logs."""
    parts = path.split("/")
    if len(parts) >= 5 and parts[1] == "f":
        mailbox_id = parts[3]
        mac_hash = hashlib.sha256(parts[4].encode("utf-8")).hexdigest()[:6]
        parts[4] = f"mac#{mac_hash}"
        if len(parts) >= 8 and parts[5] == "m":
            parts[6] = "blob#" + hashlib.sha256(parts[6].encode("utf-8")).hexdigest()[:6]
            parts[7] = "sig#" + hashlib.sha256(parts[7].encode("utf-8")).hexdigest()[:6]
        return f"mailbox_id {mailbox_id}, mac_hash {mac_hash}, route {'/'.join(parts)}"
    return f"path {path}"


app.add_middleware(RequestLoggingMiddleware)


# --- Small HTTP helpers ------------------------------------------------------


def _parse_signed_params(request: Request) -> FeedParams:
    """Parse ``limit``/``children`` exactly as they were SIGNED (no clamping).

    Verification must run against the signed values; the ceiling is applied only
    to the JMAP fetch afterwards (SPEC.md §5.1 p.4). Unknown query params are
    dropped and do not affect the MAC or the cache key (SPEC.md §4.2)."""
    qp = request.query_params
    raw_limit = qp.get("limit")
    limit = DEFAULT_LIMIT
    if raw_limit is not None:
        try:
            limit = int(raw_limit)
        except (TypeError, ValueError):
            limit = DEFAULT_LIMIT
    children = qp.get("children", "").lower() in _TRUTHY
    return FeedParams(limit=limit, children=children)


def _fetch_limit(signed: FeedParams) -> int:
    """Server-forced ceiling on how many emails we fetch (SPEC.md §4.3)."""
    return max(1, min(signed.limit, settings.max_limit))


def _accepts_gzip(request: Request) -> bool:
    return "gzip" in request.headers.get("accept-encoding", "").lower()


def _maybe_gzip(body: bytes, request: Request, headers: dict[str, str]) -> bytes:
    if _accepts_gzip(request) and len(body) >= _GZIP_MIN_BYTES:
        headers["Content-Encoding"] = "gzip"
        headers["Vary"] = "Accept-Encoding"
        return gzip.compress(body, 6)
    return body


def _strong_etag(body: bytes) -> str:
    return '"' + hashlib.sha256(body).hexdigest() + '"'


def _etag_matches(if_none_match: str, etag: str) -> bool:
    if if_none_match.strip() == "*":
        return True
    candidates = [c.strip() for c in if_none_match.split(",")]
    for cand in candidates:
        if cand.startswith("W/"):
            cand = cand[2:].strip()
        if cand == etag:
            return True
    return False


def _extract_feed_updated(body: bytes) -> datetime | None:
    m = _UPDATED_RE.search(body)
    if not m:
        return None
    text = m.group(1).decode("ascii", "replace").strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _feed_response(
    request: Request,
    body: bytes,
    etag: str,
    *,
    status: int = 200,
    extra_headers: dict[str, str] | None = None,
) -> Response:
    """Build an Atom response with ETag/Last-Modified/Cache-Control, honouring
    conditional requests -> 304 (SPEC.md §6.6)."""
    last_modified = _extract_feed_updated(body)
    headers = {
        "ETag": etag,
        "Cache-Control": "private, max-age=300",
        "X-Robots-Tag": FEED_ROBOTS,
    }
    if last_modified is not None:
        headers["Last-Modified"] = format_datetime(last_modified, usegmt=True)
    if extra_headers:
        headers.update(extra_headers)

    inm = request.headers.get("if-none-match")
    if inm and _etag_matches(inm, etag):
        return Response(status_code=304, headers=headers)
    ims = request.headers.get("if-modified-since")
    if ims and last_modified is not None and _not_modified_since(ims, last_modified):
        return Response(status_code=304, headers=headers)

    out_headers = dict(headers)
    out_body = _maybe_gzip(body, request, out_headers)
    return Response(
        content=out_body,
        status_code=status,
        media_type=ATOM_CONTENT_TYPE,
        headers=out_headers,
    )


def _not_modified_since(if_modified_since: str, last_modified: datetime) -> bool:
    try:
        since = parsedate_to_datetime(if_modified_since)
    except (TypeError, ValueError):
        return False
    if since.tzinfo is None:
        since = since.replace(tzinfo=timezone.utc)
    return last_modified.replace(microsecond=0) <= since


# --- Feed rendering (runs in one asyncio.to_thread, SPEC.md §14.1) -----------


def _make_media_url(feed_prefix: str, mac: str, signed_query: str):
    """Return a ``media_url(part)`` closure that signs the media proxy URL.

    The declared MIME type travels in ``?ct=`` (reconstructable after a cache
    wipe); the signed feed params are appended so the SAME mac re-verifies on the
    media endpoint (SPEC.md §8.1)."""

    def media_url(part: BodyPart) -> str | None:
        if part is None or not part.blob_id:
            return None
        sig = media_sig(mac, part.blob_id)
        fname = quote(part.name or "file", safe="")
        query = "ct=" + quote(part.type or "application/octet-stream", safe="")
        if signed_query:
            query += "&" + signed_query
        return f"{feed_prefix}/m/{quote(part.blob_id, safe='')}/{sig}/{fname}?{query}"

    return media_url


def _entry_title(email: Email) -> str:
    subject = (email.subject or "").strip()
    if subject:
        return subject[:MAX_TITLE_LEN]
    # Deterministic fallback for an empty subject (SPEC.md §7.3).
    who = email.from_name or email.from_email or "unknown sender"
    day = email.received_at.date().isoformat()
    return f"(no subject) — {who} — {day}"[:MAX_TITLE_LEN]


def _fallback_seed(email: Email) -> str:
    """Seed for ``atom:id`` when an email has no Message-ID (SPEC.md §7.2).

    Built ONLY from stable content fields — ``receivedAt ‖ from ‖ subject ‖
    preview`` — never from the JMAP ``Email.id``: a thread merge can recreate the
    email with a new id (RFC 8621), which would resurface the entry as unread. The
    Email.id stays a cache key and part of the permalink URL only. ``entry_id``
    hashes this seed with sha256."""
    from_field = email.from_email or email.from_name or ""
    return "\x00".join(
        (
            email.received_at.isoformat(),
            from_field,
            email.subject or "",
            email.preview or "",
        )
    )


def _categories(email: Email) -> tuple[str, ...]:
    cats: list[str] = []
    if email.list_id:
        cats.append(email.list_id)
    if email.from_email and "@" in email.from_email:
        domain = email.from_email.rsplit("@", 1)[1].strip().lower()
        if domain:
            cats.append(domain)
    return tuple(cats)


def _render_feed_body(
    *,
    emails: list[Email],
    mailbox_id: str,
    mac: str,
    signed_params: FeedParams,
    title: str,
) -> tuple[bytes, datetime | None]:
    """Render every email and serialise the Atom document (CPU-bound; call in a
    thread). Caps each entry to 200 KB and the whole feed to ~1 MB by dropping
    trailing (oldest) entries — never by cutting content further (SPEC.md §7.4)."""
    base_url = settings.base_url
    signed_query = canon_params(signed_params)
    canonical_slug = slugify(title)
    feed_prefix = f"{base_url}/f/{canonical_slug}/{mailbox_id}/{mac}"

    entries: list[FeedEntry] = []
    total_bytes = 0
    newest: datetime | None = None

    for email in emails:
        permalink = f"{feed_prefix}/e/{quote(email.id, safe='')}.html"
        if signed_query:
            permalink += "?" + signed_query
        media_url = _make_media_url(feed_prefix, mac, signed_query)
        rendered = render_email(email, media_url=media_url, permalink=permalink)
        content = truncate_html(rendered.html, MAX_ENTRY_BYTES, permalink)

        approx = len(content.encode("utf-8")) + _ENTRY_OVERHEAD
        if entries and total_bytes + approx > MAX_FEED_BYTES:
            break  # feed size cap: drop the rest, do not shrink content (§7.4)
        total_bytes += approx

        entries.append(
            FeedEntry(
                id=entry_id(email.message_id, fallback_seed=_fallback_seed(email)),
                title=_entry_title(email),
                link=permalink,
                author_name=email.from_name,
                author_email=email.from_email,
                published=email.received_at,
                updated=email.received_at,
                categories=_categories(email),
                content_html=content,
            )
        )
        if newest is None or email.received_at > newest:
            newest = email.received_at

    self_url = feed_url(base_url, canonical_slug, mailbox_id, mac, signed_params)
    feed_id = f"urn:uuid:{uuid.uuid5(NS_MAIL2RSS, mailbox_id)}"
    body = build_atom(feed_id=feed_id, title=title, self_url=self_url, entries=entries)
    return body, newest


# Deterministic base + spread for the error feed's dates. A datetime.now()
# fallback is forbidden (SPEC.md §7.3/§14.2): it makes the error feed's body,
# ETag and <updated> jitter on every regeneration. The base and span stay firmly
# in the PAST so a reader never sees a future-dated entry (which it would ignore).
_ERROR_FEED_BASE = datetime(2020, 1, 1, tzinfo=timezone.utc)
_ERROR_FEED_SPAN_S = 365 * 24 * 3600  # one year of deterministic spread


def _error_feed_when(mailbox_id: str) -> datetime:
    """A stable, byte-deterministic timestamp for the error feed, derived from the
    mailbox_id — aligned with the stable atom:id so the whole document is fixed."""
    digest = hashlib.sha256(("error:" + mailbox_id).encode("utf-8")).digest()
    offset = int.from_bytes(digest[:4], "big") % _ERROR_FEED_SPAN_S
    return _ERROR_FEED_BASE + timedelta(seconds=offset)


def _build_error_feed(mailbox_id: str, mac: str, slug: str, signed_params: FeedParams) -> bytes:
    """A valid Atom feed with one explanation entry (SPEC.md §6.4). The entry id is
    STABLE (uuid5 of "error:"+mailbox_id) and the date is DETERMINISTIC, so the
    whole document is byte-stable across polls (no resurfacing as unread)."""
    feed_id = f"urn:uuid:{uuid.uuid5(NS_MAIL2RSS, mailbox_id)}"
    stable_id = f"urn:uuid:{uuid.uuid5(NS_MAIL2RSS, 'error:' + mailbox_id)}"
    self_url = feed_url(settings.base_url, slug, mailbox_id, mac, signed_params)
    message = (
        "This folder was deleted from Fastmail, so this feed URL no longer works. "
        "Open the mail2rss page to get a fresh link."
    )
    return error_feed(
        feed_id=feed_id,
        title=slug or "mail2rss",
        self_url=self_url,
        entry_id_=stable_id,
        message=message,
        when=_error_feed_when(mailbox_id),
    )


# --- Routes: feed ------------------------------------------------------------


@app.get("/f/{slug}/{mailbox_id}/{mac}/atom.xml")
async def feed(slug: str, mailbox_id: str, mac: str, request: Request) -> Response:
    signed_params = _parse_signed_params(request)
    epoch = settings.epoch_for(mailbox_id)

    # MAC is the only thing checked; a mismatch is 404 (do not confirm the folder
    # exists). The slug is never checked or used for routing (SPEC.md §5.1).
    if not verify_feed_mac(mac, mailbox_id, signed_params, epoch):
        return Response(status_code=404)

    cache: Cache = request.app.state.cache
    tree: MailboxTree = request.app.state.tree
    jmap: JmapClient = request.app.state.jmap
    health: HealthState = request.app.state.health

    cache_key = mailbox_id + "\0" + canon_params(signed_params)

    # Fresh cache (< cache_ttl) -> serve it, honouring If-None-Match (SPEC.md §6.3).
    entry = await cache.get_feed(cache_key)
    if entry is not None and (time.time() - entry.generated_at) < settings.cache_ttl:
        return _feed_response(request, entry.body, entry.etag)

    try:
        await tree.ensure_fresh()
        mailbox = tree.get(mailbox_id)
        if mailbox is None:
            # A stale or kv-restored tree can report a genuinely-existing folder as
            # gone. Before persisting a permanent "deleted" verdict, force ONE real
            # refresh when the current tree was never successfully refreshed this
            # run (SPEC.md §6.1): don't turn a cold/stale tree into a cached
            # permanent-gone.
            if tree.last_refresh_ok is not True:
                try:
                    await _force_tree_refresh(tree)
                except (JmapError, JmapNotFound):
                    pass  # keep whatever tree we have; fall through to the error feed
                mailbox = tree.get(mailbox_id)
            if mailbox is None:
                # Permanent: the folder is gone -> explanation feed, not a bare 410.
                return await _serve_error_feed(request, mailbox_id, mac, slug, signed_params)
        fetch_ids = [mailbox_id]
        if signed_params.children:
            fetch_ids += tree.children_ids(mailbox_id)
        emails = await jmap.query_emails(fetch_ids, _fetch_limit(signed_params))
        health.record(True)
    except JmapNotFound:
        health.record(True)  # a definite answer from JMAP: the thing is gone
        return await _serve_error_feed(request, mailbox_id, mac, slug, signed_params)
    except JmapError as exc:
        health.record(False, repr(exc))
        # Never return an empty-but-valid feed on an upstream error (SPEC.md §6.4).
        if entry is not None:
            logger.warning(f"feed_stale_served: mailbox_id {mailbox_id}, error {exc!r}")
            return _feed_response(
                request, entry.body, entry.etag, extra_headers={"X-Upstream-Status": "stale"}
            )
        logger.warning(f"feed_upstream_unavailable: mailbox_id {mailbox_id}, error {exc!r}")
        return Response(status_code=503, headers={"Retry-After": "300"})

    title = tree.title(mailbox_id)
    try:
        body, _newest = await _in_thread_render(emails, mailbox_id, mac, signed_params, title)
    except Exception as exc:  # noqa: BLE001 - the render/serialise path must never 500
        # Even after the F17 strip + build_atom fail-safe, render/serialise is a
        # single point of failure. Mirror the transient-JMAP handling (SPEC.md
        # §6.4): serve a stale body if we have one, else 503 — never a 500, and
        # never an empty-but-valid feed.
        if entry is not None:
            logger.warning(f"feed_render_failed_served_stale: mailbox_id {mailbox_id}, error {exc!r}")
            return _feed_response(
                request, entry.body, entry.etag, extra_headers={"X-Upstream-Status": "stale"}
            )
        logger.error(f"feed_render_failed_no_cache: mailbox_id {mailbox_id}, error {exc!r}")
        return Response(status_code=503, headers={"Retry-After": "300"})
    etag = _strong_etag(body)
    await cache.put_feed(cache_key, body, etag, time.time())
    return _feed_response(request, body, etag)


async def _force_tree_refresh(tree: MailboxTree) -> None:
    """Force ONE tree rebuild regardless of TTL (SPEC.md §6.1).

    Used only before declaring a folder permanently gone off a stale/kv-restored
    tree, so a cold/stale snapshot is never persisted as a permanent "deleted"
    verdict. Reaches into the tree's own lock/refresh to bypass the TTL freshness
    gate that ensure_fresh() applies; on a failing refresh with an existing tree,
    _refresh() keeps the stale tree and returns without raising."""
    async with tree._lock:  # noqa: SLF001 - deliberate: force a refresh past the TTL
        await tree._refresh()  # noqa: SLF001


async def _in_thread_render(emails, mailbox_id, mac, signed_params, title):
    return await asyncio.to_thread(
        _render_feed_body,
        emails=emails,
        mailbox_id=mailbox_id,
        mac=mac,
        signed_params=signed_params,
        title=title,
    )


async def _serve_error_feed(
    request: Request,
    mailbox_id: str,
    mac: str,
    slug: str,
    signed_params: FeedParams,
) -> Response:
    # Do NOT cache the explanation feed (SPEC.md §6.1/§6.4): caching it for
    # cache_ttl would persist a "folder deleted" verdict that may really be just a
    # cold/stale tree. The body is byte-deterministic (stable id + deterministic
    # date), so regenerating it on every poll is cheap and still 304-able.
    body = _build_error_feed(mailbox_id, mac, slug, signed_params)
    etag = _strong_etag(body)
    return _feed_response(request, body, etag)


# --- Routes: permalink -------------------------------------------------------


@app.get("/f/{slug}/{mailbox_id}/{mac}/e/{email_id}.html")
async def permalink(slug: str, mailbox_id: str, mac: str, email_id: str, request: Request) -> Response:
    signed_params = _parse_signed_params(request)
    epoch = settings.epoch_for(mailbox_id)
    if not verify_feed_mac(mac, mailbox_id, signed_params, epoch):
        return Response(status_code=404)

    jmap: JmapClient = request.app.state.jmap
    tree: MailboxTree = request.app.state.tree
    health: HealthState = request.app.state.health

    try:
        email = await jmap.get_email(email_id)
        health.record(True)
    except JmapNotFound:
        health.record(True)
        return Response(status_code=410)
    except JmapError as exc:
        health.record(False, repr(exc))
        return Response(status_code=503, headers={"Retry-After": "300"})

    if email is None:
        return Response(status_code=410)  # deleted/moved (SPEC.md §9)

    # The email must actually belong to THIS folder (or a signed child) — else a
    # feed's link would read mail from any folder (SPEC.md §5.1 p.6).
    allowed = {mailbox_id}
    if signed_params.children:
        try:
            await tree.ensure_fresh()
        except JmapError:
            pass  # fall back to whatever tree we have
        allowed.update(tree.children_ids(mailbox_id))
    if not (set(email.mailbox_ids) & allowed):
        return Response(status_code=410)

    permalink_url = f"{settings.base_url}/f/{slug}/{mailbox_id}/{mac}/e/{quote(email_id, safe='')}.html"
    signed_query = canon_params(signed_params)
    if signed_query:
        permalink_url += "?" + signed_query
    feed_prefix = f"{settings.base_url}/f/{slug}/{mailbox_id}/{mac}"
    media_url = _make_media_url(feed_prefix, mac, signed_query)

    rendered = await asyncio.to_thread(
        render_email, email, media_url=media_url, permalink=permalink_url
    )

    who = escape(email.from_name or email.from_email or "unknown sender")
    when = escape(email.received_at.isoformat())
    page = render_template(
        "permalink.html",
        {
            "title": escape(_entry_title(email)),
            "meta": f"{who} · {when}",
            "content": rendered.html,  # already sanitised, feed-safe HTML
        },
    )
    return HTMLResponse(
        page,
        headers={
            "X-Robots-Tag": "noindex, nofollow, noarchive",
            "Referrer-Policy": "no-referrer",
            "Cache-Control": "private, max-age=300",
            # Only our own (media-proxied) images; no other external resources.
            "Content-Security-Policy": (
                "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; base-uri 'none'"
            ),
        },
    )


# --- Routes: media -----------------------------------------------------------


@app.get("/f/{slug}/{mailbox_id}/{mac}/m/{blob_id}/{sig}/{name}")
async def media(
    slug: str,
    mailbox_id: str,
    mac: str,
    blob_id: str,
    sig: str,
    name: str,
    request: Request,
) -> Response:
    signed_params = _parse_signed_params(request)
    epoch = settings.epoch_for(mailbox_id)
    proxy: MediaProxy = request.app.state.media
    return await proxy.handle(
        mailbox_id=mailbox_id,
        mac=mac,
        blob_id=blob_id,
        sig=sig,
        name=name,
        declared_type=request.query_params.get("ct", ""),
        params=signed_params,
        epoch=epoch,
        request=request,
    )


# --- Routes: discovery -------------------------------------------------------


@app.get("/")
async def index() -> Response:
    return await discovery.get_index()


@app.post("/")
async def index_post(request: Request) -> Response:
    return await discovery.post_index(request, request.app.state.tree, request.app.state.limiter)


# --- Routes: ops -------------------------------------------------------------


@app.get("/health")
async def health(request: Request) -> Response:
    """Liveness (always 200 while the process is up) plus the LAST known JMAP
    probe and cache/tree ages. Does NOT hit Fastmail (SPEC.md §10.4)."""
    state: HealthState = request.app.state.health
    tree: MailboxTree = request.app.state.tree
    checked = (
        datetime.fromtimestamp(state.jmap_checked_at, timezone.utc).isoformat()
        if state.jmap_checked_at is not None
        else None
    )
    return JSONResponse(
        {
            "status": "ok",
            "jmap": {
                "ok": state.jmap_ok,
                "checked_at": checked,
                "error": state.jmap_error,
            },
            "mailbox_tree": {
                "loaded": tree.has_tree,
                "folders": tree.folder_count,
                "age_seconds": tree.age_seconds,
                "last_refresh_ok": tree.last_refresh_ok,
            },
        },
        headers={"Cache-Control": "no-store", "X-Robots-Tag": FEED_ROBOTS},
    )


@app.get("/robots.txt")
async def robots() -> Response:
    return PlainTextResponse(
        "User-agent: *\nDisallow: /\n",
        headers={"X-Robots-Tag": FEED_ROBOTS, "Cache-Control": "public, max-age=86400"},
    )
