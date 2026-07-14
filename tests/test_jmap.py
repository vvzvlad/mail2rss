import json
from datetime import timezone

import httpx
import pytest
import respx

from src.jmap import JmapClient, JmapError, JmapNotFound

SESSION_URL = "https://api.fastmail.test/jmap/session"
API_URL = "https://api.fastmail.test/jmap/api/"
DOWNLOAD_URL = "https://download.fastmail.test/dl/{accountId}/{blobId}/{name}?type={type}"
ACCOUNT_ID = "u123"

SESSION_JSON = {
    "apiUrl": API_URL,
    "downloadUrl": DOWNLOAD_URL,
    "primaryAccounts": {"urn:ietf:params:jmap:mail": ACCOUNT_ID},
}

EMAIL_OBJ = {
    "id": "E1",
    "blobId": "BlobEmail",
    "messageId": ["<abc@example.com>"],
    "subject": "Привет мир",  # RFC2047 already decoded by JMAP (F5)
    "from": [{"name": "Alice", "email": "alice@example.com"}],
    "receivedAt": "2026-07-15T10:20:30Z",
    "sentAt": "2026-07-15T10:20:00Z",
    "preview": "hello preview",
    "mailboxIds": {"Mbox1": True},
    "hasAttachment": True,
    "htmlBody": [{"partId": "1", "type": "text/html"}],
    "textBody": [{"partId": "2", "type": "text/plain"}],
    "bodyValues": {
        "1": {"value": '<p>hi <img src="cid:img1"></p>', "isTruncated": True},
        "2": {"value": "hi text", "isTruncated": False},
    },
    "attachments": [
        {
            "partId": "3",
            "blobId": "BlobImg",
            "type": "image/png",
            "name": "img.png",
            "disposition": "inline",
            "cid": "img1",
            "size": 1234,
        }
    ],
    "header:List-Unsubscribe:asURLs": ["https://unsub.example.com/x"],
    "header:List-Id:asText": "newsletter.example.com",
}


def _session_route():
    return respx.get(SESSION_URL).mock(return_value=httpx.Response(200, json=SESSION_JSON))


def _client():
    return httpx.AsyncClient()


# --- Session -----------------------------------------------------------------


@respx.mock
async def test_get_session_parses_and_caches():
    route = _session_route()
    async with _client() as c:
        jc = JmapClient("secret-token", SESSION_URL, c)
        s1 = await jc.get_session()
        s2 = await jc.get_session()
    assert s1.account_id == ACCOUNT_ID
    assert s1.api_url == API_URL
    assert s1 is s2  # cached in-process
    assert route.call_count == 1


@respx.mock
async def test_session_sends_bearer_but_never_body_token():
    route = _session_route()
    async with _client() as c:
        jc = JmapClient("secret-token", SESSION_URL, c)
        await jc.get_session()
    assert route.calls.last.request.headers["Authorization"] == "Bearer secret-token"


# --- query_emails ------------------------------------------------------------


def _query_response():
    return {
        "methodResponses": [
            ["Email/query", {"accountId": ACCOUNT_ID, "ids": ["E1"]}, "q"],
            ["Email/get", {"accountId": ACCOUNT_ID, "list": [EMAIL_OBJ], "notFound": []}, "g"],
        ],
        "sessionState": "s1",
    }


@respx.mock
async def test_query_emails_single_request_two_calls_with_backref():
    _session_route()
    api = respx.post(API_URL).mock(return_value=httpx.Response(200, json=_query_response()))
    async with _client() as c:
        jc = JmapClient("tok", SESSION_URL, c)
        emails = await jc.query_emails(["Mbox1"], 20)

    assert api.call_count == 1
    body = json.loads(api.calls.last.request.content)
    calls = body["methodCalls"]
    assert len(calls) == 2
    assert calls[0][0] == "Email/query"
    assert calls[1][0] == "Email/get"
    # The #ids back-reference threads query results into get without a round-trip.
    assert calls[1][1]["#ids"] == {"resultOf": "q", "name": "Email/query", "path": "/ids"}
    assert calls[0][1]["filter"] == {"inMailbox": "Mbox1"}
    assert calls[0][1]["sort"] == [{"property": "receivedAt", "isAscending": False}]
    assert len(emails) == 1


@respx.mock
async def test_query_emails_parsing():
    _session_route()
    respx.post(API_URL).mock(return_value=httpx.Response(200, json=_query_response()))
    async with _client() as c:
        jc = JmapClient("tok", SESSION_URL, c)
        (email,) = await jc.query_emails(["Mbox1"], 20)

    # Timezone-aware UTC, taken from receivedAt, never now().
    assert email.received_at.tzinfo is not None
    assert email.received_at.utcoffset() == timezone.utc.utcoffset(None)
    assert email.received_at.year == 2026
    assert email.received_at.hour == 10 and email.received_at.minute == 20

    assert email.message_id == "<abc@example.com>"
    assert email.subject == "Привет мир"
    assert email.from_name == "Alice"
    assert email.from_email == "alice@example.com"
    assert email.mailbox_ids == ("Mbox1",)
    assert email.html_truncated is True
    assert email.html_body is not None and "cid:img1" in email.html_body
    assert email.text_body == "hi text"
    assert email.list_unsubscribe == ("https://unsub.example.com/x",)
    assert email.list_id == "newsletter.example.com"

    assert len(email.attachments) == 1
    att = email.attachments[0]
    assert att.cid == "img1"
    assert att.blob_id == "BlobImg"
    assert att.type == "image/png"
    assert att.disposition == "inline"
    assert att.size == 1234


@respx.mock
async def test_query_emails_multi_mailbox_uses_or_filter():
    _session_route()
    api = respx.post(API_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "methodResponses": [
                    ["Email/query", {"accountId": ACCOUNT_ID, "ids": []}, "q"],
                    ["Email/get", {"accountId": ACCOUNT_ID, "list": [], "notFound": []}, "g"],
                ]
            },
        )
    )
    async with _client() as c:
        jc = JmapClient("tok", SESSION_URL, c)
        await jc.query_emails(["Mbox1", "Mbox2"], 20)
    body = json.loads(api.calls.last.request.content)
    assert body["methodCalls"][0][1]["filter"] == {
        "operator": "OR",
        "conditions": [{"inMailbox": "Mbox1"}, {"inMailbox": "Mbox2"}],
    }


# --- get_email ---------------------------------------------------------------


@respx.mock
async def test_get_email_found():
    _session_route()
    respx.post(API_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "methodResponses": [
                    ["Email/get", {"accountId": ACCOUNT_ID, "list": [EMAIL_OBJ], "notFound": []}, "g"]
                ]
            },
        )
    )
    async with _client() as c:
        jc = JmapClient("tok", SESSION_URL, c)
        email = await jc.get_email("E1")
    assert email is not None and email.id == "E1"


@respx.mock
async def test_get_email_missing_returns_none():
    _session_route()
    respx.post(API_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "methodResponses": [
                    ["Email/get", {"accountId": ACCOUNT_ID, "list": [], "notFound": ["E9"]}, "g"]
                ]
            },
        )
    )
    async with _client() as c:
        jc = JmapClient("tok", SESSION_URL, c)
        assert await jc.get_email("E9") is None


# --- Mailboxes ---------------------------------------------------------------


@respx.mock
async def test_get_mailboxes_parsing():
    _session_route()
    respx.post(API_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "methodResponses": [
                    [
                        "Mailbox/get",
                        {
                            "accountId": ACCOUNT_ID,
                            "list": [
                                {"id": "M1", "name": "Inbox", "parentId": None, "role": "inbox", "totalEmails": 3},
                                {"id": "M2", "name": "Tech", "parentId": "M1", "role": None, "totalEmails": 7},
                            ],
                        },
                        "m",
                    ]
                ]
            },
        )
    )
    async with _client() as c:
        jc = JmapClient("tok", SESSION_URL, c)
        boxes = await jc.get_mailboxes()
    assert len(boxes) == 2
    inbox, tech = boxes
    assert inbox.role == "inbox" and inbox.parent_id is None
    assert tech.parent_id == "M1" and tech.role is None
    assert tech.total_emails == 7


# --- Errors ------------------------------------------------------------------


@respx.mock
async def test_http_500_raises_transient_jmap_error():
    _session_route()
    respx.post(API_URL).mock(return_value=httpx.Response(500, text="boom"))
    async with _client() as c:
        jc = JmapClient("tok", SESSION_URL, c)
        with pytest.raises(JmapError) as ei:
            await jc.query_emails(["Mbox1"], 20)
    assert ei.value.transient is True


@respx.mock
async def test_http_429_is_transient():
    _session_route()
    respx.post(API_URL).mock(return_value=httpx.Response(429, text="slow down"))
    async with _client() as c:
        jc = JmapClient("tok", SESSION_URL, c)
        with pytest.raises(JmapError) as ei:
            await jc.query_emails(["Mbox1"], 20)
    assert ei.value.transient is True


@respx.mock
async def test_unknown_mailbox_raises_not_found():
    _session_route()
    respx.post(API_URL).mock(
        return_value=httpx.Response(
            200,
            json={"methodResponses": [["error", {"type": "notFound"}, "q"]]},
        )
    )
    async with _client() as c:
        jc = JmapClient("tok", SESSION_URL, c)
        with pytest.raises(JmapNotFound):
            await jc.query_emails(["MboxGone"], 20)


# --- Blob streaming ----------------------------------------------------------


@respx.mock
async def test_stream_blob_builds_url_and_streams():
    _session_route()
    expected_url = "https://download.fastmail.test/dl/u123/BlobImg/img.png?type=image%2Fpng"
    route = respx.get(expected_url).mock(return_value=httpx.Response(200, content=b"PNGDATA"))
    async with _client() as c:
        jc = JmapClient("tok", SESSION_URL, c)
        chunks = [chunk async for chunk in jc.stream_blob("BlobImg", "img.png", "image/png")]
    assert b"".join(chunks) == b"PNGDATA"
    assert route.calls.last.request.headers["Authorization"] == "Bearer tok"


@respx.mock
async def test_stream_blob_404_raises_not_found():
    _session_route()
    respx.get(url__regex=r"https://download\.fastmail\.test/.*").mock(
        return_value=httpx.Response(404)
    )
    async with _client() as c:
        jc = JmapClient("tok", SESSION_URL, c)
        with pytest.raises(JmapNotFound):
            async for _ in jc.stream_blob("BlobGone", "x.png", "image/png"):
                pass


# --- Throttle shape ----------------------------------------------------------


async def test_jmap_rpc_bounded_times_out_inside_gate():
    import asyncio

    async with _client() as c:
        jc = JmapClient("tok", SESSION_URL, c, rpc_timeout=0.01)
        with pytest.raises(TimeoutError):
            async with jc.jmap_rpc_bounded(0.01):
                await asyncio.sleep(1)
