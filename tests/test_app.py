"""Tests for src/app.py — the HTTP feed/permalink/health routes (SPEC.md §5, §6, §9)."""

from __future__ import annotations

import json
import re

import httpx
import pytest
import respx
from lxml import etree
from starlette.testclient import TestClient

from src.app import app
from src.crypto import canon_params, feed_mac, feed_url, media_sig
from src.feed import ATOM_NS
from src.models import FeedParams
from src.settings import settings

SESSION_URL = "https://api.fastmail.com/jmap/session"
API_URL = "https://api.fastmail.test/jmap/api/"
DOWNLOAD_URL = "https://download.fastmail.test/dl/{accountId}/{blobId}/{name}?type={type}"
ACCOUNT_ID = "u1"
_ATOM = f"{{{ATOM_NS}}}"

SESSION_JSON = {
    "apiUrl": API_URL,
    "downloadUrl": DOWNLOAD_URL,
    "primaryAccounts": {"urn:ietf:params:jmap:mail": ACCOUNT_ID},
}

MAILBOX_M1 = {"id": "M1", "name": "Tech", "parentId": None, "role": None, "totalEmails": 2}

EMAIL_1 = {
    "id": "E1",
    "messageId": ["<m1@example.com>"],
    "subject": "Weekly digest",
    "from": [{"name": "News", "email": "news@example.com"}],
    "receivedAt": "2026-07-10T08:00:00Z",
    "preview": "hi",
    "mailboxIds": {"M1": True},
    "htmlBody": [{"partId": "1", "type": "text/html"}],
    "textBody": [],
    "bodyValues": {"1": {"value": "<p>Hello world</p>", "isTruncated": False}},
    "attachments": [],
    "header:List-Unsubscribe:asURLs": [],
    "header:List-Id:asText": "tech.example.com",
}


# --------------------------------------------------------------------------- #
# JMAP mock router
# --------------------------------------------------------------------------- #


class JmapMock:
    """A respx side_effect that answers Mailbox/get, Email/query and Email/get and
    records the last Email/query limit. Toggling ``fail_emails`` returns HTTP 500
    for the email calls only (the tree refresh keeps working)."""

    def __init__(self, mailboxes, emails):
        self.mailboxes = mailboxes
        self.emails = emails
        self.fail_emails = False
        self.last_query_limit = None
        self.last_query_filter = None
        self.email_call_count = 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        calls = body["methodCalls"]
        names = [c[0] for c in calls]
        if ("Email/query" in names or "Email/get" in names):
            self.email_call_count += 1
            if self.fail_emails:
                return httpx.Response(500, text="boom")
        responses = []
        for name, args, cid in calls:
            if name == "Mailbox/get":
                responses.append(["Mailbox/get", {"accountId": ACCOUNT_ID, "list": self.mailboxes}, cid])
            elif name == "Email/query":
                self.last_query_limit = args.get("limit")
                self.last_query_filter = args.get("filter")
                responses.append(
                    ["Email/query", {"accountId": ACCOUNT_ID, "ids": [e["id"] for e in self.emails]}, cid]
                )
            elif name == "Email/get":
                responses.append(
                    ["Email/get", {"accountId": ACCOUNT_ID, "list": self.emails, "notFound": []}, cid]
                )
        return httpx.Response(200, json={"methodResponses": responses})


def _mock_jmap(mailboxes=None, emails=None) -> JmapMock:
    respx.get(SESSION_URL).mock(return_value=httpx.Response(200, json=SESSION_JSON))
    mock = JmapMock(mailboxes if mailboxes is not None else [MAILBOX_M1], emails or [EMAIL_1])
    respx.post(API_URL).mock(side_effect=mock)
    return mock


@pytest.fixture(autouse=True)
def _isolated_cache(tmp_path, monkeypatch):
    # Every test gets a fresh, disposable cache under tmp — never data/cache.db.
    monkeypatch.setattr(settings, "cache_db_path", str(tmp_path / "cache.db"))


def _feed_path(mailbox_id="M1", params=FeedParams(), slug="tech", mac=None):
    epoch = settings.epoch_for(mailbox_id)
    mac = mac or feed_mac(mailbox_id, params, epoch)
    query = canon_params(params)
    path = f"/f/{slug}/{mailbox_id}/{mac}/atom.xml"
    return path + (f"?{query}" if query else "")


# --------------------------------------------------------------------------- #
# Feed: happy path + MAC
# --------------------------------------------------------------------------- #


@respx.mock
def test_valid_mac_returns_atom():
    _mock_jmap()
    with TestClient(app) as client:
        r = client.get(_feed_path())
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/atom+xml")
    root = etree.fromstring(r.content)
    assert etree.QName(root).localname == "feed"
    assert root.find(f"{_ATOM}entry") is not None
    assert "ETag" in r.headers
    assert r.headers["X-Robots-Tag"] == "noindex, nofollow, noarchive"
    assert r.headers["Cache-Control"] == "private, max-age=300"


@respx.mock
def test_tampered_mac_is_404():
    _mock_jmap()
    with TestClient(app) as client:
        r = client.get("/f/tech/M1/aaaaaaaaaaaaaaaaaaaaaaaaaa/atom.xml")
    assert r.status_code == 404


@respx.mock
def test_tampered_limit_without_resigning_is_404():
    _mock_jmap()
    # A default-signed mac in the URL, but the query bumps limit -> canon differs.
    default_mac = feed_mac("M1", FeedParams(), "")
    with TestClient(app) as client:
        r = client.get(f"/f/tech/M1/{default_mac}/atom.xml?limit=99999")
    assert r.status_code == 404


@respx.mock
def test_valid_mac_high_limit_is_served_but_clamped():
    mock = _mock_jmap()
    # A mac legitimately signed for limit=99999: honoured, but the fetch is capped.
    path = _feed_path(params=FeedParams(limit=99999))
    with TestClient(app) as client:
        r = client.get(path)
    assert r.status_code == 200
    assert mock.last_query_limit == settings.max_limit  # clamped to the ceiling


@respx.mock
def test_unknown_query_param_ignored_same_etag():
    _mock_jmap()
    with TestClient(app) as client:
        r1 = client.get(_feed_path())
        r2 = client.get(_feed_path() + "?foo=bar" if "?" not in _feed_path() else _feed_path() + "&foo=bar")
    assert r1.status_code == 200 and r2.status_code == 200
    assert r1.headers["ETag"] == r2.headers["ETag"]


@respx.mock
def test_if_none_match_returns_304():
    _mock_jmap()
    with TestClient(app) as client:
        r1 = client.get(_feed_path())
        etag = r1.headers["ETag"]
        r2 = client.get(_feed_path(), headers={"If-None-Match": etag})
    assert r2.status_code == 304
    assert r2.content == b""


# --------------------------------------------------------------------------- #
# Feed: error semantics (SPEC.md §6.4)
# --------------------------------------------------------------------------- #


@respx.mock
def test_transient_failure_with_warm_cache_serves_stale(monkeypatch):
    mock = _mock_jmap()
    monkeypatch.setattr(settings, "cache_ttl", 0)  # force re-fetch every request
    with TestClient(app) as client:
        r1 = client.get(_feed_path())
        assert r1.status_code == 200
        mock.fail_emails = True  # JMAP now 500s the email calls
        r2 = client.get(_feed_path())
    assert r2.status_code == 200
    assert r2.headers["X-Upstream-Status"] == "stale"
    # Never an empty feed on an upstream error: the stale body still has the entry.
    root = etree.fromstring(r2.content)
    assert root.find(f"{_ATOM}entry") is not None


@respx.mock
def test_transient_failure_cold_returns_503_not_empty_feed():
    mock = _mock_jmap()
    mock.fail_emails = True  # fail from the very first request (no cache)
    with TestClient(app) as client:
        r = client.get(_feed_path())
    assert r.status_code == 503
    assert r.headers["Retry-After"] == "300"
    assert r.content == b"" or b"<entry" not in r.content


@respx.mock
def test_deleted_folder_returns_explanation_feed_with_stable_id():
    # Mailbox/get returns a tree WITHOUT M1 -> the folder is gone.
    _mock_jmap(mailboxes=[{"id": "OTHER", "name": "Other", "parentId": None, "role": None, "totalEmails": 0}])
    path = _feed_path()
    with TestClient(app) as client:
        r1 = client.get(path)
        r2 = client.get(path)
    assert r1.status_code == 200 and r2.status_code == 200
    root1 = etree.fromstring(r1.content)
    root2 = etree.fromstring(r2.content)
    id1 = root1.find(f"{_ATOM}entry/{_ATOM}id").text
    id2 = root2.find(f"{_ATOM}entry/{_ATOM}id").text
    assert id1 == id2  # stable across polls -> never resurfaces as unread
    content = root1.find(f"{_ATOM}entry/{_ATOM}content").text
    assert "deleted" in content.lower()


# --------------------------------------------------------------------------- #
# Permalink (SPEC.md §9, §5.1 p.6)
# --------------------------------------------------------------------------- #


@respx.mock
def test_permalink_renders_email_in_folder():
    _mock_jmap()
    mac = feed_mac("M1", FeedParams(), "")
    with TestClient(app) as client:
        r = client.get(f"/f/tech/M1/{mac}/e/E1.html")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    assert r.headers["X-Robots-Tag"].startswith("noindex")
    assert "Hello world" in r.text
    assert 'content="no-referrer"' in r.text


@respx.mock
def test_permalink_for_email_in_other_folder_is_not_content():
    other = dict(EMAIL_1, id="E2", mailboxIds={"OTHER": True})
    _mock_jmap(emails=[other])
    mac = feed_mac("M1", FeedParams(), "")
    with TestClient(app) as client:
        r = client.get(f"/f/tech/M1/{mac}/e/E2.html")
    assert r.status_code in (404, 410)
    assert "Hello world" not in r.text


@respx.mock
def test_permalink_bad_mac_is_404():
    _mock_jmap()
    with TestClient(app) as client:
        r = client.get("/f/tech/M1/aaaaaaaaaaaaaaaaaaaaaaaaaa/e/E1.html")
    assert r.status_code == 404


# --------------------------------------------------------------------------- #
# Ops routes
# --------------------------------------------------------------------------- #


@respx.mock
def test_health_does_not_hit_fastmail():
    session = respx.get(SESSION_URL).mock(return_value=httpx.Response(200, json=SESSION_JSON))
    api = respx.post(API_URL).mock(return_value=httpx.Response(200, json={"methodResponses": []}))
    with TestClient(app) as client:
        r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert session.call_count == 0
    assert api.call_count == 0


@respx.mock
def test_index_has_no_feed_list():
    _mock_jmap()
    with TestClient(app) as client:
        r = client.get("/")
    assert r.status_code == 200
    # No feed index anywhere: the calculator's inline JS contains the literal
    # "/atom.xml" path suffix, but no concrete signed feed URL (no 26-char mac).
    assert re.search(r"/f/[^/\s\"']+/[^/\s\"']+/[a-z2-7]{26}/atom\.xml", r.text) is None
    assert r.headers["X-Robots-Tag"].startswith("noindex")


@respx.mock
def test_robots_disallows_everything():
    with TestClient(app) as client:
        r = client.get("/robots.txt")
    assert r.status_code == 200
    assert "Disallow: /" in r.text


@respx.mock
def test_unknown_path_is_404():
    with TestClient(app) as client:
        r = client.get("/nope")
    assert r.status_code == 404


@respx.mock
def test_mac_never_appears_in_logs():
    from loguru import logger

    _mock_jmap()
    path = _feed_path()
    mac = path.split("/")[4]
    captured: list[str] = []
    sink_id = logger.add(captured.append, level="DEBUG")
    try:
        with TestClient(app) as client:
            client.get(path)
    finally:
        logger.remove(sink_id)
    joined = "".join(captured)
    assert mac not in joined  # the capability token is never logged (SPEC.md §5.2 p.5)
    assert "mac_hash" in joined  # only a 6-char hash of it is


# --------------------------------------------------------------------------- #
# FIX 1: a message with U+FFFE/U+FFFF must not 500 the feed (SPEC.md §7.5 step 14)
# --------------------------------------------------------------------------- #


@respx.mock
def test_feed_with_noncharacters_returns_200_not_500():
    bad = dict(
        EMAIL_1,
        id="Ebad",
        subject="Weekly ￿ digest ￾ end",
        bodyValues={"1": {"value": "<p>Hello ￿ world ￾ \x0c</p>", "isTruncated": False}},
    )
    _mock_jmap(emails=[bad])
    with TestClient(app) as client:
        r = client.get(_feed_path())
    assert r.status_code == 200  # not a 500 from lxml's XML-compat ValueError
    root = etree.fromstring(r.content)
    assert root.find(f"{_ATOM}entry") is not None


# --------------------------------------------------------------------------- #
# FIX 2: atom:id fallback must not depend on the JMAP Email.id (SPEC.md §7.2)
# --------------------------------------------------------------------------- #


def test_fallback_atom_id_independent_of_email_id():
    from fixtures.sample_emails import make_email

    from src.app import _fallback_seed, _render_feed_body
    from src.feed import entry_id

    e1 = make_email(id="E1", message_id=None)
    e2 = make_email(id="E2-COMPLETELY-DIFFERENT", message_id=None)  # same content, diff id
    # The fallback seed is built from stable content fields only, never Email.id.
    assert _fallback_seed(e1) == _fallback_seed(e2)
    assert entry_id(None, _fallback_seed(e1)) == entry_id(None, _fallback_seed(e2))

    mac = feed_mac("M1", FeedParams(), settings.epoch_for("M1"))

    def _atom_id(email):
        body, _ = _render_feed_body(
            emails=[email], mailbox_id="M1", mac=mac, signed_params=FeedParams(), title="Tech"
        )
        return etree.fromstring(body).find(f"{_ATOM}entry/{_ATOM}id").text

    # same content, different Email.id -> SAME atom:id (proves independence)
    assert _atom_id(e1) == _atom_id(e2)
    # different content -> different atom:id
    e3 = make_email(id="E1", message_id=None, subject="A totally different subject")
    assert _atom_id(e3) != _atom_id(e1)


# --------------------------------------------------------------------------- #
# FIX 3: the error feed's dates must be deterministic (SPEC.md §7.3/§14.2)
# --------------------------------------------------------------------------- #


def test_error_feed_body_is_byte_stable_across_calls():
    from src.app import _build_error_feed

    mac = feed_mac("M1", FeedParams(), settings.epoch_for("M1"))
    a = _build_error_feed("M1", mac, "tech", FeedParams())
    b = _build_error_feed("M1", mac, "tech", FeedParams())
    assert a == b  # deterministic date -> body/ETag/<updated> never jitter


# --------------------------------------------------------------------------- #
# FIX 4: the render/serialise path must never 500 the feed route (SPEC.md §6.4)
# --------------------------------------------------------------------------- #


@respx.mock
def test_render_failure_serves_stale_when_cache_warm(monkeypatch):
    import src.app as app_mod

    _mock_jmap()
    monkeypatch.setattr(settings, "cache_ttl", 0)  # force a re-render every request
    with TestClient(app) as client:
        r1 = client.get(_feed_path())
        assert r1.status_code == 200

        def boom(**_kw):
            raise RuntimeError("render exploded")

        monkeypatch.setattr(app_mod, "_render_feed_body", boom)
        r2 = client.get(_feed_path())
    assert r2.status_code == 200  # stale served, never a 500
    assert r2.headers["X-Upstream-Status"] == "stale"
    assert b"<entry" in r2.content  # never an empty-but-valid feed


@respx.mock
def test_render_failure_cold_returns_503_not_500(monkeypatch):
    import src.app as app_mod

    _mock_jmap()

    def boom(**_kw):
        raise RuntimeError("render exploded")

    monkeypatch.setattr(app_mod, "_render_feed_body", boom)
    with TestClient(app) as client:
        r = client.get(_feed_path())
    assert r.status_code == 503  # no cache to fall back to -> 503, never 500
    assert r.headers["Retry-After"] == "300"
    assert b"<entry" not in r.content


# --------------------------------------------------------------------------- #
# FIX 9: a stale/kv-restored tree must not persist a false "folder deleted"
# --------------------------------------------------------------------------- #


@respx.mock
def test_stale_tree_missing_folder_forces_refresh_and_serves_entries():
    from src.mailbox_tree import _KV_KEY, _dump
    from src.models import Mailbox

    # Mailbox/get fails on the FIRST call (cold: the tree loads a stale snapshot
    # from kv that lacks M1), then succeeds WITH M1 on the forced refresh.
    respx.get(SESSION_URL).mock(return_value=httpx.Response(200, json=SESSION_JSON))
    calls = {"mailbox_get": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        responses = []
        for name, args, cid in body["methodCalls"]:
            if name == "Mailbox/get":
                calls["mailbox_get"] += 1
                if calls["mailbox_get"] == 1:
                    return httpx.Response(500, text="down")
                responses.append(["Mailbox/get", {"accountId": ACCOUNT_ID, "list": [MAILBOX_M1]}, cid])
            elif name == "Email/query":
                responses.append(["Email/query", {"accountId": ACCOUNT_ID, "ids": ["E1"]}, cid])
            elif name == "Email/get":
                responses.append(["Email/get", {"accountId": ACCOUNT_ID, "list": [EMAIL_1], "notFound": []}, cid])
        return httpx.Response(200, json={"methodResponses": responses})

    respx.post(API_URL).mock(side_effect=handler)

    with TestClient(app) as client:
        # Pre-seed kv with a STALE tree lacking M1 -> the cold load returns it.
        stale = _dump([Mailbox(id="OTHER", name="Other", parent_id=None, role=None, total_emails=0)])
        app.state.cache.kv_put_sync(_KV_KEY, stale)
        r = client.get(_feed_path())
    assert r.status_code == 200
    root = etree.fromstring(r.content)
    title = root.find(f"{_ATOM}entry/{_ATOM}title").text
    # A forced refresh found M1 -> real entries, NOT the "folder deleted" feed.
    assert title == "Weekly digest"


# --------------------------------------------------------------------------- #
# Hard folder allowlist (SPEC.md §4.8)
# --------------------------------------------------------------------------- #


@respx.mock
def test_allowlist_matching_folder_is_served(monkeypatch):
    _mock_jmap()  # M1 "Tech" -> path "Tech"
    monkeypatch.setattr(settings, "mail2rss_allowed_folders", "Tech")
    with TestClient(app) as client:
        r = client.get(_feed_path())
    assert r.status_code == 200
    root = etree.fromstring(r.content)
    assert root.find(f"{_ATOM}entry") is not None


@respx.mock
def test_allowlist_blocked_folder_bare_404_no_email_query(monkeypatch):
    mock = _mock_jmap()
    monkeypatch.setattr(settings, "mail2rss_allowed_folders", "Newsletters")
    with TestClient(app) as client:
        blocked = client.get(_feed_path())
        bad_mac = client.get("/f/tech/M1/aaaaaaaaaaaaaaaaaaaaaaaaaa/atom.xml")
    # Bare 404, byte-identical to the invalid-MAC 404: no body, no explanation
    # feed, nothing confirmed.
    assert blocked.status_code == 404
    assert blocked.content == b""
    assert blocked.status_code == bad_mac.status_code
    assert blocked.content == bad_mac.content
    assert blocked.headers.get("content-type") == bad_mac.headers.get("content-type")
    # The gate short-circuits before JMAP is asked for any mail.
    assert mock.email_call_count == 0


@respx.mock
def test_allowlist_gate_runs_before_cache(monkeypatch):
    _mock_jmap()
    with TestClient(app) as client:
        r1 = client.get(_feed_path())
        assert r1.status_code == 200  # primes the SQLite feed cache (fresh entry)
        # A NEW pattern now blocks the folder: the cached body must NOT be served
        # even though it is younger than cache_ttl — the gate runs first.
        monkeypatch.setattr(settings, "mail2rss_allowed_folders", "Newsletters")
        r2 = client.get(_feed_path())
    assert r2.status_code == 404
    assert r2.content == b""


@respx.mock
def test_allowlist_filters_blocked_children_from_aggregate_query(monkeypatch):
    m_ok = {"id": "M2", "name": "Allowed", "parentId": "M1", "role": None, "totalEmails": 1}
    m_no = {"id": "M3", "name": "Blocked", "parentId": "M1", "role": None, "totalEmails": 1}
    mock = _mock_jmap(mailboxes=[MAILBOX_M1, m_ok, m_no])
    monkeypatch.setattr(settings, "mail2rss_allowed_folders", "Tech,Tech/Allowed")
    with TestClient(app) as client:
        r = client.get(_feed_path(params=FeedParams(children=True)))
    assert r.status_code == 200
    # The JMAP OR filter covers the parent and the allowed child only: the
    # blocked subfolder must not leak through the parent's aggregate feed.
    fltr = mock.last_query_filter
    if "conditions" in fltr:
        ids = {cond["inMailbox"] for cond in fltr["conditions"]}
    else:
        ids = {fltr["inMailbox"]}
    assert "M1" in ids
    assert "M2" in ids
    assert "M3" not in ids


@respx.mock
def test_allowlist_blocked_permalink_and_media_are_404(monkeypatch):
    mock = _mock_jmap()
    monkeypatch.setattr(settings, "mail2rss_allowed_folders", "Newsletters")
    download = respx.get(url__regex=r"https://download\.fastmail\.test/.*").mock(
        return_value=httpx.Response(200, content=b"PNGDATA")
    )
    mac = feed_mac("M1", FeedParams(), "")
    sig = media_sig(mac, "B1")
    with TestClient(app) as client:
        rp = client.get(f"/f/tech/M1/{mac}/e/E1.html")
        rm = client.get(f"/f/tech/M1/{mac}/m/B1/{sig}/img.png?ct=image%2Fpng")
    assert rp.status_code == 404 and rp.content == b""
    assert rm.status_code == 404 and rm.content == b""
    # Neither the email nor the blob was ever fetched from Fastmail.
    assert mock.email_call_count == 0
    assert download.call_count == 0


@respx.mock
def test_allowlist_media_bad_mac_short_circuits_before_gate(monkeypatch):
    # Ordering pin: on the media route the MAC check runs BEFORE the folder
    # gate, so a prober holding no valid MAC never triggers a mailbox-tree
    # refresh — response timing cannot leak whether a blocked folder exists.
    respx.get(SESSION_URL).mock(return_value=httpx.Response(200, json=SESSION_JSON))
    api = respx.post(API_URL).mock(side_effect=JmapMock([MAILBOX_M1], [EMAIL_1]))
    monkeypatch.setattr(settings, "mail2rss_allowed_folders", "Newsletters")  # blocks "Tech"
    bad_mac = "aaaaaaaaaaaaaaaaaaaaaaaaaa"
    sig = media_sig(bad_mac, "B1")
    with TestClient(app) as client:
        r = client.get(f"/f/tech/M1/{bad_mac}/m/B1/{sig}/img.png?ct=image%2Fpng")
    assert r.status_code == 404
    assert r.content == b""
    # The gate never ran: no Mailbox/get (or any other JMAP call) was made.
    assert not api.called


@respx.mock
def test_allowlist_no_tree_fails_closed_503(monkeypatch):
    # Allowlist on, first boot during a Fastmail outage: no tree at all (not even
    # the kv fallback — the cache is fresh per test) -> fail CLOSED, never open.
    respx.get(SESSION_URL).mock(return_value=httpx.Response(200, json=SESSION_JSON))
    respx.post(API_URL).mock(return_value=httpx.Response(500, text="down"))
    monkeypatch.setattr(settings, "mail2rss_allowed_folders", "Tech")
    with TestClient(app) as client:
        r = client.get(_feed_path())
    assert r.status_code == 503
    assert r.headers["Retry-After"] == "300"
