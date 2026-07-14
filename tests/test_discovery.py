"""Tests for src/discovery.py — the secret -> links page (SPEC.md §4.4)."""

from __future__ import annotations

import httpx
import pytest
import respx
from loguru import logger
from starlette.testclient import TestClient

from src.app import app
from src.settings import settings
from tests.conftest import TEST_SECRET

SESSION_URL = "https://api.fastmail.com/jmap/session"
API_URL = "https://api.fastmail.test/jmap/api/"
ACCOUNT_ID = "u1"

SESSION_JSON = {
    "apiUrl": API_URL,
    "downloadUrl": "https://download.fastmail.test/dl/{accountId}/{blobId}/{name}?type={type}",
    "primaryAccounts": {"urn:ietf:params:jmap:mail": ACCOUNT_ID},
}

MAILBOXES = [
    {"id": "M1", "name": "Tech", "parentId": None, "role": None, "totalEmails": 5},
    {"id": "Minbox", "name": "Inbox", "parentId": None, "role": "inbox", "totalEmails": 9},
]


@pytest.fixture(autouse=True)
def _isolated_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "cache_db_path", str(tmp_path / "cache.db"))


def _mock_jmap():
    respx.get(SESSION_URL).mock(return_value=httpx.Response(200, json=SESSION_JSON))

    def handler(request):
        return httpx.Response(
            200,
            json={"methodResponses": [["Mailbox/get", {"accountId": ACCOUNT_ID, "list": MAILBOXES}, "m"]]},
        )

    respx.post(API_URL).mock(side_effect=handler)


# --------------------------------------------------------------------------- #
# POST-only: the secret must never be accepted from the query string
# --------------------------------------------------------------------------- #


@respx.mock
def test_get_with_secret_in_query_is_rejected():
    with TestClient(app) as client:
        r = client.get(f"/?secret={TEST_SECRET}")
    assert r.status_code == 200
    # GET never lists folders: no folder rows, no feed URLs.
    assert 'class="folder"' not in r.text
    assert "atom.xml" not in r.text


# --------------------------------------------------------------------------- #
# Wrong secret: neutral error, secret never logged
# --------------------------------------------------------------------------- #


@respx.mock
def test_wrong_secret_neutral_error_and_not_logged():
    captured: list[str] = []
    sink_id = logger.add(captured.append, level="DEBUG")
    try:
        with TestClient(app) as client:
            r = client.post("/", data={"secret": "definitely-wrong-secret"})
    finally:
        logger.remove(sink_id)
    assert r.status_code == 401
    assert 'class="folder"' not in r.text
    assert "Invalid secret" in r.text
    joined = "".join(captured)
    assert "definitely-wrong-secret" not in joined


# --------------------------------------------------------------------------- #
# Correct secret: folder list with URLs
# --------------------------------------------------------------------------- #


@respx.mock
def test_correct_secret_lists_folders_with_urls():
    _mock_jmap()
    with TestClient(app) as client:
        r = client.post("/", data={"secret": TEST_SECRET})
    assert r.status_code == 200
    assert "Tech" in r.text
    assert "atom.xml" in r.text  # a ready feed URL is shown
    # System folders hidden by default (SPEC.md §4.4 p.6): the inbox mailbox id
    # (which would appear inside its feed URL) is absent.
    assert "Minbox" not in r.text


@respx.mock
def test_show_all_reveals_system_folders():
    _mock_jmap()
    with TestClient(app) as client:
        r = client.post("/", data={"secret": TEST_SECRET, "show_all": "1"})
    assert r.status_code == 200
    assert "Minbox" in r.text  # the inbox folder is now listed


@respx.mock
def test_correct_secret_not_logged():
    _mock_jmap()
    captured: list[str] = []
    sink_id = logger.add(captured.append, level="DEBUG")
    try:
        with TestClient(app) as client:
            client.post("/", data={"secret": TEST_SECRET})
    finally:
        logger.remove(sink_id)
    assert TEST_SECRET not in "".join(captured)


# --------------------------------------------------------------------------- #
# OPML export
# --------------------------------------------------------------------------- #


@respx.mock
def test_opml_export():
    _mock_jmap()
    with TestClient(app) as client:
        r = client.post("/?format=opml", data={"secret": TEST_SECRET})
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/x-opml")
    assert "attachment" in r.headers["content-disposition"].lower()
    assert "<opml" in r.text
    assert "atom.xml" in r.text


# --------------------------------------------------------------------------- #
# Rate limit (SPEC.md §4.4 p.3)
# --------------------------------------------------------------------------- #


@respx.mock
def test_rate_limited_after_five_attempts():
    # Wrong secret fails before any JMAP call, so no mock is needed; the limiter is
    # checked first, so all attempts count.
    statuses = []
    with TestClient(app) as client:
        for _ in range(6):
            statuses.append(client.post("/", data={"secret": "nope"}).status_code)
    assert statuses[:5] == [401] * 5
    assert statuses[5] == 429
