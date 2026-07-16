"""Tests for src/discovery.py — the client-side link-calculator page (SPEC.md §4.4).

The page is a static calculator: the browser computes the feed MAC via WebCrypto
and the server neither receives the secret nor reveals any mailbox data. No JMAP
mocks appear here on purpose — the page must never touch Fastmail.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from src.app import app
from src.crypto import _b32, _derive_keys
from src.settings import settings

TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "templates" / "discovery.html"


@pytest.fixture(autouse=True)
def _isolated_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "cache_db_path", str(tmp_path / "cache.db"))


# --------------------------------------------------------------------------- #
# GET / — the static calculator page
# --------------------------------------------------------------------------- #


def test_get_index_serves_calculator_with_base_url():
    with TestClient(app) as client:
        r = client.get("/")
    assert r.status_code == 200
    body = r.text
    # The calculator form fields are present.
    assert 'id="secret"' in body
    assert 'id="mailbox"' in body
    # The configured BASE_URL is embedded for the client-side URL assembly.
    assert settings.base_url in body


def test_get_index_exposes_no_mailbox_data():
    with TestClient(app) as client:
        r = client.get("/")
    body = r.text
    # No folder tree, no folder rows, no OPML: the server sends only the static
    # page — folder ids come from the CLI (`mail2rss folders`).
    assert 'class="folder"' not in body
    assert 'class="folders"' not in body
    assert "opml;base64" not in body


def test_get_index_keeps_hygiene_headers():
    with TestClient(app) as client:
        r = client.get("/")
    assert r.headers["x-robots-tag"] == "noindex, nofollow, noarchive"
    assert r.headers["referrer-policy"] == "no-referrer"
    assert r.headers["cache-control"] == "no-store"
    csp = r.headers["content-security-policy"]
    assert "default-src 'none'" in csp
    assert "style-src 'unsafe-inline'" in csp
    assert "script-src 'unsafe-inline'" in csp


# --------------------------------------------------------------------------- #
# POST / — the route no longer exists
# --------------------------------------------------------------------------- #


def test_post_index_route_is_gone():
    # Starlette answers 405 on a known path with an unsupported method: the
    # server no longer accepts (or compares) a secret at all.
    with TestClient(app) as client:
        r = client.post("/", data={"secret": "whatever"})
    assert r.status_code == 405


# --------------------------------------------------------------------------- #
# JS <-> Python parity: the template's self-test vector
# --------------------------------------------------------------------------- #


def test_selftest_vector_matches_python_implementation():
    """Pin the in-browser WebCrypto MAC and src/crypto.py to the same bytes.

    The template runs feedMac(SELFTEST...) on load and refuses to work unless it
    reproduces SELFTEST.mac; here we recompute that same vector with the Python
    implementation (replicating feed_mac(), but with the template's explicit
    secret instead of settings). If either side drifts, this test goes red.
    """
    html = TEMPLATE_PATH.read_text(encoding="utf-8")
    match = re.search(
        r"SELFTEST\s*=\s*\{\s*"
        r"secret:\s*'(?P<secret>[^']+)',\s*"
        r"mailbox:\s*'(?P<mailbox>[^']+)',\s*"
        r"canon:\s*'(?P<canon>[^']*)',\s*"
        r"epoch:\s*'(?P<epoch>[^']*)',\s*"
        r"mac:\s*'(?P<mac>[^']+)'",
        html,
    )
    assert match is not None, "SELFTEST constants not found in discovery.html"

    k_feed, _ = _derive_keys(match["secret"])
    msg = b"\x00".join(
        (
            match["mailbox"].encode("utf-8"),
            match["canon"].encode("utf-8"),
            match["epoch"].encode("utf-8"),
        )
    )
    mac = _b32(hmac.new(k_feed, msg, hashlib.sha256).digest())
    assert mac == match["mac"]
