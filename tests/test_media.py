"""Tests for src/media.py — the media proxy (SPEC.md §8.1, §14.2).

The security invariant: the attacker chooses the attachment bytes, so the declared
type is authoritative only via the allowlist + nosniff, never by sniffing bytes.
"""

from __future__ import annotations

from urllib.parse import quote

import httpx
import pytest
import respx
from starlette.testclient import TestClient

from src.app import app
from src.crypto import canon_params, feed_mac, media_sig
from src.models import FeedParams
from src.settings import settings

SESSION_URL = "https://api.fastmail.com/jmap/session"
API_URL = "https://api.fastmail.test/jmap/api/"
DOWNLOAD_URL = "https://download.fastmail.test/dl/{accountId}/{blobId}/{name}?type={type}"
ACCOUNT_ID = "u1"

SESSION_JSON = {
    "apiUrl": API_URL,
    "downloadUrl": DOWNLOAD_URL,
    "primaryAccounts": {"urn:ietf:params:jmap:mail": ACCOUNT_ID},
}


@pytest.fixture(autouse=True)
def _isolated_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "cache_db_path", str(tmp_path / "cache.db"))


def _mock_session():
    respx.get(SESSION_URL).mock(return_value=httpx.Response(200, json=SESSION_JSON))


def _mock_download(content: bytes, status: int = 200):
    return respx.get(url__regex=r"https://download\.fastmail\.test/.*").mock(
        return_value=httpx.Response(status, content=content)
    )


def _media_path(
    *, blob_id="B1", name="img.png", ct="image/png", mailbox_id="M1", params=FeedParams(), mac=None, sig=None
):
    mac = mac or feed_mac(mailbox_id, params, settings.epoch_for(mailbox_id))
    sig = sig or media_sig(mac, blob_id)
    query = "ct=" + quote(ct, safe="")
    canon = canon_params(params)
    if canon:
        query += "&" + canon
    return f"/f/tech/{mailbox_id}/{mac}/m/{blob_id}/{sig}/{name}?{query}"


# --------------------------------------------------------------------------- #
# Signature checks
# --------------------------------------------------------------------------- #


@respx.mock
def test_unsigned_media_is_404():
    _mock_session()
    with TestClient(app) as client:
        r = client.get(_media_path(sig="aaaaaaaaaaaaaaaaaaaaaaaaaa"))
    assert r.status_code == 404


@respx.mock
def test_foreign_feed_sig_is_404():
    _mock_session()
    # A sig issued for a DIFFERENT feed's mac must not authorise this blob here.
    foreign_mac = feed_mac("M2", FeedParams(), "")
    foreign_sig = media_sig(foreign_mac, "B1")
    with TestClient(app) as client:
        r = client.get(_media_path(sig=foreign_sig))
    assert r.status_code == 404


@respx.mock
def test_media_mac_not_valid_for_path_mailbox_is_404():
    _mock_session()
    # Correct sig for macM2/B1, but placed under mailbox M1 in the path: the feed
    # mac must also match the path's mailbox (SPEC.md §8.1 p.3).
    mac_m2 = feed_mac("M2", FeedParams(), "")
    sig = media_sig(mac_m2, "B1")
    with TestClient(app) as client:
        r = client.get(_media_path(mailbox_id="M1", mac=mac_m2, sig=sig))
    assert r.status_code == 404


# --------------------------------------------------------------------------- #
# Content-Type handling (SPEC.md §8.1 p.5, §14.2)
# --------------------------------------------------------------------------- #


@respx.mock
def test_svg_is_not_served_inline():
    _mock_session()
    _mock_download(b"<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>")
    with TestClient(app) as client:
        r = client.get(_media_path(ct="image/svg+xml", name="x.svg"))
    assert r.status_code == 200
    # Never inline; the declared svg type is not echoed back.
    assert "attachment" in r.headers.get("content-disposition", "").lower()
    assert "svg" not in r.headers["content-type"].lower()
    assert r.headers["X-Content-Type-Options"] == "nosniff"


@respx.mock
def test_png_with_html_bytes_served_as_png_not_sniffed():
    _mock_session()
    html_bytes = b"<html><script>alert('xss')</script></html>"
    _mock_download(html_bytes)
    with TestClient(app) as client:
        r = client.get(_media_path(ct="image/png"))
    assert r.status_code == 200
    # The declared type wins; the bytes are NOT sniffed into text/html.
    assert r.headers["content-type"].startswith("image/png")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["Content-Security-Policy"] == "sandbox; default-src 'none'"
    assert "inline" in r.headers.get("content-disposition", "").lower()
    assert r.content == html_bytes  # served verbatim, just with a safe type


@respx.mock
def test_allowlisted_image_has_immutable_cache_and_length():
    _mock_session()
    _mock_download(b"PNGDATA")
    with TestClient(app) as client:
        r = client.get(_media_path(ct="image/jpeg", name="p.jpg"))
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("image/jpeg")
    assert "immutable" in r.headers["Cache-Control"]
    assert int(r.headers["Content-Length"]) == len(b"PNGDATA")


# --------------------------------------------------------------------------- #
# Size limit (SPEC.md §8.1 p.7)
# --------------------------------------------------------------------------- #


@respx.mock
def test_oversized_image_rejected():
    _mock_session()
    _mock_download(b"x" * (5 * 1024 * 1024 + 1))  # over the 5 MB cap
    with TestClient(app) as client:
        r = client.get(_media_path(ct="image/png"))
    assert r.status_code == 502


@respx.mock
def test_missing_blob_is_not_2xx():
    _mock_session()
    _mock_download(b"", status=404)
    with TestClient(app) as client:
        r = client.get(_media_path(ct="image/png"))
    assert r.status_code == 502


@respx.mock
def test_media_served_from_cache_on_second_request():
    _mock_session()
    route = _mock_download(b"PNGDATA")
    with TestClient(app) as client:
        client.get(_media_path(ct="image/png"))
        client.get(_media_path(ct="image/png"))
    # Second request is a cache hit: Fastmail is fetched only once.
    assert route.call_count == 1
