"""Tests for src/cli.py — offline URL/secret generation (SPEC.md §4.5)."""

from __future__ import annotations

from urllib.parse import urlsplit

from src.cli import build_opml, run_cli
from src.crypto import validate_secret, verify_feed_mac
from src.models import FeedParams, Mailbox
from src.settings import settings


def _mac_from_printed_url(url: str) -> tuple[str, str]:
    """Extract (mailbox_id, mac) from a /f/{slug}/{mailbox_id}/{mac}/atom.xml URL."""
    parts = urlsplit(url).path.split("/")
    # ['', 'f', slug, mailbox_id, mac, 'atom.xml']
    return parts[3], parts[4]


# --------------------------------------------------------------------------- #
# gen-secret
# --------------------------------------------------------------------------- #


def test_gen_secret_output_passes_validation(capsys):
    rc = run_cli(["gen-secret"])
    assert rc == 0
    out = capsys.readouterr().out.strip()
    assert validate_secret(out)


def test_gen_secret_is_random(capsys):
    run_cli(["gen-secret"])
    a = capsys.readouterr().out.strip()
    run_cli(["gen-secret"])
    b = capsys.readouterr().out.strip()
    assert a != b


# --------------------------------------------------------------------------- #
# url — offline, round-trips with the server's verifier
# --------------------------------------------------------------------------- #


def test_url_roundtrips_with_verify(capsys):
    rc = run_cli(["url", "--mailbox", "M9f3ac21b"])
    assert rc == 0
    url = capsys.readouterr().out.strip()
    mailbox_id, mac = _mac_from_printed_url(url)
    assert mailbox_id == "M9f3ac21b"
    # The URL the CLI printed is exactly one the running server would accept.
    epoch = settings.epoch_for(mailbox_id)
    assert verify_feed_mac(mac, mailbox_id, FeedParams(), epoch)


def test_url_with_limit_and_children_roundtrips(capsys):
    rc = run_cli(["url", "--mailbox", "M1", "--limit", "50", "--children"])
    assert rc == 0
    url = capsys.readouterr().out.strip()
    assert "children=1" in url and "limit=50" in url
    mailbox_id, mac = _mac_from_printed_url(url)
    params = FeedParams(limit=50, children=True)
    assert verify_feed_mac(mac, mailbox_id, params, settings.epoch_for(mailbox_id))


def test_url_default_has_no_query(capsys):
    run_cli(["url", "--mailbox", "M1"])
    url = capsys.readouterr().out.strip()
    assert url.endswith("/atom.xml")  # default params -> empty canonical query


# --------------------------------------------------------------------------- #
# build_opml — OPML now lives in the CLI only (SPEC.md §4.5)
# --------------------------------------------------------------------------- #


def test_build_opml_lists_folders_and_escapes_xml():
    folders = [
        (Mailbox(id="M1", name="Tech", parent_id=None, role=None, total_emails=3), "RSS/Tech"),
        (
            Mailbox(id="M2", name='B&W "News"', parent_id=None, role=None, total_emails=1),
            'RSS/B&W "News"',
        ),
    ]
    opml = build_opml(folders)
    assert "<opml" in opml
    assert opml.count("<outline") == 2  # one outline per folder
    assert "atom.xml" in opml
    # The path containing & and " is XML-escaped, never emitted raw.
    assert "RSS/B&amp;W &quot;News&quot;" in opml
    assert 'text="RSS/B&W' not in opml
