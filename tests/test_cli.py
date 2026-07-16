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


def test_build_opml_excludes_folders_blocked_by_allowlist(monkeypatch):
    monkeypatch.setattr(settings, "mail2rss_allowed_folders", "Tech")
    folders = [
        (Mailbox(id="M1", name="Tech", parent_id=None, role=None, total_emails=3), "Tech"),
        (Mailbox(id="M2", name="Secret", parent_id=None, role=None, total_emails=1), "Secret"),
    ]
    opml = build_opml(folders)
    # A URL the server would silently 404 must never be emitted (SPEC.md §4.8).
    assert opml.count("<outline") == 1
    assert "Tech" in opml
    assert "Secret" not in opml


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


# --------------------------------------------------------------------------- #
# Allowlist in the JMAP-backed listings (SPEC.md §4.8)
# --------------------------------------------------------------------------- #


def _fake_tree(monkeypatch, rows):
    """Replace src.cli._load_tree with a stub returning the prepared rows."""

    class FakeTree:
        def list_folders(self, *, include_system=False):
            return rows

    async def fake_load_tree(include_system=True):
        return FakeTree()

    monkeypatch.setattr("src.cli._load_tree", fake_load_tree)


_ALLOWLIST_ROWS = [
    (Mailbox(id="M1", name="Tech", parent_id=None, role=None, total_emails=3), "Tech"),
    (Mailbox(id="M2", name="Secret", parent_id=None, role=None, total_emails=1), "Secret"),
]


def test_feeds_excludes_blocked_folders(monkeypatch, capsys):
    _fake_tree(monkeypatch, _ALLOWLIST_ROWS)
    monkeypatch.setattr(settings, "mail2rss_allowed_folders", "Tech")
    rc = run_cli(["feeds"])
    assert rc == 0
    out = capsys.readouterr().out
    # The server would silently 404 the blocked folder: no URL is printed for it.
    assert "M1" in out and "Tech" in out
    assert "M2" not in out and "Secret" not in out


def test_opml_command_excludes_blocked_folders(monkeypatch, capsys):
    _fake_tree(monkeypatch, _ALLOWLIST_ROWS)
    monkeypatch.setattr(settings, "mail2rss_allowed_folders", "Tech")
    rc = run_cli(["opml"])
    assert rc == 0
    out = capsys.readouterr().out
    assert out.count("<outline") == 1
    assert "Secret" not in out


def test_folders_lists_everything_and_marks_blocked(monkeypatch, capsys):
    _fake_tree(monkeypatch, _ALLOWLIST_ROWS)
    monkeypatch.setattr(settings, "mail2rss_allowed_folders", "Tech")
    rc = run_cli(["folders"])
    assert rc == 0
    lines = capsys.readouterr().out.splitlines()
    # `folders` is a raw-tree inspection tool: it still lists EVERYTHING...
    m1_line = next(line for line in lines if line.startswith("M1\t"))
    m2_line = next(line for line in lines if line.startswith("M2\t"))
    # ...but marks the rows the server would 404, so patterns can be debugged.
    assert "[excluded by MAIL2RSS_ALLOWED_FOLDERS]" in m2_line
    assert "excluded" not in m1_line


def test_folders_has_no_marker_when_allowlist_off(monkeypatch, capsys):
    _fake_tree(monkeypatch, _ALLOWLIST_ROWS)
    monkeypatch.setattr(settings, "mail2rss_allowed_folders", "")
    rc = run_cli(["folders"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "M1" in out and "M2" in out
    assert "excluded" not in out
