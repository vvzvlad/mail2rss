"""Tests for src/feed.py — Atom 1.0 serialiser (SPEC.md §7.1-7.4, §11)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

from lxml import etree

from fixtures.sample_emails import make_email
from src.feed import (
    ATOM_NS,
    NS_MAIL2RSS,
    FeedEntry,
    build_atom,
    entry_id,
    error_feed,
    strip_xml_incompatible,
)
from src.render import render_email

GOLDEN = Path(__file__).resolve().parent / "fixtures" / "golden_feed.xml"
_ATOM = f"{{{ATOM_NS}}}"


# --------------------------------------------------------------------------- #
# The golden document (locks byte-determinism, SPEC.md §11)
# --------------------------------------------------------------------------- #


def build_golden() -> bytes:
    """Deterministic fixture-email -> Atom document. Shared by the test and by
    tests/fixtures/golden_feed.xml so a format change fails loudly."""
    email = make_email(
        html_body=(
            '<p>Hello <a href="https://ex.com/x?utm_source=n&amp;k=1">link</a></p>'
        ),
    )
    rendered = render_email(email, media_url=lambda _p: None)
    permalink = (
        "https://rss.example.com/f/tech/M9f3ac21b/mac26/e/Ea1b2c3d4.html"
    )
    entry = FeedEntry(
        id=entry_id(email.message_id, "unused-seed"),
        title=email.subject,
        link=permalink,
        author_name=email.from_name,
        author_email=email.from_email,
        published=email.received_at,
        updated=email.received_at,
        categories=(email.list_id or "", "example.com"),
        content_html=rendered.html,
    )
    return build_atom(
        feed_id=f"urn:uuid:{uuid.uuid5(NS_MAIL2RSS, 'M9f3ac21b')}",
        title="RSS/Tech",
        self_url="https://rss.example.com/f/tech/M9f3ac21b/mac26/atom.xml",
        entries=[entry],
    )


def test_golden_feed_matches_stored_bytes():
    assert build_golden() == GOLDEN.read_bytes()


def test_build_atom_is_byte_deterministic():
    assert build_golden() == build_golden()


# --------------------------------------------------------------------------- #
# Control characters (the verified §14.2 regression)
# --------------------------------------------------------------------------- #


def test_control_chars_in_subject_and_body_keep_feed_valid_with_all_entries():
    entries = []
    for i in range(3):
        entries.append(
            FeedEntry(
                id=f"urn:uuid:{uuid.uuid5(NS_MAIL2RSS, f'm{i}')}",
                title=f"Sub\x00ject {i}\x0c with \x08 control \ud800 chars",
                link=f"https://p/e{i}.html",
                author_name="Name\x01Here",
                author_email="a@b.c",
                published=datetime(2026, 7, 1, 12, i, tzinfo=timezone.utc),
                updated=datetime(2026, 7, 1, 12, i, tzinfo=timezone.utc),
                categories=("cat\x0cegory",),
                content_html=f"<p>Body {i}\x00 with \x0c control chars</p>",
            )
        )
    data = build_atom(
        feed_id="urn:uuid:feed",
        title="Feed\x00 title",
        self_url="https://s/atom.xml",
        entries=entries,
    )
    root = etree.fromstring(data)  # must parse — no 500, no ValueError
    assert len(root.findall(f"{_ATOM}entry")) == 3  # not a single dropped entry
    # control characters really gone
    for bad in (b"\x00", b"\x0c", b"\x08", b"\x01"):
        assert bad not in data


def test_strip_xml_incompatible_keeps_tab_lf_cr():
    assert strip_xml_incompatible("a\tb\nc\rd") == "a\tb\nc\rd"
    assert strip_xml_incompatible("a\x00b\x0cc") == "abc"


# --------------------------------------------------------------------------- #
# entry_id stability (SPEC.md §7.2, F11)
# --------------------------------------------------------------------------- #


def test_entry_id_stable_across_runs_and_folder_change():
    a = entry_id("<m@x>", "seed:folderA")
    b = entry_id("<m@x>", "seed:folderB")  # folder changed -> id must not move
    assert a == b
    assert a == entry_id("<m@x>", "seed:folderA")  # stable across runs
    assert a.startswith("urn:uuid:")


def test_entry_id_differs_for_different_message_ids():
    assert entry_id("<a@x>", "s") != entry_id("<b@x>", "s")


def test_entry_id_uses_deterministic_fallback_when_message_id_missing():
    assert entry_id(None, "same-seed") == entry_id(None, "same-seed")
    assert entry_id(None, "seed-1") != entry_id(None, "seed-2")


def test_entry_id_not_derived_from_message_id_verbatim():
    # The raw Message-ID must never be recoverable from the id (it is hashed).
    mid = "<subscriber-token-12345@esp.example>"
    assert "subscriber-token-12345" not in entry_id(mid, "s")


def test_raw_message_id_absent_from_serialized_feed():
    mid = "<subscriber-token-98765@esp.example>"
    email = make_email(message_id=mid, html_body="<p>hi</p>")
    rendered = render_email(email, media_url=lambda _p: None)
    entry = FeedEntry(
        id=entry_id(email.message_id, "s"),
        title=email.subject,
        link="https://p/e.html",
        author_name=email.from_name,
        author_email=email.from_email,
        published=email.received_at,
        updated=email.received_at,
        categories=(),
        content_html=rendered.html,
    )
    data = build_atom(
        feed_id="urn:uuid:f", title="T", self_url="https://s", entries=[entry]
    )
    assert b"subscriber-token-98765" not in data
    assert b"esp.example" not in data


# --------------------------------------------------------------------------- #
# Atom validity (SPEC.md §11)
# --------------------------------------------------------------------------- #


def test_feed_has_required_atom_elements():
    data = build_golden()
    root = etree.fromstring(data)
    assert etree.QName(root).localname == "feed"
    # required feed-level elements
    for tag in ("id", "title", "updated"):
        assert root.find(f"{_ATOM}{tag}") is not None, tag
    entries = root.findall(f"{_ATOM}entry")
    assert entries
    for entry in entries:
        for tag in ("id", "title", "updated"):
            assert entry.find(f"{_ATOM}{tag}") is not None, tag
        content = entry.find(f"{_ATOM}content")
        assert content is not None
        assert content.get("type") == "html"


def test_content_is_escaped_html_not_cdata():
    email = make_email(html_body="<p>bold <strong>x</strong></p>")
    rendered = render_email(email, media_url=lambda _p: None)
    entry = FeedEntry(
        id="urn:uuid:1", title="t", link="https://p", author_name=None,
        author_email=None, published=make_email().received_at,
        updated=make_email().received_at, categories=(), content_html=rendered.html,
    )
    data = build_atom(feed_id="urn:uuid:f", title="T", self_url="https://s", entries=[entry])
    assert b"<![CDATA[" not in data
    assert b"&lt;strong&gt;" in data  # HTML escaped inside <content>


def test_feed_updated_is_max_entry_published():
    times = [
        datetime(2026, 7, 1, 8, 0, tzinfo=timezone.utc),
        datetime(2026, 7, 3, 9, 0, tzinfo=timezone.utc),  # latest
        datetime(2026, 7, 2, 10, 0, tzinfo=timezone.utc),
    ]
    entries = [
        FeedEntry(
            id=f"urn:uuid:{i}", title="t", link=f"https://p/{i}", author_name=None,
            author_email=None, published=t, updated=t, categories=(),
            content_html="<p>x</p>",
        )
        for i, t in enumerate(times)
    ]
    data = build_atom(feed_id="urn:uuid:f", title="T", self_url="https://s", entries=entries)
    root = etree.fromstring(data)
    assert root.find(f"{_ATOM}updated").text == "2026-07-03T09:00:00Z"


def test_all_dates_are_utc_and_none_from_future_or_moving():
    data = build_golden()
    root = etree.fromstring(data)
    stamps = [el.text for el in root.iter() if etree.QName(el).localname in ("updated", "published")]
    assert stamps
    for stamp in stamps:
        assert stamp.endswith("Z")  # aware, UTC
    # deterministic: a second build yields identical timestamps
    root2 = etree.fromstring(build_golden())
    stamps2 = [el.text for el in root2.iter() if etree.QName(el).localname in ("updated", "published")]
    assert stamps == stamps2


# --------------------------------------------------------------------------- #
# error_feed (SPEC.md §6.4)
# --------------------------------------------------------------------------- #


def test_error_feed_is_valid_with_stable_id():
    stable_id = f"urn:uuid:{uuid.uuid5(NS_MAIL2RSS, 'error:M9f3ac21b')}"
    when = datetime(2026, 7, 1, 12, 0, tzinfo=timezone.utc)
    a = error_feed(
        feed_id="urn:uuid:f", title="RSS/Tech", self_url="https://s/atom.xml",
        entry_id_=stable_id, message="This folder was deleted from Fastmail.", when=when,
    )
    b = error_feed(
        feed_id="urn:uuid:f", title="RSS/Tech", self_url="https://s/atom.xml",
        entry_id_=stable_id, message="This folder was deleted from Fastmail.", when=when,
    )
    assert a == b  # byte-stable -> the error entry never resurfaces as unread
    root = etree.fromstring(a)
    entry = root.find(f"{_ATOM}entry")
    assert entry is not None
    assert entry.find(f"{_ATOM}id").text == stable_id
    assert "deleted" in entry.find(f"{_ATOM}content").text
