"""Atom 1.0 serialiser (SPEC.md §7.1-7.4). Hand-rolled on lxml.etree.

Not feedgen (SPEC.md §7.1): we need an ESCAPED ``<content type="html">`` (not
CDATA), full control over control-character stripping (F17), and byte-
deterministic output so the HTTP layer can compute a stable ETag over the body.

Every string that reaches the XML — title, author, categories, content, the feed
title, URLs — passes through ``strip_xml_incompatible``. This is not paranoia:
lxml raises ``ValueError: All strings must be XML compatible`` on a single control
character, and CDATA does not save you either — one such character in one message
would 500 the ENTIRE feed on every poll (SPEC.md §7.5 step 14, F17). Telegram
never produces them; email does, routinely.
"""

from __future__ import annotations

import hashlib
import html as _html
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Sequence

from lxml import etree

ATOM_NS = "http://www.w3.org/2005/Atom"
_A = f"{{{ATOM_NS}}}"

# Fixed namespace for every UUIDv5 feed/entry id (SPEC.md §7.2). NEVER change it:
# it is baked into every atom:id ever emitted, and a change resurfaces every entry
# as unread in every reader (F11).
NS_MAIL2RSS: uuid.UUID = uuid.UUID("71c87a5c-0436-4213-9233-f2620401eec7")

# XML 1.0 forbids these control characters (tab/LF/CR are allowed and kept). Lone
# surrogates are stripped too — lxml rejects them (SPEC.md §7.5 step 14, F17).
_XML_INCOMPATIBLE = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff]")

# Deterministic feed-level <updated> when a feed happens to have no entries.
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

# A feed-level author guarantees RFC 4287 validity even when an entry (an error or
# degraded record) carries no author of its own.
_FEED_AUTHOR = "mail2rss"


def strip_xml_incompatible(s: str) -> str:
    """Remove XML-incompatible control characters and lone surrogates (F17)."""
    if not s:
        return s
    return _XML_INCOMPATIBLE.sub("", s)


@dataclass(frozen=True)
class FeedEntry:
    """One Atom entry. All string fields are stripped of XML-incompatible
    characters at serialisation time."""

    id: str  # "urn:uuid:..."
    title: str
    link: str  # permalink; unique per entry
    author_name: str | None
    author_email: str | None
    published: datetime  # aware
    updated: datetime  # aware
    categories: tuple[str, ...]
    content_html: str


def entry_id(message_id: str | None, fallback_seed: str) -> str:
    """Stable, deterministic ``urn:uuid:`` id for an entry (SPEC.md §7.2).

    From the RFC 5322 Message-ID when present; otherwise from a hash of a
    deterministic fallback seed. NEVER derive it from the JMAP Email id, a
    position/index or a content hash — a changing id resurfaces the entry as
    unread in Miniflux (F11). The raw Message-ID is never emitted into the feed;
    it is only hashed here.
    """
    if message_id:
        name = strip_xml_incompatible(message_id)
    else:
        name = hashlib.sha256(fallback_seed.encode("utf-8")).hexdigest()
    return f"urn:uuid:{uuid.uuid5(NS_MAIL2RSS, name)}"


def build_atom(
    *,
    feed_id: str,
    title: str,
    self_url: str,
    entries: Sequence[FeedEntry],
) -> bytes:
    """Serialise a full Atom 1.0 document to deterministic UTF-8 bytes."""
    feed = etree.Element(_A + "feed", nsmap={None: ATOM_NS})
    _text_child(feed, "title", title)
    _text_child(feed, "id", feed_id)
    updated = max((e.updated for e in entries), default=_EPOCH)
    _text_child(feed, "updated", _rfc3339(updated))
    author = etree.SubElement(feed, _A + "author")
    _text_child(author, "name", _FEED_AUTHOR)
    self_link = etree.SubElement(feed, _A + "link")
    self_link.set("rel", "self")
    self_link.set("type", "application/atom+xml")
    self_link.set("href", strip_xml_incompatible(self_url))

    for entry in entries:
        _entry_element(feed, entry)

    return etree.tostring(
        feed, xml_declaration=True, encoding="UTF-8", pretty_print=False
    )


def error_feed(
    *,
    feed_id: str,
    title: str,
    self_url: str,
    entry_id_: str,
    message: str,
    when: datetime,
) -> bytes:
    """A VALID Atom document carrying one explanatory entry (SPEC.md §6.4).

    ``entry_id_`` must be STABLE (the caller passes ``uuid5(ns, "error:" +
    mailbox_id)``) — otherwise the error entry resurfaces as unread on every poll.
    """
    entry = FeedEntry(
        id=entry_id_,
        title=message,
        link=self_url,
        author_name=None,
        author_email=None,
        published=when,
        updated=when,
        categories=(),
        content_html=f"<p>{_html.escape(message)}</p>",
    )
    return build_atom(feed_id=feed_id, title=title, self_url=self_url, entries=[entry])


# --------------------------------------------------------------------------- #
# Internals
# --------------------------------------------------------------------------- #


def _entry_element(feed: etree._Element, entry: FeedEntry) -> None:
    el = etree.SubElement(feed, _A + "entry")
    _text_child(el, "title", entry.title)
    _text_child(el, "id", entry.id)
    link = etree.SubElement(el, _A + "link")
    link.set("rel", "alternate")
    link.set("href", strip_xml_incompatible(entry.link))
    if entry.author_name or entry.author_email:
        author = etree.SubElement(el, _A + "author")
        if entry.author_name:
            _text_child(author, "name", entry.author_name)
        if entry.author_email:
            _text_child(author, "email", entry.author_email)
    _text_child(el, "published", _rfc3339(entry.published))
    _text_child(el, "updated", _rfc3339(entry.updated))
    for category in entry.categories:
        cat = etree.SubElement(el, _A + "category")
        cat.set("term", strip_xml_incompatible(category))
    content = etree.SubElement(el, _A + "content")
    content.set("type", "html")
    # lxml escapes .text automatically -> an escaped <content type="html">,
    # not CDATA (SPEC.md §7.1). Strip control chars first or lxml raises (F17).
    content.text = strip_xml_incompatible(entry.content_html)


def _text_child(parent: etree._Element, tag: str, text: str) -> etree._Element:
    el = etree.SubElement(parent, _A + tag)
    el.text = strip_xml_incompatible(text or "")
    return el


def _rfc3339(dt: datetime) -> str:
    """Format an aware datetime as RFC 3339 UTC. published/updated come from the
    email's receivedAt — a moving datetime.now() fallback is forbidden (§7.3)."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    stamp = dt.strftime("%Y-%m-%dT%H:%M:%S")
    if dt.microsecond:
        stamp += f".{dt.microsecond:06d}"
    return stamp + "Z"
