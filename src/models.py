"""Shared data contract between all mail2rss modules.

These dataclasses are the boundary between the JMAP client (src/jmap.py) and
everything downstream (render, feed, media, discovery, app). They are frozen:
nothing in the pipeline mutates an Email in place.

Nothing here talks to the network, the cache or the settings — keep it that way,
this module must stay importable from anywhere without side effects.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

# Feed parameter defaults (SPEC.md §4.3). They are also the values that
# canon(params) omits from the canonical string, so a default feed canonicalises
# to "" — see src/crypto.py:canon_params.
DEFAULT_LIMIT = 20
DEFAULT_CHILDREN = False


@dataclass(frozen=True)
class Mailbox:
    """A JMAP Mailbox (SPEC.md §6.1). `id` is immutable (F3) — it is what the
    feed URL addresses and what the MAC signs."""

    id: str
    name: str
    parent_id: str | None
    # Lowercase JMAP role: inbox/archive/drafts/sent/trash/junk, or None for a
    # user-created folder. Used to hide system folders on the discovery page.
    role: str | None
    total_emails: int


@dataclass(frozen=True)
class BodyPart:
    """One MIME part of an email, as described by JMAP.

    `type` is the MIME type AS DECLARED by the sender. It is attacker-controlled
    and must never be trusted for anything but an allowlist check (SPEC.md §8.1):
    we serve the declared type only if it is in the image allowlist, and always
    with X-Content-Type-Options: nosniff. We never sniff the bytes.
    """

    part_id: str | None
    blob_id: str | None
    type: str
    name: str | None
    disposition: str | None  # "inline" | "attachment" | None
    cid: str | None  # angle brackets already stripped by the JMAP server
    size: int


@dataclass(frozen=True)
class Email:
    """An email as fetched from JMAP, before any rendering/sanitising."""

    # JMAP Email id: immutable in practice, used as a cache key and in the
    # permalink URL. NEVER used as the atom:id — see SPEC.md §7.2.
    id: str
    # First element of the JMAP `messageId` property (RFC 5322 Message-ID).
    # This is what atom:id is derived from. May be missing on broken senders.
    message_id: str | None
    subject: str  # already RFC2047-decoded by JMAP (F5); may be ""
    from_name: str | None
    from_email: str | None
    # Timezone-aware UTC. Always present in JMAP; a fallback to now() is
    # forbidden (SPEC.md §7.3, §14.2).
    received_at: datetime
    preview: str
    mailbox_ids: tuple[str, ...]
    html_body: str | None  # concatenated bodyValues of the htmlBody parts
    text_body: str | None
    html_truncated: bool  # any consumed bodyValue had isTruncated
    attachments: tuple[BodyPart, ...]
    list_unsubscribe: tuple[str, ...]
    list_id: str | None


@dataclass(frozen=True)
class FeedParams:
    """Feed parameters carried in the query string and covered by the MAC (§4.3)."""

    limit: int = DEFAULT_LIMIT
    children: bool = DEFAULT_CHILDREN


@dataclass(frozen=True)
class JmapSession:
    """The bits of the JMAP session object we actually use (SPEC.md §6.1)."""

    api_url: str
    # RFC 6570 level-1 URI template with {accountId}/{blobId}/{name}?type={type}.
    # Note this points at a DIFFERENT host than api_url (fastmailusercontent.com,
    # F6) — that is expected, not a redirect to be followed.
    download_url: str
    account_id: str
