"""Key derivation, feed/media signatures and URL building (SPEC.md §4.2).

The whole authorisation model of mail2rss lives here: the URL *is* the config,
and the MAC in the URL is the only thing that proves the URL was issued by the
owner of MAIL2RSS_SECRET.

    K_feed  = HKDF-SHA256(MAIL2RSS_SECRET, info="mail2rss/feed-mac/v1")
    K_media = HKDF-SHA256(MAIL2RSS_SECRET, info="mail2rss/media-sig/v1")

    mac = base32( HMAC-SHA256(K_feed,  mailbox_id || 0x00 || canon(params) || 0x00 || epoch) )[:26]
    sig = base32( HMAC-SHA256(K_media, mac        || 0x00 || blob_id) )[:26]

Two rules that are NOT negotiable (both are bugs found in a sibling project):

1. Keys are DERIVED from the secret, never stored on disk. There is no key file
   anywhere. Wiping data/ must not kill media URLs already sitting in Miniflux.
2. Verification is ALWAYS hmac.compare_digest, and a failed verification never
   logs the expected value (nor the secret, nor the mac).

HKDF is implemented here over hmac/hashlib (RFC 5869) rather than pulling in
`cryptography`: it is ~10 lines and saves a heavyweight dependency.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import unicodedata
from functools import lru_cache

from src.models import DEFAULT_CHILDREN, DEFAULT_LIMIT, FeedParams

# --- Constants ---------------------------------------------------------------

# HKDF info strings: domain separation between the two keys. One HMAC key must
# not serve two different purposes (SPEC.md §4.2).
_INFO_FEED = b"mail2rss/feed-mac/v1"
_INFO_MEDIA = b"mail2rss/media-sig/v1"

# 26 base32 chars = 130 bits of a 256-bit HMAC. 128 bits is the design target.
MAC_LEN = 26

# MAIL2RSS_SECRET: 128 bit, base32, lowercase, unpadded -> exactly 26 chars from
# the lowercased RFC 4648 alphabet (a-z, 2-7).
SECRET_LEN = 26
_SECRET_RE = re.compile(r"\A[a-z2-7]{26}\Z")
_SECRET_BYTES = 16

SLUG_MAX_LEN = 40
SLUG_FALLBACK = "feed"

# Cosmetic only: lets a Cyrillic folder name produce a readable slug instead of
# collapsing to the fallback. The slug is never verified or routed on (§4.1 p.2).
_TRANSLIT = {
    "а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e", "ё": "e",
    "ж": "zh", "з": "z", "и": "i", "й": "i", "к": "k", "л": "l", "м": "m",
    "н": "n", "о": "o", "п": "p", "р": "r", "с": "s", "т": "t", "у": "u",
    "ф": "f", "х": "h", "ц": "c", "ч": "ch", "ш": "sh", "щ": "sch", "ъ": "",
    "ы": "y", "ь": "", "э": "e", "ю": "yu", "я": "ya",
}


# --- HKDF (RFC 5869) ---------------------------------------------------------


def _hkdf_sha256(ikm: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-SHA256 with an empty salt (RFC 5869 §2.2-2.3)."""
    prk = hmac.new(b"\x00" * hashlib.sha256().digest_size, ikm, hashlib.sha256).digest()
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


@lru_cache(maxsize=4)
def _derive_keys(secret: str) -> tuple[bytes, bytes]:
    """(K_feed, K_media) for a secret. Cached: HKDF on every request is waste."""
    ikm = secret.encode("utf-8")
    return _hkdf_sha256(ikm, _INFO_FEED), _hkdf_sha256(ikm, _INFO_MEDIA)


def _secret() -> str:
    # Local import: src.settings imports validate_secret from this module, so a
    # module-level import here would be a cycle. The secret is validated at
    # startup, so by the time anything calls a MAC function it is well-formed.
    from src.settings import settings

    return settings.mail2rss_secret


# --- Secret ------------------------------------------------------------------


def gen_secret() -> str:
    """Generate a MAIL2RSS_SECRET: 128 bit, base32, lowercase, unpadded."""
    return base64.b32encode(secrets.token_bytes(_SECRET_BYTES)).decode("ascii").rstrip("=").lower()


def validate_secret(secret: str) -> bool:
    """True iff `secret` has exactly the shape gen_secret() produces.

    A secret that fails this check must prevent startup (SPEC.md §4.4 p.1): this
    is what keeps `hunter2` out of the env. The all-identical-bytes case is
    rejected too — that is the one degenerate value a human could plausibly type
    ("aaaa..."), and a real generated secret hits it with probability 2^-120.
    """
    if not isinstance(secret, str) or not _SECRET_RE.match(secret):
        return False
    raw = base64.b32decode(secret.upper() + "=" * 6)
    if len(raw) != _SECRET_BYTES:
        return False
    return len(set(raw)) > 1


# --- Canonical parameters ----------------------------------------------------


def canon_params(params: FeedParams) -> str:
    """Canonical query string for the MAC and the cache key (SPEC.md §4.2).

    Only known parameters, defaults omitted, keys sorted, `k=v` joined by `&`.
    A default feed canonicalises to "". Unknown parameters are dropped by the
    caller before this point — otherwise `?x=1` would work as a cache-buster.
    """
    parts: list[str] = []
    if params.children != DEFAULT_CHILDREN:
        parts.append(f"children={1 if params.children else 0}")
    if params.limit != DEFAULT_LIMIT:
        parts.append(f"limit={params.limit}")
    return "&".join(sorted(parts))


# --- Feed MAC ----------------------------------------------------------------


def _b32(digest: bytes) -> str:
    return base64.b32encode(digest).decode("ascii").rstrip("=").lower()[:MAC_LEN]


def feed_mac(mailbox_id: str, params: FeedParams, epoch: str) -> str:
    """MAC covering the mailbox, the canonical params and the revocation epoch."""
    k_feed, _ = _derive_keys(_secret())
    msg = b"\x00".join(
        (
            mailbox_id.encode("utf-8"),
            canon_params(params).encode("utf-8"),
            epoch.encode("utf-8"),
        )
    )
    return _b32(hmac.new(k_feed, msg, hashlib.sha256).digest())


def verify_feed_mac(mac: str, mailbox_id: str, params: FeedParams, epoch: str) -> bool:
    """Constant-time check of a feed MAC. Never logs, never returns the expected value."""
    expected = feed_mac(mailbox_id, params, epoch)
    # Compare bytes, not str: a mac taken from a URL path may contain non-ASCII,
    # and compare_digest raises TypeError on non-ASCII str.
    return hmac.compare_digest(expected.encode("utf-8"), mac.encode("utf-8"))


# --- Media signature ---------------------------------------------------------


def media_sig(mac: str, blob_id: str) -> str:
    """Signature for a media URL, scoped to the feed's mac (SPEC.md §8.1 p.3).

    Without the scope this endpoint would be an enumerable proxy to every blob in
    the account, including mail from folders this feed has nothing to do with.
    The signature is deliberately eternal: Miniflux keeps the entry HTML forever,
    so an expiring signature means broken images in old entries.
    """
    _, k_media = _derive_keys(_secret())
    msg = mac.encode("utf-8") + b"\x00" + blob_id.encode("utf-8")
    return _b32(hmac.new(k_media, msg, hashlib.sha256).digest())


def verify_media_sig(sig: str, mac: str, blob_id: str) -> bool:
    """Constant-time check of a media signature."""
    expected = media_sig(mac, blob_id)
    return hmac.compare_digest(expected.encode("utf-8"), sig.encode("utf-8"))


# --- Slug and URL ------------------------------------------------------------


def slugify(name: str) -> str:
    """Cosmetic slug for the URL. NEVER used for verification or routing (§4.1 p.2).

    The server does not compare, validate or redirect on the slug: renaming a
    folder must not break a subscription.
    """
    lowered = "".join(_TRANSLIT.get(ch, ch) for ch in name.lower())
    ascii_only = unicodedata.normalize("NFKD", lowered).encode("ascii", "ignore").decode("ascii")
    slug = re.sub(r"[^a-z0-9]+", "-", ascii_only).strip("-")
    slug = slug[:SLUG_MAX_LEN].strip("-")
    return slug or SLUG_FALLBACK


def feed_url(base_url: str, slug: str, mailbox_id: str, mac: str, params: FeedParams) -> str:
    """Build /f/{slug}/{mailbox_id}/{mac}/atom.xml with the canonical query.

    `mailbox_id` goes into the path as-is: a JMAP Id is only [A-Za-z0-9_-] (F4),
    so there is nothing to escape.
    """
    url = f"{base_url.rstrip('/')}/f/{slug}/{mailbox_id}/{mac}/atom.xml"
    query = canon_params(params)
    return f"{url}?{query}" if query else url
