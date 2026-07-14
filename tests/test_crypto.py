import re

from src import crypto
from src.crypto import (
    canon_params,
    feed_mac,
    feed_url,
    gen_secret,
    media_sig,
    slugify,
    validate_secret,
    verify_feed_mac,
    verify_media_sig,
)
from src.models import FeedParams


# --- Secret ------------------------------------------------------------------


def test_gen_secret_passes_validation():
    for _ in range(50):
        assert validate_secret(gen_secret())


def test_weak_secrets_rejected():
    assert not validate_secret("hunter2")
    assert not validate_secret("")
    assert not validate_secret("a" * 26)  # all-identical bytes
    assert not validate_secret("A2B3C4D5E6F7G8H9J2K3L4M5N6")  # uppercase not accepted
    assert not validate_secret("o2au6sdynfj7xokdurkazuwho")  # 25 chars, too short


def test_gen_secret_shape():
    s = gen_secret()
    assert len(s) == 26
    assert re.fullmatch(r"[a-z2-7]{26}", s)


# --- canon_params ------------------------------------------------------------


def test_canon_default_is_empty():
    assert canon_params(FeedParams()) == ""


def test_canon_omits_defaults_and_sorts():
    assert canon_params(FeedParams(limit=100)) == "limit=100"
    assert canon_params(FeedParams(children=True)) == "children=1"
    # keys sorted: children before limit
    assert canon_params(FeedParams(limit=100, children=True)) == "children=1&limit=100"


# --- Feed MAC ----------------------------------------------------------------


def test_mac_is_26_char_base32():
    mac = feed_mac("Mbox1", FeedParams(), "")
    assert re.fullmatch(r"[a-z2-7]{26}", mac)


def test_mac_deterministic_across_runs():
    # Simulate two independent process starts: clear the derived-key cache so the
    # result cannot depend on in-process memoisation.
    crypto._derive_keys.cache_clear()
    m1 = feed_mac("Mbox1", FeedParams(), "")
    crypto._derive_keys.cache_clear()
    m2 = feed_mac("Mbox1", FeedParams(), "")
    assert m1 == m2
    assert verify_feed_mac(m1, "Mbox1", FeedParams(), "")


def test_tampered_limit_invalidates_mac():
    mac = feed_mac("Mbox1", FeedParams(limit=20), "")
    # A default feed's mac must not verify once limit is bumped in the URL.
    assert not verify_feed_mac(mac, "Mbox1", FeedParams(limit=100), "")


def test_mac_from_feed_a_does_not_verify_for_feed_b():
    mac_a = feed_mac("MboxA", FeedParams(), "")
    assert not verify_feed_mac(mac_a, "MboxB", FeedParams(), "")


def test_epoch_bump_changes_only_that_mailbox():
    a0 = feed_mac("MboxA", FeedParams(), "")
    b0 = feed_mac("MboxB", FeedParams(), "")
    # Bump the epoch of MboxA only (its epoch string goes "" -> "2").
    a1 = feed_mac("MboxA", FeedParams(), "2")
    b1 = feed_mac("MboxB", FeedParams(), "")
    assert a1 != a0  # A's URL rotated
    assert b1 == b0  # B untouched


def test_verify_constant_time_and_robust():
    mac = feed_mac("Mbox1", FeedParams(), "")
    assert verify_feed_mac(mac, "Mbox1", FeedParams(), "") is True
    assert verify_feed_mac("wrong", "Mbox1", FeedParams(), "") is False
    # Differing lengths must not raise (compare_digest handles it).
    assert verify_feed_mac(mac + "x", "Mbox1", FeedParams(), "") is False


# --- Media signature ---------------------------------------------------------


def test_media_sig_roundtrip():
    mac = feed_mac("Mbox1", FeedParams(), "")
    sig = media_sig(mac, "Blob1")
    assert re.fullmatch(r"[a-z2-7]{26}", sig)
    assert verify_media_sig(sig, mac, "Blob1")


def test_media_sig_scoped_to_mac_and_blob():
    mac_a = feed_mac("MboxA", FeedParams(), "")
    mac_b = feed_mac("MboxB", FeedParams(), "")
    sig = media_sig(mac_a, "Blob1")
    # A sig issued for feed A does not authorise the same blob under feed B.
    assert not verify_media_sig(sig, mac_b, "Blob1")
    # Nor a different blob under the same feed.
    assert not verify_media_sig(sig, mac_a, "Blob2")


# --- slugify -----------------------------------------------------------------


def test_slugify_basic():
    assert slugify("RSS/Tech") == "rss-tech"
    assert slugify("Hello World") == "hello-world"
    assert re.fullmatch(r"[a-z0-9-]+", slugify("Hello World"))


def test_slugify_transliterates_cyrillic():
    slug = slugify("Технологии")
    assert slug and re.fullmatch(r"[a-z0-9-]+", slug)
    assert slug != crypto.SLUG_FALLBACK


def test_slugify_fallback_and_length():
    assert slugify("!!!") == "feed"
    assert slugify("") == "feed"
    assert len(slugify("a" * 100)) <= 40


# --- feed_url ----------------------------------------------------------------


def test_feed_url_default_has_no_query():
    url = feed_url("https://x.test/", "tech", "Mbox1", "MAC", FeedParams())
    assert url == "https://x.test/f/tech/Mbox1/MAC/atom.xml"


def test_feed_url_includes_canonical_query():
    url = feed_url("https://x.test", "tech", "Mbox1", "MAC", FeedParams(limit=50, children=True))
    assert url == "https://x.test/f/tech/Mbox1/MAC/atom.xml?children=1&limit=50"
