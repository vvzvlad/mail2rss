import os
import shutil
import time

import pytest

from src import cache as cache_module
from src.cache import Cache


@pytest.fixture
def cache(tmp_path):
    db = tmp_path / "state" / "cache.db"
    c = Cache(str(db), max_media_bytes=10 * 1024 * 1024)
    c.init_sync()
    return c


# --- Basic round-trips -------------------------------------------------------


def test_feed_cache_roundtrip(cache):
    assert cache.get_feed_sync("k") is None
    cache.put_feed_sync("k", b"<feed/>", "etag-1", generated_at=123.0)
    entry = cache.get_feed_sync("k")
    assert entry is not None
    assert entry.body == b"<feed/>"
    assert entry.etag == "etag-1"
    assert entry.generated_at == 123.0


def test_feed_cache_upsert(cache):
    cache.put_feed_sync("k", b"v1", "e1")
    cache.put_feed_sync("k", b"v2", "e2")
    entry = cache.get_feed_sync("k")
    assert entry.body == b"v2" and entry.etag == "e2"


def test_kv_roundtrip(cache):
    assert cache.kv_get_sync("tree") is None
    cache.kv_put_sync("tree", '{"a":1}')
    assert cache.kv_get_sync("tree") == '{"a":1}'
    cache.kv_put_sync("tree", '{"a":2}')
    assert cache.kv_get_sync("tree") == '{"a":2}'


def test_media_roundtrip(cache):
    rec = cache.put_media_sync("Blob1", b"IMGBYTES", "image/png")
    assert os.path.exists(rec.path)
    assert rec.content_type == "image/png"
    assert rec.size == 8
    got = cache.get_media_sync("Blob1")
    assert got is not None
    assert got.path == rec.path
    assert got.content_type == "image/png"


async def test_async_wrappers(cache):
    await cache.put_feed("k", b"body", "e")
    entry = await cache.get_feed("k")
    assert entry.body == b"body"
    await cache.kv_put("x", "y")
    assert await cache.kv_get("x") == "y"
    rec = await cache.put_media("B", b"data", "image/gif")
    got = await cache.get_media("B")
    assert got.size == rec.size


# --- Schema versioning -------------------------------------------------------


def test_schema_mismatch_drops_and_recreates(tmp_path, monkeypatch):
    db = tmp_path / "cache.db"
    c1 = Cache(str(db))
    c1.init_sync()
    c1.put_feed_sync("k", b"stale", "e")
    assert c1.get_feed_sync("k") is not None

    # A later deployment ships a newer schema: the whole db is dropped, not migrated.
    monkeypatch.setattr(cache_module, "SCHEMA_VERSION", cache_module.SCHEMA_VERSION + 1)
    c2 = Cache(str(db))
    c2.init_sync()
    assert c2.get_feed_sync("k") is None  # old data gone
    # New cache still works.
    c2.put_feed_sync("k2", b"fresh", "e2")
    assert c2.get_feed_sync("k2").body == b"fresh"


# --- Disposability -----------------------------------------------------------


def test_missing_data_dir_is_created(tmp_path):
    db = tmp_path / "deeply" / "nested" / "data" / "cache.db"
    assert not db.parent.exists()
    c = Cache(str(db))
    c.init_sync()
    assert db.exists()
    assert db.parent.exists()


def test_deleting_data_dir_leaves_service_working(tmp_path):
    # SPEC.md §3.2 / §11.8: the cache is disposable — wiping data/ must leave the
    # service fully working, just cold.
    data_dir = tmp_path / "data"
    db = data_dir / "cache.db"
    c = Cache(str(db))
    c.init_sync()
    c.put_feed_sync("k", b"body", "e")
    c.put_media_sync("Blob1", b"IMG", "image/png")
    assert c.get_media_sync("Blob1") is not None

    # Nuke the whole data directory out from under the running service.
    shutil.rmtree(data_dir)
    assert not data_dir.exists()

    # A cold miss, not a crash: previously cached entries are simply gone.
    assert c.get_feed_sync("k") is None
    assert c.get_media_sync("Blob1") is None
    # And the cache transparently recreates itself and keeps working.
    c.put_feed_sync("k2", b"again", "e2")
    assert c.get_feed_sync("k2").body == b"again"
    rec = c.put_media_sync("Blob2", b"IMG2", "image/png")
    assert os.path.exists(rec.path)


# --- LRU eviction ------------------------------------------------------------


def test_lru_eviction_respects_cap(tmp_path):
    # Cap of 500 bytes; each blob is 200 bytes, so at most two fit.
    db = tmp_path / "cache.db"
    c = Cache(str(db), max_media_bytes=500)
    payload = b"x" * 200

    c.put_media_sync("A", payload, "image/png")
    time.sleep(0.01)
    c.put_media_sync("B", payload, "image/png")
    time.sleep(0.01)
    c.put_media_sync("C", payload, "image/png")  # total would be 600 > 500

    # Total on-disk size is back under the cap.
    total = sum(
        os.path.getsize(os.path.join(root, f))
        for root, _dirs, files in os.walk(c._media_dir)
        for f in files
    )
    assert total <= 500

    # The least-recently-used entry (A) was evicted; the newest (C) survives.
    assert c.get_media_sync("A") is None
    assert c.get_media_sync("C") is not None


def test_lru_touch_protects_recently_read(tmp_path):
    db = tmp_path / "cache.db"
    c = Cache(str(db), max_media_bytes=500)
    payload = b"x" * 200

    c.put_media_sync("A", payload, "image/png")
    time.sleep(0.01)
    c.put_media_sync("B", payload, "image/png")
    time.sleep(0.01)
    # Touch A so it is now the most-recently-used, then insert C.
    assert c.get_media_sync("A") is not None
    time.sleep(0.01)
    c.put_media_sync("C", payload, "image/png")

    # B (untouched, oldest access) should be the one evicted, not A.
    assert c.get_media_sync("A") is not None
    assert c.get_media_sync("B") is None
