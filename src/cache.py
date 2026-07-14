"""Disposable SQLite cache (SPEC.md §3.2).

This cache is NOT a source of truth. Deleting data/ (the whole directory, the db
file, or the media dir) must leave the service fully working — just cold. That is
a hard requirement, tested in tests/test_cache.py.

Design decisions taken straight from the spec / §14.2:

- Blob bodies are content-addressed FILES under data/media/, with only metadata
  in SQLite. Blobs are immutable (RFC 8620 §6.2), so there is no invalidation —
  only LRU eviction by total on-disk size, capped by a setting (default 500 MB).
- Sync functions are suffixed `_sync` and run through asyncio.to_thread; the
  async wrappers never touch SQLite on the event loop.
- Schema version lives in PRAGMA user_version. On a mismatch the whole db file is
  DROPPED and recreated — the cache is disposable, so migrations (and the
  ALTER-TABLE-with-swallowed-errors dance a sibling project does) are needless
  complexity here.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import sqlite3
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from loguru import logger

# Bump this to force every deployment to drop and rebuild the cache. There are no
# migrations — a version mismatch means "throw it away and start cold".
SCHEMA_VERSION = 1

_BUSY_TIMEOUT_MS = 5000

_CREATE_STATEMENTS = (
    "CREATE TABLE IF NOT EXISTS feed_cache ("
    "key TEXT PRIMARY KEY, body BLOB NOT NULL, etag TEXT NOT NULL, generated_at REAL NOT NULL)",
    "CREATE TABLE IF NOT EXISTS media_cache ("
    "blob_id TEXT PRIMARY KEY, path TEXT NOT NULL, content_type TEXT NOT NULL, "
    "size INTEGER NOT NULL, added REAL NOT NULL)",
    "CREATE TABLE IF NOT EXISTS kv ("
    "key TEXT PRIMARY KEY, value TEXT NOT NULL, updated REAL NOT NULL)",
)


@dataclass(frozen=True)
class FeedCacheEntry:
    body: bytes
    etag: str
    generated_at: float


@dataclass(frozen=True)
class MediaRecord:
    blob_id: str
    path: str
    content_type: str
    size: int
    added: float


class Cache:
    """A thin wrapper over a disposable SQLite file plus an on-disk media dir.

    Construct it with explicit paths (tests use a tempfile) or via
    Cache.from_settings(). All state lives under the db file's directory.
    """

    def __init__(self, db_path: str, media_dir: str | None = None, max_media_bytes: int = 500 * 1024 * 1024) -> None:
        self._db_path = Path(db_path)
        self._media_dir = Path(media_dir) if media_dir else self._db_path.parent / "media"
        self._max_media_bytes = max_media_bytes

    @classmethod
    def from_settings(cls) -> "Cache":
        # Local import so importing this module does not require a full env
        # (settings would refuse to build without credentials).
        from src.settings import settings

        return cls(settings.cache_db_path, max_media_bytes=settings.media_cache_max_bytes)

    # --- Connection / schema -------------------------------------------------

    def _ensure_dirs(self) -> None:
        # Recreate the tree even if data/ was wiped at runtime — recovery must be
        # transparent, this is what makes the cache truly disposable.
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._media_dir.mkdir(parents=True, exist_ok=True)

    def _connect(self) -> sqlite3.Connection:
        self._ensure_dirs()
        conn = sqlite3.connect(self._db_path, timeout=_BUSY_TIMEOUT_MS / 1000)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MS}")
        for stmt in _CREATE_STATEMENTS:
            conn.execute(stmt)
        conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        return conn

    def _read_version(self) -> int | None:
        """PRAGMA user_version of the existing db, or None if there is no db yet."""
        if not self._db_path.exists():
            return None
        conn = sqlite3.connect(self._db_path)
        try:
            return int(conn.execute("PRAGMA user_version").fetchone()[0])
        finally:
            conn.close()

    def _drop_db(self) -> None:
        for suffix in ("", "-wal", "-shm"):
            path = Path(str(self._db_path) + suffix)
            path.unlink(missing_ok=True)

    def init_sync(self) -> None:
        """Prepare the cache: create dirs, drop-and-recreate on a schema mismatch."""
        self._ensure_dirs()
        version = self._read_version()
        if version is not None and version != SCHEMA_VERSION:
            logger.info(f"cache_schema_mismatch: found {version}, want {SCHEMA_VERSION}, dropping")
            self._drop_db()
        conn = self._connect()
        conn.close()

    async def init(self) -> None:
        await asyncio.to_thread(self.init_sync)

    # --- feed_cache ----------------------------------------------------------

    def get_feed_sync(self, key: str) -> FeedCacheEntry | None:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT body, etag, generated_at FROM feed_cache WHERE key=?", (key,)
            ).fetchone()
        finally:
            conn.close()
        if row is None:
            return None
        return FeedCacheEntry(body=bytes(row[0]), etag=row[1], generated_at=float(row[2]))

    def put_feed_sync(self, key: str, body: bytes, etag: str, generated_at: float | None = None) -> None:
        ts = time.time() if generated_at is None else generated_at
        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO feed_cache (key, body, etag, generated_at) VALUES (?,?,?,?) "
                "ON CONFLICT(key) DO UPDATE SET body=excluded.body, etag=excluded.etag, "
                "generated_at=excluded.generated_at",
                (key, sqlite3.Binary(body), etag, ts),
            )
            conn.commit()
        finally:
            conn.close()

    async def get_feed(self, key: str) -> FeedCacheEntry | None:
        return await asyncio.to_thread(self.get_feed_sync, key)

    async def put_feed(self, key: str, body: bytes, etag: str, generated_at: float | None = None) -> None:
        await asyncio.to_thread(self.put_feed_sync, key, body, etag, generated_at)

    # --- media_cache ---------------------------------------------------------

    def _media_path(self, blob_id: str) -> Path:
        # Content-addressed by a hash of the blob id: keeps filenames filesystem-
        # safe regardless of what a JMAP blobId contains.
        digest = hashlib.sha256(blob_id.encode("utf-8")).hexdigest()
        return self._media_dir / digest

    def get_media_sync(self, blob_id: str) -> MediaRecord | None:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT path, content_type, size, added FROM media_cache WHERE blob_id=?",
                (blob_id,),
            ).fetchone()
            if row is None:
                return None
            path = row[0]
            if not os.path.exists(path):
                # File vanished (data/ wiped) but the row survived a WAL flush —
                # drop the stale row and report a miss so the caller re-fetches.
                conn.execute("DELETE FROM media_cache WHERE blob_id=?", (blob_id,))
                conn.commit()
                return None
            # LRU touch: `added` doubles as last-access time for eviction ordering.
            now = time.time()
            conn.execute("UPDATE media_cache SET added=? WHERE blob_id=?", (now, blob_id))
            conn.commit()
            return MediaRecord(blob_id=blob_id, path=path, content_type=row[1], size=int(row[2]), added=now)
        finally:
            conn.close()

    def put_media_sync(self, blob_id: str, data: bytes, content_type: str) -> MediaRecord:
        self._ensure_dirs()
        path = self._media_path(blob_id)
        # Unique temp name so a concurrent writer of the same blob cannot share
        # (and corrupt) our scratch file; os.replace then publishes atomically.
        tmp = path.parent / f"{path.name}.{uuid.uuid4().hex}.tmp"
        tmp.write_bytes(data)
        os.replace(tmp, path)  # atomic publish
        now = time.time()
        record = MediaRecord(
            blob_id=blob_id, path=str(path), content_type=content_type, size=len(data), added=now
        )
        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO media_cache (blob_id, path, content_type, size, added) VALUES (?,?,?,?,?) "
                "ON CONFLICT(blob_id) DO UPDATE SET path=excluded.path, "
                "content_type=excluded.content_type, size=excluded.size, added=excluded.added",
                (blob_id, record.path, content_type, record.size, now),
            )
            conn.commit()
            self._evict_sync(conn)
        finally:
            conn.close()
        return record

    def _evict_sync(self, conn: sqlite3.Connection) -> None:
        """LRU eviction by total on-disk size (§3.2). Least-recently-used first."""
        total = conn.execute("SELECT COALESCE(SUM(size), 0) FROM media_cache").fetchone()[0]
        if total <= self._max_media_bytes:
            return
        rows = conn.execute("SELECT blob_id, path, size FROM media_cache ORDER BY added ASC").fetchall()
        evicted = 0
        for blob_id, path, size in rows:
            if total <= self._max_media_bytes:
                break
            try:
                os.remove(path)
            except FileNotFoundError:
                pass
            conn.execute("DELETE FROM media_cache WHERE blob_id=?", (blob_id,))
            total -= size
            evicted += 1
        conn.commit()
        if evicted:
            logger.info(f"media_cache_evicted: entries {evicted}, remaining_bytes {total}")

    async def get_media(self, blob_id: str) -> MediaRecord | None:
        return await asyncio.to_thread(self.get_media_sync, blob_id)

    async def put_media(self, blob_id: str, data: bytes, content_type: str) -> MediaRecord:
        return await asyncio.to_thread(self.put_media_sync, blob_id, data, content_type)

    # --- kv (mailbox tree, etc.) --------------------------------------------

    def kv_get_sync(self, key: str) -> str | None:
        conn = self._connect()
        try:
            row = conn.execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
        finally:
            conn.close()
        return None if row is None else row[0]

    def kv_put_sync(self, key: str, value: str) -> None:
        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO kv (key, value, updated) VALUES (?,?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated=excluded.updated",
                (key, value, time.time()),
            )
            conn.commit()
        finally:
            conn.close()

    async def kv_get(self, key: str) -> str | None:
        return await asyncio.to_thread(self.kv_get_sync, key)

    async def kv_put(self, key: str, value: str) -> None:
        await asyncio.to_thread(self.kv_put_sync, key, value)
