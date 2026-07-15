"""Folder-tree resolver with a TTL cache (SPEC.md §6.1).

JMAP has no "full path" property (F3), so the path shown to humans on the
discovery page is BUILT here by walking ``parent_id``. The feed ``<title>`` is
the live ``Mailbox.name`` — a rename is reflected without changing the URL
(SPEC.md §4.1 p.2, §7.3).

Resilience rule (SPEC.md §6.1): a refresh failure must NOT blank every feed. On a
transient Fastmail hiccup we keep serving the last good tree; only the very first
build failing (and with no on-disk fallback) is fatal to a request. The tree is
also persisted to the disposable kv cache, so a cold start during an outage can
still serve the last known folders.

Nothing here mutates the mailbox — it only reads ``Mailbox/get``.
"""

from __future__ import annotations

import asyncio
import json
import time

from loguru import logger

from src.cache import Cache
from src.jmap import JmapClient, JmapError, JmapNotFound
from src.models import Mailbox

# JMAP roles that mark a system folder (SPEC.md §4.4 p.6). Hidden by default on
# the discovery page — not forbidden, just not offered.
SYSTEM_ROLES: frozenset[str] = frozenset(
    {"inbox", "archive", "drafts", "sent", "trash", "junk"}
)

# Cache key for the persisted tree in the kv table.
_KV_KEY = "mailbox_tree"


def _dump(boxes: list[Mailbox]) -> str:
    return json.dumps(
        [
            {
                "id": b.id,
                "name": b.name,
                "parent_id": b.parent_id,
                "role": b.role,
                "total_emails": b.total_emails,
            }
            for b in boxes
        ]
    )


def _load(raw: str) -> list[Mailbox]:
    return [
        Mailbox(
            id=d["id"],
            name=d["name"],
            parent_id=d["parent_id"],
            role=d["role"],
            total_emails=int(d["total_emails"]),
        )
        for d in json.loads(raw)
    ]


class MailboxTree:
    """A TTL-cached view of the Fastmail folder tree.

    ``ensure_fresh()`` is the only async entry point; the getters below operate on
    the current in-memory snapshot and never touch the network.
    """

    def __init__(self, jmap: JmapClient, ttl: float, cache: Cache | None = None) -> None:
        self._jmap = jmap
        self._ttl = ttl
        self._cache = cache
        self._by_id: dict[str, Mailbox] = {}
        self._children: dict[str | None, list[str]] = {}
        self._built_monotonic: float = 0.0
        self._built_wall: float | None = None
        self._last_refresh_ok: bool | None = None
        self._last_refresh_error: str | None = None
        self._lock = asyncio.Lock()

    # --- Refresh -------------------------------------------------------------

    async def ensure_fresh(self) -> None:
        """Rebuild the tree if it has never been built or is past its TTL.

        Keeps the last good tree on a transient failure. Raises ``JmapError`` only
        when there is no tree at all (not even an on-disk fallback) — the very
        first build failing is the one case that is fatal to a request.
        """
        if self._by_id and (time.monotonic() - self._built_monotonic) < self._ttl:
            return
        async with self._lock:
            # Re-check under the lock: another coroutine may have just refreshed.
            if self._by_id and (time.monotonic() - self._built_monotonic) < self._ttl:
                return
            await self._refresh()

    async def force_refresh(self) -> None:
        """Rebuild the tree once regardless of the TTL freshness gate.

        Used before declaring a folder permanently gone off a stale/kv-restored
        tree (SPEC.md §6.1). On a failing refresh with an existing tree, _refresh()
        keeps the stale tree and returns without raising.
        """
        async with self._lock:
            await self._refresh()

    async def _refresh(self) -> None:
        try:
            boxes = await self._jmap.get_mailboxes()
        except (JmapError, JmapNotFound) as exc:
            self._last_refresh_ok = False
            self._last_refresh_error = repr(exc)
            if self._by_id:
                # A transient hiccup must not blank every feed (SPEC.md §6.1).
                logger.warning(f"mailbox_tree_refresh_kept_stale: error {exc!r}")
                # Do not advance built_monotonic — retry on the next request.
                self._built_monotonic = time.monotonic() - self._ttl
                return
            cached = await self._load_from_cache()
            if cached is not None:
                logger.warning(f"mailbox_tree_cold_from_cache: folders {len(cached)}, error {exc!r}")
                self._apply(cached)
                self._built_monotonic = time.monotonic()  # serve the fallback for one TTL
                return
            logger.error(f"mailbox_tree_cold_build_failed: error {exc!r}")
            raise
        self._apply(boxes)
        self._built_monotonic = time.monotonic()
        self._built_wall = time.time()
        self._last_refresh_ok = True
        self._last_refresh_error = None
        logger.info(f"mailbox_tree_refreshed: folders {len(boxes)}")
        await self._persist(boxes)

    async def _load_from_cache(self) -> list[Mailbox] | None:
        if self._cache is None:
            return None
        try:
            raw = await self._cache.kv_get(_KV_KEY)
        except Exception as exc:  # noqa: BLE001 - cache is best-effort
            logger.warning(f"mailbox_tree_cache_read_failed: error {exc!r}")
            return None
        if not raw:
            return None
        try:
            return _load(raw)
        except (ValueError, KeyError) as exc:
            logger.warning(f"mailbox_tree_cache_parse_failed: error {exc!r}")
            return None

    async def _persist(self, boxes: list[Mailbox]) -> None:
        if self._cache is None:
            return
        try:
            await self._cache.kv_put(_KV_KEY, _dump(boxes))
        except Exception as exc:  # noqa: BLE001 - persistence is best-effort
            logger.warning(f"mailbox_tree_persist_failed: error {exc!r}")

    def _apply(self, boxes: list[Mailbox]) -> None:
        by_id: dict[str, Mailbox] = {}
        children: dict[str | None, list[str]] = {}
        for box in boxes:
            by_id[box.id] = box
        for box in boxes:
            children.setdefault(box.parent_id, []).append(box.id)
        self._by_id = by_id
        self._children = children

    # --- Getters (sync, snapshot-only) --------------------------------------

    def get(self, mailbox_id: str) -> Mailbox | None:
        return self._by_id.get(mailbox_id)

    def children_ids(self, mailbox_id: str) -> list[str]:
        """Direct AND transitive descendants of a folder.

        ``children=1`` includes mail from every subfolder, so the OR filter must
        cover the whole subtree, not only the immediate children (SPEC.md §4.3)."""
        out: list[str] = []
        stack = list(self._children.get(mailbox_id, []))
        seen: set[str] = set()
        while stack:
            child = stack.pop()
            if child in seen:
                continue
            seen.add(child)
            out.append(child)
            stack.extend(self._children.get(child, []))
        return out

    def title(self, mailbox_id: str) -> str:
        """Feed ``<title>`` = the live folder name (SPEC.md §7.3)."""
        box = self._by_id.get(mailbox_id)
        return box.name if box is not None else mailbox_id

    def is_system(self, mailbox_id: str) -> bool:
        box = self._by_id.get(mailbox_id)
        return box is not None and box.role in SYSTEM_ROLES

    def path_of(self, mailbox_id: str) -> str:
        """Human "Parent/Child" path built by walking ``parent_id``.

        A literal ``/`` inside a folder name is escaped as ``\\/`` so the
        separator stays unambiguous (SPEC.md §6.1)."""
        box = self._by_id.get(mailbox_id)
        if box is None:
            return mailbox_id
        parts: list[str] = []
        seen: set[str] = set()
        cur: Mailbox | None = box
        while cur is not None and cur.id not in seen:
            seen.add(cur.id)
            parts.append(cur.name.replace("/", "\\/"))
            cur = self._by_id.get(cur.parent_id) if cur.parent_id else None
        return "/".join(reversed(parts))

    def list_folders(self, *, include_system: bool = False) -> list[tuple[Mailbox, str]]:
        """All folders as ``(mailbox, path)``, sorted by path.

        System folders (SPEC.md §4.4 p.6) are excluded unless ``include_system``."""
        rows: list[tuple[Mailbox, str]] = []
        for box in self._by_id.values():
            if not include_system and box.role in SYSTEM_ROLES:
                continue
            rows.append((box, self.path_of(box.id)))
        rows.sort(key=lambda item: item[1].lower())
        return rows

    def list_user_folders(self) -> list[tuple[Mailbox, str]]:
        """User-created folders only (SPEC.md §6.1)."""
        return self.list_folders(include_system=False)

    # --- Health --------------------------------------------------------------

    @property
    def has_tree(self) -> bool:
        return bool(self._by_id)

    @property
    def folder_count(self) -> int:
        return len(self._by_id)

    @property
    def last_refresh_ok(self) -> bool | None:
        return self._last_refresh_ok

    @property
    def age_seconds(self) -> float | None:
        """Wall-clock age of the last successful JMAP refresh, or None."""
        if self._built_wall is None:
            return None
        return max(0.0, time.time() - self._built_wall)
