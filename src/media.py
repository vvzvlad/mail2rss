"""Media proxy — the most security-sensitive endpoint (SPEC.md §8.1, §14.2).

The attacker picks the attachment bytes by emailing you, so the threat model is
harder than a sibling project's: an SVG or HTML served *inline* from our origin
(whose URLs carry feed tokens) is stored XSS. Hence the iron rules:

- the Content-Type is ONLY the JMAP-declared type, and ONLY if it is in the image
  allowlist; the bytes are NEVER sniffed (no python-magic);
- ``image/svg+xml`` is rejected — anything outside the allowlist is served as a
  download (``Content-Disposition: attachment``), never inline;
- ``X-Content-Type-Options: nosniff`` is always present — it is what makes our
  declared type authoritative — together with a ``sandbox`` CSP.

The declared MIME type travels in the ``ct`` query parameter of the media URL:
``data/`` is disposable (SPEC.md §3.2), so after a cache wipe the type must be
reconstructable from the URL alone — it cannot live only in the cache. The type
is unsigned, which is safe: the allowlist + ``nosniff`` mean the worst an attacker
can do is relabel bytes they can already fetch as one allowed image type.

SSRF-free: we never fetch a URL from the email, only Fastmail's ``downloadUrl``
template with a signed ``blobId`` (src/jmap.py).
"""

from __future__ import annotations

import asyncio

from loguru import logger
from starlette.requests import Request
from starlette.responses import FileResponse, Response

from src.cache import Cache, MediaRecord
from src.crypto import verify_feed_mac, verify_media_sig
from src.jmap import JmapClient, JmapError, JmapNotFound
from src.models import FeedParams

# The ONLY content types we will ever serve inline (SPEC.md §8.1 p.5). SVG is
# deliberately absent: it is an XSS vector.
IMAGE_ALLOWLIST: frozenset[str] = frozenset(
    {"image/png", "image/jpeg", "image/gif", "image/webp", "image/avif"}
)

# Per-image limits (SPEC.md §8.1 p.7).
MAX_MEDIA_BYTES = 5 * 1024 * 1024
DOWNLOAD_TIMEOUT_S = 10.0

# Mandatory security headers on every media response (SPEC.md §8.1 p.5).
_BASE_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "sandbox; default-src 'none'",
    "Cache-Control": "private, immutable, max-age=31536000",
    "X-Robots-Tag": "noindex, nofollow, noarchive",
}


class _MediaTooLarge(Exception):
    pass


def _normalise_type(declared: str) -> str:
    """Lower-case the bare MIME type, dropping any parameters (``; charset=...``)."""
    return (declared or "").split(";", 1)[0].strip().lower()


def _safe_filename(name: str | None) -> str:
    """A filename safe for a Content-Disposition header (no CR/LF/quotes)."""
    cleaned = "".join(ch for ch in (name or "") if ch.isprintable() and ch not in '"\r\n')
    cleaned = cleaned.strip() or "file"
    return cleaned[:200]


class MediaProxy:
    """Streams (and disk-caches) email blobs from Fastmail behind our signatures."""

    def __init__(self, cache: Cache, jmap: JmapClient) -> None:
        self._cache = cache
        self._jmap = jmap
        # In-flight dedup: one lock per blob so two concurrent requests for the
        # same blob do not both hit Fastmail (SPEC.md §14.1).
        self._locks: dict[str, asyncio.Lock] = {}
        self._locks_guard = asyncio.Lock()

    async def handle(
        self,
        *,
        mailbox_id: str,
        mac: str,
        blob_id: str,
        sig: str,
        name: str,
        declared_type: str,
        params: FeedParams,
        epoch: str,
        request: Request,
    ) -> Response:
        """Verify the signatures, then serve the blob (cache or Fastmail)."""
        # Both checks fail-closed to 404 so we never confirm a blob exists
        # (SPEC.md §8.1 p.3, §5.1 p.2). media_sig binds sig to (mac, blob);
        # feed_mac binds mac to THIS mailbox path — a media URL is only valid
        # inside its own signed feed.
        if not verify_media_sig(sig, mac, blob_id):
            return Response(status_code=404)
        if not verify_feed_mac(mac, mailbox_id, params, epoch):
            return Response(status_code=404)

        declared = _normalise_type(declared_type)

        record = await self._cache.get_media(blob_id)
        if record is None:
            record = await self._fetch_and_cache(blob_id, name, declared)
            if record is None:
                # Blob gone or upstream failure — nothing to serve.
                return Response(status_code=502)
        return self._serve(record, declared, name)

    # --- Serving -------------------------------------------------------------

    def _serve(self, record: MediaRecord, declared: str, name: str) -> Response:
        headers = dict(_BASE_HEADERS)
        filename = _safe_filename(name)
        if declared in IMAGE_ALLOWLIST:
            # Authoritative declared type + nosniff -> the browser will not treat
            # the bytes as anything else even if they happen to be HTML.
            return FileResponse(
                record.path,
                media_type=declared,
                headers=headers,
                filename=filename,
                content_disposition_type="inline",
            )
        # Outside the allowlist (incl. image/svg+xml): force a download, never
        # inline, with a generic type so nothing is rendered in-browser.
        return FileResponse(
            record.path,
            media_type="application/octet-stream",
            headers=headers,
            filename=filename,
            content_disposition_type="attachment",
        )

    # --- Fetch + cache -------------------------------------------------------

    async def _lock_for(self, blob_id: str) -> asyncio.Lock:
        async with self._locks_guard:
            lock = self._locks.get(blob_id)
            if lock is None:
                lock = asyncio.Lock()
                self._locks[blob_id] = lock
            return lock

    async def _fetch_and_cache(
        self, blob_id: str, name: str, declared: str
    ) -> MediaRecord | None:
        lock = await self._lock_for(blob_id)
        async with lock:
            # Re-check under the lock: a concurrent request may have just filled it.
            record = await self._cache.get_media(blob_id)
            if record is not None:
                return record
            try:
                data = await self._download(blob_id, name, declared)
            except JmapNotFound:
                logger.info(f"media_blob_not_found: blob {blob_id}")
                return None
            except _MediaTooLarge:
                logger.warning(f"media_blob_too_large: blob {blob_id}, cap {MAX_MEDIA_BYTES}")
                return None
            except (JmapError, asyncio.TimeoutError) as exc:
                logger.warning(f"media_download_failed: blob {blob_id}, error {exc!r}")
                return None
            content_type = declared or "application/octet-stream"
            record = await self._cache.put_media(blob_id, data, content_type)
            logger.info(f"media_cached: blob {blob_id}, bytes {len(data)}")
            return record

    async def _download(self, blob_id: str, name: str, declared: str) -> bytes:
        """Stream the blob with a hard size cap and timeout (SPEC.md §8.1 p.7)."""
        buffer = bytearray()
        type_for_url = declared or "application/octet-stream"
        async with asyncio.timeout(DOWNLOAD_TIMEOUT_S):
            async for chunk in self._jmap.stream_blob(blob_id, name or "file", type_for_url):
                buffer += chunk
                if len(buffer) > MAX_MEDIA_BYTES:
                    raise _MediaTooLarge()
        return bytes(buffer)
