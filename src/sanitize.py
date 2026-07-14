"""HTML sanitiser — the security gate (SPEC.md §7.5 step 13, §14.1).

This is the LAST stage of the content pipeline: every transformation in
src/render.py runs first, and whatever they produce passes through here before it
can reach a feed. The contract is copied deliberately from pyrogram-bridge's
sanitizer.py (SPEC.md §14.1):

- fail-closed: any exception inside the sanitiser returns ``html.escape(raw)``;
  raw HTML is NEVER passed through on error;
- a single error event name (``html_sanitization_error``) plus a caller-supplied
  ``log_context``, so every call site is greppable under one name;
- a performance warning if a single sanitise takes longer than 50 ms.

There must be exactly ONE tag allow-list in the whole repository (SPEC.md §11) —
this module owns it. tests/test_sanitize.py locks that invariant.

Uses nh3 (a binding to Rust ammonia), NOT bleach: bleach is EOL and receives no
security fixes (SPEC.md F15).
"""

from __future__ import annotations

import html as _html
import time

import nh3
from loguru import logger

# The one and only tag allow-list (SPEC.md §7.5 step 13). Do not duplicate this
# set anywhere else in the tree — a second, drifting copy is exactly how these
# sanitisers grow holes.
ALLOWED_TAGS: frozenset[str] = frozenset(
    {
        "p", "br", "hr", "h1", "h2", "h3", "h4", "h5", "h6",
        "strong", "b", "em", "i", "u", "s",
        "code", "pre", "blockquote", "q", "cite",
        "ul", "ol", "li", "dl", "dt", "dd",
        "a", "img", "figure", "figcaption", "picture", "source",
        "table", "thead", "tbody", "tfoot", "tr", "th", "td", "caption",
        "small", "sub", "sup", "abbr", "time", "span", "div",
    }
)

ALLOWED_ATTRIBUTES: dict[str, set[str]] = {
    "a": {"href", "title"},
    "img": {"src", "alt", "title", "width", "height"},
    "td": {"colspan", "rowspan"},
    "th": {"colspan", "rowspan"},
    "time": {"datetime"},
    "abbr": {"title"},
}

# clean_content_tags removes the element AND its text content, unlike simply
# leaving a tag out of ALLOWED_TAGS (which strips the tag but KEEPS its text).
# Without this, <style>…</style> would leak its CSS into the feed as visible
# text (SPEC.md §7.5 step 13 note).
CLEAN_CONTENT_TAGS: frozenset[str] = frozenset(
    {
        "script", "style", "noscript", "iframe", "object", "embed",
        "form", "input", "button", "select", "option", "textarea",
        "svg", "title", "head",
    }
)

# No data:, cid: or javascript: — only these three schemes survive.
ALLOWED_URL_SCHEMES: frozenset[str] = frozenset({"http", "https", "mailto"})

LINK_REL = "noopener noreferrer nofollow"

# A single sanitise slower than this is worth a diagnostic warning.
_SLOW_MS = 50.0


def sanitize_html(html: str, *, log_context: str = "") -> str:
    """Sanitise an HTML fragment with nh3 using the one repository allow-list.

    Fail-closed: on ANY exception the raw input is returned HTML-escaped, never
    passed through unchanged. Returns feed-safe HTML.
    """
    start = time.perf_counter()
    try:
        cleaned = nh3.clean(
            html,
            tags=set(ALLOWED_TAGS),
            attributes={tag: set(attrs) for tag, attrs in ALLOWED_ATTRIBUTES.items()},
            clean_content_tags=set(CLEAN_CONTENT_TAGS),
            strip_comments=True,  # kills MSO conditional comments (belt and braces)
            link_rel=LINK_REL,
            url_schemes=set(ALLOWED_URL_SCHEMES),
            url_relative="deny",  # belt and braces for F10 (no relative URL survives)
        )
        return cleaned
    except Exception as exc:  # noqa: BLE001 - fail-closed is the whole point
        # Fail-closed: escape the raw input rather than emit unsanitised HTML.
        logger.error(
            f"html_sanitization_error: context {log_context or '-'}, error {exc!r}"
        )
        raw = html if isinstance(html, str) else str(html)
        return _html.escape(raw)
    finally:
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        if elapsed_ms > _SLOW_MS:
            size = len(html) if isinstance(html, str) else 0
            logger.warning(
                f"diag_sanitize_slow: context {log_context or '-'}, "
                f"elapsed_ms {elapsed_ms:.1f}, size {size}"
            )
