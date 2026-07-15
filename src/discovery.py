"""The secret -> links page and OPML export (SPEC.md §4.4).

What the secret gates here is the FOLDER LISTING (real mailbox data reachable only
through our Fastmail token) — NOT link generation. Generating a MAC reveals
nothing: a wrong secret just yields a URL that 404s (SPEC.md §4.4). So:

- POST only; the secret is read from the BODY, never a query param (a GET would
  leak it into access logs, history and Referer — SPEC.md §4.4 p.2);
- constant-time compare against ``settings.mail2rss_secret``;
- the secret is NEVER logged and never echoed into a traceback;
- a wrong secret returns a neutral error (no timing signal, constant-time);
- rate limit 5/min per IP — anti-DoS, not anti-brute-force (128-bit secret).

The secret's STRENGTH is enforced at startup by settings (SPEC.md §4.4 p.1), so it
is not re-policed here.
"""

from __future__ import annotations

import base64
import hmac
import re
import time
from collections import deque
from html import escape
from pathlib import Path
from urllib.parse import parse_qs

from loguru import logger
from starlette.requests import Request
from starlette.responses import HTMLResponse, Response

from src.crypto import feed_mac, feed_url, slugify
from src.mailbox_tree import MailboxTree
from src.models import FeedParams
from src.settings import settings

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"

# Anti-DoS budget for the discovery form (SPEC.md §4.4 p.3).
RATE_LIMIT = 5
RATE_WINDOW_S = 60.0
# Hard cap on how many IPs the limiter tracks, so the map can never grow without
# bound (SPEC.md §5 "caches without caps").
RATE_MAX_IPS = 10_000

_PLACEHOLDER_RE = re.compile(r"\$\{(\w+)\}")

# Headers shared by every discovery response (capability-URL hygiene, SPEC.md §5.2).
_PAGE_HEADERS = {
    "X-Robots-Tag": "noindex, nofollow, noarchive",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    # No external resources; first-party inline script/style only (SPEC.md §5.2 p.7).
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
        "img-src 'self'; form-action 'self'; base-uri 'none'"
    ),
}


def render_template(name: str, mapping: dict[str, str]) -> str:
    """Fill ``${key}`` tokens from ``mapping``.

    Uses ``re.sub`` (not ``str.format``/``string.Template.substitute``) so that
    substituted values — which may legitimately contain ``$`` or ``{}`` — are NOT
    re-scanned for placeholders. Missing keys become empty strings.
    """
    tmpl = (TEMPLATES_DIR / name).read_text(encoding="utf-8")
    return _PLACEHOLDER_RE.sub(lambda m: mapping.get(m.group(1), ""), tmpl)


class RateLimiter:
    """Per-IP sliding-window limiter (in-memory; the app is single-process).

    The bucket map is bounded (SPEC.md §5): every call first prunes IPs whose last
    hit fell outside the window, and a hard cap evicts the oldest IPs if the map
    still overflows — so a flood of distinct source IPs cannot grow it forever."""

    def __init__(
        self, limit: int = RATE_LIMIT, window: float = RATE_WINDOW_S, max_ips: int = RATE_MAX_IPS
    ) -> None:
        self._limit = limit
        self._window = window
        self._max_ips = max_ips
        self._hits: dict[str, deque[float]] = {}

    def allow(self, ip: str) -> bool:
        now = time.monotonic()
        self._prune(now)
        bucket = self._hits.setdefault(ip, deque())
        while bucket and now - bucket[0] > self._window:
            bucket.popleft()
        if len(bucket) >= self._limit:
            return False
        bucket.append(now)
        return True

    def _prune(self, now: float) -> None:
        """Drop buckets with no hit inside the window; hard-cap tracked IPs."""
        stale = [ip for ip, b in self._hits.items() if not b or now - b[-1] > self._window]
        for ip in stale:
            del self._hits[ip]
        overflow = len(self._hits) - self._max_ips
        if overflow > 0:
            # Evict the IPs whose most recent hit is oldest, until under the cap.
            oldest = sorted(self._hits, key=lambda k: self._hits[k][-1])[:overflow]
            for ip in oldest:
                del self._hits[ip]


def client_ip(request: Request) -> str:
    """Best-effort client IP, honouring the first X-Forwarded-For hop (Traefik)."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# --------------------------------------------------------------------------- #
# GET /  — the form
# --------------------------------------------------------------------------- #


async def get_index() -> HTMLResponse:
    """The empty form (SPEC.md §4.4). No folder data is exposed without a POST."""
    html = render_template(
        "discovery.html",
        {"error": "", "content": "", "script": "", "show_all_checked": ""},
    )
    return HTMLResponse(html, headers=dict(_PAGE_HEADERS))


# --------------------------------------------------------------------------- #
# POST / — secret -> folder list / OPML
# --------------------------------------------------------------------------- #


async def post_index(request: Request, tree: MailboxTree, limiter: RateLimiter) -> Response:
    ip = client_ip(request)
    if not limiter.allow(ip):
        logger.warning(f"discovery_rate_limited: ip {ip}")
        return _page(error="Too many attempts. Please wait a minute.", status=429)

    raw = await request.body()
    form = parse_qs(raw.decode("utf-8", "replace"), keep_blank_values=True)
    secret = _first(form, "secret")
    show_all = _first(form, "show_all") == "1"
    want_opml = (
        _first(form, "format") == "opml"
        or request.query_params.get("format") == "opml"
        or "text/x-opml" in request.headers.get("accept", "").lower()
    )

    # Constant-time compare. The secret is NEVER logged (SPEC.md §4.4 p.4).
    expected = settings.mail2rss_secret
    if not hmac.compare_digest(secret.encode("utf-8"), expected.encode("utf-8")):
        logger.warning(f"discovery_auth_failed: ip {ip}")
        return _page(error="Invalid secret.", status=401)

    try:
        await tree.ensure_fresh()
    except Exception as exc:  # noqa: BLE001 - JMAP down: show a message, do not 500
        logger.warning(f"discovery_tree_unavailable: error {exc!r}")
        return _page(error="Could not reach Fastmail right now. Try again shortly.", status=503)

    folders = tree.list_folders(include_system=show_all)

    if want_opml:
        opml = build_opml(folders)
        return Response(
            opml.encode("utf-8"),
            media_type="text/x-opml; charset=utf-8",
            headers={
                **_PAGE_HEADERS,
                "Content-Disposition": 'attachment; filename="mail2rss.opml"',
            },
        )

    return _page(
        error="",
        content=_folder_section(folders),
        script=_COPY_SCRIPT,
        show_all=show_all,
    )


def _first(form: dict[str, list[str]], key: str) -> str:
    values = form.get(key)
    return values[0] if values else ""


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #


def _page(
    *,
    error: str = "",
    content: str = "",
    script: str = "",
    show_all: bool = False,
    status: int = 200,
) -> HTMLResponse:
    error_html = f'<div class="error">{escape(error)}</div>' if error else ""
    html = render_template(
        "discovery.html",
        {
            "error": error_html,
            "content": content,
            "script": script,
            "show_all_checked": "checked" if show_all else "",
        },
    )
    return HTMLResponse(html, status_code=status, headers=dict(_PAGE_HEADERS))


def _folder_section(folders) -> str:
    if not folders:
        return "<p>No folders to show.</p>"
    rows = [_folder_row(mailbox, path) for mailbox, path in folders]
    # OPML download as an INLINE data: link (SPEC.md §4.4): the OPML is generated
    # here on the first POST and offered as a base64 data URI, so the secret never
    # round-trips a second time and never sits in a hidden form field. A top-level
    # <a download> navigation is not blocked by the page CSP (default-src 'none').
    opml_b64 = base64.b64encode(build_opml(folders).encode("utf-8")).decode("ascii")
    opml_link = (
        f'<p><a download="mail2rss.opml" href="data:text/x-opml;base64,{opml_b64}">'
        "Download OPML (all listed folders)</a></p>"
    )
    return (
        f"<p>{len(folders)} folder(s). Feed defaults: 20 entries.</p>"
        + opml_link
        + '<ul class="folders">'
        + "".join(rows)
        + "</ul>"
    )


def _folder_row(mailbox, path: str) -> str:
    epoch = settings.epoch_for(mailbox.id)
    slug = slugify(mailbox.name)
    base = settings.base_url

    default_url = feed_url(base, slug, mailbox.id, feed_mac(mailbox.id, FeedParams(), epoch), FeedParams())
    child_params = FeedParams(children=True)
    child_url = feed_url(base, slug, mailbox.id, feed_mac(mailbox.id, child_params, epoch), child_params)

    return (
        '<li class="folder">'
        f'<div><span class="path">{escape(path)}</span> '
        f'<span class="count">{mailbox.total_emails} email(s)</span></div>'
        f'<input class="url" readonly value="{escape(default_url, quote=True)}">'
        f'<button class="copy" type="button" data-clip="{escape(default_url, quote=True)}">copy</button>'
        '<details><summary class="muted">include subfolders</summary>'
        f'<input class="url" readonly value="{escape(child_url, quote=True)}">'
        f'<button class="copy" type="button" data-clip="{escape(child_url, quote=True)}">copy</button>'
        "</details>"
        "</li>"
    )


def build_opml(folders) -> str:
    """OPML 2.0 of all listed folders' default feed URLs (SPEC.md §4.4)."""
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<opml version="2.0">',
        "<head><title>mail2rss</title></head>",
        "<body>",
    ]
    for mailbox, path in folders:
        epoch = settings.epoch_for(mailbox.id)
        url = feed_url(
            settings.base_url,
            slugify(mailbox.name),
            mailbox.id,
            feed_mac(mailbox.id, FeedParams(), epoch),
            FeedParams(),
        )
        text = escape(path, quote=True)
        lines.append(
            f'  <outline text="{text}" title="{text}" type="rss" '
            f'xmlUrl="{escape(url, quote=True)}"/>'
        )
    lines += ["</body>", "</opml>"]
    return "\n".join(lines)


# First-party inline script: attach clipboard copy to the buttons. No external
# resources are loaded (SPEC.md §5.2 p.7).
_COPY_SCRIPT = (
    "<script>document.querySelectorAll('button.copy').forEach(function(b){"
    "b.addEventListener('click',function(){"
    "navigator.clipboard&&navigator.clipboard.writeText(b.getAttribute('data-clip'));"
    "var t=b.textContent;b.textContent='copied';"
    "setTimeout(function(){b.textContent=t;},1200);});});</script>"
)
