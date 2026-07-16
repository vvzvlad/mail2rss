"""The link-calculator page (SPEC.md §4.4).

The page is a pure CLIENT-SIDE calculator: the browser derives K_feed and
computes the feed MAC itself (WebCrypto: HKDF-SHA256 + HMAC-SHA256, byte-for-byte
the scheme from src/crypto.py) and assembles the final URL locally. The server
neither receives the secret nor reveals any mailbox data — there is no POST route
and no folder tree or OPML over HTTP — so there is no oracle to protect. Folder
listing and OPML live in the CLI only (`mail2rss folders`, `mail2rss opml`,
SPEC.md §4.5). The server's sole contribution is serving this static page with
the configured BASE_URL embedded.
"""

from __future__ import annotations

import re
from pathlib import Path

from starlette.responses import HTMLResponse

from src.settings import settings

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"

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


async def get_index() -> HTMLResponse:
    """The static calculator page (SPEC.md §4.4). No mailbox data is served."""
    html = render_template("discovery.html", {"base_url": settings.base_url})
    return HTMLResponse(html, headers=dict(_PAGE_HEADERS))
