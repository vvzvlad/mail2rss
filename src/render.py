"""Email -> feed-safe HTML (SPEC.md §7.5, §7.5.1, §7.6).

Pure, side-effect-free core. Given an ``Email`` this produces sanitised,
feed-safe HTML. It does NOT do HTTP, JMAP, signing or caching — the media URL is
injected by the caller (which owns the HMAC signing in src/crypto.py).

The pipeline ORDER is part of the spec (SPEC.md §7.5): the sanitiser runs LAST,
as a security gate, never first. ``render_email`` MUST NOT RAISE — on any internal
failure it returns a degraded stub with ``degraded=True`` (SPEC.md §7.5.1);
silently dropping the email is forbidden.
"""

from __future__ import annotations

import html as _html
import re
from dataclasses import dataclass
from typing import Callable
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import lxml.html
from loguru import logger
from lxml import etree

from src.models import BodyPart, Email
from src.sanitize import sanitize_html

# Elements removed together WITH their content during the lxml pre-pass
# (SPEC.md §7.5 step 3). This is NOT the sanitiser allow-list — it is a
# structural pre-clean. Removing <head>/<title> here also drops the document
# chrome; removing <style>/<script> here means their text never survives even
# before the sanitiser sees the fragment.
_REMOVE_WITH_CONTENT = (
    "script", "style", "noscript", "iframe", "object", "embed",
    "form", "input", "button", "select", "option", "textarea",
    "svg", "head", "title",
)

# Styling / layout attributes stripped from every element (SPEC.md §7.5 step 11):
# Miniflux discards them anyway, and partially applied CSS reads worse than none.
_STRIP_ATTRS = (
    "style", "class", "bgcolor", "background",
    "align", "valign", "cellpadding", "cellspacing", "border",
)

# Tracking query parameters removed from links (SPEC.md §7.5 step 8).
_TRACKING_PARAMS_EXACT = {"mc_eid", "fbclid", "gclid", "yclid", "_openstat"}

# Links we never touch — they carry one-shot tokens (SPEC.md §7.5 step 9).
_UNSUB_MARKERS = ("unsubscribe", "preferences", "optout", "opt-out", "opt_out")

# Known tracking-pixel path fragments (SPEC.md §7.5 step 7).
_TRACKER_PATHS = ("/open", "/o/", "/track/", "/pixel")

_HTTP_SCHEMES = ("http", "https")

_URL_RE = re.compile(r"(https?://[^\s<>\"']+)", re.IGNORECASE)
_EMAIL_RE = re.compile(r"([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})")


@dataclass(frozen=True)
class RenderedEmail:
    """Result of rendering one email into feed-safe HTML."""

    html: str  # sanitised, feed-safe, NOT truncated
    degraded: bool  # True if the body could not be rendered (SPEC.md §7.5.1)


def render_email(
    email: Email,
    *,
    media_url: Callable[[BodyPart], str | None],
    permalink: str | None = None,
) -> RenderedEmail:
    """Render ``email`` into sanitised, feed-safe HTML (not truncated).

    ``media_url(part)`` is injected by the caller (it does the HMAC signing).
    Returning None means the part cannot be served -> the <img> is dropped.

    ``permalink`` is optional: when supplied it is used as the "open message"
    link inside the degraded stub (SPEC.md §7.5.1 requires the stub to link to
    the permalink; the mandatory call form omits it, so it is keyword-optional).

    Never raises: on any internal failure a degraded stub is returned with
    ``degraded=True`` (SPEC.md §7.5.1). Silently dropping the email is forbidden.
    """
    ctx = f"email {email.id}"
    try:
        html_body = email.html_body
        text_body = email.text_body
        if html_body and html_body.strip():
            inner = _transform_html(html_body, email, media_url)
        elif text_body and text_body.strip():
            inner = text_to_html(text_body)
        else:
            inner = _no_content_stub(email, media_url)
        inner += _unsubscribe_footer(email)
        cleaned = sanitize_html(inner, log_context=ctx)
        return RenderedEmail(html=cleaned, degraded=False)
    except Exception as exc:  # noqa: BLE001 - must never raise (SPEC.md §7.5.1)
        logger.warning(f"render_degraded: {ctx}, error {exc!r}")
        stub = _degraded_stub(email, permalink)
        cleaned = sanitize_html(stub, log_context=f"{ctx} degraded")
        return RenderedEmail(html=cleaned, degraded=True)


# --------------------------------------------------------------------------- #
# HTML pipeline (SPEC.md §7.5 steps 2-11)
# --------------------------------------------------------------------------- #


def _transform_html(
    raw: str,
    email: Email,
    media_url: Callable[[BodyPart], str | None],
) -> str:
    """Run the lxml transformation pipeline and return inner-body HTML.

    Steps 2-11 of SPEC.md §7.5. Step 1 (body pick) is the caller's; steps 12-14
    (footer, sanitise, XML-char stripping) happen outside this function.
    """
    doc = lxml.html.document_fromstring(raw)

    # Step 2: base href — read it, remember it, then remove the tag(s).
    base_href: str | None = None
    for base in doc.iter("base"):
        href = (base.get("href") or "").strip()
        if href and base_href is None:
            base_href = href
    for base in list(doc.iter("base")):
        if base.getparent() is not None:
            base.drop_tree()

    # Step 3: remove-with-content + comments + namespaced (v:/o:/w:/x:) elements.
    _strip_with_content(doc)

    body = doc.find("body")
    if body is None:
        body = doc

    # Steps 4 & 5: absolutise/rewrite image sources, drop tracking pixels.
    cid_map = {part.cid: part for part in email.attachments if part.cid}
    for img in list(body.iter("img")):
        _process_img(img, base_href, cid_map, media_url)

    # Steps 4 & 8: absolutise link hrefs, strip tracking params.
    for anchor in list(body.iter("a", "area")):
        _process_link(anchor, base_href)

    # Step 10: semantise layout — unwrap font/center, then layout tables.
    for el in list(body.iter("font", "center")):
        if el.getparent() is not None:
            el.drop_tag()
    _unwrap_layout_tables(body)

    # Step 11: strip all styling/layout attributes.
    for el in body.iter():
        if not isinstance(el.tag, str):
            continue
        for attr in _STRIP_ATTRS:
            if attr in el.attrib:
                del el.attrib[attr]

    return _serialize_inner(body)


def _strip_with_content(doc: lxml.html.HtmlElement) -> None:
    """SPEC.md §7.5 step 3: remove dangerous/chrome elements with their content,
    all HTML comments (kills MSO conditional comments) and all namespaced
    elements (v:/o:/w:/x:) — otherwise the sanitiser unwraps the latter and a
    VML button's fallback text is emitted a second time next to the real one."""
    etree.strip_elements(doc, *_REMOVE_WITH_CONTENT, with_tail=False)
    etree.strip_elements(doc, etree.Comment, with_tail=False)
    # Namespaced elements have a str tag containing ':' (e.g. "o:p", "v:shape").
    for el in [e for e in doc.iter() if isinstance(e.tag, str) and ":" in e.tag]:
        if el.getparent() is not None:
            el.drop_tree()


def _drop(el: lxml.html.HtmlElement) -> None:
    """Remove an element together with its content, keeping surrounding text."""
    if el.getparent() is not None:
        el.drop_tree()


def _process_img(
    img: lxml.html.HtmlElement,
    base_href: str | None,
    cid_map: dict[str, BodyPart],
    media_url: Callable[[BodyPart], str | None],
) -> None:
    """SPEC.md §7.5 steps 4-7 for one <img>: absolutise/rewrite src, then drop it
    if it is unresolvable, a leftover cid, a disallowed scheme or a tracking
    pixel."""
    src = (img.get("src") or "").strip()
    if not src:
        _drop(img)
        return
    scheme = urlsplit(src).scheme.lower()

    if scheme == "cid":
        cid = src[4:].strip().strip("<>")
        part = cid_map.get(cid)
        url = media_url(part) if part is not None else None
        if url:
            img.set("src", url)
        else:
            _drop(img)  # unresolved cid -> remove the <img> entirely
            return
    elif scheme in _HTTP_SCHEMES:
        pass  # already absolute
    elif scheme == "":
        # Relative URL: resolve against <base>, else drop the image.
        resolved = urljoin(base_href, src) if base_href else ""
        if resolved and urlsplit(resolved).scheme.lower() in _HTTP_SCHEMES:
            img.set("src", resolved)
        else:
            _drop(img)  # not one relative URL may reach the feed (F10)
            return
    else:
        _drop(img)  # data:, javascript:, etc.
        return

    if _is_tracking_pixel(img):
        _drop(img)


def _process_link(anchor: lxml.html.HtmlElement, base_href: str | None) -> None:
    """SPEC.md §7.5 steps 4, 8, 9 for one <a>/<area>."""
    href = (anchor.get("href") or "").strip()
    if not href:
        return
    scheme = urlsplit(href).scheme.lower()

    if scheme == "":
        resolved = urljoin(base_href, href) if base_href else ""
        if resolved and urlsplit(resolved).scheme.lower() in ("http", "https", "mailto"):
            href = resolved
            anchor.set("href", href)
        else:
            anchor.attrib.pop("href", None)  # unresolvable relative -> drop attr
            return
    elif scheme in _HTTP_SCHEMES:
        pass
    elif scheme == "mailto":
        return  # nothing to strip from a mailto
    else:
        anchor.attrib.pop("href", None)  # javascript:, etc. — let it become plain
        return

    # Step 9: never touch unsubscribe/preferences/optout links (one-shot tokens).
    if any(marker in href.lower() for marker in _UNSUB_MARKERS):
        return
    cleaned = _strip_tracking_params(href)
    if cleaned != href:
        anchor.set("href", cleaned)


def _strip_tracking_params(url: str) -> str:
    """SPEC.md §7.5 step 8: drop utm_* and known tracking query parameters."""
    parts = urlsplit(url)
    if not parts.query:
        return url
    kept = [
        (key, value)
        for key, value in parse_qsl(parts.query, keep_blank_values=True)
        if not (key.lower().startswith("utm_") or key.lower() in _TRACKING_PARAMS_EXACT)
    ]
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(kept), parts.fragment)
    )


def _parse_dim(value: str | None) -> int | None:
    """Parse an integer pixel dimension from an attribute like '1' or '1px'."""
    if value is None:
        return None
    match = re.match(r"\s*(-?\d+)", value)
    return int(match.group(1)) if match else None


def _css_dim(style: str, prop: str) -> float | None:
    """Parse a pixel dimension for `prop` from an inline style string."""
    match = re.compile(
        r"(?:^|;)\s*%s\s*:\s*([0-9.]+)\s*px" % re.escape(prop), re.IGNORECASE
    ).search(style)
    return float(match.group(1)) if match else None


def _is_tracking_pixel(img: lxml.html.HtmlElement) -> bool:
    """SPEC.md §7.5 step 7: width/height <= 1 (attribute OR inline style),
    zero area, display:none, or a known tracker path."""
    style = (img.get("style") or "")
    dims = (
        _parse_dim(img.get("width")),
        _parse_dim(img.get("height")),
        _css_dim(style, "width"),
        _css_dim(style, "height"),
    )
    for dim in dims:
        if dim is not None and dim <= 1:  # <= 1 also covers a zero-area pixel
            return True
    if "display:none" in style.replace(" ", "").lower():
        return True
    src = (img.get("src") or "").lower()
    return any(path in src for path in _TRACKER_PATHS)


def _unwrap_layout_tables(body: lxml.html.HtmlElement) -> None:
    """SPEC.md §7.5 step 10: unwrap layout tables (no <th>/<caption>); a one-link
    button-table becomes <p><a>. Data tables (with <th>/<caption>) are kept."""
    for _ in range(50):  # bounded; converts innermost layout tables first
        target = None
        for table in body.iter("table"):
            if table.find(".//th") is not None or table.find(".//caption") is not None:
                continue  # real data table — leave it alone
            if table.find(".//table") is not None:
                continue  # process the innermost table first
            target = table
            break
        if target is None:
            return
        _convert_layout_table(target)


def _convert_layout_table(table: lxml.html.HtmlElement) -> None:
    parent = table.getparent()
    if parent is None:
        return
    anchors = table.findall(".//a")
    all_text = "".join(table.itertext()).strip()

    # One-link button-table -> <p><a>text</a></p>.
    if len(anchors) == 1:
        anchor = anchors[0]
        anchor_text = "".join(anchor.itertext()).strip()
        if anchor_text and anchor_text == all_text:
            para = etree.Element("p")
            new_a = etree.SubElement(para, "a")
            if anchor.get("href"):
                new_a.set("href", anchor.get("href"))
            new_a.text = anchor_text
            para.tail = table.tail
            parent.replace(table, para)
            return

    # Generic unwrap: table -> div of row-divs of cell-divs (reading order kept).
    container = etree.Element("div")
    for row in table.findall(".//tr"):
        row_div = etree.SubElement(container, "div")
        for cell in row.findall("./td") + row.findall("./th"):
            cell_div = etree.SubElement(row_div, "div")
            cell_div.text = cell.text
            for child in list(cell):
                cell_div.append(child)  # reparents the child out of the cell
    container.tail = table.tail
    parent.replace(table, container)


def _serialize_inner(body: lxml.html.HtmlElement) -> str:
    """Serialise the inner HTML of `body` (children + leading text)."""
    parts: list[str] = []
    if body.text:
        parts.append(_html.escape(body.text, quote=False))
    for child in body:
        parts.append(lxml.html.tostring(child, encoding="unicode"))
    return "".join(parts)


# --------------------------------------------------------------------------- #
# Stubs (SPEC.md §7.5.1, §7.6)
# --------------------------------------------------------------------------- #


def _unsubscribe_footer(email: Email) -> str:
    """SPEC.md §7.5 step 12: a footer with the List-Unsubscribe link, if any."""
    url = _first_unsub_url(email.list_unsubscribe)
    if not url:
        return ""
    return f'<hr><p><a href="{_html.escape(url, quote=True)}">Unsubscribe</a></p>'


def _first_unsub_url(candidates: tuple[str, ...]) -> str | None:
    for raw in candidates:
        url = (raw or "").strip().strip("<>")
        if urlsplit(url).scheme.lower() in ("http", "https", "mailto"):
            return url
    return None


def _no_content_stub(email: Email, media_url: Callable[[BodyPart], str | None]) -> str:
    """SPEC.md §7.6: neither html nor text — note plus an attachment list."""
    parts = ["<p>This message has no textual content.</p>"]
    attachments = [a for a in email.attachments if (a.disposition or "") != "inline"]
    if attachments:
        items = []
        for part in attachments:
            name = part.name or part.blob_id or "attachment"
            url = media_url(part)
            if url:
                items.append(
                    f'<li><a href="{_html.escape(url, quote=True)}">'
                    f"{_html.escape(name, quote=False)}</a></li>"
                )
            else:
                items.append(f"<li>{_html.escape(name, quote=False)}</li>")
        parts.append("<p>Attachments:</p><ul>" + "".join(items) + "</ul>")
    return "".join(parts)


def _degraded_stub(email: Email, permalink: str | None) -> str:
    """SPEC.md §7.5.1: subject + sender + date + permalink + a "could not render"
    note. Degradation, not silence — the email must stay visible in the feed."""
    subject = _html.escape(email.subject or "(no subject)", quote=False)
    sender = _html.escape(
        email.from_name or email.from_email or "unknown sender", quote=False
    )
    date = _html.escape(email.received_at.isoformat(), quote=False)
    link = ""
    if permalink:
        link = (
            f'<p><a href="{_html.escape(permalink, quote=True)}">'
            "Open message →</a></p>"
        )
    return (
        f"<p><strong>{subject}</strong></p>"
        f"<p>From: {sender}<br>Date: {date}</p>"
        f"<p>The message body could not be rendered.</p>{link}"
    )


# --------------------------------------------------------------------------- #
# text/plain fallback (SPEC.md §7.6) and truncation (SPEC.md §7.4)
# --------------------------------------------------------------------------- #


def text_to_html(text: str) -> str:
    """Convert a text/plain body to HTML (SPEC.md §7.6).

    Handles format=flowed / DelSp (RFC 3676) so soft-wrapped 72-char lines are
    rejoined; a blank line starts a new <p>, a single newline is a <br>, "> "
    quotes become <blockquote>, and URLs/emails are linkified. Not wrapped in
    <pre> (that breaks wrapping on mobile).
    """
    if not text:
        return "<p></p>"
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = _unflow(text.split("\n"))

    blocks: list[str] = []
    para: list[str] = []
    for line in lines:
        if line.strip() == "":
            if para:
                blocks.append(_render_para(para))
                para = []
        else:
            para.append(line)
    if para:
        blocks.append(_render_para(para))
    return "".join(blocks) or "<p></p>"


def _unflow(lines: list[str]) -> list[str]:
    """RFC 3676: undo space-stuffing and rejoin flowed (soft-wrapped) lines."""
    # Un-stuff a single leading space that flowed encoding may have added.
    unstuffed = [line[1:] if line.startswith(" ") else line for line in lines]
    merged: list[str] = []
    buffer = ""
    flowing = False
    for line in unstuffed:
        buffer = buffer + line if flowing else line
        # A line ending in a space is soft-wrapped, except the "-- " sig marker.
        if line.endswith(" ") and line != "-- ":
            flowing = True
        else:
            merged.append(buffer)
            buffer = ""
            flowing = False
    if flowing or buffer:
        merged.append(buffer)
    return merged


def _render_para(lines: list[str]) -> str:
    if lines and all(line.lstrip().startswith(">") for line in lines):
        inner = []
        for line in lines:
            stripped = line.lstrip()[1:]
            if stripped.startswith(" "):
                stripped = stripped[1:]
            inner.append(stripped)
        if not any(line.strip() for line in inner):
            inner = [""]
        return "<blockquote>" + _render_para(inner) + "</blockquote>"
    body = "<br>".join(_linkify(line) for line in lines)
    return f"<p>{body}</p>"


def _linkify(segment: str) -> str:
    """Escape text and turn bare URLs into <a> links (emails become mailto)."""
    out: list[str] = []
    pos = 0
    for match in _URL_RE.finditer(segment):
        out.append(_linkify_emails(segment[pos:match.start()]))
        url, trailing = _trim_url(match.group(0))
        out.append(
            f'<a href="{_html.escape(url, quote=True)}">'
            f"{_html.escape(url, quote=False)}</a>"
        )
        out.append(_html.escape(trailing, quote=False))
        pos = match.end()
    out.append(_linkify_emails(segment[pos:]))
    return "".join(out)


def _linkify_emails(segment: str) -> str:
    out: list[str] = []
    pos = 0
    for match in _EMAIL_RE.finditer(segment):
        out.append(_html.escape(segment[pos:match.start()], quote=False))
        addr = match.group(0)
        out.append(
            f'<a href="mailto:{_html.escape(addr, quote=True)}">'
            f"{_html.escape(addr, quote=False)}</a>"
        )
        pos = match.end()
    out.append(_html.escape(segment[pos:], quote=False))
    return "".join(out)


def _trim_url(url: str) -> tuple[str, str]:
    """Split trailing sentence punctuation off a bare URL."""
    trailing = ""
    while url and url[-1] in ".,;:!?)]}’”":
        trailing = url[-1] + trailing
        url = url[:-1]
    return url, trailing


def truncate_html(html: str, limit_bytes: int, permalink: str) -> str:
    """Truncate feed HTML at a BLOCK-ELEMENT boundary (SPEC.md §7.4).

    Never cuts mid-string (that yields broken XML): whole top-level elements are
    kept until the byte budget is reached, then a "read the full message" link is
    appended. Output is XML-serialised (void tags self-closed) so it parses as XML.
    """
    read_more = (
        f'<p><a href="{_html.escape(permalink, quote=True)}">'
        "Читать письмо целиком →</a></p>"
    )
    if len(html.encode("utf-8")) <= limit_bytes:
        return html
    try:
        container = lxml.html.fragment_fromstring(html, create_parent="body")
    except Exception:  # noqa: BLE001 - malformed input still gets a valid tail
        return read_more

    kept: list[str] = []
    total = 0
    if container.text and container.text.strip():
        leading = _html.escape(container.text, quote=False)
        kept.append(leading)
        total += len(leading.encode("utf-8"))
    for child in container:
        chunk = etree.tostring(child, encoding="unicode")  # XML: void tags closed
        chunk_len = len(chunk.encode("utf-8"))
        if kept and total + chunk_len > limit_bytes:
            break
        kept.append(chunk)
        total += chunk_len
    return "".join(kept) + read_more
