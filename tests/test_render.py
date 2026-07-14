"""Tests for src/render.py — email -> feed-safe HTML (SPEC.md §7.5, §7.5.1, §7.6)."""

from __future__ import annotations

from lxml import etree

from fixtures.sample_emails import HAZARD_HTML, inline_image, make_email
from src.render import RenderedEmail, render_email, text_to_html, truncate_html


def _media(part):
    """Injected media_url: serves inline images, drops nothing by default."""
    if part is None or part.blob_id is None:
        return None
    return f"https://media.example.com/blob/{part.blob_id}"


def render(email, **kw):
    return render_email(email, media_url=_media, **kw)


# --------------------------------------------------------------------------- #
# cid images (SPEC.md §7.5 steps 5-6, §8.1)
# --------------------------------------------------------------------------- #


def test_cid_image_rewritten_to_media_url():
    email = make_email(
        html_body='<p><img src="cid:logo" alt="l"></p>',
        attachments=(inline_image(cid="logo", blob_id="Bxyz"),),
    )
    out = render(email).html
    assert "https://media.example.com/blob/Bxyz" in out
    assert "cid:" not in out


def test_unresolved_cid_image_removed():
    email = make_email(html_body='<p><img src="cid:nope" alt="x">text</p>')
    out = render(email).html
    assert "cid:" not in out
    assert "<img" not in out
    assert "text" in out  # surrounding content preserved


def test_media_url_returning_none_drops_image():
    part = inline_image(cid="logo", blob_id=None)  # _media returns None for it
    email = make_email(html_body='<img src="cid:logo">', attachments=(part,))
    out = render(email).html
    assert "<img" not in out


# --------------------------------------------------------------------------- #
# tracking pixels (SPEC.md §7.5 step 7)
# --------------------------------------------------------------------------- #


def test_tracking_pixel_by_attribute_removed():
    email = make_email(
        html_body='<img src="https://t/p.gif" width="1" height="1">keep'
    )
    out = render(email).html
    assert "<img" not in out
    assert "keep" in out


def test_tracking_pixel_by_inline_style_removed():
    email = make_email(
        html_body='<img src="https://t/p.gif" style="width:1px;height:1px">'
    )
    assert "<img" not in render(email).html


def test_tracking_pixel_display_none_removed():
    email = make_email(html_body='<img src="https://t/p.gif" style="display:none">')
    assert "<img" not in render(email).html


def test_tracking_pixel_by_known_path_removed():
    email = make_email(html_body='<img src="https://x.example/track/beacon.gif">')
    assert "<img" not in render(email).html


# --------------------------------------------------------------------------- #
# MSO conditional comments + VML button (SPEC.md §7.5 step 3)
# --------------------------------------------------------------------------- #


def test_mso_vml_fallback_not_duplicated():
    out = render(make_email(html_body=HAZARD_HTML)).html
    # The VML button's fallback text lives inside an MSO conditional comment; it
    # must not appear at all, and certainly not twice next to the real button.
    assert out.count("DUPLICATE BUTTON TEXT") == 0
    assert "office spam" not in out  # namespaced <o:p> removed with content


# --------------------------------------------------------------------------- #
# no relative URLs / no styling survives (SPEC.md §7.5 steps 4, 11, F10)
# --------------------------------------------------------------------------- #


def test_no_relative_urls_or_styling_survives():
    out = render(make_email(html_body=HAZARD_HTML)).html
    for banned in ("style=", "class=", "bgcolor", "align=", "cellpadding", "cellspacing"):
        assert banned not in out, banned
    # relative link resolved against <base>, not left relative
    assert "deal.html" not in out or "https://ex.com/campaign/deal.html" in out
    # no bare relative src/href anywhere
    assert 'src="/' not in out
    assert 'href="/' not in out


def test_layout_table_unwrapped_button_becomes_link():
    out = render(make_email(html_body=HAZARD_HTML)).html
    # The single-link button-table collapses to a paragraph link.
    assert "Big Call To Action" in out
    assert "https://ex.com/cta" in out


def test_tracking_params_stripped_but_unsubscribe_untouched():
    out = render(make_email(html_body=HAZARD_HTML)).html
    # utm_* stripped from the ordinary (tracked) link, resolved against <base>
    assert "https://ex.com/campaign/deal.html?id=7" in out
    assert "utm_medium" not in out  # only appeared on the tracked link -> gone
    assert "utm_source=news" not in out  # the tracked link's utm_source is gone
    # the unsubscribe link is never touched: its one-time token AND its query
    # survive verbatim (utm_source=x is only on that link) (SPEC.md §7.5 step 9)
    assert "token=onetime-abc" in out
    assert "utm_source=x" in out


def test_list_unsubscribe_footer_added():
    email = make_email(
        html_body="<p>hi</p>",
        list_unsubscribe=("<https://ex.com/unsub?tok=z>", "mailto:u@ex.com"),
    )
    out = render(email).html
    assert "https://ex.com/unsub?tok=z" in out
    assert "Unsubscribe" in out


# --------------------------------------------------------------------------- #
# degradation — must not raise, must not drop (SPEC.md §7.5.1)
# --------------------------------------------------------------------------- #


def test_render_never_raises_on_garbage_returns_degraded(monkeypatch):
    import src.render as render_mod

    def explode(*_a, **_k):
        raise ValueError("lxml blew up")

    monkeypatch.setattr(render_mod.lxml.html, "document_fromstring", explode)
    email = make_email(
        html_body="<p>anything</p>", subject="Subj", from_name=None, from_email="s@x.y"
    )
    result = render(email, permalink="https://p/e.html")
    assert isinstance(result, RenderedEmail)
    assert result.degraded is True
    # stub still carries subject + sender + a permalink so the email stays visible
    assert "Subj" in result.html
    assert "s@x.y" in result.html
    assert "https://p/e.html" in result.html


def test_malformed_html_does_not_raise():
    email = make_email(html_body="<div><p>unclosed <b>tags <table><tr><td>x")
    result = render(email)
    assert isinstance(result, RenderedEmail)
    assert result.degraded is False  # lxml is lenient; body still rendered


# --------------------------------------------------------------------------- #
# text/plain fallback (SPEC.md §7.6)
# --------------------------------------------------------------------------- #


def test_no_content_stub_lists_attachments():
    from src.models import BodyPart

    att = BodyPart(
        part_id="1", blob_id="Bpdf", type="application/pdf", name="report.pdf",
        disposition="attachment", cid=None, size=2048,
    )
    email = make_email(html_body=None, text_body=None, attachments=(att,))
    out = render(email).html
    assert "report.pdf" in out
    assert "https://media.example.com/blob/Bpdf" in out
    assert render(email).degraded is False  # no-content is normal, not degraded


def test_text_body_used_when_no_html():
    email = make_email(html_body=None, text_body="Plain line one.\n\nSecond paragraph.")
    out = render(email).html
    assert "Plain line one." in out
    assert "Second paragraph." in out
    assert "<p>" in out


def test_flowed_text_has_no_ragged_lines():
    # format=flowed: each soft-wrapped line ends with a space and must rejoin.
    flowed = (
        "This paragraph was wrapped by a flowed encoder into several \n"
        "short lines each ending with a trailing space so a naive \n"
        "reader would otherwise show ragged 72-char lines.\n"
    )
    out = text_to_html(flowed)
    first_para = out.split("</p>")[0]
    assert "<br>" not in first_para  # rejoined into one flowing paragraph
    assert "ragged 72-char lines." in first_para


def test_text_linkifies_urls_and_emails():
    out = text_to_html("See https://example.com/a?b=1 or write to me@example.com.")
    assert '<a href="https://example.com/a?b=1">' in out
    assert '<a href="mailto:me@example.com">' in out


def test_text_quotes_become_blockquote():
    out = text_to_html("Intro.\n\n> quoted one\n> quoted two\n\nEnd.")
    assert "<blockquote>" in out
    assert "quoted one" in out


def test_text_not_wrapped_in_pre():
    out = text_to_html("line one\nline two")
    assert "<pre" not in out


# --------------------------------------------------------------------------- #
# truncation (SPEC.md §7.4)
# --------------------------------------------------------------------------- #


def test_truncate_cuts_on_block_boundary_and_stays_xml():
    html = "".join(f"<div>block number {i} carrying text</div>" for i in range(30))
    out = truncate_html(html, 150, "https://p/e.html")
    # parses as XML (no mid-string cut, void tags self-closed)
    etree.fromstring("<root>" + out + "</root>")
    assert "Читать письмо целиком" in out
    assert len(out.encode("utf-8")) < len(html.encode("utf-8"))
    # cut fell on a </div> boundary, not inside a tag or text run
    assert "block number 0" in out


def test_truncate_noop_when_within_limit():
    html = "<p>short</p>"
    assert truncate_html(html, 10_000, "https://p/e.html") == html
