"""Shared email fixtures for the render/feed tests.

`make_email` builds an `Email` with sensible defaults that individual tests
override. The raw-HTML constants below stand in for saved JMAP `Email/get`
body values (SPEC.md §11: HTML with tables + MSO conditionals, cid images,
control characters, etc.).
"""

from __future__ import annotations

from datetime import datetime, timezone

from src.models import BodyPart, Email

FIXED_RECEIVED = datetime(2026, 7, 1, 12, 30, 45, tzinfo=timezone.utc)


def make_email(**overrides) -> Email:
    """Build an Email fixture; override any field via keyword."""
    defaults = dict(
        id="Ea1b2c3d4",
        message_id="<msg-0001@newsletter.example.com>",
        subject="Weekly digest",
        from_name="Example News",
        from_email="news@example.com",
        received_at=FIXED_RECEIVED,
        preview="This week in tech",
        mailbox_ids=("M9f3ac21b",),
        html_body=None,
        text_body=None,
        html_truncated=False,
        attachments=(),
        list_unsubscribe=(),
        list_id="newsletter.example.com",
    )
    defaults.update(overrides)
    return Email(**defaults)


def inline_image(cid: str = "logo", blob_id: str = "Bimg001") -> BodyPart:
    return BodyPart(
        part_id="2",
        blob_id=blob_id,
        type="image/png",
        name="logo.png",
        disposition="inline",
        cid=cid,
        size=1024,
    )


# An email that mixes almost every hazard the pipeline must neutralise.
HAZARD_HTML = """<html><head><title>Should be gone</title>
<style>.leak { color: red; } /* MUST NOT LEAK AS TEXT */</style></head>
<body>
<base href="https://ex.com/campaign/">
<!--[if mso]>
<v:roundrect xmlns:v="urn:schemas-microsoft-com:vml" href="https://ex.com/btn">
<w:anchorlock/><center>DUPLICATE BUTTON TEXT</center></v:roundrect>
<![endif]-->
<o:p>office spam</o:p>
<p style="color:black" class="hdr" bgcolor="#ffffff" align="center">Hello reader</p>
<img src="cid:logo" alt="logo">
<img src="cid:missing" alt="missing inline">
<img src="/pixel.gif" width="1" height="1" alt="pixel-attr">
<img src="https://ex.com/img.png" style="width:1px;height:1px" alt="pixel-style">
<img src="https://ex.com/hidden.png" style="display:none" alt="pixel-hidden">
<img src="https://tracker.example/open?id=42" alt="pixel-path">
<a href="deal.html?utm_source=news&utm_medium=email&id=7">Read the deal</a>
<a href="https://ex.com/unsubscribe?token=onetime-abc&utm_source=x">Unsubscribe here</a>
<table cellpadding="0" cellspacing="0" border="0">
  <tr><td><a href="https://ex.com/cta">Big Call To Action</a></td></tr>
</table>
<table><tr><td>Row A cell 1</td><td>Row A cell 2</td></tr></table>
</body></html>"""
