"""Tests for src/sanitize.py — the security gate (SPEC.md §7.5 step 13, §11)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import src.sanitize as sanitize
from src.sanitize import ALLOWED_TAGS, sanitize_html

SRC_DIR = Path(__file__).resolve().parent.parent / "src"


def test_style_block_content_does_not_leak_as_text():
    # clean_content_tags (not merely "absent from tags") is required: otherwise
    # the CSS text survives as visible text.
    out = sanitize_html("<style>.secret { color: red }</style>visible")
    assert "color: red" not in out
    assert ".secret" not in out
    assert "visible" in out


def test_script_content_removed_with_tag():
    out = sanitize_html("<script>alert('xss')</script>ok")
    assert "alert" not in out
    assert "ok" in out


def test_disallowed_url_schemes_dropped():
    out = sanitize_html(
        '<a href="javascript:alert(1)">x</a>'
        '<a href="data:text/html,evil">y</a>'
        '<img src="cid:leftover">'
    )
    assert "javascript:" not in out
    assert "data:" not in out
    assert "cid:" not in out


def test_allowed_schemes_survive():
    out = sanitize_html('<a href="https://ok/">a</a><a href="mailto:x@y.z">b</a>')
    assert "https://ok/" in out
    assert "mailto:x@y.z" in out


def test_relative_urls_denied():
    out = sanitize_html('<a href="/relative/path">x</a>')
    assert "/relative/path" not in out


def test_links_get_rel_noopener_noreferrer_nofollow():
    out = sanitize_html('<a href="https://ok/">x</a>')
    assert 'rel="noopener noreferrer nofollow"' in out


def test_fail_closed_escapes_on_error(monkeypatch):
    # Force the sanitiser to raise -> it must escape the raw input, never pass it
    # through unchanged.
    def boom(*_a, **_k):
        raise RuntimeError("nh3 exploded")

    monkeypatch.setattr(sanitize.nh3, "clean", boom)
    raw = "<b>bold</b><script>alert(1)</script>"
    out = sanitize_html(raw, log_context="unit")
    assert "<b>" not in out  # escaped, not passed through
    assert "&lt;b&gt;" in out
    assert "&lt;script&gt;" in out


def test_single_allowlist_in_repo():
    # SPEC.md §11: exactly ONE tag allow-list / one nh3 configuration in the tree.
    py_files = list(SRC_DIR.glob("*.py"))
    allowlist_defs = 0
    nh3_calls = 0
    for path in py_files:
        text = path.read_text(encoding="utf-8")
        allowlist_defs += len(re.findall(r"^ALLOWED_TAGS\b", text, re.MULTILINE))
        nh3_calls += text.count("nh3.clean(")
    assert allowlist_defs == 1, f"expected one ALLOWED_TAGS definition, found {allowlist_defs}"
    assert nh3_calls == 1, f"expected one nh3.clean() call site, found {nh3_calls}"


def test_allowlist_covers_email_structure():
    # A regression against accidentally dropping tags email bodies rely on.
    for tag in ("table", "tr", "td", "blockquote", "h1", "h6", "figure", "img", "a"):
        assert tag in ALLOWED_TAGS
