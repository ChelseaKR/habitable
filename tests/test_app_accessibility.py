# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Automated accessibility invariants for the app shell (WCAG 2.2 AA basics).

This is not a substitute for axe + manual NVDA/VoiceOver review (tracked in the
ACR), but it gates the structural mistakes that are cheap to catch: language,
title, viewport, a skip link to a real target, labelled controls, alt text, no
positive tabindex, landmarks, and a single h1.
"""

from __future__ import annotations

from html.parser import HTMLParser
from pathlib import Path

_INDEX = Path(__file__).resolve().parent.parent / "app" / "index.html"
_EXEMPT_INPUT_TYPES = {"hidden", "submit", "button", "reset", "image"}


class _A11yParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.html_lang: str | None = None
        self.title_text = ""
        self._in_title = False
        self.has_viewport = False
        self.has_manifest = False
        self.ids: set[str] = set()
        self.label_for: set[str] = set()
        self.anchor_targets: list[str] = []
        self.controls: list[tuple[str, str, bool]] = []  # (label, id, has_aria_or_nested)
        self.img_missing_alt = 0
        self.positive_tabindex = 0
        self.h1 = 0
        self.main = 0
        self._label_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        d = {k: (v or "") for k, v in attrs}
        if tag == "html":
            self.html_lang = d.get("lang")
        elif tag == "title":
            self._in_title = True
        elif tag == "meta" and d.get("name") == "viewport":
            self.has_viewport = True
        elif tag == "link" and "manifest" in d.get("rel", ""):
            self.has_manifest = True
        elif tag == "main":
            self.main += 1
        elif tag == "h1":
            self.h1 += 1
        elif tag == "a" and d.get("href", "").startswith("#"):
            self.anchor_targets.append(d["href"][1:])
        elif tag == "img" and "alt" not in d:
            self.img_missing_alt += 1
        if d.get("id"):
            self.ids.add(d["id"])
        if tag == "label":
            self._label_depth += 1
            if d.get("for"):
                self.label_for.add(d["for"])
        if d.get("tabindex", "").lstrip("-").isdigit() and int(d["tabindex"]) > 0:
            self.positive_tabindex += 1
        if tag in {"input", "select", "textarea"}:
            input_type = d.get("type", "text")
            if not (tag == "input" and input_type in _EXEMPT_INPUT_TYPES):
                labelled = (
                    bool(d.get("aria-label") or d.get("aria-labelledby") or d.get("title"))
                    or self._label_depth > 0
                )
                name = d.get("id") or input_type
                self.controls.append((name, d.get("id", ""), labelled))

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        elif tag == "label":
            self._label_depth = max(0, self._label_depth - 1)

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title_text += data


def _parse() -> _A11yParser:
    assert _INDEX.is_file(), f"missing app shell: {_INDEX}"
    parser = _A11yParser()
    parser.feed(_INDEX.read_text(encoding="utf-8"))
    return parser


def test_language_title_viewport_manifest() -> None:
    p = _parse()
    assert p.html_lang, "<html> needs a lang attribute"
    assert p.title_text.strip(), "page needs a non-empty <title>"
    assert p.has_viewport, "responsive viewport meta is required"
    assert p.has_manifest, "PWA manifest link is required"


def test_skip_link_targets_a_real_element() -> None:
    p = _parse()
    assert any(target in p.ids for target in p.anchor_targets), (
        "a skip link should target an existing element id (e.g. #main)"
    )
    assert p.main >= 1 and p.h1 == 1, "exactly one <h1> and a <main> landmark expected"


def test_every_control_is_labelled() -> None:
    p = _parse()
    unlabeled = [
        name
        for name, control_id, has_aria in p.controls
        if not (has_aria or (control_id and control_id in p.label_for))
    ]
    assert not unlabeled, f"form controls without a label: {unlabeled}"


def test_images_have_alt_and_no_positive_tabindex() -> None:
    p = _parse()
    assert p.img_missing_alt == 0, "every <img> needs an alt attribute (empty if decorative)"
    assert p.positive_tabindex == 0, "no positive tabindex values allowed"


def test_aria_describedby_targets_exist() -> None:
    """Any aria-describedby must point at an element that actually exists."""
    html = _INDEX.read_text(encoding="utf-8")
    p = _parse()
    import re

    referenced = re.findall(r'aria-describedby="([^"]+)"', html)
    for group in referenced:
        for ident in group.split():
            assert ident in p.ids, f"aria-describedby points at missing id: {ident}"
