# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Positioning, safety-routing, and responsive contracts for the public homepage."""

from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path
from typing import cast
from urllib.parse import parse_qs, urlparse

import pytest

_SITE_ROOT = Path(__file__).resolve().parent.parent / "site"
_REPO_ROOT = _SITE_ROOT.parent
_LANDING = _SITE_ROOT / "index.html"
_PILOT_URL = "https://github.com/ChelseaKR/habitable/issues/new?template=reviewer-intake.yml"


def _normalize(parts: list[str]) -> str:
    return re.sub(r"\s+", " ", " ".join(parts)).strip()


def _normalize_inline(parts: list[str]) -> str:
    return re.sub(r"\s+", " ", "".join(parts)).strip()


class _PositioningParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.visible_parts: list[str] = []
        self.headings: dict[str, list[str]] = {"h1": [], "h2": [], "h3": []}
        self.links: list[dict[str, str]] = []
        self.form_count = 0
        self._in_body = False
        self._ignored_depth = 0
        self._heading_tag: str | None = None
        self._heading_parts: list[str] = []
        self._link: dict[str, str] | None = None
        self._link_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name: value or "" for name, value in attrs}
        if tag == "body":
            self._in_body = True
        elif tag in {"script", "style"}:
            self._ignored_depth += 1
        elif self._in_body and tag in self.headings:
            self._heading_tag = tag
            self._heading_parts = []
        elif self._in_body and tag == "a":
            self._link = values
            self._link_parts = []
        elif self._in_body and tag == "form":
            self.form_count += 1

    def handle_endtag(self, tag: str) -> None:
        if tag == "body":
            self._in_body = False
        elif tag in {"script", "style"}:
            self._ignored_depth -= 1
        elif tag == self._heading_tag:
            self.headings[tag].append(_normalize_inline(self._heading_parts))
            self._heading_tag = None
            self._heading_parts = []
        elif tag == "a" and self._link is not None:
            self._link["text"] = _normalize_inline(self._link_parts)
            self.links.append(self._link)
            self._link = None
            self._link_parts = []

    def handle_data(self, data: str) -> None:
        if not self._in_body or self._ignored_depth:
            return
        if data.strip():
            self.visible_parts.append(data.strip())
        if self._heading_tag is not None:
            self._heading_parts.append(data)
        if self._link is not None:
            self._link_parts.append(data)


def _landing() -> _PositioningParser:
    parser = _PositioningParser()
    parser.feed(_LANDING.read_text(encoding="utf-8"))
    return parser


def test_hero_uses_the_case_building_thesis_and_honest_alpha_boundary() -> None:
    parser = _landing()
    assert parser.headings["h1"] == ["A building problem leaves a trail. Keep the whole trail."]

    body = _normalize(parser.visible_parts)
    assert "Habitable Evidence" in body
    assert "not independently audited or proven in court" in body
    assert "Do not rely on it for a real legal matter yet" in body
    assert "court-organized alpha packet" in body
    assert "court-ready" not in body.casefold()


def test_primary_actions_route_to_pilot_sample_and_evidence_method() -> None:
    parser = _landing()
    by_id = {link["id"]: link for link in parser.links if link.get("id")}

    assert by_id["pilot-cta"]["href"] == _PILOT_URL
    pilot = urlparse(by_id["pilot-cta"]["href"])
    assert pilot.scheme == "https"
    assert pilot.netloc == "github.com"
    assert parse_qs(pilot.query) == {"template": ["reviewer-intake.yml"]}
    assert by_id["pilot-cta"]["text"] == "Offer a synthetic-data pilot"

    assert by_id["sample-cta"]["href"] == "sample-packet/packet.html"
    assert by_id["method-cta"]["href"] == "how-it-works/"
    assert by_id["method-cta"]["text"] == "Read how the evidence method works"

    body = _normalize(parser.visible_parts)
    assert "The pilot link opens a public GitHub form" in body
    assert "Never include tenant names, addresses, photos, evidence, or case details" in body
    assert parser.form_count == 0, "the static site must not collect pilot or tenant data"

    intake = (_REPO_ROOT / ".github" / "ISSUE_TEMPLATE" / "reviewer-intake.yml").read_text(
        encoding="utf-8"
    )
    assert "Evaluate using synthetic `habitable demo` data only" in intake
    assert "will not handle real tenant data" in intake
    assert "not the place to submit findings" in intake.replace("**", "")


def test_each_audience_has_an_explicit_route() -> None:
    parser = _landing()
    headings = parser.headings["h3"]
    assert "Tenant unions" in headings
    assert "Legal aid, attorneys, and inspectors" in headings
    assert "Reviewers and contributors" in headings

    link_text = {link["text"] for link in parser.links}
    assert link_text >= {
        "Plan a bounded union evaluation",
        "Follow the legal-aid review guide",
        "Follow the inspector review guide",
        "Read the open trust gates",
        "Browse the source",
    }


def test_open_review_and_pilot_gaps_are_visible() -> None:
    body = _normalize(_landing().visible_parts)
    for gap in (
        "An independent security and cryptography audit",
        "Housing-law review of the legal framing and packet workflow",
        "A real tenant-union or legal-aid pilot with documented outcomes",
        "A recorded human NVDA and VoiceOver pass",
        "signed native distribution",
    ):
        assert gap in body

    assert "cannot prove what a photo depicts" in body
    assert "whether a particular court or agency will admit it" in body


def test_help_links_use_authoritative_public_resources() -> None:
    parser = _landing()
    expected = {
        "https://www.usa.gov/tenant-rights",
        "https://oag.ca.gov/tenants",
        "https://selfhelp.courts.ca.gov/get-free-or-low-cost-legal-help",
    }
    actual = {link["href"] for link in parser.links if link["href"] in expected}
    assert actual == expected
    assert {urlparse(url).netloc for url in actual} == {
        "www.usa.gov",
        "oag.ca.gov",
        "selfhelp.courts.ca.gov",
    }

    body = _normalize(parser.visible_parts)
    assert "not legal advice, an emergency service, or a place to post evidence" in body
    assert "Do not put tenant names, addresses, photos, or case details in GitHub issues" in body


@pytest.mark.a11y
@pytest.mark.parametrize("width,height", [(320, 800), (1280, 900)])
def test_landing_reflows_and_keeps_primary_actions_tappable(width: int, height: int) -> None:
    pytest.importorskip("playwright.sync_api")
    from playwright.sync_api import Error as PlaywrightError
    from playwright.sync_api import sync_playwright

    with sync_playwright() as playwright:
        try:
            browser = playwright.chromium.launch()
        except PlaywrightError as exc:
            pytest.skip(f"Chromium not available: {exc}")
        try:
            page = browser.new_page(viewport={"width": width, "height": height})
            page.goto(_LANDING.as_uri(), wait_until="load")
            dimensions = cast(
                dict[str, int],
                page.evaluate(
                    """() => ({
                      viewport: document.documentElement.clientWidth,
                      content: document.documentElement.scrollWidth
                    })"""
                ),
            )
            assert dimensions["content"] <= dimensions["viewport"]
            assert page.locator("h1").is_visible()
            for selector in ("#pilot-cta", "#sample-cta"):
                box = page.locator(selector).bounding_box()
                assert box is not None
                assert box["width"] >= 44
                assert box["height"] >= 44
        finally:
            browser.close()
