# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Public review-hub content, safety, interaction, and reflow contracts."""

from __future__ import annotations

import json
import re
from html.parser import HTMLParser
from pathlib import Path
from typing import cast
from urllib.parse import unquote, urlparse

import pytest

_SITE = Path(__file__).resolve().parent.parent / "site"
_REVIEW = _SITE / "review" / "index.html"
_CHANGES = _SITE / "review" / "changes" / "index.html"
_CANONICAL = "https://habitable.chelseakr.com/review/"


class _ReviewParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[dict[str, str]] = []
        self.meta: list[dict[str, str]] = []
        self.ids: set[str] = set()
        self.json_ld: list[str] = []
        self.slide_count = 0
        self.task_count = 0
        self.form_count = 0
        self.input_types: list[str] = []
        self.visible: list[str] = []
        self._in_body = False
        self._ignored_depth = 0
        self._json_parts: list[str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name: value or "" for name, value in attrs}
        self._collect_element(tag, values)
        if tag == "body":
            self._in_body = True
        elif tag in {"script", "style"}:
            self._ignored_depth += 1
            if tag == "script" and values.get("type") == "application/ld+json":
                self._json_parts = []

    def _collect_element(self, tag: str, values: dict[str, str]) -> None:
        if values.get("id"):
            self.ids.add(values["id"])
        if tag in {"a", "link"}:
            self.links.append(values)
        elif tag == "meta":
            self.meta.append(values)
        elif tag == "form":
            self.form_count += 1
        elif tag == "input":
            self.input_types.append(values.get("type", "text").casefold())
        if "data-slide" in values:
            self.slide_count += 1
        if values.get("id", "").startswith("task-"):
            self.task_count += 1

    def handle_endtag(self, tag: str) -> None:
        if tag == "body":
            self._in_body = False
        elif tag in {"script", "style"}:
            self._ignored_depth -= 1
            if tag == "script" and self._json_parts is not None:
                self.json_ld.append("".join(self._json_parts))
                self._json_parts = None

    def handle_data(self, data: str) -> None:
        if self._json_parts is not None:
            self._json_parts.append(data)
        elif self._in_body and self._ignored_depth == 0 and data.strip():
            self.visible.append(data.strip())


def _parse(path: Path = _REVIEW) -> _ReviewParser:
    parser = _ReviewParser()
    parser.feed(path.read_text(encoding="utf-8"))
    return parser


def _text(path: Path = _REVIEW) -> str:
    return re.sub(r"\s+", " ", " ".join(_parse(path).visible)).strip()


def test_review_page_has_complete_metadata_and_structured_scope() -> None:
    parser = _parse()
    named = {item["name"]: item["content"] for item in parser.meta if item.get("name")}
    canonicals = [item for item in parser.links if item.get("rel") == "canonical"]
    assert canonicals == [{"rel": "canonical", "href": _CANONICAL}]
    assert 120 <= len(named["description"]) <= 170
    assert named["robots"] == "index, follow, max-image-preview:large"
    assert len(parser.json_ld) == 1
    graph = json.loads(parser.json_ld[0])["@graph"]
    assert {item["@type"] for item in graph} == {"WebPage", "BreadcrumbList"}
    assert graph[0]["mainEntityOfPage"] == _CANONICAL


def test_four_tracks_are_bounded_and_security_is_not_called_an_audit() -> None:
    body = _text()
    assert {
        "organizer-track",
        "legal-track",
        "accessibility-track",
        "security-track",
    } <= _parse().ids
    assert "Tenant organizer / workflow fit" in body
    assert "45 min" in body
    assert "Legal aid / recipient comprehension" in body
    assert "20 min" in body
    assert "keyboard or assistive technology" in body
    assert "This is focused review, not an independent audit or security certification" in body
    certification_boundary = (
        "A review can identify a problem; it cannot by itself certify accessibility, "
        "security, legal fitness, or admissibility"
    )
    assert certification_boundary in body


def test_six_tasks_name_effort_and_expected_output() -> None:
    parser = _parse()
    body = _text()
    assert parser.task_count == 6
    assert {
        "task-organizer",
        "task-legal",
        "task-keyboard",
        "task-screen-reader",
        "task-threat-model",
        "task-verifier",
    } <= parser.ids
    assert body.count("Expected output:") == 6
    for code in ("OR-01", "LA-01", "AX-01", "AX-02", "SE-01", "SE-02"):
        assert code in body
    for effort in ("20 min", "30 min", "45 min", "60 min"):
        assert effort in body


def test_feedback_routes_are_separate_and_accept_no_evidence() -> None:
    parser = _parse()
    body = _text()
    hrefs = {link.get("href", "") for link in parser.links}
    assert "https://github.com/ChelseaKR/habitable/discussions/127" in hrefs
    assert any("issues?q=" in href for href in hrefs)
    assert "mailto:ckellyreif@gmail.com?subject=%5Bhabitable%20organization%20review%5D" in hrefs
    assert "https://github.com/ChelseaKR/habitable/security/advisories/new" in hrefs
    assert "No evidence uploads anywhere" in body
    assert "Email is not an evidence-transfer system" in body
    assert "do not upload a recording" in body
    assert parser.form_count == 0
    assert "file" not in parser.input_types


def test_walkthrough_is_user_started_75_seconds_and_has_a_transcript() -> None:
    parser = _parse()
    source = _REVIEW.read_text(encoding="utf-8")
    body = _text()
    assert parser.slide_count == 6
    assert 'data-duration-ms="75000"' in source
    assert "Start 75-second walkthrough" in body
    assert "Nothing starts until you choose Start" in body
    assert body.count("Chapter ") >= 6
    assert "integrity: intact" in body
    assert "timestamp authority: NOT TRUSTED" in body
    assert "evidence readiness: NOT READY" in body
    assert (_REVIEW.parent / "walkthrough.js").is_file()
    assert (_REVIEW.parent / "review.css").is_file()


def test_change_log_starts_honestly_and_defines_recurring_entry_fields() -> None:
    body = _text(_CHANGES)
    assert "No outside findings recorded yet" in body
    assert "not a reviewer finding" in body
    assert "What reviewers found" in body
    assert "What changed" in body
    assert "after each completed review and at least monthly while review intake is active" in body
    for field in (
        "date",
        "reviewer role and credit preference",
        "synthetic scope",
        "finding",
        "project response",
        "remaining gap",
        "status",
    ):
        assert field in body


@pytest.mark.parametrize("page", [_REVIEW, _CHANGES])
def test_review_internal_links_resolve(page: Path) -> None:
    parser = _parse(page)
    for link in parser.links:
        href = link.get("href", "")
        parsed = urlparse(href)
        if not href or parsed.scheme or href.startswith("//"):
            continue
        local = unquote(parsed.path)
        target = (page.parent / local).resolve() if local else page
        if target.is_dir():
            target = target / "index.html"
        assert target.is_file(), f"missing internal target from {page}: {href}"


@pytest.mark.a11y
@pytest.mark.parametrize("width,height", [(320, 800), (1280, 900)])
def test_review_reflows_and_walkthrough_controls_work(width: int, height: int) -> None:
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
            page.goto(_REVIEW.as_uri(), wait_until="load")
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
            assert page.locator("[data-walk-controls]").is_visible()
            assert page.locator("[data-slide]:visible").count() == 1
            page.locator("[data-walk-next]").click()
            assert page.locator('[data-walk-chapter="1"]').get_attribute("aria-current") == "step"
            toggle = page.locator("[data-walk-toggle]")
            toggle.click()
            assert toggle.get_attribute("aria-pressed") == "true"
            toggle.click()
            assert toggle.get_attribute("aria-pressed") == "false"
            for selector in ("[data-walk-toggle]", "[data-walk-prev]", "[data-walk-next]"):
                box = page.locator(selector).bounding_box()
                assert box is not None
                assert box["height"] >= 44
        finally:
            browser.close()
