# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Safety, CSV, and internal-link contracts for the tenant-union survey template."""

from __future__ import annotations

import csv
import re
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse

_SITE = Path(__file__).resolve().parent.parent / "site"
_SURVEY = _SITE / "templates" / "tenant-union-building-condition-survey" / "index.html"
_CSV = _SURVEY.with_name("tenant-union-building-condition-survey.csv")
_FIELDS = (
    "survey_record_reference",
    "unit_or_member_reference",
    "scope",
    "area_label",
    "condition_category",
    "condition_description",
    "reported_occurrence_date",
    "survey_recorded_date",
    "recurrence_status",
    "recurrence_notes",
    "repair_request_date",
    "repair_request_method",
    "repair_request_reference",
    "response_date",
    "response_summary",
    "access_date",
    "access_status",
    "official_record_type",
    "official_record_reference",
    "permission_to_aggregate",
    "aggregation_limits",
    "organizer_campaign_status",
    "follow_up_owner",
    "supporting_record_reference",
    "last_reviewed_date",
    "organizer_notes",
)


class _ContractParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.anchors: list[dict[str, str | None]] = []
        self.main_anchors: list[str] = []
        self.scripts: list[dict[str, str | None]] = []
        self.tags: list[str] = []
        self.visible_parts: list[str] = []
        self._in_body = False
        self._in_main = False
        self._ignored_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        self.tags.append(tag)
        if tag == "body":
            self._in_body = True
        elif tag == "main":
            self._in_main = True
        elif tag in {"script", "style"}:
            self._ignored_depth += 1
        if tag == "script":
            self.scripts.append(values)
        if tag == "a":
            self.anchors.append(values)
            href = values.get("href")
            if self._in_main and href:
                self.main_anchors.append(href)

    def handle_endtag(self, tag: str) -> None:
        if tag == "body":
            self._in_body = False
        elif tag == "main":
            self._in_main = False
        elif tag in {"script", "style"}:
            self._ignored_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._in_body and self._ignored_depth == 0 and data.strip():
            self.visible_parts.append(data.strip())


def _parse(path: Path) -> _ContractParser:
    parser = _ContractParser()
    parser.feed(path.read_text(encoding="utf-8"))
    return parser


def _resolved_page(source: Path, href: str) -> Path | None:
    parsed = urlparse(href)
    if parsed.scheme or parsed.netloc:
        return None
    target = (source.parent / parsed.path).resolve()
    if target.is_dir() or parsed.path.endswith("/"):
        target /= "index.html"
    return target


def test_survey_csv_is_utf8_header_only_and_uses_bounded_fields() -> None:
    raw = _CSV.read_bytes()
    assert not raw.startswith(b"\xef\xbb\xbf")
    text = raw.decode("utf-8")
    reader = csv.reader(text.splitlines())
    assert tuple(next(reader)) == _FIELDS
    assert list(reader) == []

    direct_identity_fields = {
        "tenant_name",
        "member_name",
        "street_address",
        "apartment_number",
        "phone",
        "email",
    }
    assert direct_identity_fields.isdisjoint(_FIELDS)


def test_survey_download_is_static_local_and_collects_nothing() -> None:
    parser = _parse(_SURVEY)
    downloads = [anchor for anchor in parser.anchors if "download" in anchor]
    assert downloads == [
        {
            "class": "download-action",
            "href": "tenant-union-building-condition-survey.csv",
            "download": None,
            "type": "text/csv",
        }
    ]
    assert _resolved_page(_SURVEY, downloads[0]["href"] or "") == _CSV
    assert not ({"form", "input", "textarea", "select", "button"} & set(parser.tags))
    assert parser.scripts == [{"type": "application/ld+json"}]


def test_survey_explains_every_safety_and_interpretation_boundary() -> None:
    parser = _parse(_SURVEY)
    visible = re.sub(r"\s+", " ", " ".join(parser.visible_parts)).casefold()
    required_phrases = {
        "pseudonymous references",
        "private_unit",
        "common_area",
        "reported occurrence date",
        "recurrence_status",
        "repair_request_reference",
        "response_summary",
        "access_status",
        "official_record_reference",
        "permission_to_aggregate",
        "organizer_campaign_status",
        "underlying private records",
        "does not verify evidence",
        "does not diagnose",
        "not legal advice",
        "does not prove current conditions, notice, receipt",
        "reviewed 10 july 2026",
    }
    missing = {phrase for phrase in required_phrases if phrase not in visible}
    assert not missing

    hrefs = {anchor.get("href") for anchor in parser.anchors}
    assert hrefs >= {
        "https://tenantsunion.org/programs/how-to-organize-your-tenant-council",
        "https://www.metcouncilonhousing.org/help-answers/getting-repairs/",
    }


def test_survey_has_three_contextual_inbound_paths() -> None:
    sources = [
        _SITE / "index.html",
        _SITE / "tenant-unions" / "index.html",
        _SITE / "documentation-checklist" / "index.html",
    ]
    linked_from = {
        source
        for source in sources
        if any(_resolved_page(source, href) == _SURVEY for href in _parse(source).main_anchors)
    }
    assert linked_from == set(sources)
