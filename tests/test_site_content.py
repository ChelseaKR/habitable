# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""People-first SEO, link, and claim contracts for the public content guides."""

from __future__ import annotations

import json
import re
from datetime import date
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse

import pytest

_SITE = Path(__file__).resolve().parent.parent / "site"
_BASE = "https://chelseakr.github.io/habitable/"
_PAGE_META = {
    "how-it-works": (
        "How Habitable Evidence Works | Offline Repair Records",
        "Learn how Habitable Evidence organizes repair conditions, notices, responses, sealed "
        "captures, and selective exports in one offline record.",
    ),
    "documentation-checklist": (
        "Safe Repair Documentation Checklist | Habitable Evidence",
        "Use this safety-first checklist to organize repair photos, notices, responses, and "
        "recurring conditions without posting private tenant data online.",
    ),
    "tenant-unions": (
        "Tenant Union Evaluation Guide | Habitable Evidence",
        "A bounded, synthetic-data evaluation plan for tenant unions reviewing Habitable Evidence "
        "workflows, privacy boundaries, and adoption gates.",
    ),
    "legal-aid-reviewers": (
        "Legal Aid Evidence Packet Review | Habitable Evidence",
        "Review Habitable Evidence packet structure, integrity checks, disclosure, accessibility, "
        "and limits with synthetic data before any real-case use.",
    ),
    "inspectors-code-enforcement": (
        "Housing Inspector Review Guide | Habitable Evidence",
        "See how a synthetic Habitable Evidence packet presents conditions, timelines, notices, "
        "and integrity records for inspector or code-enforcement review.",
    ),
    "trust-limitations": (
        "Trust, Security & Legal Limits | Habitable Evidence",
        "Understand what Habitable Evidence integrity checks can establish, what remains unproven, "
        "and which security, privacy, and legal gates remain open.",
    ),
}


class _ContentParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.html_attrs: dict[str, str] = {}
        self.meta: list[dict[str, str]] = []
        self.links: list[dict[str, str]] = []
        self.anchors: list[str] = []
        self.images: list[dict[str, str]] = []
        self.ids: set[str] = set()
        self.json_ld: list[str] = []
        self.title_parts: list[str] = []
        self.h1_parts: list[str] = []
        self.visible_parts: list[str] = []
        self.main_count = 0
        self.h1_count = 0
        self.collection_controls: list[str] = []
        self.non_json_scripts: list[dict[str, str]] = []
        self._in_title = False
        self._in_h1 = False
        self._in_body = False
        self._ignored_depth = 0
        self._json_parts: list[str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name: value or "" for name, value in attrs}
        self._record_document_node(tag, values)
        self._record_parser_state(tag)
        self._record_public_surface_constraint(tag, values)

    def _record_document_node(self, tag: str, values: dict[str, str]) -> None:
        if tag == "html":
            self.html_attrs = values
        elif tag == "meta":
            self.meta.append(values)
        elif tag == "link":
            self.links.append(values)
        elif tag == "a" and values.get("href"):
            self.anchors.append(values["href"])
        elif tag == "img":
            self.images.append(values)

    def _record_parser_state(self, tag: str) -> None:
        if tag == "main":
            self.main_count += 1
        elif tag == "title":
            self._in_title = True
        elif tag == "h1":
            self.h1_count += 1
            self._in_h1 = True
        elif tag == "body":
            self._in_body = True

    def _record_public_surface_constraint(self, tag: str, values: dict[str, str]) -> None:
        if values.get("id"):
            self.ids.add(values["id"])
        if tag in {"form", "input", "textarea", "select", "button"}:
            self.collection_controls.append(tag)
        if tag in {"script", "style"}:
            self._ignored_depth += 1
        if tag == "script":
            if values.get("type") == "application/ld+json":
                self._json_parts = []
            else:
                self.non_json_scripts.append(values)

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        elif tag == "h1":
            self._in_h1 = False
        elif tag == "body":
            self._in_body = False
        if tag in {"script", "style"}:
            self._ignored_depth -= 1
        if tag == "script" and self._json_parts is not None:
            self.json_ld.append("".join(self._json_parts))
            self._json_parts = None

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title_parts.append(data)
        if self._in_h1:
            self.h1_parts.append(data)
        if self._json_parts is not None:
            self._json_parts.append(data)
        elif self._in_body and self._ignored_depth == 0 and data.strip():
            self.visible_parts.append(data.strip())


def _parse(path: Path) -> _ContentParser:
    parser = _ContentParser()
    parser.feed(path.read_text(encoding="utf-8"))
    return parser


def _meta_values(parser: _ContentParser, attribute: str) -> dict[str, str]:
    return {
        item[attribute]: item["content"]
        for item in parser.meta
        if item.get(attribute) and "content" in item
    }


def _resolve_local(source: Path, href: str) -> Path | None:
    parsed = urlparse(href)
    if parsed.scheme or parsed.netloc:
        return None
    target = (source.parent / parsed.path).resolve()
    if target.is_dir() or parsed.path.endswith("/"):
        target /= "index.html"
    return target


@pytest.mark.parametrize("slug", _PAGE_META)
def test_content_page_has_unique_consistent_metadata(slug: str) -> None:
    expected_title, expected_description = _PAGE_META[slug]
    canonical = f"{_BASE}{slug}/"
    parser = _parse(_SITE / slug / "index.html")
    named = _meta_values(parser, "name")
    open_graph = _meta_values(parser, "property")
    title = "".join(parser.title_parts).strip()

    assert parser.html_attrs["lang"] == "en"
    assert title == expected_title
    assert 50 <= len(title) <= 60
    assert named["description"] == expected_description
    assert 120 <= len(named["description"]) <= 160
    assert named["robots"] == "index, follow, max-image-preview:large"
    assert [link for link in parser.links if link.get("rel") == "canonical"] == [
        {"rel": "canonical", "href": canonical}
    ]

    assert open_graph["og:type"] == "article"
    assert open_graph["og:site_name"] == "Habitable Evidence"
    assert open_graph["og:url"] == canonical
    assert open_graph["og:title"] == expected_title
    assert open_graph["og:description"] == expected_description
    assert open_graph["og:image"].startswith(f"{_BASE}img/")
    assert open_graph["og:image:alt"]
    assert named["twitter:card"] == "summary"
    assert named["twitter:title"] == expected_title
    assert named["twitter:description"] == expected_description
    assert named["twitter:image"] == open_graph["og:image"]


@pytest.mark.parametrize("slug", _PAGE_META)
def test_content_page_uses_only_truthful_article_and_breadcrumb_schema(slug: str) -> None:
    _, expected_description = _PAGE_META[slug]
    canonical = f"{_BASE}{slug}/"
    parser = _parse(_SITE / slug / "index.html")

    assert len(parser.json_ld) == 1
    document = json.loads(parser.json_ld[0])
    assert document["@context"] == "https://schema.org"
    graph = document["@graph"]
    assert [item["@type"] for item in graph] == ["Article", "BreadcrumbList"]

    article = graph[0]
    assert article["description"] == expected_description
    assert article["mainEntityOfPage"] == canonical
    assert article["inLanguage"] == "en"
    assert article["author"] == {
        "@type": "Person",
        "name": "Chelsea Kelly-Reif",
        "url": "https://chelseakr.github.io/",
    }
    assert date.fromisoformat(article["datePublished"]) <= date.today()
    assert date.fromisoformat(article["dateModified"]) <= date.today()
    assert "review" not in article
    assert "aggregateRating" not in article

    crumbs = graph[1]["itemListElement"]
    assert [crumb["@type"] for crumb in crumbs] == ["ListItem", "ListItem"]
    assert [crumb["position"] for crumb in crumbs] == [1, 2]
    assert crumbs[0]["item"] == _BASE
    assert crumbs[-1]["item"] == canonical


@pytest.mark.parametrize("slug", _PAGE_META)
def test_content_page_is_semantic_static_and_claim_safe(slug: str) -> None:
    parser = _parse(_SITE / slug / "index.html")
    visible = " ".join(parser.visible_parts)
    normalized = re.sub(r"\s+", " ", visible).casefold()

    assert parser.main_count == 1
    assert parser.h1_count == 1
    assert len(parser.h1_parts) > 0
    assert parser.collection_controls == []
    assert parser.non_json_scripts == []
    assert "not legal advice" in normalized or "legal boundary" in normalized
    assert "synthetic" in normalized
    assert "court-ready" not in normalized
    assert "admissib" not in normalized
    assert "successful pilot" not in normalized
    assert "completed pilot" not in normalized
    assert "has been independently audited" not in normalized
    assert "guaranteed" not in normalized
    assert "submit tenant data" in normalized or "do not send tenant" in normalized

    for image in parser.images:
        target = _resolve_local(_SITE / slug / "index.html", image["src"])
        assert target is not None, f"content image must deploy locally: {image['src']}"
        assert target.is_file(), f"missing image: {target}"
        assert image.get("width") and image.get("height")
        assert "alt" in image


def test_public_content_links_resolve_and_pages_are_cross_linked() -> None:
    pages = [_SITE / "index.html", *(_SITE / slug / "index.html" for slug in _PAGE_META)]
    inbound: dict[str, set[Path]] = {slug: set() for slug in _PAGE_META}

    for page in pages:
        parser = _parse(page)
        for href in parser.anchors:
            target = _resolve_local(page, href)
            if target is None:
                continue
            assert _SITE.resolve() in {target, *target.parents}, f"link escapes site: {href}"
            assert target.is_file(), f"broken link from {page.relative_to(_SITE)}: {href}"
            for slug in _PAGE_META:
                if target == (_SITE / slug / "index.html").resolve() and target != page.resolve():
                    inbound[slug].add(page)

    homepage_links = set(_parse(_SITE / "index.html").anchors)
    for slug, sources in inbound.items():
        assert f"{slug}/" in homepage_links, f"homepage does not link to {slug}"
        assert len(sources) >= 3, f"{slug} needs multiple useful internal paths"


@pytest.mark.parametrize("slug", _PAGE_META)
def test_content_assets_resolve(slug: str) -> None:
    page = _SITE / slug / "index.html"
    parser = _parse(page)
    local_assets = [
        item["href"] for item in parser.links if item.get("rel") in {"icon", "stylesheet"}
    ]
    assert local_assets == ["../img/icon.svg", "../content.css"]
    for href in local_assets:
        target = _resolve_local(page, href)
        assert target is not None and target.is_file()


def test_metadata_is_unique_across_content_guides() -> None:
    titles = {title for title, _ in _PAGE_META.values()}
    descriptions = {description for _, description in _PAGE_META.values()}
    assert len(titles) == len(_PAGE_META)
    assert len(descriptions) == len(_PAGE_META)


@pytest.mark.parametrize("slug", _PAGE_META)
def test_inline_emphasis_does_not_join_visible_words(slug: str) -> None:
    """Closing inline markup must not collapse adjacent words in rendered copy."""
    html = (_SITE / slug / "index.html").read_text(encoding="utf-8")
    assert not re.search(r"</(?:strong|em|a|span)>[A-Za-z]", html)


def test_public_issue_links_carry_a_visible_privacy_warning() -> None:
    for slug in _PAGE_META:
        parser = _parse(_SITE / slug / "index.html")
        if not any("github.com/ChelseaKR/habitable/issues/new" in href for href in parser.anchors):
            continue
        visible = " ".join(parser.visible_parts).casefold()
        assert "public github issue" in visible
        assert "never include tenant" in visible or "do not include client" in visible
