# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Technical SEO contract for the GitHub Pages landing page."""

from __future__ import annotations

import json
from datetime import date
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse
from xml.etree import ElementTree

_SITE = Path(__file__).resolve().parent.parent / "site"
_CANONICAL = "https://chelseakr.github.io/habitable/"
_TITLE = "Habitable Evidence — Offline Tenant Repair Documentation"
_DESCRIPTION = (
    "Habitable Evidence helps tenants and unions document repairs, notices, photos, and "
    "timelines offline—then share a packet anyone can verify."
)


class _LandingParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.meta: list[dict[str, str]] = []
        self.links: list[dict[str, str]] = []
        self.images: list[dict[str, str]] = []
        self.json_ld: list[str] = []
        self.title_parts: list[str] = []
        self.visible_text_parts: list[str] = []
        self._in_title = False
        self._in_body = False
        self._ignored_depth = 0
        self._json_parts: list[str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name: value or "" for name, value in attrs}
        if tag == "meta":
            self.meta.append(values)
        elif tag == "link":
            self.links.append(values)
        elif tag == "img":
            self.images.append(values)
        elif tag == "title":
            self._in_title = True
        elif tag == "body":
            self._in_body = True
        elif tag in {"script", "style"}:
            self._ignored_depth += 1
            if tag == "script" and values.get("type") == "application/ld+json":
                self._json_parts = []

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        elif tag == "body":
            self._in_body = False
        elif tag in {"script", "style"}:
            self._ignored_depth -= 1
            if tag == "script" and self._json_parts is not None:
                self.json_ld.append("".join(self._json_parts))
                self._json_parts = None

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title_parts.append(data)
        if self._json_parts is not None:
            self._json_parts.append(data)
        elif self._in_body and self._ignored_depth == 0 and data.strip():
            self.visible_text_parts.append(data.strip())


def _landing() -> _LandingParser:
    parser = _LandingParser()
    parser.feed((_SITE / "index.html").read_text(encoding="utf-8"))
    return parser


def _meta_values(parser: _LandingParser, attribute: str) -> dict[str, str]:
    return {
        item[attribute]: item["content"]
        for item in parser.meta
        if item.get(attribute) and "content" in item
    }


def test_landing_metadata_is_complete_and_consistent() -> None:
    parser = _landing()
    title = "".join(parser.title_parts).strip()
    named = _meta_values(parser, "name")
    open_graph = _meta_values(parser, "property")

    assert title == _TITLE
    assert 30 <= len(title) <= 60
    assert named["description"] == _DESCRIPTION
    assert 120 <= len(named["description"]) <= 160
    assert named["robots"] == "index, follow, max-image-preview:large"

    canonicals = [link for link in parser.links if link.get("rel") == "canonical"]
    assert canonicals == [{"rel": "canonical", "href": _CANONICAL}]

    expected_open_graph = {
        "og:type": "website",
        "og:locale": "en_US",
        "og:site_name": "Habitable Evidence",
        "og:url": _CANONICAL,
        "og:title": _TITLE,
        "og:description": _DESCRIPTION,
        "og:image": f"{_CANONICAL}img/app-en.png",
        "og:image:type": "image/png",
        "og:image:width": "2200",
        "og:image:height": "3000",
    }
    assert open_graph.items() >= expected_open_graph.items()

    expected_twitter = {
        "twitter:card": "summary",
        "twitter:title": _TITLE,
        "twitter:description": _DESCRIPTION,
        "twitter:image": f"{_CANONICAL}img/app-en.png",
    }
    assert named.items() >= expected_twitter.items()

    favicons = [link for link in parser.links if link.get("rel") == "icon"]
    assert favicons == [{"rel": "icon", "href": "img/icon.svg", "type": "image/svg+xml"}]
    assert (_SITE / favicons[0]["href"]).is_file()


def test_structured_data_matches_visible_project_claims() -> None:
    parser = _landing()
    assert len(parser.json_ld) == 1
    document = json.loads(parser.json_ld[0])
    assert document["@context"] == "https://schema.org"

    graph = document["@graph"]
    by_type = {item["@type"]: item for item in graph}
    assert by_type.keys() >= {
        "Person",
        "WebSite",
        "WebPage",
        "ImageObject",
        "SoftwareApplication",
        "SoftwareSourceCode",
    }
    # The page calls this an independent personal project. An Organization node would
    # manufacture an entity that does not exist, so the public author is the publisher.
    assert "Organization" not in by_type

    page = by_type["WebPage"]
    assert page["url"] == _CANONICAL
    assert page["name"] == _TITLE
    assert page["description"] == _DESCRIPTION

    software = by_type["SoftwareApplication"]
    assert software["name"] == "habitable"
    assert software["applicationCategory"] == "UtilitiesApplication"
    assert software["operatingSystem"] == "Any operating system that supports Python 3.14"
    assert software["isAccessibleForFree"] is True
    assert software["offers"] == {"@type": "Offer", "price": 0}
    assert "aggregateRating" not in software
    assert "review" not in software

    source = by_type["SoftwareSourceCode"]
    assert source["codeRepository"] == "https://github.com/ChelseaKR/habitable"
    assert source["programmingLanguage"] == "Python"
    assert source["license"] == "https://spdx.org/licenses/AGPL-3.0-or-later.html"

    visible_text = " ".join(parser.visible_text_parts)
    assert by_type["Person"]["name"] in visible_text
    assert "Python (3.14)" in visible_text
    assert "AGPL-3.0" in visible_text


def test_sitemap_lists_the_canonical_indexable_pages() -> None:
    sitemap = ElementTree.parse(_SITE / "sitemap.xml")
    namespace = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
    urls = sitemap.findall("sm:url", namespace)
    expected = [
        _CANONICAL,
        f"{_CANONICAL}how-it-works/",
        f"{_CANONICAL}documentation-checklist/",
        f"{_CANONICAL}guides/preserve-maintenance-request-records/",
        f"{_CANONICAL}tenant-unions/",
        f"{_CANONICAL}legal-aid-reviewers/",
        f"{_CANONICAL}inspectors-code-enforcement/",
        f"{_CANONICAL}trust-limitations/",
    ]
    assert [url.findtext("sm:loc", namespaces=namespace) for url in urls] == expected

    for url in urls:
        last_modified = url.findtext("sm:lastmod", namespaces=namespace)
        assert last_modified is not None
        assert date.fromisoformat(last_modified) <= date.today()
    assert sitemap.findall(".//sm:priority", namespace) == []
    assert sitemap.findall(".//sm:changefreq", namespace) == []


def test_robots_allows_the_pages_base_path_and_advertises_sitemap() -> None:
    lines = {
        line.strip()
        for line in (_SITE / "robots.txt").read_text(encoding="utf-8").splitlines()
        if line.strip()
    }
    assert lines == {
        "User-agent: *",
        "Allow: /habitable/",
        f"Sitemap: {_CANONICAL}sitemap.xml",
    }


def test_landing_images_reserve_layout_space_and_defer_screenshots() -> None:
    parser = _landing()
    assert parser.images
    for image in parser.images:
        assert int(image["width"]) > 0
        assert int(image["height"]) > 0
        source = image["src"]
        parsed = urlparse(source)
        assert not parsed.scheme, f"expected a locally deployed image, got {source}"
        assert (_SITE / parsed.path).is_file(), f"missing image: {source}"

    screenshots = [image for image in parser.images if image["src"].endswith(".png")]
    assert len(screenshots) == 3
    for image in screenshots:
        assert image["loading"] == "lazy"
        assert image["decoding"] == "async"
