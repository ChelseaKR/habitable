# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Technical SEO contract for the GitHub Pages landing page."""

from __future__ import annotations

import json
from datetime import date
from hashlib import sha256
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse
from xml.etree import ElementTree

_SITE = Path(__file__).resolve().parent.parent / "site"
_CANONICAL = "https://habitable.chelseakr.com/"
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


def _parse(markup: str) -> _LandingParser:
    parser = _LandingParser()
    parser.feed(markup)
    return parser


def _landing() -> _LandingParser:
    return _parse((_SITE / "index.html").read_text(encoding="utf-8"))


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


# Every published page, in sitemap order: the path it answers on, the date the
# sitemap tells a crawler it last changed, and the SHA-256 of the bytes that
# date describes.
#
# The digest is here because `lastmod` is the one sitemap field a search engine
# still reads, and only for as long as it is true. Nothing about a hand-written
# sitemap notices when a page is edited and its date is not, and this one had
# gone eleven weeks stale exactly that way. So the date is pinned to the bytes:
# edit a page and the digest stops matching, and the failure says to move both.
_PUBLISHED: tuple[tuple[str, str, str], ...] = (
    ("", "2026-07-23", "86409460d70fe37379a25fd7cc03097170b581f1212ae4e68fc2bbedccff8624"),
    (
        "how-it-works/",
        "2026-08-28",
        "8db5441de82be7d87480a22f6fc8c6c157618b287c70a06c434da015e3d60a7c",
    ),
    (
        "documentation-checklist/",
        "2026-08-28",
        "2ad9d0aea40433da765366c6609c992d4b958edd97f3b3b2416479c2fb107040",
    ),
    (
        "guides/preserve-maintenance-request-records/",
        "2026-08-28",
        "12908268e99a65165c182bd8a4c6bb4950ad0410fb120ee99ffc19e75fe76004",
    ),
    (
        "guides/housing-inspection-records/",
        "2026-08-28",
        "026779b8b912f51cb7d90f59803595f5a56507ad1aa0bf88720a8677881f6f7b",
    ),
    (
        "tenant-unions/",
        "2026-08-28",
        "8101d8f0a67eba6ac4b79a3ccf2f7e180311ef0ce8a4bfb9365a9556ee282f94",
    ),
    (
        "templates/tenant-union-building-condition-survey/",
        "2026-08-28",
        "a60ba212a72b342244aa4591028f25a497e4aa3db69080981b311dcf59549426",
    ),
    (
        "legal-aid-reviewers/",
        "2026-08-28",
        "f1ac30292a59341d4f62f11820138ca1447c80465563723dbcc9ef6f6d1e8896",
    ),
    (
        "inspectors-code-enforcement/",
        "2026-08-28",
        "29a6a9e3ad75df355ec54625ac1b890a04215ae39c6c6669ebfb6ec0e5dc4f86",
    ),
    (
        "trust-limitations/",
        "2026-08-28",
        "12fb29a5140acf17dd0a551432d73d26489f34c5a9478a59d859432de323d5fe",
    ),
    ("review/", "2026-08-28", "2a5730cde544b5349c0de4bebfa27d7bc4409b8fb92369912a34ed2d8ca56f50"),
    (
        "review/changes/",
        "2026-08-28",
        "ee38956b23857d12dc77c5e364d99f95df2e27b1b67ea37c8a6fa21cf553448e",
    ),
)


def _page_file(path: str) -> Path:
    return _SITE / path / "index.html"


def test_sitemap_lists_the_canonical_indexable_pages() -> None:
    sitemap = ElementTree.parse(_SITE / "sitemap.xml")
    namespace = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
    urls = sitemap.findall("sm:url", namespace)
    expected = [f"{_CANONICAL}{path}" for path, _, _ in _PUBLISHED]
    assert [url.findtext("sm:loc", namespaces=namespace) for url in urls] == expected

    for url in urls:
        last_modified = url.findtext("sm:lastmod", namespaces=namespace)
        assert last_modified is not None
        assert date.fromisoformat(last_modified) <= date.today()
    assert sitemap.findall(".//sm:priority", namespace) == []
    assert sitemap.findall(".//sm:changefreq", namespace) == []


def test_every_sitemap_url_resolves_to_a_page_that_was_published() -> None:
    """A sitemap entry with no page behind it is a 404 handed to a crawler."""
    for path, _, _ in _PUBLISHED:
        assert _page_file(path).is_file(), path


def test_each_sitemap_date_still_describes_the_bytes_it_was_written_for() -> None:
    """`lastmod` is only worth publishing while it is true.

    A stale date is not a neutral one: a crawler that has already read a page
    and is told it has not changed since has been given a reason not to look
    again. So the date is pinned to a digest of the page it describes.
    """
    sitemap = ElementTree.parse(_SITE / "sitemap.xml")
    namespace = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
    dates = {
        url.findtext("sm:loc", namespaces=namespace): url.findtext(
            "sm:lastmod", namespaces=namespace
        )
        for url in sitemap.findall("sm:url", namespace)
    }
    for path, last_modified, digest in _PUBLISHED:
        current = sha256(_page_file(path).read_bytes()).hexdigest()
        assert current == digest, (
            f"{path or '/'} has changed since its sitemap date was written. "
            f"Set its lastmod to the date of this change and its digest to "
            f"{current}."
        )
        assert dates[f"{_CANONICAL}{path}"] == last_modified, path


def test_no_published_page_is_left_out_of_the_sitemap_without_saying_so() -> None:
    """A page can be left out of the sitemap. It cannot be left out silently.

    `site/sample-packet/packet.html` was reachable, linked from the homepage,
    and in neither the sitemap nor a `noindex` -- so a crawler was free to
    index a synthetic tenancy record as an ordinary page of this site. Either
    a page is offered for indexing here, or it says it is not for indexing.
    """
    listed = {_page_file(path).resolve() for path, _, _ in _PUBLISHED}
    for page in sorted(_SITE.rglob("*.html")):
        if page.resolve() in listed:
            continue
        parser = _parse(page.read_text(encoding="utf-8"))
        directive = next(
            (meta.get("content", "") for meta in parser.meta if meta.get("name") == "robots"),
            "",
        )
        assert "noindex" in directive, (
            f"{page.relative_to(_SITE)} is published, is not in the sitemap, and "
            f"does not say it is not for indexing"
        )


def test_robots_allows_everything_and_advertises_the_sitemap() -> None:
    """It used to allow `/habitable/`, the old GitHub Pages project path.

    That path has not existed since the site moved to its own domain. An
    `Allow` with no `Disallow` beside it blocks nothing either way, so the line
    was harmless and wrong, which is the kind of thing that survives longest.
    """
    lines = {
        line.strip()
        for line in (_SITE / "robots.txt").read_text(encoding="utf-8").splitlines()
        if line.strip()
    }
    assert lines == {
        "User-agent: *",
        "Allow: /",
        f"Sitemap: {_CANONICAL}sitemap.xml",
    }


def test_robots_names_no_path_this_site_does_not_serve() -> None:
    for line in (_SITE / "robots.txt").read_text(encoding="utf-8").splitlines():
        directive, _, value = line.partition(":")
        if directive.strip().lower() not in {"allow", "disallow"}:
            continue
        path = value.strip()
        if path in {"", "/"}:
            continue
        assert (_SITE / path.lstrip("/")).exists(), (
            f"robots.txt names {path}, which this site does not serve"
        )


def test_landing_images_reserve_layout_space_without_a_screenshot_gallery() -> None:
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
    assert screenshots == []

    html = (_SITE / "index.html").read_text(encoding="utf-8")
    assert html.count('class="sample-event ') == 4
    assert html.count("<details") >= 4
