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
# A share card is only a share card at the shape the networks crop to. The site
# shipped a 2200x3000 portrait screenshot as `og:image`, which LinkedIn, Slack,
# and X centre-crop to a landscape box: the title and the packet both fell out
# of frame. 1200x630 is the size every one of them renders whole.
_SOCIAL_CARD = "img/social-card.png"
_SOCIAL_CARD_URL = f"{_CANONICAL}{_SOCIAL_CARD}"
_SOCIAL_CARD_SIZE = (1200, 630)


def _png_size(path: Path) -> tuple[int, int]:
    """Width and height from a PNG IHDR, without a decoder dependency."""
    header = path.read_bytes()[:24]
    assert header[:8] == b"\x89PNG\r\n\x1a\n", f"{path} is not a PNG"
    return int.from_bytes(header[16:20], "big"), int.from_bytes(header[20:24], "big")


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
        "og:image": _SOCIAL_CARD_URL,
        "og:image:type": "image/png",
        "og:image:width": str(_SOCIAL_CARD_SIZE[0]),
        "og:image:height": str(_SOCIAL_CARD_SIZE[1]),
    }
    assert open_graph.items() >= expected_open_graph.items()

    expected_twitter = {
        "twitter:card": "summary_large_image",
        "twitter:title": _TITLE,
        "twitter:description": _DESCRIPTION,
        "twitter:image": _SOCIAL_CARD_URL,
    }
    assert named.items() >= expected_twitter.items()

    favicons = [link for link in parser.links if link.get("rel") == "icon"]
    assert favicons == [{"rel": "icon", "href": "img/icon.svg", "type": "image/svg+xml"}]
    assert (_SITE / favicons[0]["href"]).is_file()


def test_every_page_shares_a_landscape_card_that_is_actually_published() -> None:
    """An `og:image` is a promise about bytes a stranger's machine will fetch.

    Two ways it goes wrong quietly, and both had happened here: the URL can
    name a file that is not in `site/`, so the share renders blank; or the file
    can be there at the wrong shape, so the networks crop it and the card that
    reaches a reader is a slice of a screenshot with the title cut off.
    """
    card = _SITE / _SOCIAL_CARD
    assert card.is_file(), f"{_SOCIAL_CARD} is referenced but not published"
    assert _png_size(card) == _SOCIAL_CARD_SIZE

    for path, _, _ in _PUBLISHED:
        parser = _parse(_page_file(path).read_text(encoding="utf-8"))
        named = _meta_values(parser, "name")
        open_graph = _meta_values(parser, "property")
        page = path or "/"
        assert open_graph["og:title"], page
        assert open_graph["og:description"], page
        assert open_graph["og:image"] == _SOCIAL_CARD_URL, page
        assert open_graph["og:image:alt"], page
        assert named["twitter:card"] == "summary_large_image", page
        assert named["twitter:image"] == _SOCIAL_CARD_URL, page


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
    (
        "",
        "2026-09-01",
        "676c6a85f4a55f64326552f77b9ca9583c694da03d65703ed1dfaefb66b43218",
    ),
    (
        "how-it-works/",
        "2026-09-01",
        "64453f5aa76d01ad5d94ecbaa197ff7c478582a55948011607edf6fb202f5561",
    ),
    (
        "documentation-checklist/",
        "2026-09-01",
        "0df61f3bb5268997e1d8e71edc310900bd261186e7d216e3ed00006b6b4a7764",
    ),
    (
        "guides/preserve-maintenance-request-records/",
        "2026-09-01",
        "9afc51ef17922e5ea27ae9162535a5be5fdbd470d367f58598da5c29bc2f8424",
    ),
    (
        "guides/housing-inspection-records/",
        "2026-09-01",
        "356a276aa0f841f29b2aeb53e0c290eebde22703338e1d3db6df38eaf551cbc9",
    ),
    (
        "tenant-unions/",
        "2026-09-01",
        "0a1d805ae1b455ad701897d4e3751c17b29834c9d1d58800d34a7be8fe211f00",
    ),
    (
        "templates/tenant-union-building-condition-survey/",
        "2026-09-01",
        "c74d777665cb771f64b46696f51a0ad0395ffdb968714cdb119f686362058bfb",
    ),
    (
        "legal-aid-reviewers/",
        "2026-09-01",
        "39fd69af675687a909abc30f646c7517b6e20edc9a8f15a21d1889d165f031a7",
    ),
    (
        "inspectors-code-enforcement/",
        "2026-09-01",
        "b6cb67fe3dc663f4483bcb3811a16719fa4194090e3d53d153fe0c5ab453bbf3",
    ),
    (
        "trust-limitations/",
        "2026-09-01",
        "12b9d26730b25a6c7ec9f9502392e99bc4e581b587acd85aec642f3892a8b07b",
    ),
    (
        "review/",
        "2026-09-04",
        "e991e270df193b7aa0847e29d37a43556ab9b5a0b908591f7d629c4eabd01354",
    ),
    (
        "review/changes/",
        "2026-09-01",
        "80bd6f2af311fb1244cd9fb12c40e1fc649cfb96912e55552b01c00c2a267826",
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
