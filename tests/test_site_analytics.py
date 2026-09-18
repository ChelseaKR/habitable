# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Google Analytics 4 on the documentation website, and nowhere else.

Owner decision, 2026-09-17: GA4 on every public site, with the privacy copy updated
to match. The website (`site/`) is the only surface; the app, the CLI and the relay
keep the no-telemetry rule. These tests hold the site to what
`site/trust-limitations/#analytics` tells a reader:

* statically: exactly one `analytics.js` per page, the footer note and link on every
  page, the loader carrying the agreed ID, host, consent defaults and config, and no
  loader on the synthetic sample packet;
* in a real browser (marked ``a11y``, which is the CI job that installs Chromium): on
  habitable.chelseakr.com with no signal it loads with the agreed configuration and
  one scrubbed page view; under Global Privacy Control, Do Not Track, the stored
  opt-out or any other host it loads nothing; the button opts out and back in; and a
  negative control proves the harness sees GA load once the GPC guard is removed.

Every Google request in the browser tests is answered locally or aborted, so nothing
reaches the property.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

import pytest

_SITE = Path(__file__).resolve().parent.parent / "site"
_LOADER = _SITE / "analytics.js"
_ID = "G-BMJYDCX015"
_HOST = "habitable.chelseakr.com"
_KEY = "habitable.chelseakr.com:analytics-opt-out"


class _Scripts(HTMLParser):
    """Every <script> start tag's attributes, as the browser's tokenizer would see them."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.scripts: list[dict[str, str | None]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "script":
            self.scripts.append(dict(attrs))


def _scripts(source: str) -> list[dict[str, str | None]]:
    parser = _Scripts()
    parser.feed(source)
    return parser.scripts


def _pages() -> list[Path]:
    return sorted(p for p in _SITE.rglob("*.html") if "sample-packet" not in p.parts)


def _prefix(page: Path) -> str:
    return "../" * (len(page.relative_to(_SITE).parts) - 1)


def test_the_site_pages_are_the_twelve_this_file_reasons_about() -> None:
    assert len(_pages()) == 12, [str(p.relative_to(_SITE)) for p in _pages()]


@pytest.mark.parametrize("page", _pages(), ids=lambda p: str(p.relative_to(_SITE)))
def test_every_page_loads_the_one_loader_from_its_head(page: Path) -> None:
    source = page.read_text(encoding="utf-8")
    loaders = [s for s in _scripts(source) if "analytics.js" in (s.get("src") or "")]
    assert loaders == [{"src": f"{_prefix(page)}analytics.js", "defer": None}], loaders
    assert source.index("analytics.js") < source.index("</head>")
    assert "googletagmanager" not in source, "gtag.js must only ever be added by the loader"


@pytest.mark.parametrize("page", _pages(), ids=lambda p: str(p.relative_to(_SITE)))
def test_every_footer_says_so_and_links_the_disclosure(page: Path) -> None:
    source = page.read_text(encoding="utf-8")
    footer = source[source.index("<footer") : source.index("</footer>")]
    assert footer.count('class="analytics-note"') == 1
    assert "Google Analytics" in footer and "the app sends nothing" in footer
    assert footer.count('<span class="analytics-opt-out" hidden></span>') == 1
    link = re.search(r'<a href="([^"]*#analytics)">Privacy and analytics</a>', footer)
    assert link is not None
    target = link.group(1).split("#", 1)[0]
    resolved = (page.parent / target / "index.html") if target else page
    assert resolved.resolve() == (_SITE / "trust-limitations" / "index.html").resolve()


def test_the_disclosure_says_what_the_loader_does() -> None:
    source = (_SITE / "trust-limitations" / "index.html").read_text(encoding="utf-8")
    section = source[source.index('id="analytics"') :]
    section = section[: section.index("</section>")]
    for claim in (
        "Google LLC",
        "utm_source",
        "_ga",
        "European Economic Area",
        "Google signals and ad personalization are disabled",
        "14 months",
        "Global Privacy Control",
        "Do Not Track",
        "Opt out of analytics",
        "Opt back in",
        "The app, the command-line tool and the relay send nothing",
    ):
        assert claim in section, claim


def test_the_synthetic_sample_packet_carries_no_loader() -> None:
    """The packet is a generated evidence artifact whose bytes other tests pin."""
    for page in (_SITE / "sample-packet").rglob("*.html"):
        assert "analytics.js" not in page.read_text(encoding="utf-8"), page


def test_the_loader_carries_the_agreed_configuration() -> None:
    loader = _LOADER.read_text(encoding="utf-8")
    assert f'var ID = "{_ID}";' in loader
    assert f'var HOST = "{_HOST}";' in loader
    assert f'var KEY = "{_KEY}";' in loader
    assert "n.globalPrivacyControl === true" in loader
    assert 'dnt === "1" || dnt === "yes"' in loader
    assert "w.location.hostname !== HOST" in loader
    assert "allow_google_signals: false" in loader
    assert "allow_ad_personalization_signals: false" in loader
    assert "send_page_view: false" in loader
    regions = re.search(r"var REGIONS = \[(.*?)\];", loader, re.S)
    assert regions is not None
    codes = set(re.findall(r'"([A-Z]{2})"', regions.group(1)))
    eu27 = {
        "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IE",
        "IT", "LV", "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE",
    }  # fmt: skip
    assert eu27 | {"IS", "LI", "NO", "GB", "CH"} <= codes
    assert "US" not in codes


# ---------------------------------------------------------------------------------
# In a real browser
# ---------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def browser() -> Iterator[Any]:
    pytest.importorskip("playwright.sync_api")
    from playwright.sync_api import Error as PlaywrightError
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        try:
            launched = p.chromium.launch()
        except PlaywrightError as exc:
            pytest.skip(f"Chromium not available: {exc}")
        yield launched
        launched.close()


class _Visit:
    def __init__(self, page: Any, google: list[str]) -> None:
        self.page = page
        self.google = google

    def layer(self) -> list[list[Any]]:
        result: list[list[Any]] = self.page.evaluate(
            "() => (window.dataLayer || []).map(e => JSON.parse(JSON.stringify(Array.from(e))))"
        )
        return result

    def nothing_loaded(self) -> bool:
        loaded: bool = self.page.evaluate(
            "() => window.dataLayer !== undefined || "
            "!!document.querySelector('script[src*=\"googletagmanager\"]')"
        )
        return not loaded and not self.google


def _visit(
    browser: Any,
    path: str = "how-it-works/",
    *,
    host: str = _HOST,
    init: str | None = None,
    loader: str | None = None,
) -> _Visit:
    context = browser.new_context()
    google: list[str] = []
    if init:
        context.add_init_script(init)

    def serve(route: Any) -> None:
        url = route.request.url
        local = url.split(host, 1)[1].split("?", 1)[0].split("#", 1)[0]
        target = _SITE / local.lstrip("/")
        if target.is_dir():
            target = target / "index.html"
        if loader is not None and target == _LOADER:
            route.fulfill(body=loader, content_type="text/javascript")
        elif target.is_file():
            route.fulfill(path=str(target))
        else:
            route.fulfill(status=404, body="")

    def stub_google(route: Any) -> None:
        google.append(route.request.url)
        if "googletagmanager.com/gtag/js" in route.request.url:
            route.fulfill(body="/* stub */", content_type="text/javascript")
        else:
            route.abort()

    context.route(re.compile(r"https?://[^/]*google[^/]*/.*"), stub_google)
    context.route(f"https://{host}/**", serve)
    page = context.new_page()
    page.goto(f"https://{host}/{path}?utm_source=flyer&unit=4B", wait_until="load")
    page.wait_for_timeout(300)
    return _Visit(page, google)


@pytest.mark.a11y
def test_on_the_production_host_it_loads_with_the_agreed_configuration(browser: Any) -> None:
    visit = _visit(browser)
    layer = visit.layer()
    assert [c for c in visit.google if "gtag/js" in c] == [
        f"https://www.googletagmanager.com/gtag/js?id={_ID}"
    ]
    regional, global_, redaction, js, config, page_set, event = layer
    assert regional[:2] == ["consent", "default"]
    assert regional[2]["analytics_storage"] == "denied"
    assert regional[2]["ad_storage"] == "denied"
    assert {"DE", "GB", "CH"} <= set(regional[2]["region"])
    assert global_[2] == {
        "ad_storage": "denied",
        "ad_user_data": "denied",
        "ad_personalization": "denied",
        "analytics_storage": "granted",
    }
    assert redaction == ["set", "ads_data_redaction", True]
    assert js[0] == "js"
    assert config == [
        "config",
        _ID,
        {
            "send_page_view": False,
            "allow_google_signals": False,
            "allow_ad_personalization_signals": False,
        },
    ]
    assert page_set[1]["page_location"] == f"https://{_HOST}/how-it-works/?utm_source=flyer"
    assert event == ["event", "page_view"]


@pytest.mark.a11y
@pytest.mark.parametrize(
    ("label", "init", "check"),
    [
        (
            "GPC",
            "Object.defineProperty(Navigator.prototype, 'globalPrivacyControl', {get: () => true})",
            "() => navigator.globalPrivacyControl === true",
        ),
        (
            "DNT",
            "Object.defineProperty(Navigator.prototype, 'doNotTrack', {get: () => '1'})",
            "() => navigator.doNotTrack === '1'",
        ),
        (
            "stored opt-out",
            f"localStorage.setItem('{_KEY}', '1')",
            f"() => localStorage.getItem('{_KEY}') === '1'",
        ),
    ],
)
def test_a_signal_or_the_opt_out_loads_nothing(
    browser: Any, label: str, init: str, check: str
) -> None:
    visit = _visit(browser, init=init)
    assert visit.page.evaluate(check), f"{label}: the setup did not take effect"
    assert visit.nothing_loaded(), (label, visit.google)


@pytest.mark.a11y
def test_any_other_host_loads_nothing(browser: Any) -> None:
    visit = _visit(browser, host="habitable.example")
    assert visit.page.evaluate("() => location.hostname") == "habitable.example"
    assert visit.nothing_loaded(), visit.google


@pytest.mark.a11y
def test_the_footer_button_opts_out_and_back_in(browser: Any) -> None:
    visit = _visit(browser)
    button = visit.page.locator("footer .analytics-opt-out button")
    assert button.count() == 1
    assert button.inner_text() == "Opt out of analytics"
    box = button.bounding_box()
    assert box is not None and box["height"] >= 24
    button.click()
    assert visit.page.evaluate(f"() => localStorage.getItem('{_KEY}')") == "1"
    assert button.inner_text() == "Opt back in"
    status = visit.page.locator("footer .analytics-opt-out [role=status]")
    assert status.inner_text() == "Analytics is off in this browser."
    assert visit.page.evaluate(f"() => window['ga-disable-{_ID}']") is True
    before = len(visit.google)
    visit.page.reload(wait_until="load")
    visit.page.wait_for_timeout(300)
    assert len(visit.google) == before, "a reload after opting out reached Google"
    visit.page.locator("footer .analytics-opt-out button").click()
    assert visit.page.evaluate(f"() => localStorage.getItem('{_KEY}')") is None
    visit.page.wait_for_timeout(300)
    assert any("gtag/js" in url for url in visit.google[before:]), "opting back in did not load GA"


@pytest.mark.a11y
def test_negative_control_the_harness_sees_a_missing_gpc_guard(browser: Any) -> None:
    source = _LOADER.read_text(encoding="utf-8")
    guard = "    if (n.globalPrivacyControl === true) return true;\n"
    assert source.count(guard) == 1
    sabotaged = source.replace(guard, "")
    assert guard not in sabotaged and sabotaged != source
    init = "Object.defineProperty(Navigator.prototype, 'globalPrivacyControl', {get: () => true})"
    visit = _visit(browser, init=init, loader=sabotaged)
    assert visit.page.evaluate("() => navigator.globalPrivacyControl === true")
    assert not visit.nothing_loaded(), "the harness could not see GA load without its GPC guard"
