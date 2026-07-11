# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""axe-core scan of the Pages-deployed static site (P1-6, A11Y-01/02).

Before this test existed, `site/index.html` (and the committed sample packet
under `site/sample-packet/`) were the one Pages-deployed, publicly reachable
surface scanned by nothing: `tests/test_htmlpacket.py` covers a *freshly
generated* packet.html, not this literal committed static copy, and nothing
covered the landing page at all. Same pattern as `test_htmlpacket.py`: real
Chromium + axe-core, skip cleanly if the browser isn't installed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

_SITE_ROOT = Path(__file__).resolve().parent.parent / "site"


def _run_axe(html_path: Path) -> list[dict[str, object]]:
    pytest.importorskip("playwright.sync_api")
    pytest.importorskip("axe_playwright_python.sync_playwright")
    from axe_playwright_python.sync_playwright import Axe
    from playwright.sync_api import Error as PlaywrightError
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        try:
            browser = p.chromium.launch()
        except PlaywrightError as exc:
            pytest.skip(f"Chromium not available: {exc}")
        try:
            page = browser.new_page()
            page.goto(html_path.as_uri(), wait_until="load")
            results = Axe().run(page)
        finally:
            browser.close()
    return [
        v
        for v in results.response.get("violations", [])
        if v.get("impact") in {"moderate", "serious", "critical"}
    ]


@pytest.mark.a11y
def test_landing_page_passes_axe() -> None:
    html_path = _SITE_ROOT / "index.html"
    assert html_path.is_file(), "site/index.html not found — has the landing page moved?"
    blocking = _run_axe(html_path)
    assert not blocking, [v["id"] for v in blocking]


@pytest.mark.a11y
@pytest.mark.parametrize(
    "relative_path",
    [
        "how-it-works/index.html",
        "documentation-checklist/index.html",
        "guides/preserve-maintenance-request-records/index.html",
        "tenant-unions/index.html",
        "legal-aid-reviewers/index.html",
        "inspectors-code-enforcement/index.html",
        "trust-limitations/index.html",
    ],
)
def test_public_content_guides_pass_axe(relative_path: str) -> None:
    html_path = _SITE_ROOT / relative_path
    assert html_path.is_file(), f"public content guide not found: {relative_path}"
    blocking = _run_axe(html_path)
    assert not blocking, [v["id"] for v in blocking]


@pytest.mark.a11y
def test_committed_sample_packet_passes_axe() -> None:
    """The committed static sample under site/sample-packet/ is a separate artifact
    from the freshly-generated packet tests/test_htmlpacket.py checks — it can drift
    from the generator (e.g. after a template change) without that test catching it."""
    html_path = _SITE_ROOT / "sample-packet" / "packet.html"
    assert html_path.is_file(), "site/sample-packet/packet.html not found."
    blocking = _run_axe(html_path)
    assert not blocking, [v["id"] for v in blocking]
