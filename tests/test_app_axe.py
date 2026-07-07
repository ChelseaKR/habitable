# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Browser-based accessibility gate: a real axe-core scan of the running app.

This complements the structural checks in ``test_app_accessibility.py`` with an
actual WCAG audit (axe-core) in a headless browser. It is marked ``a11y`` and
skips cleanly where Playwright or its Chromium build is unavailable, so the main
gate runs everywhere; CI installs Chromium and runs it for real.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterator

import pytest

pytest.importorskip("playwright.sync_api")
pytest.importorskip("axe_playwright_python.sync_playwright")

from axe_playwright_python.sync_playwright import Axe
from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import sync_playwright

from habitable.appserver import make_app_server
from habitable.vault import Vault

# Block (don't just warn on) anything WCAG-meaningful.
_BLOCKING_IMPACTS = {"serious", "critical", "moderate"}


@pytest.fixture
def served_app(make_vault: Callable[..., Vault]) -> Iterator[str]:
    vault = make_vault()
    vault.document.add_issue(category="mold", room="bath", title="Mold", issue_id="i1")
    vault.save()
    server = make_app_server("127.0.0.1", 0, vault)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        # The token rides in the URL fragment; the app moves it into a request header.
        yield f"http://127.0.0.1:{port}/#token={server.session_token}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _scan(url: str, *, switch_to_spanish: bool = False) -> list[dict[str, object]]:
    with sync_playwright() as p:
        try:
            browser = p.chromium.launch()
        except PlaywrightError as exc:  # browser binary not installed
            pytest.skip(f"Chromium not available for axe scan: {exc}")
        try:
            page = browser.new_page()
            page.goto(url, wait_until="networkidle")
            page.wait_for_timeout(400)
            if switch_to_spanish:
                page.click("#lang-es")
                page.wait_for_timeout(300)
            results = Axe().run(page)
        finally:
            browser.close()
    violations: list[dict[str, object]] = results.response.get("violations", [])
    return [v for v in violations if v.get("impact") in _BLOCKING_IMPACTS]


@pytest.mark.a11y
def test_app_passes_axe_english(served_app: str) -> None:
    blocking = _scan(served_app)
    assert not blocking, [f"{v['id']} ({v['impact']})" for v in blocking]


@pytest.mark.a11y
def test_app_passes_axe_spanish(served_app: str) -> None:
    blocking = _scan(served_app, switch_to_spanish=True)
    assert not blocking, [f"{v['id']} ({v['impact']})" for v in blocking]
