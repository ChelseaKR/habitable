# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Keyboard operability and reflow — the automatable half of the manual protocol.

axe-core does not exercise keyboard navigation, focus order, traps, or reflow.
These Playwright tests do: the skip link is first in tab order, every major
control is reachable by Tab without a trap, and the layout reflows at a 320px
width with no horizontal scrolling (WCAG 2.1.1, 2.4.3, 1.4.10). The screen-reader
*announcement* pass still requires a human (see manual-testing.md).
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterator

import pytest

pytest.importorskip("playwright.sync_api")

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import sync_playwright

from habitable.appserver import make_app_server
from habitable.vault import Vault

_ACTIVE = """
() => {
  const a = document.activeElement;
  if (!a) return null;
  if (a.id) return a.id;
  if (a.className && typeof a.className === 'string') return '.' + a.className.split(' ')[0];
  return a.tagName.toLowerCase();
}
"""
# A representative set of controls that must all be keyboard-reachable.
_EXPECTED = {
    "lang-en",
    "lang-es",
    "refresh-btn",
    "resolve-btn",
    "ai-category",
    "cap-file",
    "tl-type",
    "ex-issue",
}


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


@pytest.mark.a11y
def test_keyboard_navigation_has_skip_link_and_no_trap(served_app: str) -> None:
    with sync_playwright() as p:
        try:
            browser = p.chromium.launch()
        except PlaywrightError as exc:
            pytest.skip(f"Chromium not available: {exc}")
        try:
            page = browser.new_page()
            page.goto(served_app, wait_until="networkidle")
            page.wait_for_timeout(300)

            page.keyboard.press("Tab")
            first = page.evaluate(_ACTIVE)
            assert first == ".skip-link", f"first Tab should focus the skip link, got {first!r}"

            sequence = [first]
            for _ in range(60):
                page.keyboard.press("Tab")
                sequence.append(page.evaluate(_ACTIVE))
        finally:
            browser.close()

    reached = {item for item in sequence if item}
    missing = _EXPECTED - reached
    assert not missing, f"controls not keyboard-reachable: {sorted(missing)}"
    # No trap: focus cycles (the skip link is reached again rather than being stuck).
    assert sequence[1:].count(".skip-link") >= 1, "focus did not cycle — possible keyboard trap"


@pytest.mark.a11y
def test_reflows_at_320px_without_horizontal_scroll(served_app: str) -> None:
    with sync_playwright() as p:
        try:
            browser = p.chromium.launch()
        except PlaywrightError as exc:
            pytest.skip(f"Chromium not available: {exc}")
        try:
            page = browser.new_page(viewport={"width": 320, "height": 800})
            page.goto(served_app, wait_until="networkidle")
            page.wait_for_timeout(300)
            overflow = page.evaluate(
                "() => document.documentElement.scrollWidth - document.documentElement.clientWidth"
            )
        finally:
            browser.close()
    assert overflow <= 2, f"horizontal overflow at 320px width: {overflow}px (WCAG 1.4.10 reflow)"
