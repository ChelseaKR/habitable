# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Automated accessibility invariants for the app shell (WCAG 2.2 AA basics).

This is not a substitute for axe + manual NVDA/VoiceOver review (tracked in the
ACR), but it gates the structural mistakes that are cheap to catch: language,
title, viewport, a skip link to a real target, labelled controls, alt text, no
positive tabindex, landmarks, and a single h1.
"""

from __future__ import annotations

import contextlib
import json
import re
import threading
from collections.abc import Callable, Iterator
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

import pytest

from habitable.appserver import make_app_server
from habitable.vault import Vault

_APP = Path(__file__).resolve().parent.parent / "app"
_INDEX = _APP / "index.html"
_APP_JS = _APP / "app.js"
_EN = _APP / "i18n" / "en.json"
_EXEMPT_INPUT_TYPES = {"hidden", "submit", "button", "reset", "image"}


class _A11yParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.html_lang: str | None = None
        self.title_text = ""
        self._in_title = False
        self.has_viewport = False
        self.has_manifest = False
        self.ids: set[str] = set()
        self.label_for: set[str] = set()
        self.anchor_targets: list[str] = []
        self.controls: list[tuple[str, str, bool]] = []  # (label, id, has_aria_or_nested)
        self.img_missing_alt = 0
        self.positive_tabindex = 0
        self.h1 = 0
        self.main = 0
        self._label_depth = 0
        # (id, role, aria-live) for every element that declares a live region.
        self.live_regions: list[tuple[str, str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:  # noqa: C901
        # P1-4 follow-up: this structural-check parser grew one branch per HTML
        # feature it asserts on; splitting per-tag handlers is the fix, not urgent.
        d = {k: (v or "") for k, v in attrs}
        if tag == "html":
            self.html_lang = d.get("lang")
        elif tag == "title":
            self._in_title = True
        elif tag == "meta" and d.get("name") == "viewport":
            self.has_viewport = True
        elif tag == "link" and "manifest" in d.get("rel", ""):
            self.has_manifest = True
        elif tag == "main":
            self.main += 1
        elif tag == "h1":
            self.h1 += 1
        elif tag == "a" and d.get("href", "").startswith("#"):
            self.anchor_targets.append(d["href"][1:])
        elif tag == "img" and "alt" not in d:
            self.img_missing_alt += 1
        if d.get("id"):
            self.ids.add(d["id"])
        if d.get("aria-live") or d.get("role") == "status":
            self.live_regions.append((d.get("id", ""), d.get("role", ""), d.get("aria-live", "")))
        if tag == "label":
            self._label_depth += 1
            if d.get("for"):
                self.label_for.add(d["for"])
        if d.get("tabindex", "").lstrip("-").isdigit() and int(d["tabindex"]) > 0:
            self.positive_tabindex += 1
        if tag in {"input", "select", "textarea"}:
            input_type = d.get("type", "text")
            if not (tag == "input" and input_type in _EXEMPT_INPUT_TYPES):
                labelled = (
                    bool(d.get("aria-label") or d.get("aria-labelledby") or d.get("title"))
                    or self._label_depth > 0
                )
                name = d.get("id") or input_type
                self.controls.append((name, d.get("id", ""), labelled))

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        elif tag == "label":
            self._label_depth = max(0, self._label_depth - 1)

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title_text += data


def _parse() -> _A11yParser:
    assert _INDEX.is_file(), f"missing app shell: {_INDEX}"
    parser = _A11yParser()
    parser.feed(_INDEX.read_text(encoding="utf-8"))
    return parser


def test_language_title_viewport_manifest() -> None:
    p = _parse()
    assert p.html_lang, "<html> needs a lang attribute"
    assert p.title_text.strip(), "page needs a non-empty <title>"
    assert p.has_viewport, "responsive viewport meta is required"
    assert p.has_manifest, "PWA manifest link is required"


def test_skip_link_targets_a_real_element() -> None:
    p = _parse()
    assert any(target in p.ids for target in p.anchor_targets), (
        "a skip link should target an existing element id (e.g. #main)"
    )
    assert p.main >= 1 and p.h1 == 1, "exactly one <h1> and a <main> landmark expected"


def test_every_control_is_labelled() -> None:
    p = _parse()
    unlabeled = [
        name
        for name, control_id, has_aria in p.controls
        if not (has_aria or (control_id and control_id in p.label_for))
    ]
    assert not unlabeled, f"form controls without a label: {unlabeled}"


def test_images_have_alt_and_no_positive_tabindex() -> None:
    p = _parse()
    assert p.img_missing_alt == 0, "every <img> needs an alt attribute (empty if decorative)"
    assert p.positive_tabindex == 0, "no positive tabindex values allowed"


def test_aria_describedby_targets_exist() -> None:
    """Any aria-describedby must point at an element that actually exists.

    Every assertion here lives inside a loop over ``re.findall``, so an empty
    match list is a silent pass. The pattern only recognizes double-quoted
    attributes, so switching the markup to single quotes -- or moving the
    attribute to a JS-set property -- would retire this check without a word.
    The floor below is what makes the loop's silence audible, in the same style
    as ``test_golden.py`` and ``test_verify_fuzz.py``.
    """
    html = _INDEX.read_text(encoding="utf-8")
    p = _parse()
    referenced = re.findall(r"""aria-describedby=["\']([^"\']+)["\']""", html)
    assert referenced, (
        "no aria-describedby attributes were found in app/index.html. Either the "
        "descriptions were removed, or the markup changed shape and this check is "
        "now scanning for something that is not there."
    )
    for group in referenced:
        for ident in group.split():
            assert ident in p.ids, f"aria-describedby points at missing id: {ident}"


# --- Async status transitions are announced (issue #243) ---------------------
#
# "Waiting for a timestamp token" -> "timestamp token attached" is the moment a
# capture gains its independent time proof. A sighted user watches the number in
# the status grid change. Before this region existed a screen-reader user was
# told nothing at all about it: the change happens outside the focus path, and
# the status grid is (rightly) not itself a live region, or every refresh would
# read the whole grid aloud.
#
# These tests prove the region exists, is separate from the general #announcer,
# and updates on exactly the transition. They do NOT prove the announcement is
# *useful* — whether it lands at a sensible moment and reads clearly through NVDA
# or VoiceOver is the human screen-reader pass in #126, which this does not close.


def _en_plural_branch(key: str, selector: str) -> str:
    """The ``one``/``other`` branch of an ICU plural message in ``en.json``.

    The browser test asserts on rendered copy, and copy moves. Deriving the
    expectation from the shipped bundle keeps the assertion about *behaviour*
    (the transition was announced) instead of freezing one English sentence into
    a test that a later plain-language pass would have to edit.
    """
    message = str(json.loads(_EN.read_text(encoding="utf-8"))[key])
    match = re.search(rf"(?:^|\s){re.escape(selector)}\s*\{{", message)
    assert match, f"{key} has no {selector!r} plural branch: {message!r}"
    # Scan to the matching brace rather than the first one: a branch may itself
    # contain "{placeholder}", and the message always closes with "}}".
    depth = 0
    start = match.end() - 1
    for index in range(start, len(message)):
        if message[index] == "{":
            depth += 1
        elif message[index] == "}":
            depth -= 1
            if depth == 0:
                return message[start + 1 : index]
    raise AssertionError(f"{key} has unbalanced braces: {message!r}")


def test_status_transitions_have_their_own_live_region() -> None:
    """A dedicated polite region carries the awaiting -> timestamped transition.

    It is deliberately not the general ``#announcer``: that node is emptied and
    re-filled on a 30ms timer for every action result, so a result resolving in
    the same tick would clear this message before assistive tech ever saw it —
    and this is the one status change that most affects what the record can
    prove. Delete ``#status-announcer`` and this test fails.
    """
    p = _parse()
    by_id = {region[0]: region for region in p.live_regions}
    assert "status-announcer" in by_id, (
        "no #status-announcer live region in app/index.html; async status "
        "transitions would go unannounced again (issue #243)"
    )
    _, role, live = by_id["status-announcer"]
    assert role == "status", "the status transition region needs role=status"
    assert live == "polite", "status transitions must not interrupt; aria-live=polite"
    assert "announcer" in by_id, "the general #announcer region must still exist"
    assert by_id["announcer"] != by_id["status-announcer"], (
        "the two live regions must be distinct nodes"
    )

    js = _APP_JS.read_text(encoding="utf-8")
    assert 'getElementById("status-announcer")' in js, (
        "the region exists in the markup but nothing writes to it"
    )
    assert "msg_timestamp_attached" in js, (
        "the announced sentence must come from the i18n bundles like every other string"
    )


@contextlib.contextmanager
def _served(vault: Vault) -> Iterator[str]:
    """Serve *vault* on a loopback port, yielding the token-carrying app URL."""
    server = make_app_server("127.0.0.1", 0, vault)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/#token={server.session_token}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _status_payload(timestamped: int, awaiting: int) -> dict[str, object]:
    """A minimal /api/status body with the two counts the transition is read from."""
    return {
        "unit": "4B",
        "case_id": "case-4B",
        "fingerprint": "aa11",
        "issues": [],
        "capture_count": timestamped + awaiting,
        "evidence_count": timestamped + awaiting,
        "artifact_count": 0,
        "relationship_count": 0,
        "profile": "",
        "profiles": [],
        "timestamped": timestamped,
        "awaiting": awaiting,
        "deferred": awaiting,
        "custody_ok": True,
        "custody_length": 1,
        "storage": {
            "sealed_originals_bytes": 0,
            "shared_copies_bytes": 0,
            "metadata_bytes": 0,
            "total_bytes": 0,
        },
        "allow_metered": True,
    }


@pytest.mark.a11y
def test_awaiting_to_timestamped_is_announced_once_and_never_on_first_paint(
    make_vault: Callable[..., Vault],
) -> None:
    """The transition speaks exactly once, and silence is proven to be real silence.

    Three renders are driven through a stubbed /api/status so the counts move on
    command rather than needing a reachable timestamp authority:

    1. first paint at 2 waiting / 0 stamped — the region stays empty. The grid is
       asserted to have actually rendered, so this is silence from a working app
       and not the vacuous pass of a page that never loaded.
    2. a refresh at 0 waiting / 2 stamped — the region carries the announcement.
    3. a second refresh with the same counts — the region is emptied again, so the
       same sentence is never read a second time and the next real transition is
       still a change assistive tech will notice.
    """
    playwright_api: Any = pytest.importorskip("playwright.sync_api")

    vault = make_vault()
    vault.save()
    renders = [(0, 2), (2, 0), (2, 0)]
    served: list[int] = []

    def stub_status(route: Any) -> None:
        payload = _status_payload(*renders[min(len(served), len(renders) - 1)])
        served.append(1)
        route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps(payload),
        )

    with _served(vault) as url, playwright_api.sync_playwright() as p:
        try:
            browser = p.chromium.launch()
        except playwright_api.Error as exc:  # pragma: no cover - environment dependent
            pytest.skip(f"Chromium not available: {exc}")
        try:
            # The app registers a service worker for offline use, and a service
            # worker re-issues fetches outside the page — page-level routes never
            # see them, so the stub would be silently bypassed and every assertion
            # below would be measuring the real vault. Block the worker and route
            # at the context, which is the only layer that intercepts either way.
            context = browser.new_context(service_workers="block")
            context.route("**/api/status", stub_status)
            page = context.new_page()
            page.goto(url, wait_until="networkidle")
            page.wait_for_timeout(400)

            assert page.text_content("#st-awaiting") == "2", (
                "the stubbed status never rendered; the silence below would prove nothing"
            )
            assert page.text_content("#status-announcer") == "", (
                "first paint must not announce a transition that did not happen"
            )

            page.click("#refresh-btn")
            page.wait_for_timeout(400)
            spoken = page.text_content("#status-announcer")
            expected = _en_plural_branch("msg_timestamp_attached", "other").replace("#", "2")
            assert spoken == expected, (
                f"the awaiting -> timestamped transition was not announced (region held {spoken!r})"
            )

            page.click("#refresh-btn")
            page.wait_for_timeout(400)
            assert page.text_content("#status-announcer") == "", (
                "a re-render that moved nothing must not leave the sentence standing "
                "to be read again"
            )
        finally:
            browser.close()
