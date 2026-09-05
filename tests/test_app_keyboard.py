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

import re
import threading
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

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
    "atlas-filter-issue",
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
@pytest.mark.parametrize(
    ("opener_selector", "dialog_selector", "representative_control"),
    [
        ('[data-open-dialog="issue-dialog"]', "#issue-dialog", "ai-category"),
        ('[data-open-dialog="capture-dialog"]', "#capture-dialog", "cap-file"),
        ('[data-open-dialog="timeline-dialog"]', "#timeline-dialog", "tl-type"),
        ('[data-open-dialog="artifact-dialog"]', "#artifact-dialog", "art-file"),
    ],
)
def test_entry_dialogs_are_keyboard_reachable_and_return_focus(
    served_app: str,
    opener_selector: str,
    dialog_selector: str,
    representative_control: str,
) -> None:
    with sync_playwright() as p:
        try:
            browser = p.chromium.launch()
        except PlaywrightError as exc:
            pytest.skip(f"Chromium not available: {exc}")
        try:
            page = browser.new_page()
            page.goto(served_app, wait_until="networkidle")
            opener = page.locator(opener_selector).first
            opener.focus()
            page.keyboard.press("Enter")
            dialog = page.locator(dialog_selector)
            assert dialog.evaluate("(element) => element.open")

            reached: list[str | None] = []
            for _ in range(30):
                active = page.evaluate(_ACTIVE)
                reached.append(active)
                if active == representative_control:
                    break
                page.keyboard.press("Tab")
            assert representative_control in reached

            page.keyboard.press("Escape")
            assert not dialog.evaluate("(element) => element.open")
            assert opener.evaluate("(element) => element === document.activeElement")
        finally:
            browser.close()


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


@pytest.mark.a11y
def test_token_fragment_is_scrubbed_and_same_tab_reload_stays_authenticated(
    served_app: str,
) -> None:
    """The bootstrap secret leaves the address bar without breaking a normal reload."""
    with sync_playwright() as p:
        try:
            browser = p.chromium.launch()
        except PlaywrightError as exc:
            pytest.skip(f"Chromium not available: {exc}")
        try:
            page = browser.new_page()
            page.goto(served_app, wait_until="networkidle")
            page.wait_for_function("() => document.getElementById('st-unit').textContent === '4B'")
            assert "token=" not in page.url

            page.reload(wait_until="networkidle")
            page.wait_for_function("() => document.getElementById('st-unit').textContent === '4B'")
            assert "token=" not in page.url
        finally:
            browser.close()


@pytest.mark.a11y
def test_malformed_token_fragment_does_not_abort_shell_boot(served_app: str) -> None:
    """Hostile percent escapes are discarded and scrubbed instead of crashing JS."""
    malformed_url = served_app.split("#", 1)[0] + "#token=%"
    with sync_playwright() as p:
        try:
            browser = p.chromium.launch()
        except PlaywrightError as exc:
            pytest.skip(f"Chromium not available: {exc}")
        try:
            page = browser.new_page()
            page.goto(malformed_url, wait_until="networkidle")
            page.wait_for_function("() => window.location.hash === ''")
            assert page.locator("#refresh-btn").is_visible()
        finally:
            browser.close()


_FOCUS_PROBE = """
() => {
  const a = document.activeElement;
  if (!a || a === document.body || a === document.documentElement) return null;
  const r = a.getBoundingClientRect();
  const name = a.id ? '#' + a.id
    : (typeof a.className === 'string' && a.className ? '.' + a.className.split(' ')[0]
    : a.tagName.toLowerCase());
  return {
    name: name,
    top: Math.round(r.top),
    inViewport: r.bottom > 0 && r.top < window.innerHeight
  };
}
"""


@pytest.mark.a11y
def test_tabbing_at_speed_never_leaves_focus_off_screen(served_app: str) -> None:
    """Issue #202, re-diagnosed: focus must be visible at real typing speed.

    The issue reported focus landing "hundreds of pixels above the viewport" past
    the export controls and blamed tab order leaking into a stale Atlas view,
    suggesting `inert` or a focus trap as the remedy. That diagnosis is wrong and
    the remedy would have been harmful: this app is a single scrolling document
    with no view switching, so those controls are not stale, and making them inert
    would delete real controls from the keyboard path.

    The actual cause is `scroll-behavior: smooth` on `html` (styles.css:48). It is
    wanted for the skip link and in-page anchors, but it also animates the scroll
    the browser performs when Tab moves focus below the fold, and that animation is
    slower than a keypress. Measured with a generous 800ms settle between presses,
    zero stops are off-screen; measured at ordinary keyboard speed, twenty are. The
    user-visible defect is real (WCAG 2.4.7 Focus Visible, 2.4.3 Focus Order); only
    the mechanism in the report was not.

    So this test presses Tab at a deliberately *fast* cadence. A slow one would
    pass against the unfixed page and pin nothing at all -- which is how the
    defect survived an existing keyboard suite in the first place.
    """
    with sync_playwright() as p:
        try:
            browser = p.chromium.launch()
        except PlaywrightError as exc:
            pytest.skip(f"Chromium not available: {exc}")
        try:
            page = browser.new_page(viewport={"width": 1280, "height": 900})
            page.goto(served_app, wait_until="networkidle")
            page.wait_for_timeout(400)

            offscreen: list[tuple[int, str, int]] = []
            reached: set[str] = set()
            for press in range(1, 41):
                page.keyboard.press("Tab")
                page.wait_for_timeout(30)  # faster than a smooth-scroll animation, on purpose
                info = page.evaluate(_FOCUS_PROBE)
                if info is None:
                    continue  # the browser's own body/chrome stop in the focus cycle
                reached.add(str(info["name"]))
                if not info["inViewport"]:
                    offscreen.append((press, str(info["name"]), int(info["top"])))

            # The walk has to actually get somewhere, or "nothing was off-screen"
            # would be true of a page that never moved focus at all.
            assert len(reached) >= 15, f"tab walk only reached {len(reached)} controls: {reached}"
            assert ".make-copy" in reached, (
                "the walk never reached the export submit button, so it never "
                "covered the region issue #202 is about"
            )
            assert not offscreen, (
                "focus left the viewport with no visible focus indicator at "
                f"{len(offscreen)} stop(s): {offscreen}"
            )
        finally:
            browser.close()


# A description is only attached to its control if a *sighted* reader can see
# that it is. This walks every aria-describedby pair in a real viewport and asks
# whether anything else the reader would parse as a separate item has landed in
# the gap between them.
#
# "Anything else" is every element that renders words of its own -- text in its
# own child text nodes, not through a descendant -- plus every form control, so
# a bare <select> with no text still counts. An element is only interposing when
# it lies wholly inside the vertical band between the control and its
# description *and* overlaps the description horizontally: in a multi-column
# grid the neighbouring column is beside the pair, not between them, and
# flagging it would make this check noise.
_DESCRIBEDBY_ADJACENCY = """
() => {
  const MIN = 3;  // sub-pixel and sr-only (1x1) boxes are not things a reader sees
  const visible = (el) => {
    const r = el.getBoundingClientRect();
    if (r.width < MIN || r.height < MIN) return false;
    if (el.checkVisibility && !el.checkVisibility({
      contentVisibilityAuto: true, opacityProperty: true, visibilityProperty: true
    })) return false;
    // A closed <details> still reports boxes for its collapsed contents in
    // Chromium; only its <summary> is on screen.
    for (let a = el.parentElement; a; a = a.parentElement) {
      if (a.tagName === 'DETAILS' && !a.open &&
          a.firstElementChild && !a.firstElementChild.contains(el)) return false;
    }
    return true;
  };
  const items = [];
  document.querySelectorAll('body *').forEach((el) => {
    if (!visible(el)) return;
    const ownText = Array.from(el.childNodes)
      .filter((n) => n.nodeType === Node.TEXT_NODE)
      .map((n) => n.textContent.trim())
      .join('');
    if (!ownText && !/^(input|select|textarea)$/i.test(el.tagName)) return;
    items.push(el);
  });
  const name = (el) => (el.id ? '#' + el.id : el.tagName.toLowerCase())
    + '[' + (el.textContent || '').trim().replace(/\\s+/g, ' ').slice(0, 30) + ']';

  const findings = [];
  const pairs = [];
  document.querySelectorAll('[aria-describedby]').forEach((control) => {
    if (!visible(control)) return;
    control.getAttribute('aria-describedby').split(/\\s+/).filter(Boolean).forEach((id) => {
      const description = document.getElementById(id);
      if (!description || !visible(description)) return;
      pairs.push(name(control) + ' -> #' + id);
      const c = control.getBoundingClientRect();
      const d = description.getBoundingClientRect();
      const bandTop = Math.min(c.bottom, d.bottom);
      const bandBottom = Math.max(c.top, d.top);
      const between = [];
      items.forEach((other) => {
        if (other === control || other === description) return;
        if (other.contains(control) || other.contains(description)) return;
        if (control.contains(other) || description.contains(other)) return;
        const r = other.getBoundingClientRect();
        if (r.top < bandTop - 1 || r.bottom > bandBottom + 1) return;
        if (r.right <= d.left + 1 || r.left >= d.right - 1) return;
        between.push(name(other));
      });
      if (between.length) {
        findings.push({
          control: name(control),
          description: '#' + id,
          between: between,
          gap: Math.round(d.top - c.bottom)
        });
      }
    });
  });
  return { pairs: pairs, findings: findings };
}
"""

#: The shell shows five described controls on the page itself and one in each of
#: the capture, timeline and issue dialogs; every dialog is visited, so the walk
#: measures at least this many pairs. A floor, not an exact count -- adding a
#: description should not fail this test.
_MIN_DESCRIBED_PAIRS = 7

#: Every dialog is opened in turn so the controls inside it are measured too.
#: They overlap each other when opened together, which would make the geometry
#: meaningless, so each is opened and closed on its own.
_DIALOGS = ("capture-dialog", "timeline-dialog", "artifact-dialog", "issue-dialog")


@pytest.mark.a11y
@pytest.mark.parametrize("width", [320, 1280])
def test_every_description_renders_beside_the_control_it_describes(
    served_app: str, width: int
) -> None:
    """Issue #270: at 320px a privacy warning reflowed under the wrong control.

    ``#ex-originals-help`` -- "The originals ... can still hold location and other
    hidden details, so include them only when the recipient needs them" -- was a
    *sibling* of the checkbox it describes, two grid items further on. At desktop
    width the two-column export fieldset happened to stack them; at 320px the grid
    collapses to one column and the paragraph landed below the "Handoff view"
    select instead. A sighted reader on a narrow phone therefore read a warning
    about sending location data to a landlord as advice about choosing a handoff
    view. ``aria-describedby`` was correct throughout, so screen readers were
    fine and nothing in the suite went red: the same measurement found
    ``#st-awaiting-help`` ("your photo is already sealed and safe...") reading as
    help for "Photos" at every width below 900px.

    The existing ``test_reflows_at_320px_without_horizontal_scroll`` passes on
    both of those layouts, because nothing overflows -- the string fits, it just
    lands in the wrong place. So this measures the thing that was actually wrong:
    for every ``aria-describedby`` pair, in a real viewport, nothing a reader
    would parse as a separate item may sit between the control and its
    description. That closes the class rather than pinning the one instance, and
    it fails on a fix that only moves the paragraph one slot up.

    Both widths are measured: 320px is where the reflow broke it, and 1280px
    proves the fix did not buy narrow-screen adjacency by breaking the desktop
    layout it already had.
    """
    with sync_playwright() as p:
        try:
            browser = p.chromium.launch()
        except PlaywrightError as exc:
            pytest.skip(f"Chromium not available: {exc}")
        try:
            page = browser.new_page(viewport={"width": width, "height": 900})
            page.goto(served_app, wait_until="networkidle")
            page.wait_for_timeout(400)
            # The page stays measurable behind an open dialog, so each sweep sees
            # the shell's own pairs again; key by (control, description) to count
            # and report each pair once.
            pairs: set[str] = set()
            findings: dict[str, dict[str, Any]] = {}
            sweeps = [None, *_DIALOGS]
            for dialog in sweeps:
                if dialog is not None:
                    page.evaluate(f"() => document.getElementById({dialog!r}).showModal()")
                    page.wait_for_timeout(150)
                measured = page.evaluate(_DESCRIBEDBY_ADJACENCY)
                pairs.update(str(pair) for pair in measured["pairs"])
                for finding in measured["findings"]:
                    findings[f"{finding['control']} -> {finding['description']}"] = finding
                if dialog is not None:
                    page.evaluate(f"() => document.getElementById({dialog!r}).close()")
        finally:
            browser.close()

    # An empty findings list is the pass, so the count is what makes the silence
    # audible: a markup change that hid every description would otherwise retire
    # this check without a word (cf. test_aria_describedby_targets_exist).
    assert len(pairs) >= _MIN_DESCRIBED_PAIRS, (
        f"only {len(pairs)} visible aria-describedby pairs were measured at "
        f"{width}px ({sorted(pairs)}), below the floor of {_MIN_DESCRIBED_PAIRS}. "
        "Either the descriptions were removed or this probe is no longer finding "
        "the page."
    )
    assert not findings, "\n".join(
        f"{f['control']} is described by {f['description']}, but {f['gap']}px of "
        f"other content sits between them at {width}px: {f['between']}"
        for f in findings.values()
    )


# --- issue #275: no action may drop focus to <body> --------------------------------

#: `withBusy(btn, ...)` call sites in `app/app.js`. Pinned rather than derived so
#: that adding a tenth action fails here and the author has to come back and add it
#: to `_BUSY_ACTIONS` below. A floor on the walk alone would not catch that: nine
#: covered actions clears a floor of nine whether or not a tenth exists.
_WITHBUSY_CALL_SITES = 9

#: One entry in the walk per call site. `wireRefreshButton()` is a single call site
#: serving two buttons; the second (`#status-retry`) exists only inside the
#: failed-status panel, and `tests/test_app_accessibility.py` builds that panel and
#: asserts on its focus hand-off directly, so the walk drives `#refresh-btn` for it.
_BUSY_ACTION_COUNT = _WITHBUSY_CALL_SITES

_APP_SCRIPT = Path(__file__).resolve().parent.parent / "app" / "app.js"


def _prepare_add_issue(page: Any, photo: Path) -> None:
    page.click('[data-open-dialog="issue-dialog"]')
    page.fill("#ai-category", "mold")


def _prepare_capture(page: Any, photo: Path) -> None:
    page.click('[data-open-dialog="capture-dialog"]')
    page.set_input_files("#cap-file", str(photo))


def _prepare_timeline(page: Any, photo: Path) -> None:
    page.click('[data-open-dialog="timeline-dialog"]')
    page.select_option("#tl-type", "inspection")
    page.select_option("#tl-source", "firsthand")
    page.fill("#tl-occurred", "2026-01-02")
    page.fill("#tl-text", "The inspector visited and photographed the wall.")


def _prepare_artifact(page: Any, photo: Path) -> None:
    page.click('[data-open-dialog="artifact-dialog"]')
    page.set_input_files("#art-file", str(photo))
    page.fill("#art-title", "Notice")
    page.fill("#art-source", "Landlord")
    page.fill("#art-date", "2026-01-02")


def _prepare_relationship(page: Any, photo: Path) -> None:
    page.click("details.advanced-tools > summary")
    page.fill("#rel-source", "aaaaaaaa")
    page.fill("#rel-target", "bbbbbbbb")


def _prepare_advanced(page: Any, photo: Path) -> None:
    page.click("details.advanced-tools > summary")


def _prepare_nothing(page: Any, photo: Path) -> None:
    return None


#: Every action in the app that goes through `withBusy()`: a name, the setup it needs
#: to get past its own validation (an action that fails validation returns before
#: `withBusy()` is reached and would prove nothing), the control that starts it, and
#: whether focus must come back to that control specifically.
#:
#: The last flag is the difference between "focus survived" and "the contract holds".
#: For the five controls that are still on screen afterwards, `withBusy()` owes the
#: reader that exact control back. The four dialog submits are the case it declines:
#: their button is inside a dialog that the success handler closes, so a native
#: <dialog> hands focus to whatever opened it -- correct, and not `withBusy()`'s doing,
#: so they are held to the weaker "not <body>" only.
_BUSY_ACTIONS: tuple[tuple[str, Any, str, bool], ...] = (
    ("add issue", _prepare_add_issue, '#add-issue-form button[type="submit"]', False),
    ("capture", _prepare_capture, '#capture-form button[type="submit"]', False),
    ("timeline entry", _prepare_timeline, '#timeline-form button[type="submit"]', False),
    ("artifact", _prepare_artifact, '#artifact-form button[type="submit"]', False),
    ("relationship", _prepare_relationship, '#relationship-form button[type="submit"]', True),
    ("handoff profile", _prepare_advanced, '#profile-form button[type="submit"]', True),
    ("export", _prepare_nothing, '#export-form button[type="submit"]', True),
    ("add missing timestamps", _prepare_nothing, "#resolve-btn", True),
    ("refresh", _prepare_nothing, "#refresh-btn", True),
)


def test_the_focus_walk_covers_every_withbusy_call_site() -> None:
    """A new `withBusy()` call site must be added to the walk, not silently skipped.

    The browser walk below can only prove the actions it drives. If someone wires a
    tenth action and does not list it, the walk still passes -- so the count of call
    sites in the script is pinned here, and gaining or losing one fails until a
    person decides which list is wrong.
    """
    script = _APP_SCRIPT.read_text(encoding="utf-8")
    # Any `withBusy(<identifier>, ...)`: the declaration is excluded by the lookbehind,
    # and the prose references in the comments carry no argument, so neither inflates
    # the count. Matching on the argument shape rather than the literal name `btn`
    # keeps a renamed variable from reading as a deleted call site.
    sites = re.findall(r"(?<!function )\bwithBusy\(\s*[A-Za-z_$][\w$]*\s*,", script)
    assert len(sites) == _WITHBUSY_CALL_SITES, (
        f"app/app.js has {len(sites)} withBusy(...) call sites, not "
        f"{_WITHBUSY_CALL_SITES}. Add the new action to _BUSY_ACTIONS below (or "
        "remove the retired one) and update this count -- an action nobody drives "
        "is an action nobody has proved keeps focus."
    )
    assert len(_BUSY_ACTIONS) == _BUSY_ACTION_COUNT, (
        f"_BUSY_ACTIONS drives {len(_BUSY_ACTIONS)} actions, not {_BUSY_ACTION_COUNT}"
    )


@pytest.mark.a11y
def test_no_action_leaves_keyboard_focus_on_the_document_body(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path]
) -> None:
    """Issue #275: `withBusy()` disabled the focused button and dropped focus.

    A disabled element cannot hold focus, so every submit in the app left the
    reader at `<body>` -- the next Tab restarted from the top of the page, mid-task
    (WCAG 2.4.3). #269 repaired the two Refresh buttons at their own call site; the
    contract now lives in `withBusy()` itself, so this drives *every* action that
    goes through it rather than the two that were noticed.

    Each action is keyboard-driven -- focus the control, press Enter -- because that
    is the reader who loses something. A mouse user on a platform that does not
    focus buttons on click never held focus, and `withBusy()` deliberately does not
    move focus for them.
    """
    vault = make_vault()
    vault.document.add_issue(category="mold", room="bath", title="Mold", issue_id="i1")
    vault.save()
    photo = make_jpeg()
    server = make_app_server("127.0.0.1", 0, vault)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{port}/#token={server.session_token}"

    landed: dict[str, str] = {}
    not_returned: list[str] = []
    try:
        with sync_playwright() as p:
            try:
                browser = p.chromium.launch()
            except PlaywrightError as exc:
                pytest.skip(f"Chromium not available: {exc}")
            try:
                for name, prepare, selector, returns_to_control in _BUSY_ACTIONS:
                    page = browser.new_page()
                    page.goto(url, wait_until="networkidle")
                    page.wait_for_function(
                        "() => document.getElementById('st-unit').textContent === '4B'"
                    )
                    prepare(page, photo)
                    control = page.locator(selector).first
                    control.focus()
                    assert page.evaluate(_ACTIVE), f"{name}: nothing was focused before Enter"
                    page.keyboard.press("Enter")
                    # Every one of these announces something, success or failure, so
                    # a non-empty announcer means the round trip really completed --
                    # a fixed sleep would let a slow action pass while still in
                    # flight, with the button not yet re-enabled.
                    page.wait_for_function(
                        "() => document.getElementById('announcer').textContent.trim() !== ''"
                    )
                    landed[name] = page.evaluate(_ACTIVE) or "BODY"
                    if returns_to_control and not control.evaluate(
                        "(el) => el === document.activeElement && !el.disabled"
                    ):
                        not_returned.append(name)
                    page.close()
            finally:
                browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    # The floor is what makes an empty sweep audible: if every action silently
    # failed to run, `landed` would be short and the assertions below would be
    # passing on nothing at all.
    assert len(landed) == _BUSY_ACTION_COUNT, (
        f"only {len(landed)} of {_BUSY_ACTION_COUNT} actions were driven: {sorted(landed)}"
    )
    stranded = sorted(name for name, active in landed.items() if active in {"BODY", "body"})
    assert not stranded, (
        "these actions dropped keyboard focus to <body>, so the reader's next Tab "
        f"restarts from the top of the page (WCAG 2.4.3): {stranded}. "
        f"Where focus landed: {landed}"
    )
    assert not not_returned, (
        "these controls were still on screen and re-enabled afterwards, so "
        "withBusy() owed the reader that control back and did not hand it over: "
        f"{sorted(not_returned)}. Where focus landed: {landed}"
    )
