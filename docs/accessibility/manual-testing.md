<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Manual accessibility testing protocol

Automated tools (the `axe-core` gate in CI, plus the structural and i18n tests)
catch a large share of issues but **cannot** confirm that the app is actually
usable with assistive technology. This protocol is the human half of the WCAG 2.2
AA commitment. Run it before each release and record the date, tester, AT
versions, and findings in `docs/audits/`.

## What automation already covers (don't re-test by hand)

- A live **axe-core** scan of the running app in EN and ES, blocking on any
  moderate/serious/critical violation (`tests/test_app_axe.py`, the `a11y` CI job).
- Structure: language, title, viewport, skip link to a real target, one `h1`,
  landmarks, labelled controls, alt text, no positive `tabindex`
  (`tests/test_app_accessibility.py`).
- EN/ES string parity (`tests/test_app_i18n.py`) and PWA installability
  (`tests/test_app_pwa.py`).

## Manual passes (the part a human must do)

Start the app with `uv run habitable app --vault <vault>` and test the full flow:
add an issue → capture a photo → add a timeline entry → resolve timestamps →
export and read the result.

### 1. Keyboard only (no mouse)
- Tab/Shift-Tab reach every control in a sensible order; focus is always visible.
- The **skip link** appears on first Tab and jumps to `<main>`.
- All buttons/forms operate with Enter/Space; selects with arrow keys.
- No keyboard trap; the language toggle is reachable and operable.

### 2. Screen readers
Run at least one Windows and one Apple/Linux reader:
- **NVDA + Firefox** (Windows), **VoiceOver + Safari** (macOS/iOS), and
  **Orca + Firefox** (Linux) as available.
- Each landmark (banner, the labelled alpha-warning region, main, contentinfo)
  is announced; headings form a coherent outline.
- Every field's label and required state is announced; the resolve button
  announces its help text (`aria-describedby`).
- Results and errors spoken via the polite live region after each action.
- Switching to Español updates the page language so the reader switches voice.

### 3. Low vision / zoom / contrast
- Zoom to **200%** and reflow at a **320px**-wide viewport: no loss of content
  or function, no horizontal scrolling of text.
- Verify text contrast ≥ 4.5:1 against the shipped palette (a tool such as the
  browser's contrast checker); confirm status is conveyed in **words**, not
  color alone.
- Test with `prefers-reduced-motion` enabled.

### 4. Cognitive / stress
- Confirm there are no time limits and no surprise data loss; the alpha warning
  is always present; actions are reversible or clearly explained.

## Exported packet

- Confirm the **PDF** opens with the document *title* shown (not the file name)
  and the correct language; text is selectable and reads in order.
- Because full PDF/UA structure tagging is not yet provided (see the ACR), the
  packet also ships machine-readable `bundle.json`; treat that as the canonical,
  fully accessible record until tagged-PDF support lands.

## Recording results

Add a dated entry under `docs/audits/` (tester, AT + browser versions, pass/fail
per section, and any issues filed). A release does not ship with an open
moderate-or-worse manual finding.
