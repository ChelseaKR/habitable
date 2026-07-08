# 5. G12 (CLDR/tzdata freshness) stays N/A: hand-rolled EN/ES tables, no ICU dependency by design

- Status: Accepted
- Date: 2026-07-05

## Context

The internationalization standard's mechanical gate G12 pins a CLDR/ICU floor
(`babel>=2.16`, CLDR/ICU >= 48.2, `tzdata >= 2026a`) for repos that render
CLDR-formatted numbers, currency, or dates. `docs/I18N.md` originally recorded
G12 as **"N/A-until-used"**, reasoning that habitable did no locale-aware
formatting at all.

FIX-12 shipped real pluralization and locale-aware number formatting
(`src/habitable/i18n.py`'s `format_number`, the ICU-MessageFormat-subset plural
renderer, and `scripts/check_i18n_parity.py`'s G5 plural/placeholder parity
gate). That invalidated the *literal* words of the old reason — habitable now
does locale-aware formatting — while the audit (2026-07-05, I18N-14/DOC-14)
correctly flagged the stale "N/A-until-used" text as no longer honest on its
face, even though the underlying decision not to take a CLDR/ICU dependency was
still probably right.

The real question G12 is asking: is the number/date formatting backed by CLDR
data that itself needs a freshness/upgrade cadence? Two paths were available:

- **(a)** Take the `babel` (or PyICU) dependency now, formally live-ify G12,
  and adopt the CLDR upgrade cadence the standard describes.
- **(b)** Keep the formatting **hand-rolled** — a fixed, small, EN/ES-only
  grouping/decimal-separator table with no external CLDR/ICU data — and write a
  *new*, accurate N/A rationale grounded in that choice, rather than silently
  leaving the old (now-false) one standing.

## Decision

**(b).** habitable's number and date formatting (`i18n.py`'s `_SEPARATORS: dict[str,
tuple[str, str]]` — the (group, decimal) separator pair per locale used by
`format_number`, and the parallel hand-written `_MONTHS_ABBR` table used by
`format_date`/`format_datetime`) is a **hand-rolled, two-locale table**, not a
CLDR/ICU-backed formatter. It covers exactly the grouping/decimal convention
difference between English and Spanish (plus abbreviated month names), which is
stable, well-known, and does not require pulling in `babel`/PyICU's full CLDR
dataset (with its own update cadence, dependency weight, and supply-chain
surface) for a handful of hard-coded characters and month strings.

G12 therefore remains **N/A**, but for the *correct*, current reason: there is
no CLDR/ICU dependency to keep fresh, by design, not because "no formatting
exists" (that clause is no longer true and must not be repeated).

This is explicitly a **revisit trigger, not a permanent exemption**: the day a
third locale ships whose number formatting differs in more than the
group/decimal separator (e.g. a locale needing real CLDR plural-rule tables
beyond the `one`/`other` categories this project's ICU-MessageFormat subset
already hand-implements, or right-to-left digit shaping), the hand-rolled table
stops being adequate and G12 goes live per the cadence already documented in
`docs/I18N.md`.

## Consequences

- `docs/I18N.md`'s G12 row is corrected to state this ADR's reasoning instead
  of the stale "no locale-aware formatting" claim (DOC-14, I18N-14 resolved).
- No new dependency is added today; `pyproject.toml` gains no `babel`/PyICU
  entry.
- **Trigger to revisit:** adding a third UI locale (workstream B, "languages
  beyond EN/ES"). At that point, re-open this ADR's decision before assuming
  the hand-rolled table still suffices.
- If a locale needs full CLDR plural categories (`zero`, `two`, `few`, `many`)
  beyond `one`/`other`, that is also a trigger, independent of locale count.
