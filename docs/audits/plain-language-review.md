<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Plain-language & cognitive review — in-app copy + setup guide

**Date:** 2026-07-02 (follow-up completed 2026-07-22)
**Scope:** `app/i18n/en.json`, `app/i18n/es.json`, `docs/setup-guide.md`
**Roadmap items:** R-41 (plain-language & cognitive review) / R-04 (human,
non-lawyerly Spanish)
**Reviewer:** maintainer pass (see *What remains* for the native-speaker and
tester follow-ups this does **not** replace)

This is the review-record artifact for the roadmap "reviewed plain-language pass"
exit criterion. It records the target, the method, every term changed and why,
and what is deliberately left for a human / native-speaker pass. Like the other
files in this directory, it is a committed, diffable record rather than a claim in
prose.

## Why this review exists

The people using habitable are often documenting a problem at midnight after a
fight with a landlord. **Stress lowers effective reading level.** The persona
study (`docs/research/synthetic-personas-feedback.md`) was blunt: the Spanish was
*correct* but "sounded like a lawyer," and a tenant once left a photo "Awaiting
timestamp" for a day, afraid to close the screen. The governing house style is
[`docs/localization-guide.md` §"Writing good copy"](../localization-guide.md); this
pass applies it to the in-app strings and the setup guide.

## Target and method

- **Reading-level target:** roughly **US grade 6–8** for ordinary UI copy and the
  setup guide. Short sentences, everyday words, one action per step, a calm and
  reassuring register. **Measured, not asserted** — the English bundle currently
  scores **Flesch–Kincaid grade 5.6** on ordinary UI prose; see
  [*Measured score*](#measured-score) below for the method, the honest-limits
  number, and what to do when it drifts.
- **Method:** read every user-facing string in both bundles and every line of the
  setup guide; flag terms of art and multi-clause sentences; replace jargon with a
  plainer phrasing, **or** gloss it in place (a short in-context help string, or a
  one-time parenthetical on first use in the guide). Spanish was rewritten for
  *meaning*, not word-for-word, in informal **tú** register to match the existing
  bundle.
- **Hard constraint — do not soften the honest-limits strings.** Plain is not the
  same as soft. The legally-sensitive keys listed in
  [`localization-guide.md` §"Legally-sensitive strings"](../localization-guide.md)
  (`alpha_*`, `verify_intact` / `verify_failed`, `custody_intact` /
  `custody_broken`, `capture_timestamped_no`, `footer_note`) were left with their
  warning force intact and were **not** reworded.
- **Key parity preserved.** No i18n key was renamed or removed. Values changed in
  place; two new help keys were added to **both** locales and wired into the
  markup. Guarded by `tests/test_app_i18n.py` and `scripts/check_i18n_parity.py`
  (EN/ES key, placeholder, and plural-category parity).

## Measured score

Added 2026-09-04 (issue #246). Until then the grade 6–8 target above was applied
by judgment and no score was ever computed — a target you do not measure is the
kind of unverified claim this project refuses to make about anything else.

[`scripts/report_readability.py`](../../scripts/report_readability.py) computes
it. It scores the **rendered** English strings, not the raw JSON: it runs every
value in `app/i18n/en.json` through the same ICU subset the app renders, picking
one plural branch (`other`) and replacing `{count}`-style placeholders with the
numeral a reader actually sees, so `{count, plural, =0 {No timestamps waiting}
one {# timestamp waiting} other {# timestamps waiting}}` is scored as "3
timestamps waiting". Regenerate the numbers below with:

```sh
uv run python scripts/report_readability.py
```

Snapshot of `app/i18n/en.json` (285 keys) on 2026-09-04:

| Corpus | Strings | Flesch–Kincaid | Reading ease | SMOG |
| --- | ---: | ---: | ---: | ---: |
| **Ordinary UI prose** — what the grade 6–8 target is about | 57 | **5.6** | 66.7 | 8.6 |
| **Honest-limits strings** — reported, never a target | 23 | 11.0 | 33.9 | 11.8 |
| Every string pooled — depressed by one-word labels | 285 | 7.9 | 46.0 | 8.6 |

Ordinary UI prose reads at **grade 5.6**, at or below the stated target. Read
that as "about grade 6," not as three significant figures: English syllable
counting is heuristic without a pronunciation dictionary, and the heuristic
over-counts compounds — it hears three syllables in "timestamp," which is
everywhere in this bundle — so the reported grade is a slight over-estimate. The
205 one-word labels ("Heat", "Refresh") are counted but not scored; a grade level
for a button is noise, and pooling hundreds of them flatters the average, which
is why the pooled row is there but is not the headline.

**This reports; it does not gate.** `make verify` does not fail on a readability
number, deliberately. A hard threshold would press hardest on exactly the
sentences that must stay blunt, and the cheapest way to pass one is to soften a
warning. The honest-limits strings — the keys in
[`localization-guide.md` §"Legally-sensitive strings"](../localization-guide.md)
plus the limit-stating strings named with their reasons in the script's
`_ADDITIONAL_HONEST_LIMITS` — are therefore scored on their own row and held out
of the headline number. They sit at grade 11.4 **on purpose**: "not
evidence-ready" and "this does not decide admissibility" are dense because they
are precise. If a threshold is ever added, that printed list is the exemption
list it must honour.

**When the score drifts.** Re-run the script whenever UI strings change (the same
instruction this whole review ends on) and update the table above.

- *Ordinary prose above grade 8:* look at the strings the script names under
  *Hardest ordinary strings*, shorten sentences and swap long words, re-run. It
  is a prompt to edit copy, not a build failure.
- *Honest-limits number moves:* check **why** before being pleased. That row
  going **down** because a limitation was hedged, softened, or dropped is a
  regression even though the score improved. The warning force of those strings
  outranks their grade level, always.
- *A new string states a limit, a warning, a privacy property, or a verdict:* add
  it to the guide's table (or to `_ADDITIONAL_HONEST_LIMITS` with a reason) so it
  is scored on the honest-limits row rather than dragging ordinary prose.

**Spanish is not scored.** Flesch–Kincaid and SMOG are English formulas; running
them over `app/i18n/es.json` would produce a wrong number wearing a right
number's clothes. Spanish needs a Spanish formula (Fernández Huerta / INFLESZ),
which is its own piece of work — see item 2 of *What remains*.

`tests/test_readability_report.py` keeps the script honest: it pins that a number
is still produced from a populated corpus, that ICU plurals are rendered to one
branch, that the honest-limits keys are read from the localization guide rather
than a private copy, and that deliberately unreadable copy still exits 0.

## Terms changed and why

| Key(s) | Was (EN) | Now (EN) | Why |
| --- | --- | --- | --- |
| `status_fingerprint` | "Device fingerprint" | "Device ID" | "fingerprint" is a term of art; "Device ID" is plainer. The setup guide now glosses the CLI's "fingerprint" as the same value. |
| `status_awaiting` | "Awaiting timestamp" | "Waiting for timestamp" | "Awaiting" is formal; "waiting for" is everyday English. Directly targets the "afraid to close the screen" failure mode. |
| `status_custody` | "Chain of custody" | "Evidence trail" | Legal term of art. "Evidence trail" keeps the "unbroken recorded sequence" meaning in plain words. The verdicts (`custody_intact`/`custody_broken`) are unchanged. |
| `capture_hash_label` | "Content hash" | "Content fingerprint" | "hash" is a term of art; "fingerprint" is the standard plain metaphor for a content digest. |
| `field_dev_tsa` (+ new `field_dev_tsa_help`) | "Use offline dev timestamp" | "Use a practice timestamp (offline testing)" + in-context help | "dev timestamp" is developer jargon. The new help line is **honesty-critical**: it says the practice timestamp is not trusted and does not prove the time to a court. |
| `field_include_originals` (+ new `field_include_originals_help`) | "Include sealed originals" | "Include the sealed original photos" + in-context help | "sealed originals" is opaque. Help explains they are full-quality photos that can still carry location/hidden data (mirrors the packet's residual-metadata disclosure, R-27). |
| `field_kind` / `error_kind_required` | "Kind" / "Please enter a kind." | "Type" / "Please enter a type." | "Kind" as a field label is ambiguous. |
| `field_text` / `error_text_required` | "Text" / "Please enter some text." | "What happened" / "Please describe what happened." | A timeline note is "what happened," not "text." |
| `export_disclosures` | "Disclosures" | "Important notes" | "Disclosures" is above the target reading level; the disclosure *content* (from the signed bundle) is unchanged. |
| `app_tagline`, `meta_description` | "local-first … habitability problems / evidence tool" | "housing problems … runs on your own device" | "local-first" and "habitability" are jargon; "housing problems" and "runs on your own device" are plainer. |
| `issue_none_available` | "No issues available yet" | "No issues yet" | Shorter. |

### Spanish-specific (R-04)

- **De-lawyered** the tagline/description: `habitabilidad` → `vivienda`; dropped the
  stiff `evidencia de habitabilidad` calque; added the warm "en tu propio
  dispositivo."
- **Terminology consistency completed 2026-07-22:** the bundle now uses
  **`sello de tiempo`** consistently for "timestamp." The `resolve_*` values were
  changed from implementation jargon to the action-first "Add missing timestamp
  tokens" / "Agregar sellos de tiempo faltantes"; the quoted
  `capture_awaiting_reassure` next step and its guard test changed in the same
  patch.
- `status_fingerprint`: `Huella del dispositivo` → **`ID del dispositivo`**;
  `capture_hash_label`: `Hash del contenido` → **`Huella del contenido`** (frees
  "huella" for the content digest, its natural plain metaphor).
- `status_custody`: `Cadena de custodia` → **`Cadena de la evidencia`** — drops the
  term-of-art *custodia* while keeping a feminine head noun so the unchanged,
  sensitive verdicts `Intacta` / `Rota` still agree grammatically.

## What was deliberately kept

- **Honest-limits / verdict strings** (see method) — kept at full strength.
- **Model vocabulary that also appears in the CLI, docs, and packet** — *issue*,
  *capture*, *packet*, *timestamp*, *vault*. These are the words a tenant will meet
  across the whole tool and in court; renaming them only in the app would desync
  the app from the CLI and the setup guide. They are **glossed** on first use in
  the setup guide instead.
- **`Severity`** as a form label — standard, widely understood in context; flagged
  below for the human pass to confirm.

## What remains (not covered by this pass)

This is a maintainer pass. It does **not** substitute for:

1. **Native-speaker Spanish review.** Confirm register (tú), regional neutrality,
   and the `Cadena de la evidencia` / `Intacta` / `Rota` gender reading in the
   live `<dt>`/`<dd>` status grid. Owner still needed (tracked in the i18n
   native-ES benchmark note).
2. **A measured readability score for Spanish.** English is now measured and
   recorded above (*Measured score*; `scripts/report_readability.py`). Spanish is
   not, and deliberately so: Flesch–Kincaid and SMOG are English formulas, and a
   Flesch–Kincaid number for `app/i18n/es.json` would be a wrong number wearing a
   right number's clothes. Scoring the Spanish bundle needs a Spanish-appropriate
   formula (Fernández Huerta / INFLESZ) and its own pass.
3. **Cognitive walk-through with a real user under stress**, and a screen-reader
   read-through of the new help strings (they are wired via `aria-describedby`;
   the automated `tests/test_app_accessibility.py` confirms the targets resolve,
   but not that they *sound* clear via NVDA/VoiceOver — see
   `docs/accessibility/manual-testing.md`).
4. **Re-scan of `Severity`** and the `issue`/`capture` model nouns with a plain-
   language editor to decide whether a fuller rename (with matching CLI/doc changes)
   is worth it.
5. ~~**Text-expansion check at 320px** for the two new, longer help strings in both
   locales.~~ **Done 2026-09-04 (issue #249) — negative result.** Both were looked
   at in a 320px Chromium viewport in EN and ES. `field_dev_tsa_help` wraps to 3
   lines in both locales; `field_include_originals_help` wraps to 4 (EN) and 5
   (ES) at 12px/18px in a 262–280px column. Spanish runs ~16–17% longer than
   English, adds at most one line, and neither string overflows its container,
   truncates, or forces horizontal scrolling (`document.scrollWidth ==
   clientWidth` in all four cases). No shortening needed, so no limitation was
   dropped. This was the one-time look at two known-long strings; #208's
   pseudo-locale gate is what catches the *class* of problem going forward.
Re-run this review whenever UI strings change; the string list above can grow.
