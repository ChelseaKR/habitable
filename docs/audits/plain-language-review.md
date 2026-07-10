<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Plain-language & cognitive review — in-app copy + setup guide

**Date:** 2026-07-02
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
  reassuring register.
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
- **Partial terminology consistency fix:** the bundle mixes *sello de tiempo* and
  *marca de tiempo* for "timestamp." Standardized on **`sello de tiempo`** (matches
  the status grid and the packet) across `status_*`, `field_dev_tsa*`, `capture_*`,
  and `export_timestamped`. `resolve_deferred` / `resolve_help` / `msg_resolved`
  still say *marca de tiempo* — left alone on this pass because a concurrently
  merged change already touched their English wording, and
  `capture_awaiting_reassure` (guard-tested by
  `test_awaiting_timestamp_copy_is_reassuring`) quotes `resolve_deferred`'s exact
  text, EN and ES. Finishing the `resolve_*` terminology fix is tracked under *What
  remains*.
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
2. **A measured readability score.** Target is stated as grade 6–8 but was applied
   by judgment, not a computed Flesch–Kincaid / SMOG pass over the rendered copy.
3. **Cognitive walk-through with a real user under stress**, and a screen-reader
   read-through of the new help strings (they are wired via `aria-describedby`;
   the automated `tests/test_app_accessibility.py` confirms the targets resolve,
   but not that they *sound* clear via NVDA/VoiceOver — see
   `docs/accessibility/manual-testing.md`).
4. **Re-scan of `Severity`** and the `issue`/`capture` model nouns with a plain-
   language editor to decide whether a fuller rename (with matching CLI/doc changes)
   is worth it.
5. **Text-expansion check at 320px** for the two new, longer help strings in both
   locales (the layout is tested to a 320px reflow; eyeball the Spanish, which runs
   longer).
6. **Finishing the `resolve_*` terminology fix.** `resolve_deferred`, `resolve_help`,
   and `msg_resolved` still say *marca de tiempo* / "resolve/awaiting" rather than
   *sello de tiempo* / plain action-first wording. Changing them also requires
   updating `capture_awaiting_reassure`'s quoted reference in both locales and the
   guard test `test_awaiting_timestamp_copy_is_reassuring` (`tests/test_app_i18n.py`)
   in the same change.

Re-run this review whenever UI strings change; the string list above can grow.
