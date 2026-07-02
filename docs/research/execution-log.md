<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Synthetic-persona backlog — execution log

> Companion to [`synthetic-personas-feedback.md`](synthetic-personas-feedback.md). It records what
> was actually executed against that study's 51 remediations (`R-##`) and 27 expansions (`E-##`),
> and — honestly — what was not, and why.
>
> **History.** The first pass ran in an environment **without Python 3.14**, so `make verify`
> couldn't run; it shipped **documentation only**, plus one syntax-only fix verified by
> byte-compilation (BUG-01). A **second pass** then provisioned Python 3.14 (via `uv python install`)
> and ran the **full gate** (`make verify` green: ruff + mypy --strict + pytest ≥85%; the browser axe
> scans skip locally because the chromium download mirror is blocked, but the structural a11y tests
> and CI's axe gate cover them). That second pass made BUG-01 durable and implemented the
> packet-disclosure code items below. Everything else remains **documentation**, which the persona
> study identified as roughly half the product's value (legal scaffolding, honest-limits framing,
> auditor materials, interop contracts, adoption/ops/governance).

## Legend

- ✅ **Done** — shipped in this change set.
- 📝 **Spec written, code deferred** — the exact copy/contract is now written and ready to wire in;
  the code change is deferred because it needs the unrunnable gate.
- ⛔ **Deferred (needs code + gate)** — requires app/library code; not safe to ship unvalidated here.
- 👤 **Not executable by an agent** — needs real people, money, or real-world events; materials to
  unblock it were prepared where possible.

## Bonus fix found while reading the source

| ID | What | Status | Where |
| --- | --- | --- | --- |
| BUG-01 | The Apache-2.0 **verifier subset would not import on Python ≤ 3.13**: three multi-type `except` clauses lacked parentheses (valid only under PEP 758 / Python 3.14), contradicting the CHANGELOG's claim that the subset was made portable for legal-aid embedders. Root cause: ruff's formatter targets `py314` and *strips* the parentheses, so a plain re-parenthesize would be reverted by the next `make fmt`. **Fix:** reference a named exception tuple (`except _SOME_ERRORS:`) — formatter-stable and portable — and add a regression **guard test** (`test_verifier_subset_avoids_py314_only_except_syntax`). | ✅ Fixed, gate-green, guarded | `src/habitable/verify.py`, `tsa.py`, `exif.py`; `tests/test_guards.py` |

## Done (✅) — shipped documentation

| ID | Item | Deliverable |
| --- | --- | --- |
| R-37 | Standalone cryptographic design spec | `docs/crypto-spec.md` |
| R-38 | Key-management security narrative | `docs/crypto-spec.md` §3.1 |
| R-39 | Verifier decision/truth table | `docs/verifier-decision-table.md` |
| R-31 | Cross-check with general RFC 3161 / hashing tools | `docs/verifier-decision-table.md` §5 |
| E-26 | Formal JSON Schema for `bundle.json` + semver contract | `docs/packet-bundle.schema.json`, `docs/bundle-schema.md` |
| R-51 | Documented, versioned bundle with stability contract | `docs/bundle-schema.md` |
| E-27 | Verifier-embedding cookbook | `docs/embedding-the-verifier.md` |
| E-18 | "How to attack a habitable packet" red-team doc | `docs/audits/packet-attack-redteam.md` |
| E-19 | Declaration / witness-foundation templates | `docs/legal/declaration-template.md` |
| R-30 | Foundation guidance for counsel | `docs/legal/foundation-guidance.md` |
| E-20 | CA jurisdiction pack (evidence notes + "what to expect on cross") | `docs/legal/california-evidence-notes.md` |
| R-34 | Document CA-only scope of legal guidance | `docs/legal/README.md` |
| E-10 | Adoption / workshop / train-the-trainer kit | `docs/adoption/workshop-facilitator-guide.md`, `docs/adoption/README.md` |
| R-20 | Printable quick-start, EN + ES | `docs/adoption/quickstart-en.md`, `docs/adoption/quickstart-es.md` |
| E-21 | Board / decision-maker risk briefing | `docs/adoption/board-risk-briefing.md` |
| E-25 | Funder impact + sustainability brief | `docs/funding-impact-brief.md` |
| R-42 | Good-first-issues set + newcomer architecture walkthrough | `docs/good-first-issues.md` |
| R-47 | Localization-contributor workflow + legally-sensitive-string flagging | `docs/localization-guide.md` |
| E-24 | Localization guide (incl. RTL/glossary cautions) | `docs/localization-guide.md` |
| E-14 | "Key custody for unions" playbook | `docs/key-custody-playbook.md` |
| R-36 | Custody-transfer / membership-churn flow (manual, on existing commands) | `docs/custody-transfer.md` (linked from `key-custody-playbook.md`, `adoption/board-risk-briefing.md`, `adoption/README.md`) |
| R-45 | Relay operator no-log self-audit + log schema | `docs/relay-operator-self-audit.md` |
| R-46 | What a relay operator can/cannot observe | `docs/relay-observability-matrix.md` |
| R-33 | Make relay-metadata disclosure prominent | `docs/relay-observability-matrix.md` |

## Done (✅) — code, validated under `make verify` (second pass)

| ID | Item | Deliverable |
| --- | --- | --- |
| R-26 | Plain-language "what this packet proves / does not" on every packet | New `src/habitable/disclosure.py` (single localized source) rendered as a structured section at the top of `packet.html` and the PDF (`htmlpacket.py`, `pdf.py`); covered by existing packet tests. |
| R-29 | Packet itself states authorship/depiction not proven | Same disclosure: explicit "does not prove who took it / that it depicts this unit / the condition itself / admissibility." |
| R-40 | Point recipients to the accessible HTML packet | The disclosure's "how to verify" line names `packet.html` as the accessible reading and `habitable verify` / standard-tool cross-check. |
| R-27 | Tell recipients shared copies strip location; flag residual PII | Localized "what this packet discloses" block in `packet.html`/`packet.pdf` (location removed; and, when sealed originals are embedded, a residual-metadata warning); the machine-readable `disclosures` list is now in the signed `bundle.json` (schema updated). |
| R-08 | Structured, AT-/script-friendly verifier output | `habitable verify --json` emits a full structured report (overall + per-item verdicts, notes); covered by `tests/test_cli_demo.py`. |
| R-31 | Assert the TSA trust chain from the CLI | `habitable verify --trusted-cert PEM` (repeatable) anchors each timestamp to a trusted root (the verifier already supported `trusted_certs`; this exposes it); covered by `tests/test_packet_verify.py`. |
| R-16 | Multiple-TSA redundancy by default | Capture stamps every configured authority (`extra_tsas`); the primary token stays in `timestamp`, independent tokens go in `additional_timestamps`; the verifier accepts an item if ≥1 authority verifies and reports `verified_authorities`. Backward-compatible (additive; old single-authority packets unchanged). Covered by `tests/test_packet_verify.py`. |
| R-35 | Minimal-disclosure export scoping, defensible against over-broad discovery | Each packet now self-documents its scope: `scope_statement()` in `disclosure.py` (single localized EN/ES source) feeds a `scope.statement` + `scope.exclusions` object in the signed `bundle.json` (schema updated) and the English `disclosures` list, and renders — localized — in `packet.html`/`packet.pdf`. New standalone doc `docs/legal/minimal-disclosure.md` (what a packet contains/omits, why minimal, responding to over-broad discovery), linked from `docs/legal/README.md` and the *Discovery caution* section of `foundation-guidance.md`. Issue-scoped exports already excluded other issues' captures and timeline; now asserted in tests. Covered by `tests/test_packet_verify.py`. |
| BUG-01 | Verifier-subset cross-Python portability | Named-tuple `except` form + regression guard test (see above). |
| R-04 / R-41 | Plain-language & cognitive review of the in-app copy + setup guide | Grade-6–8 plain-language pass across `app/i18n/en.json`, `app/i18n/es.json`, and `docs/setup-guide.md`: jargon ("Device fingerprint" → "Device ID", "Chain of custody" → "Evidence trail", "Awaiting timestamp" → "Waiting for timestamp", "Content hash" → "Content fingerprint") replaced or glossed with in-context help wired via `aria-describedby`; the Spanish de-lawyered and its timestamp term (`sello de tiempo`) made consistent. Honest-limits strings kept at full strength; EN/ES key + placeholder + plural-category parity held (`tests/test_app_i18n.py`, `scripts/check_i18n_parity.py`). Dated review record: `docs/audits/plain-language-review.md`. **Left:** native-speaker ES review + a stressed-user cognitive walk-through. |

## Done (✅) — in-app status legibility & a11y copy (third pass)

Plain, reassuring EN/ES status copy; no dead-end empty states; an ARIA live-region
announcement on every async transition (kept clear-then-set so repeats re-announce); and a
non-auditory success cue (a short haptic buzz plus a `prefers-reduced-motion`-guarded visual
pulse on the announcer). Static-shell only — no new dependencies, offline-first preserved.

| ID | Item | Deliverable |
| --- | --- | --- |
| R-01 | Plain, reassuring evidence-status labels (EN+ES) | `app/i18n/{en,es}.json` (`status_awaiting` reworded; new `status_awaiting_help`, `status_timestamped_help`); visible help `<p id="st-awaiting-help">` in `app/index.html` (associated via `aria-describedby`), toggled by `renderStatus` in `app/app.js`. |
| R-17 | Reassure that a long awaiting-timestamp gap does not weaken the evidence | Same `status_awaiting_help` copy — the photo is already sealed at capture; the timestamp only proves *when* and attaches automatically once back online. |
| R-02 | No dead-end empty states — every idle state names a next action | `issues_empty_next` (wired into `#issues-empty`) and a next-action `issue_none_available`, EN+ES. |
| R-07 | ARIA live-region announcements on async transitions | Existing clear-then-set `announce()` retained; capture / resolve / export announce their outcome (awaiting→timestamped via `msg_resolved`). |
| R-10 | Non-auditory equivalent for the success cue | `signalSuccess()` in `app/app.js` — `navigator.vibrate(35)` plus a `.flash-ok` pulse (`app/styles.css`, reduced-motion-guarded) — on capture, resolve, and verified export. |

Covered by the existing structural a11y gate (`tests/test_app_accessibility.py`, incl.
`aria-describedby` target check), the EN/ES parity gates (`tests/test_app_i18n.py`,
`scripts/check_i18n_parity.py`), and the browser axe/keyboard scans. **Left (R-41):** a full
reading-level pass and in-app jargon glossary remain deferred.

## Spec written, code deferred (📝)

The canonical text/contract now exists; wiring it into the app needs further work.

| ID | Item | What exists now / what's left |
| --- | --- | --- |
| R-04 | Plain-language Spanish ("not lawyerly") | **Done — moved to the ✅ table above.** Human-Spanish quick-start (`quickstart-es.md`), the localized packet disclosure (ES), and now the in-app `app/i18n/es.json` copy pass have all shipped (see `docs/audits/plain-language-review.md`). |
| R-23 | Custodial recovery-blob storage without a honeypot | Practices shipped in `key-custody-playbook.md`; **left:** any helper tooling. |
| R-50 | Partner/reviewer vetting guidance | Addressed in the red-team doc (A11); **left:** a short standalone note if wanted. |

## Deferred — needs code + the (unrunnable) gate (⛔)

App/library/UX work, not safe to ship unvalidated here. Grouped by the persona study's themes.

- **Status legibility & a11y copy:** R-01, R-02, R-07, R-10, R-17, and R-41 are now done in-app (see the ✅ sections above).
- **Tenant capture/recurrence/storage:** R-03, R-05, R-18, R-19, E-01, E-02.
- **Safety / shared-device / duress:** R-12, R-13, R-14, R-15, R-49, E-06.
- **Recovery & key lifecycle UX:** R-09, R-11, R-24, E-05, E-13.
- **Defaults & integrity surfacing:** R-22.
- **Organizer/sync:** R-21, E-11, E-12.
- **Recipient verification & packet:** R-25→**E-15** (zero-install recipient verifier).
- **Jurisdiction/recipient rendering:** R-28, E-16, E-17.
- **Localization/RTL code:** R-48.
- **Platform/interop/relay code:** E-07, E-08, E-09, E-22, E-23.
- **Capture-time alt text:** E-03.
- **Calm/assisted mode:** R-09-adjacent, E-04.
- **Dev ergonomics:** R-43 (devcontainer — buildable but unverifiable here).
- **Process:** R-44 (maintenance-cost weighting — partly reflected by preferring config/doc surfaces in this very change).

## Not executable by an agent (👤) — materials prepared

These are the v1.0-gate items that, by their nature, require real humans, money, or real-world
events. This change set prepares the materials that unblock them:

| Gate item | Prepared material |
| --- | --- |
| Independent **security & cryptographic audit** | `docs/crypto-spec.md`, `docs/verifier-decision-table.md`, `docs/audits/packet-attack-redteam.md` |
| Recorded human **screen-reader pass** | (existing `docs/accessibility/manual-testing.md`; a11y copy specs above) |
| Real **tenant-union / legal-aid pilot** | `docs/adoption/*`, `docs/legal/*` |
| **Grant funding** secured | `docs/funding-impact-brief.md` |
| Lawyer's vetting of legal framing | `docs/legal/*` (explicitly flagged as needing a licensed CA attorney) |

## Declined (invariant conflicts)

Unchanged from the study — see
[Requests we should decline](synthetic-personas-feedback.md#requests-we-should-decline-invariant-conflicts).
A web dashboard, project-run cloud backup, usage analytics, operator-side passphrase recovery,
duress "guarantees," fake-photo detection, and admissibility promises remain refused, with honest
alternatives documented there.

## Suggested next pass (when the gate can run)

1. Wire the 📝 items (small copy/render changes) and run `make verify` + `make a11y`.
2. ✅ **Done.** Added a CI **cross-Python compile check** for the verifier subset so BUG-01
   cannot recur — the `verifier-portability` job in `.github/workflows/ci.yml` byte-compiles
   the Apache-2.0 subset on Python 3.12 and 3.13 (the portability floor: `canonical.py` uses
   PEP 695 `type` statements, so 3.9–3.11 cannot parse it), catching any 3.14-only syntax
   before merge. This is the CI counterpart to the `test_verifier_subset_avoids_py314_only_except_syntax`
   guard test.
3. Validate the high-value ⛔ bets (E-15 recipient verifier, E-01/R-05 recurrence, E-19 in a real
   forum) with real pilot/legal partners before building.
