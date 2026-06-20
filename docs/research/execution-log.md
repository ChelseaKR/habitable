<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Synthetic-persona backlog — execution log

> Companion to [`synthetic-personas-feedback.md`](synthetic-personas-feedback.md). It records what
> was actually executed against that study's 51 remediations (`R-##`) and 27 expansions (`E-##`),
> and — honestly — what was not, and why.
>
> **The hard constraint.** This work was done in an environment **without Python 3.14**, so
> `uv sync` / `make verify` (ruff + mypy --strict + pytest ≥85% + the axe a11y gate) **could not be
> run**. Shipping unvalidated changes to a security-critical, alpha legal-evidence tool would be
> irresponsible, so **no behavioral code or gated app/i18n files were changed** — with one exception:
> a syntax-only fix that is *verified* correct by byte-compilation and matches the CHANGELOG's stated
> intent (see BUG-01). Everything else executed here is **documentation**, which the persona study
> itself identified as roughly half the product's value (legal scaffolding, honest-limits framing,
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
| BUG-01 | The Apache-2.0 **verifier subset would not import on Python ≤ 3.13**: three multi-type `except` clauses lacked parentheses (valid only under PEP 758 / Python 3.14), contradicting the CHANGELOG's claim that the subset was made portable for legal-aid embedders. | ✅ Fixed & verified (byte-compiles on 3.11) | `src/habitable/verify.py`, `tsa.py`, `exif.py` |

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
| R-45 | Relay operator no-log self-audit + log schema | `docs/relay-operator-self-audit.md` |
| R-46 | What a relay operator can/cannot observe | `docs/relay-observability-matrix.md` |
| R-33 | Make relay-metadata disclosure prominent | `docs/relay-observability-matrix.md` |

## Spec written, code deferred (📝)

The canonical text/contract now exists; wiring it into the app/packet needs the gate.

| ID | Item | What exists now / what's left |
| --- | --- | --- |
| R-26 | Plain-language "what this proves / does not" cover page on every packet | Exact framing drafted in `docs/legal/foundation-guidance.md` and the red-team doc; **left:** render it onto `packet.html`/`packet.pdf` (`packet.py`/`htmlpacket.py`/`pdf.py`). |
| R-29 | Packet itself states authorship/depiction not proven | Same source text; **left:** same packet-rendering change. |
| R-40 | Point recipients to the accessible HTML packet | Covered in adoption + embedding docs; **left:** a line in the packet/cover output. |
| R-04 | Plain-language Spanish ("not lawyerly") | A human-Spanish quick-start shipped (`quickstart-es.md`); **left:** the in-app `app/i18n/es.json` copy pass. |
| R-17 | Meaning of a long awaiting-timestamp gap | Explained in `crypto-spec.md`/`verifier-decision-table.md`; **left:** surface in-app at the status. |
| R-23 | Custodial recovery-blob storage without a honeypot | Practices shipped in `key-custody-playbook.md`; **left:** any helper tooling. |
| R-50 | Partner/reviewer vetting guidance | Addressed in the red-team doc (A11); **left:** a short standalone note if wanted. |

## Deferred — needs code + the (unrunnable) gate (⛔)

App/library/UX work, not safe to ship unvalidated here. Grouped by the persona study's themes.

- **Status legibility & a11y copy:** R-01, R-02, R-07, R-08, R-10, R-41.
- **Tenant capture/recurrence/storage:** R-03, R-05, R-18, R-19, E-01, E-02.
- **Safety / shared-device / duress:** R-12, R-13, R-14, R-15, R-49, E-06.
- **Recovery & key lifecycle UX:** R-09, R-11, R-24, E-05, E-13.
- **Defaults & integrity surfacing:** R-16, R-22.
- **Organizer/sync:** R-21, E-11, E-12.
- **Recipient verification & packet:** R-25→**E-15** (zero-install recipient verifier), R-27.
- **Jurisdiction/recipient rendering:** R-28, E-16, E-17.
- **Disclosure scoping:** R-35.
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
2. Add a CI **cross-Python compile check** for the verifier subset so BUG-01 cannot recur.
3. Validate the high-value ⛔ bets (E-15 recipient verifier, E-01/R-05 recurrence, E-19 in a real
   forum) with real pilot/legal partners before building.
