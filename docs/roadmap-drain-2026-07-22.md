<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Roadmap drain and execution register — 2026-07-22

This register reconciles the strategic [`ROADMAP.md`](../ROADMAP.md), the dated
[`RESEARCH-ROADMAP.md`](RESEARCH-ROADMAP.md), the capability ledger, current
tests, and the live GitHub queue. It is the execution snapshot for the
2026-07-22 roadmap drain.

The checkout was clean on `main` at
`7c61721db6dba0ac4b175901ff26fe9a88496a91`. After `git fetch origin --prune`,
`HEAD` and `origin/main` resolved to that same commit. No feature branch or
unpublished local commit was treated as shipped.

## Status overview

| State | Count | Meaning |
| --- | ---: | --- |
| **Shipped or reconciled** | 18 themes | Code, tests, automation, or maintained documentation exist on `main`; stale roadmap wording is corrected or linked below. |
| **Externally blocked** | 9 outcomes | Completion requires a real reviewer, partner, device measurement, translator/maintainer, or funded field event. |
| **Decision/ecosystem/trigger blocked** | 3 outcomes | Packaging or governance work waits on a supported dependency path, pilot platform choice, or sustained-contributor trigger. |
| **Protocol/research blocked** | 3 capabilities | Building before the named review or technical trigger would violate an explicit safety or compatibility gate. |
| **Open agent-executable feature issues** | 0 | GitHub has no open implementation issue after the audit. |

The six open GitHub issues, #121–#126, are deliberately bounded human-review
tasks: threat-model challenge, packet cold-read, organizer workflow,
keyboard-only path, verifier tamper exercise, and screen-reader path. They are
inputs to the external gates, not unfinished feature tickets. Open PR #132 is a
documentation-standards change and is outside this roadmap drain.

## What was drained

The older research backlogs still preserve their original dates and hypotheses.
The following current-main evidence closes or supersedes their implementation
work:

| Theme | Current disposition | Main-tree evidence |
| --- | --- | --- |
| Release authenticity and provenance | **Shipped** | Signed `v*` tag ruleset, signature/version/mainline guards, exact-artifact promotion, SBOM, Sigstore provenance, reproducible wheel/sdist and relay image |
| Verifier hardening and recipient truth states | **Shipped** | Hostile-input tests, path confinement, JSON output, trusted-root input, golden compatibility, explicit integrity/trust/readiness separation |
| Timeline and recurrence | **Shipped** | Timeline 2.0 / packet v3, occurrence/source semantics, links, recurrence reopening, custody binding and migration contract |
| Key lifecycle and co-custody | **Shipped technically; human validation open** | Passphrase hardening, DEK rotation, recovery blobs, M-of-N recovery, custody playbook and CLI round trips |
| Peer trust and sync integrity | **Shipped** | Case-bound pairing, authenticated sync v2, replay protection, signed receipts, incremental originals, per-field provenance |
| Offline transfer and data-cost controls | **Shipped** | Sneakernet export/import, byte accounting, storage footprint, metered/Wi-Fi gate |
| Organizer campaign view | **Shipped as CLI/local output** | Multi-vault health roll-up and independently verifiable per-unit packet export |
| Metadata resistance | **Shipped as an opt-in bounded layer** | `PaddingTransport` buckets size and hides real-message count within a cover batch; timing, IP, and room activity remain disclosed |
| Media and corroborating instruments | **Shipped** | Still images, audio/video and sensor CSV share the seal/hash/timestamp/custody path |
| Evidence strength | **Shipped with limits** | On-device factor report; no truth, admissibility, or win prediction |
| Portability and interoperability | **Shipped baseline** | Versioned schema, embedding guide, Apache-licensed kernel, strict BagIt adapter, legal-aid receipt example |
| Aggregate organizing commons | **Shipped as opt-in local export** | On-device k-anonymous aggregate with explicit contribution and suppression rules |
| App status, storage, and case chronology | **Shipped** | EN/ES local app, interactive chronology, proof overlays, storage/network status, automated accessibility gates |
| Plain-language action wording | **Shipped in this drain** | The last `resolve_*` implementation jargon became “Add missing timestamp tokens” / “Agregar sellos de tiempo faltantes,” with parity guards |
| Data-flow transparency | **Shipped** | Local data-flow X-ray and executable no-plaintext-to-relay proof |
| Contributor onboarding | **Shipped technically** | Bootstrap, devcontainer, architecture walkthrough, good-first-issue set; sustained outside contribution remains an outcome |
| Governance/audit preparation | **Shipped as process material** | Responsible-tech declaration, frozen threat baseline, review hub, audit/reviewer briefs, disclosure path |
| Education/adoption preparation | **Shipped as material** | EN/ES quick starts, setup guide, workshop guide, board briefing, legal scaffolding and pilot brief |

## Remaining outcomes and why they stay open

Every remaining item has a trigger, owner type, and completion artifact. None is
an unowned “later” bullet.

| Remaining outcome | State | Trigger / dependency | Completion artifact |
| --- | --- | --- | --- |
| Independent security and cryptographic audit | **Externally blocked** | Fund and engage an independent reviewer | Dated report in `docs/audits/`; findings remediated or formally accepted |
| Recorded NVDA + VoiceOver pass | **Externally blocked** | Human testers using the named AT/platform matrix | Dated manual-test record with no open moderate-or-worse finding |
| Tenant-union or legal-aid pilot | **Externally blocked** | Partner accepts the synthetic-only safety boundary, then separately approves any real-data phase | Written outcome including packet fitness, failures, and stop/continue decision |
| Independent threat-model/legal framing review | **Externally blocked** | Security reviewer plus licensed forum-specific legal reviewer | Signed-off residual-risk and framing notes; no admissibility claim |
| Recovery and multi-device usability validation | **Externally blocked** | Non-technical organizers perform pair, backup, rotate, lose-device, and restore drills | Observed task record and fixes; technical round trips already pass |
| Native mobile package | **Ecosystem blocked** | Supported `cryptography`/Pillow mobile wheels or an owned, reviewed cross-build; store signing identities | Reproducible signed on-device package, update path, security and AT passes |
| Desktop package | **Decision blocked** | A pilot selects a desktop platform and support/update commitment | Signed DMG/MSIX/package, no-terminal install, rollback/update runbook |
| Additional language | **Externally blocked** | Native translator and ongoing legally sensitive string owner | Complete catalog, human review, parity/RTL/expansion gates |
| Jurisdiction-specific template | **Externally blocked** | Licensed local reviewer, dated primary sources, maintenance owner | Versioned presentation-only profile with review date and expiry policy |
| Named low-end-device performance baseline | **Externally blocked** | Obtain the selected reference device after the packaging target is known | Reproducible measurement replacing the current 10× CI model |
| Sustained contributor/shared-governance transition | **Trigger blocked** | At least one sustained outside contributor | Updated `GOVERNANCE`/maintainers decision process |
| Funding and workshop outcomes | **Externally blocked** | Funder/partner decision and a real facilitated workshop | Funding terms and workshop report without user telemetry |

## Protocol and research gates

### Scoped/rehashed custody views

Issue/date-scoped packets and issue-subset organizer shares remain fail-closed.
Re-enabling them is not a UI task. The safe sequence is:

1. Specify packet v4 and sync v3 `custody_view` objects with a canonical scope
   descriptor, source-chain head, ordered selected-entry commitments, explicit
   omission statement, domain-separated view hashes, and producer signature.
2. Decide what relationship to the source proof can be shown without exporting
   excluded identifiers. Do not claim the view is a complete source chain.
3. Add old-version goldens, cross-scope unlinkability checks, mutation/reorder/
   substitution tests, atomic publication, and replay/downgrade tests.
4. Obtain independent cryptographic review of the specification and test
   vectors.
5. Only then implement packet and sync encoders/decoders, verifier verdicts,
   CLI/app selectors, migrations, and recipient disclosure.

Exit: a recipient can verify the view, its declared scope, and its producer
signature; no excluded identifier or arbitrary link appears; v1–v3 packets and
v1–v2 sync remain compatible.

### Full merge/conflict history

Signed provenance identifies the winning current value, but the state-based CRDT
does not retain every overwritten value. A true review history needs a versioned
append-only field-change log, authenticated writes, deterministic compaction, and
privacy rules for exports. It should be validated with organizer workflows before
changing the CRDT schema. Until then, the CLI provenance view must not be described
as a complete edit history.

### Tagged PDF/UA

The accessible HTML packet remains the designated conformant rendering. PDF/UA
work resumes only when an open, maintainable tagging path can emit a correct
structure tree and pass both machine and human AT checks. Selectable text,
language metadata, and bookmarks do not satisfy that gate.

## Roadmap operating rule

The authoritative truth order is:

1. executable behavior and tests;
2. [`docs/capabilities.md`](capabilities.md);
3. this dated execution register and the root roadmap;
4. dated research/ideation documents.

At each release, copy unresolved rows forward only when their trigger still
holds. Close a row only with its completion artifact. If a proposed item has no
owner, trigger, safe exit criterion, and invariant fit, it does not enter the
roadmap.

The post-drain opportunity portfolio is in
[`novel-use-cases-plan.md`](novel-use-cases-plan.md).
