<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Responsible-Tech Audits — habitable

Instantiates [`standards/RESPONSIBLE-TECH-FRAMEWORK.md`](standards/RESPONSIBLE-TECH-FRAMEWORK.md).
Last regenerated: 2026-07-17.

This file is the repo's A–F applicability declaration and audit index. It supplies the
*frame* (what could go wrong, who is hurt, what we commit to) and points at the committed
artifacts; every numeric threshold lives in the owning standard under
[`standards/`](standards/README.md) and is referenced, never restated. Everything here is a
**self-assessment by the maintainer** — the independent security and cryptographic review,
the recorded human screen-reader pass, and the lawyer review of the legal framing are all
still **open** (they are v1.0 gate items in [`../ROADMAP.md`](../ROADMAP.md), and each
produces a dated artifact in [`audits/`](audits/README.md) when it actually happens — it is
not marked done by this document).

## Applicability

- **A Ethics:** applies — see [Audit A](#a-ethics--responsibility).
- **B Bias:** applies, narrowly — habitable ranks, scores, and classifies **no people**;
  the live fairness surface is EN/ES capability parity and plain-language reach. See
  [Audit B](#b-bias--fairness).
- **C Privacy:** applies — DPIA-style statement: [`privacy.md`](privacy.md). See
  [Audit C](#c-privacy--data-protection).
- **D Transparency:** applies — honest-limits framing is the product's core posture. See
  [Audit D](#d-transparency--explainability).
- **E Accessibility:** applies — ACR: [`accessibility/ACR.md`](accessibility/ACR.md). See
  [Audit E](#e-accessibility).
- **F Security:** applies — threat model: [`threat-model.md`](threat-model.md). See
  [Audit F](#f-security).
- **AI-EVAL:** **N/A — no LLM or AI features.** No LLM SDK in `[project].dependencies` or
  the dev group; no AI code paths (also declared in the README conformance table, row 9).
- **I18N:** applies — bilingual EN/ES civic surface with enforced parity:
  [`I18N.md`](I18N.md); CLDR N/A-by-design decision in
  [`adr/0005-i18n-g12-cldr-na-by-design.md`](adr/0005-i18n-g12-cldr-na-by-design.md).

Every N/A above carries its reason inline; a missing section would be a defect, a justified
N/A is conformance.

## A. Ethics & responsibility

- **What could go wrong?** The worst plausible failure is a tenant relying on the tool in a
  real dispute and being harmed by it: evidence that does not hold up, a leak that enables
  retaliation, or overclaimed capability ("court-proof") that a courtroom then dismantles.
  The worst plausible misuse is coercive: someone forcing a tenant to open their vault, or
  the tool being pointed at people rather than housing conditions.
- **How do we test for it?** The threat model names the adversary (a retaliating landlord)
  and walks the coercion cases ([`threat-model.md`](threat-model.md),
  [`adr/0007-limits-first-distress-decoy-vault-model.md`](adr/0007-limits-first-distress-decoy-vault-model.md));
  the packet red-team exercises hostile-input and doctored-evidence cases
  ([`audits/packet-attack-redteam.md`](audits/packet-attack-redteam.md)).
- **What do we commit to?** The README "Hard rules" and `ROADMAP.md` §Non-goals are the
  non-goals statement: no server-side personal data, no telemetry, no central authority, no
  admissibility promises, alpha caveat until the v1.0 gate. Declined-by-invariant requests
  (cloud backup, analytics, fake-photo detection, forensic-proof duress) stay declined and
  are recorded with honest alternatives in
  [`research/synthetic-personas-feedback.md`](research/synthetic-personas-feedback.md).
- **Enforcement.** AUTO — tamper-evidence and no-plaintext guarantees are tested in CI
  (`make verify`; [`prove-no-plaintext.md`](prove-no-plaintext.md)); the capability ledger's
  evidence paths are machine-checked on every PR (`make doc-links` over
  [`capabilities.md`](capabilities.md)). REVIEW — accountable owner is the maintainer
  (solo-maintainer status is explicit in
  [`adr/0006-solo-maintainer-review-count-exception.md`](adr/0006-solo-maintainer-review-count-exception.md));
  changes to the threat model route through CODEOWNERS.

## B. Bias & fairness

- **What could go wrong?** The tool serves English speakers better than Spanish speakers,
  or literate-technical users better than everyone else — an equity failure in a tool for
  California tenants. Representational harm (stereotyping tenants) is possible in docs and
  site copy.
- **How do we test for it?** EN/ES key-and-placeholder parity is a merge-blocking CI gate
  (`make i18n`; [`I18N.md`](I18N.md)); a dated plain-language/cognitive-load review of the
  in-app copy is committed ([`audits/plain-language-review.md`](audits/plain-language-review.md)).
- **What do we commit to?** EN and ES are first-class, capability-equal surfaces, not
  translation afterthoughts; no inference of sensitive attributes, ever (nothing in the
  vault schema records protected characteristics, and no feature classifies people).
- **Scoping note (why "narrowly").** The record-strength self-assessment
  (`src/habitable/strength.py`) scores *records*, not people: its inputs are verifiable
  record properties (token presence, authority counts, recurrence), never content judgment
  or anything about a person. That boundary is a design invariant; any change to it needs a
  REVIEW-gated ethics pass.
- **Enforcement.** AUTO — the i18n gates above. REVIEW — representational-harm review of
  new user-facing copy rides the plain-language review cadence.

## C. Privacy & data-protection

- **What could go wrong?** The vault holds images of homes, addresses (EXIF/GPS), and
  housing timelines for people in an acute power imbalance. A leak, a subpoena-able
  central store, or silent metadata in an export could each enable retaliation.
- **How do we test for it?** The DPIA-style statement is a committed, maintained artifact
  ([`privacy.md`](privacy.md)); exports strip private metadata and tests assert it; the
  no-plaintext guarantee has its own documented proof procedure
  ([`prove-no-plaintext.md`](prove-no-plaintext.md)); sync has a dedicated threat model
  ([`sync-threat-model.md`](sync-threat-model.md)).
- **What do we commit to?** No server-side personal data, no telemetry, no analytics (also
  none on the Pages site); local-first encrypted storage; the relay sees only opaque
  ciphertext and is documented against its own observability matrix
  ([`relay-observability-matrix.md`](relay-observability-matrix.md)); minimal-disclosure
  export scoping is self-documented in every packet.
- **Enforcement.** AUTO — encryption, metadata-strip, disclosure-scoping, and
  tamper-evidence behavior are covered by the test suite in the merge gate; gitleaks runs
  pre-commit and in CI, TruffleHog weekly
  ([`../.github/workflows/ci.yml`](../.github/workflows/ci.yml),
  [`../.github/workflows/secret-scan-scheduled.yml`](../.github/workflows/secret-scan-scheduled.yml)).
  REVIEW — DPIA re-read on release; it is versioned with the repo, not a one-time PDF.

## D. Transparency & explainability

- **What could go wrong?** Overclaiming is this product's most dangerous failure mode: a
  tenant or lawyer trusting a claim ("verified", "signed", "court-ready") that the code
  does not actually establish. The repo's own history includes corrected overclaims (the
  a11y sentence and "signed releases" README fixes of 2026-07-05) — treated as the failure
  mode to guard against, not an embarrassment to hide.
- **How do we test for it?** The capability ledger ties every public claim to a local
  evidence file and CI fails when a path drifts ([`capabilities.md`](capabilities.md),
  `make doc-links`); the verifier's behavior is pinned to a published decision table
  ([`verifier-decision-table.md`](verifier-decision-table.md)) and a golden corpus.
- **What do we commit to?** Verdict separation — packet integrity, timestamp-authority
  trust, and evidence readiness are reported as three independent claims, never collapsed
  ([`adr/0008-separate-integrity-timestamp-trust-and-readiness.md`](adr/0008-separate-integrity-timestamp-trust-and-readiness.md));
  "not legal advice / no admissibility guarantee" framing everywhere; degraded states are
  disclosed at the point of use (awaiting-timestamp, duress limits). No model cards or
  datasheets: no AI in the stack (see Applicability).
- **Enforcement.** AUTO — ledger evidence paths and doc links in the merge gate;
  disclosure-behavior tests in the suite. REVIEW — honesty-of-framing review on claims
  changes; legal framing has an open HUMAN gate (lawyer review, v1.0).

## E. Accessibility

- **What could go wrong?** A disabled tenant cannot complete the primary task (capture →
  export → hand over a packet), or the exported packet itself is unreadable to a
  screen-reader user on the receiving side.
- **How do we test for it?** Automated: the axe-core browser gate over the app shell, the
  generated packet HTML, the committed sample packet, and the site pages is merge-blocking
  ([`../.github/workflows/a11y.yml`](../.github/workflows/a11y.yml), `make a11y`). Manual:
  the protocol is documented ([`accessibility/manual-testing.md`](accessibility/manual-testing.md)).
- **What do we commit to?** WCAG 2.2 AA as the floor; the accessible HTML packet is a
  conformant rendering by design
  ([`adr/0004-accessible-html-packet-as-conformant-rendering.md`](adr/0004-accessible-html-packet-as-conformant-rendering.md));
  the ACR states conformance honestly, including its Not-Evaluated rows
  ([`accessibility/ACR.md`](accessibility/ACR.md)).
- **Enforcement.** AUTO — axe zero-violation gate in CI. REVIEW — **open gap:** the
  recorded human NVDA + VoiceOver pass has not happened; it is a v1.0 gate item and
  resolves the ACR's Not-Evaluated rows only when a dated recording lands in
  [`audits/`](audits/README.md). pa11y-ci and Lighthouse are not wired in this repo (axe is
  the browser engine in the gate today); adding them is tracked in the portfolio standard,
  not silently claimed here.

## F. Security

- **What could go wrong?** See [`threat-model.md`](threat-model.md) — the adversary is a
  retaliating landlord with resources and motive; the crown jewels are vault
  confidentiality and packet tamper-evidence. The verifier must never accept altered
  evidence as intact.
- **How do we test for it?** STRIDE-style threat model with content-pinned baselines for
  external review ([`audits/threat-model-baseline.md`](audits/threat-model-baseline.md),
  current B1); packet-attack red-team ([`audits/packet-attack-redteam.md`](audits/packet-attack-redteam.md));
  fuzz and tamper-detection tests in the merge gate; hostile-input hardening across
  crypto/sync/TSA/media landed 2026-07-13.
- **What do we commit to?** No fixed HIGH/CRITICAL findings ship unremediated; scanners
  block rather than advise; supply-chain posture per the security standard (all `uses:`
  SHA-pinned; CycloneDX SBOM + build provenance attestation on releases; byte-reproducible
  wheel/sdist and relay-image checks; signed-tag guard in
  [`../.github/workflows/release.yml`](../.github/workflows/release.yml)).
- **Enforcement.** AUTO — CodeQL (python + actions), gitleaks (pre-commit + CI) and weekly
  TruffleHog, pip-audit, Trivy container scan, zizmor workflow-SAST, Harden-Runner, the
  95% coverage floor on the evidence-integrity core (`crypto.py`, `vault.py`, `tsa.py`,
  `verify.py`), and OpenSSF Scorecard with the honest committed baseline
  ([`audits/scorecard-2026-07.md`](audits/scorecard-2026-07.md)). REVIEW — **open gap:**
  the independent security + cryptographic review (v1.0 gate; reviewer onboarding is ready
  in [`audits/onboarding.md`](audits/onboarding.md) and
  [`recruitment/role-auditor.md`](recruitment/role-auditor.md)).

### ASVS 5.0 declaration

habitable's self-assessed floor is **OWASP ASVS 5.0 Level 1**, with the L2 posture applied
to the surfaces that are actually exposed:

- **Why L1 is the declared floor:** the portfolio standard targets L2 for "PII-holding or
  externally-exposed systems", meaning *services*. habitable is architecturally neither: it
  operates no service holding user data — tenant data exists only in an encrypted vault on
  the user's own device, and the project runs no account system, no API, and no central
  store (see [`privacy.md`](privacy.md) §2).
- **Why the authentication/session/access-control families are largely N/A:** there are no
  accounts, no server-side identities, and no roles to authorize. The two real
  authentication surfaces — the loopback app-server's per-session token and the relay's
  authenticated case-bound pairing
  ([`adr/0009-authenticated-case-bound-sync-v2.md`](adr/0009-authenticated-case-bound-sync-v2.md))
  — are assessed under the threat model and covered by tests, and the relay (the one
  optionally network-exposed component) is held to the stricter posture: fail-closed
  parsing, bounded retained state, and an operator self-audit
  ([`relay-operator-self-audit.md`](relay-operator-self-audit.md)).
- **Status:** self-assessment. It becomes externally validated only when the independent
  review above happens; until then no stronger claim is made.

### Secret-management policy

- **Repository/CI:** no long-lived secrets. CI runs on the ephemeral `GITHUB_TOKEN` with
  `contents: read` at workflow level and job-scoped write grants where required
  (release/pages); there are no cloud credentials, deploy keys, or third-party API tokens
  in this repo's workflows. Secret scanning is layered: gitleaks pre-commit, gitleaks on
  every PR, TruffleHog weekly.
- **Product keys:** tenant/union key material never touches the repository or any project
  infrastructure — custody, rotation, and recovery are documented in
  [`key-management.md`](key-management.md) and [`key-custody-playbook.md`](key-custody-playbook.md).
- **Release signing:** the release workflow enforces a signed-tag guard against
  `.github/allowed_signers`; the signing key is generated and held by the maintainer only
  (procedure: [`releasing.md`](releasing.md)).

### VEX posture

No HIGH or CRITICAL vulnerability is currently waived as unfixable; the dependency and
container scans block on fixed HIGH+CRITICAL findings. If an unfixable-for-now finding
ever needs a documented waiver, an OpenVEX statement will be attached alongside the release
SBOM and recorded in [`audits/`](audits/README.md) with its rationale and owner — waivers
are artifacts, not comments.

## Governance (AI repos only)

N/A — no AI system in the stack, so no AI risk register, impact assessment, ISO 42001 SoA,
or EU AI Act classification is required. This line exists so the decision is written down
rather than silent; it must be revisited before any AI feature is ever added (none is
planned — see `ROADMAP.md` §Non-goals).

---

Last verified: 2026-07-17 · Recheck cadence: quarterly, on any release, and immediately
when an open gap above (recorded AT pass, independent security/crypto review, lawyer
review) produces its artifact.
