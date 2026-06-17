# Audits

This directory holds habitable's **audit-as-artifact** record. The same way the
evidence engine treats a photo's hash and timestamp as committed, checkable facts
rather than assurances, we treat the project's own security and accessibility
posture as committed artifacts rather than claims in a README.

A tool that asks tenants under threat of retaliation to trust it owes them
evidence of its own. So the reviews live here, in version control, where anyone can
read them, diff them across releases, and see when something changed.

## What gets committed here

- **Security reviews** — findings from internal and (eventually) external review,
  with their resolution or accepted-risk rationale.
- **Dependency audits** — `pip-audit` output, capturing known-vulnerable
  dependencies and the bump or mitigation taken.
- **CodeQL results of note** — static-analysis findings worth recording, with
  triage (true positive and fixed, or false positive and why).
- **Accessibility conformance** — the Accessibility Conformance Report lives at
  [`../accessibility/ACR.md`](../accessibility/ACR.md) (VPAT 2.5, Rev 508), covering
  the WCAG 2.2 A/AA success criteria, the Revised Section 508 software and
  support-documentation criteria, and the Functional Performance Criteria.
- **Threat-model baselines** — content-pinned freezes of
  [`../threat-model.md`](../threat-model.md) handed to external reviewers, each with a
  maintainer re-review and the residual risks to confirm. See
  [`threat-model-baseline.md`](threat-model-baseline.md) (current: **B1**).

How to start a review of habitable — scope, run instructions, and synthetic data —
is in [`onboarding.md`](onboarding.md).

These artifacts are **regenerated and re-committed on each release**, so a given
tag carries the audit state that was true for it. `pip-audit` and CodeQL also run
in CI on every change, but the committed snapshots here are the durable, citable
record.

## Initial self-review (2026-06-17, v0.1.0)

This is the first entry, and it is deliberately modest.

- **Stage.** habitable is **alpha and concept-stage**. The architecture and the
  evidence method are documented and partly implemented; the project is not yet
  fit for relied-upon use in a real case.
- **Cryptography.** The cryptographic work uses well-reviewed primitives via the
  `cryptography` library (SHA-256, RSA/PKCS#1 v1.5, Ed25519, X.509) and standard
  **RFC 3161** trusted timestamping (CMS `SignedData` over `TSTInfo`). We have
  written no novel cryptography. The standard timestamp path is exercised fully
  offline by a local RFC 3161 issuer; the bundled Ed25519 dev TSA is explicitly
  **non-production** and always reports an untrusted chain.
- **No external audit yet.** **No third-party security audit has been performed.**
  This self-review is not a substitute for one, and nothing here should be read as
  an independent attestation.
- **Known limitations** are tracked honestly in the threat model at
  [`../threat-model.md`](../threat-model.md) — including relay metadata exposure,
  the limits of the duress-safe state against a coercing or forensic adversary, and
  what a timestamp does and does not prove.
- **Quality gates.** `make verify` runs the full gate: `ruff`, `mypy --strict`, and
  `pytest` with property-based convergence tests and tamper-detection tests against
  clean, altered, and chain-broken fixtures, at roughly **85% coverage**.
  `pip-audit` and CodeQL run in CI.
