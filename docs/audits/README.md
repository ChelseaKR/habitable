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
  the absence of any duress-safe state, coercion/forensic exposure, and
  what a timestamp does and does not prove.
- **Quality gates.** `make verify` runs the full gate: `ruff`, `mypy --strict`, and
  `pytest` with property-based convergence tests and tamper-detection tests against
  clean, altered, and chain-broken fixtures, at roughly **85% coverage**.
  `pip-audit` and CodeQL run in CI.

## Findings addressed pre-audit

Issues the project found and fixed in its own review, recorded here so the trail is
honest before external eyes arrive. These predate any third-party audit.

| Date | Severity | Finding | Resolution |
| --- | --- | --- | --- |
| 2026-06-17 | Medium (privacy) | A custody-actor identity (an importing peer's fingerprint, `details.from`) and the tenant's original source filename (`details.source`) were carried in the **exported, signed `bundle.json`**, weakening the "exports name no one" guarantee in threat model §4. | Moved both to a **vault-only `private_details`** field that is never hashed and never exported; the union keeps them for its own audit. Previously-produced packets still verify. Regression-guarded by `tests/test_guards.py`; released in v0.2.0. |
| 2026-06-17 | Low (robustness) | The verifier could crash on hostile input: invalid-UTF-8 bundle bytes, and a malformed custody chain. Found by the fuzz/property harness. | Both are now clean rejections (`VerificationError` / a failed verdict), never a crash. |
| 2026-06-17 | Low (interop) | The RFC 3161 client assumed SHA-256 and RSA and mis-read a name-form `PKIStatus`, so it failed against some real public authorities. | Follows the token's own digest algorithm, dispatches RSA + ECDSA, accepts int/name `PKIStatus`; verified against DigiCert and FreeTSA in a network-gated CI job. |

The privacy finding post-dates the freeze of [threat-model baseline **B1**](threat-model-baseline.md): the baseline text did not over-claim (§4 promised only that actor/salt/signature are dropped), but the fix strengthens the spirit of that section. The baseline document remains valid as frozen; this fix does not require a new baseline.
