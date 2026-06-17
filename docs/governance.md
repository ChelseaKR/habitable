# Governance

How **habitable** is governed: who decides, how the rules hold, and why no one — not even
the maintainer — can read or revoke a union's data. This is deliberately short.

> **Stage:** alpha / concept. The design is documented; the build has not started. Process
> below is what this project commits to, not a record of a mature one. Expect it to change,
> with changes recorded as ADRs.

## Project status & independence

habitable is an **independent personal open-source project** by Chelsea Kelly-Reif, built on
the author's own time and equipment. It is **not affiliated with, sponsored by, or a work
product of any employer or client**; it is **not a government system** and was not built for a
government customer. It contains **no proprietary or client material** — the techniques
(RFC 3161 timestamping, SHA-256 hashing, CRDT sync, end-to-end encryption) are general and
publicly known. **All sample data is synthetic**; no real tenant data is committed, ever. The
full statement is in [`NOTICE`](../NOTICE).

## Decision-making

- **Maintainer-led (benevolent maintainer)** at this stage. Chelsea Kelly-Reif is the final
  decision-maker. As contributors arrive, this section will be updated to share that authority.
- **Decisions of consequence are recorded as ADRs** in [`docs/adr/`](adr/) — architecture,
  cryptographic choices, the packet format, the verification protocol, the threat model, and any
  change touching the hard rules. An ADR states the context, the decision, and what it rules out.
- **The hard rules in the [README](../README.md#hard-rules-enforced-not-aspirational) are
  invariants.** No server-side personal data; no central authority over a union's records;
  mandatory tamper-evidence; sealed originals with minimizing sharing; retaliation as the threat
  model. A change that weakens any of these is out of scope by definition — it does not get
  weighed against features. Proposals that touch their boundaries need an ADR explaining how the
  invariant is preserved.

## Versioning & compatibility

- **The package follows [SemVer](https://semver.org/).**
- **The packet format and the verification protocol are versioned independently** of the package,
  because they are long-lived contracts: a packet exported today may be checked in court years
  from now. **Older packets must keep verifying.** A change that would break verification of an
  existing valid packet is not allowed; new formats are additive, and the verifier accepts every
  version it has ever emitted.
- **Deprecations are documented in [`CHANGELOG.md`](../CHANGELOG.md)** with the migration path and,
  for format or protocol changes, the version they land in.

## Releases

Releases are **tagged and signed**. Each release is reproducible and provenanced:

- **Pinned, locked dependencies** via [`uv.lock`](../uv.lock).
- **GitHub Actions pinned to commit SHAs** (not floating tags).
- **Build-provenance attestations** published with the artifacts.
- **`make verify` is the merge gate** and the release gate — ruff format + check, `mypy --strict`,
  and the full test suite (including tamper-detection and CRDT-convergence tests) must be green.
  Nothing merges or releases red.

## Audit-as-artifact discipline

Reviews are **committed artifacts, not promises**, and are **regenerated on releases** so they
track the code rather than a marketing moment:

- **Security and accessibility reviews** live under [`docs/audits/`](audits/).
- The **Accessibility Conformance Report (ACR)** — VPAT 2.5 (Rev 508), covering WCAG 2.x A/AA and
  the Section 508 functional performance criteria — lives at
  [`docs/accessibility/ACR.md`](accessibility/ACR.md).
- The threat model lives at [`docs/threat-model.md`](threat-model.md). Accessibility is a
  merge-blocking CI gate; a regression fails the build.

## Licensing & contributions

- **AGPL-3.0-or-later** is the project license, and it is part of the safety case, not just a
  preference. AGPL **closes the hosted-service loophole**: anyone who runs a modified relay or a
  hosted variant for others must publish their changes, so a fork that secretly weakens privacy or
  tamper-evidence cannot be offered as a service without disclosure.
- **The verification tool is additionally available under Apache-2.0** (an additional permission
  under AGPL §7). This lets a court, an inspector, a legal-aid group, or an opposing party embed
  packet verification in their own software and redistribute it without the AGPL reaching their
  code. Merely *running* the verifier never triggers copyleft. See [`NOTICE`](../NOTICE).
- **DCO sign-off is required** — sign commits with `git commit -s` to certify the
  [Developer Certificate of Origin](https://developercertificate.org/). Contributions are licensed
  under AGPL-3.0-or-later (verification tooling additionally under Apache-2.0).
- **A Code of Conduct applies** ([`CODE_OF_CONDUCT.md`](../CODE_OF_CONDUCT.md)). Contribution
  mechanics — conventional commits, tests for evidence paths, keeping the verifier independent —
  are in [`CONTRIBUTING.md`](../CONTRIBUTING.md).

## How the union owns its data

Governance of the *project* is separate from control of a union's *data* — and the second does
not exist. By design:

- **There is no operator who can read or revoke a union's data.** habitable ships no account
  system, no central database, and no admin. Each union holds its own keys and its own records;
  plaintext never leaves a device unencrypted. The optional relay sees ciphertext only; the
  timestamp authority sees a bare hash.
- **Forking the code or self-hosting the relay changes nothing about who can read the data** —
  still no one but the keyholders. There is no privileged build, no maintainer key, and no toggle
  that grants access. This is enforced by the architecture, not by policy or by trust in whoever
  maintains the project.

Because the project never holds a union's contents, **nothing it operates can be subpoenaed for
them.** The union decides what to disclose, to whom, and when.
