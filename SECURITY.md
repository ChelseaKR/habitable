# Security policy

habitable is built for people under threat of retaliation. Its security is the
product, not a feature — so please report problems, and please do so privately
until they are fixed.

## Reporting a vulnerability

**Preferred:** use GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository (the **Security** tab → *Report a vulnerability*), **if that
option is showing as available on the Security tab**. This keeps the report
confidential and lets us coordinate a fix and advisory.

**Fallback (use this if the Security tab has no "Report a vulnerability" button,
or you'd rather not use GitHub):** email the maintainer directly at
**ckellyreif@gmail.com** with a subject line starting `[habitable security]`.
This channel exists so a reporter is never stuck with no way in, regardless of
the repository's current GitHub configuration.

Please include: what you found, how to reproduce it (on synthetic data — never
real tenant data), the impact you foresee, and any suggested remediation.

We aim to acknowledge a report within **3 business days** and to ship a fix or a
documented mitigation within **90 days**, coordinating disclosure with you. There
is no paid bug bounty; credit is given in the advisory unless you prefer
anonymity.

## What we care about most

The guarantees in `README.md` and `docs/threat-model.md` are the security
contract. Reports that undermine any of these are highest priority:

- **Confidentiality at rest / in transit** — any way to read vault contents
  without the key, or to recover plaintext from a relay or timestamp authority.
- **Tamper-evidence** — any way to alter a sealed original, a chain of custody,
  or a timestamp token such that `habitable verify` still reports a packet as
  intact (e.g. backdating without detection).
- **Unintended disclosure** — any path by which an exported packet leaks location
  or custody identities contrary to the sharing policy.
- **Verifier soundness** — any way the standalone verifier accepts evidence it
  should reject (or the reverse).

## Scope and limits

- **Supported versions:** pre-1.0, only the **latest release** is supported.
  There is no back-porting of fixes to older tags; upgrade to the latest release
  to get a fix.
- This is alpha, concept-stage software. **Do not rely on it for real legal
  matters yet.** See *Honest limits* in `README.md`.
- Cryptography uses well-reviewed primitives via `cryptography` and standard
  RFC 3161 timestamping; we are not rolling our own ciphers. Reports of misuse of
  those primitives are in scope; theoretical breaks of the primitives themselves
  are out of scope here.
- The bundled development TSA (`DevTSA`) is explicitly **non-production** and is
  not a trusted timestamp source; that is by design, not a vulnerability.

## Severity tiers and response targets

Severity is judged against the security contract above (confidentiality,
tamper-evidence, unintended disclosure, verifier soundness). Targets are for a
small volunteer project and are goals, not guarantees.

| Severity | Examples | Acknowledge | Fix / mitigation target |
| --- | --- | --- | --- |
| **Critical** | Read vault contents without the key; verifier accepts tampered/backdated evidence as intact; plaintext recoverable from a relay | 2 business days | 14 days (or a documented interim mitigation) |
| **High** | Packet leaks location/identities contrary to policy; signing/verification bypass under realistic conditions | 3 business days | 30 days |
| **Medium** | DoS of the relay/verifier; metadata exposure beyond what the threat model documents | 5 business days | 90 days |
| **Low** | Hardening gaps, defense-in-depth, doc/UX issues with a security angle | best effort | next release |

A fix ships with a regression test and a published advisory (crediting the
reporter unless they prefer anonymity). The coordinated-disclosure flow is
exercised end to end (report → ack → fix → advisory) before v1.0.

## Supply chain

Dependencies are pinned and locked (`uv.lock`); GitHub Actions are pinned to
commit SHAs; the relay base image is pinned by digest; CI runs `pip-audit` and
CodeQL. Signed releases with build provenance and an SBOM are tracked for v1.0
(see the roadmap). Reports about the build or release path are welcome.
