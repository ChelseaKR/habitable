# Security policy

habitable is built for people under threat of retaliation. Its security is the
product, not a feature — so please report problems, and please do so privately
until they are fixed.

## Reporting a vulnerability

**Preferred:** use GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository (the **Security** tab → *Report a vulnerability*). This keeps
the report confidential and lets us coordinate a fix and advisory.

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

- This is alpha, concept-stage software. **Do not rely on it for real legal
  matters yet.** See *Honest limits* in `README.md`.
- Cryptography uses well-reviewed primitives via `cryptography` and standard
  RFC 3161 timestamping; we are not rolling our own ciphers. Reports of misuse of
  those primitives are in scope; theoretical breaks of the primitives themselves
  are out of scope here.
- The bundled development TSA (`DevTSA`) is explicitly **non-production** and is
  not a trusted timestamp source; that is by design, not a vulnerability.

## Supply chain

Dependencies are pinned and locked (`uv.lock`); GitHub Actions are pinned to
commit SHAs; CI runs `pip-audit` and CodeQL. Reports about the build or release
path are welcome.
