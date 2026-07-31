# Sustainability & bus-factor

> **Status: alpha / concept stage.** A tool that asks tenants under threat to depend on it
> owes them an honest account of whether it will still be there — and, just as important,
> whether their evidence survives even if the project does not. This statement covers the
> maintenance model, dependency and security upkeep, funding, and the **bus-factor minimum**:
> what a successor needs, and the guarantee that already-produced packets remain verifiable
> independently of this project's continued existence.

## 1. The durability guarantee that does not depend on us

The most important sustainability property is designed in, not promised:

- **Produced packets are self-contained and independently verifiable.** A packet carries its
  signed `bundle.json`, the media, the RFC 3161 timestamp tokens (and archive chain), and an
  accessible `packet.html`. Verification re-derives every hash and checks every signature with
  **no call back to this project and no server.**
- **The verifier is offered under Apache-2.0** (the "verification subset", an additional
  permission under AGPL §7 — see [`../NOTICE`](../NOTICE)). A court, inspector, or legal-aid
  group can embed and redistribute verification in their own software. **Even if this
  repository disappears, anyone holding the verifier can still check a packet**, and the
  evidence method ([`evidence-method.md`](evidence-method.md)) is documented well enough to
  re-implement.
- **The packet format and verification protocol are versioned as long-lived contracts**
  ([`governance.md`](governance.md)): older packets must keep verifying; changes are additive.

So the floor on sustainability is high: a tenant's exported evidence does not rot if funding
or maintenance stops.

## 2. Maintenance model

- **Independent personal open-source project** by Chelsea Kelly-Reif, on the author's own time
  and equipment — not a funded product and not affiliated with any employer or client
  ([`governance.md`](governance.md)).
- **Maintainer-led** today, with [`governance.md`](governance.md) committing to share authority
  as sustained contributors arrive.
- **`make verify` is the merge and release gate** (ruff, mypy --strict, full tests incl.
  tamper-detection and CRDT-convergence, plus enforced application and protected-core
  coverage floors); accessibility is a merge-blocking CI
  gate. Quality does not depend on remembering to check — red does not merge or release.

## 3. Dependencies & security upkeep

- **Pinned and locked:** [`uv.lock`](../uv.lock) pins the Python toolchain (3.14) and all deps;
  the relay base image is pinned by digest; GitHub Actions are pinned to commit SHAs.
- **Automated surveillance:** `pip-audit` and CodeQL run in CI on every change; Dependabot
  proposes dependency bumps; a public-TSA integration job guards real RFC 3161 interop.
- **Small, well-reviewed dependency surface** built on the `cryptography` library and standard
  formats — no novel cryptography to maintain (see [`audits/README.md`](audits/README.md)).
- **Coordinated disclosure** via [`../SECURITY.md`](../SECURITY.md); findings are committed as
  artifacts under [`audits/`](audits/).

## 4. Funding & cost to run

habitable is **free software with no operating cost imposed on users**: it runs locally, with
no server the project must pay to keep online. Optional infrastructure (a sync relay) is
**self-hostable** by a union, and public RFC 3161 authorities are free to query. There is no
hosted service whose shutdown would strand users. The project currently has **no external
funding**; if that changes it will be disclosed in [`governance.md`](governance.md) and
[`../NOTICE`](../NOTICE), and it does not alter the no-operator-holds-data architecture.

## 5. Bus-factor minimum

The current bus factor is **one**. That is acceptable for alpha *only because* of the §1
durability guarantee — users' produced evidence does not depend on the maintainer being
reachable. The minimum a successor (or a fork) needs to keep the project itself alive is
deliberately small and entirely in the repository:

- **How to build, test, and gate:** [`../README.md`](../README.md), [`../Makefile`](../Makefile)
  (`make verify`), and `uv sync` — reproducible from a clean checkout with only `uv` + `git`.
- **How to release:** [`releasing.md`](releasing.md) — tagging, SBOM, signed provenance.
- **Why the design is the way it is:** the ADRs in [`adr/`](adr/), the
  [threat model](threat-model.md) and its frozen [baseline](audits/threat-model-baseline.md),
  and [`evidence-method.md`](evidence-method.md).
- **What must never be weakened:** the hard rules / invariants in the README and
  [`governance.md`](governance.md). A successor inherits these as constraints, not options.
- **Secrets a successor would need are NOT in the repo and are not the project's to hold:** no
  maintainer key grants access to any union's data (by design there is none), and no signing
  secret is required to *verify* packets. Release-signing identity and the GitHub/PyPI publishing
  rights are the only handover items, and they are operational, not data-bearing.

**What is explicitly NOT a single point of failure:** a user's evidence (self-verifying
packets), the ability to verify (Apache-2.0 standalone verifier), and the ability to rebuild
the tool (documented method + ADRs + locked deps). Losing the maintainer would stall *new
development*; it would not invalidate anyone's evidence or lock anyone out of their data.

## 6. Honest limits

Sustainability is a posture, not a promise. There is no SLA, no guaranteed response time, and
no commitment that the project reaches v1.0. **Until the alpha caveat is removed**, habitable
should not be relied on for a real matter regardless of how durable the format is. What this
document commits to is that the things that *would* harm a user if the project lapsed — their
evidence, their ability to verify it, their access to their own data — are designed not to
depend on the project's survival.
