# Get involved — call for reviewers

> **Status: alpha / concept stage.** habitable is an offline-first,
> end-to-end-encrypted tool for tenants to document habitability problems as
> tamper-evident evidence. It is an **independent personal open-source project** by
> Chelsea Kelly-Reif, with **no external funding** and a **bus factor of one**. The
> machinery — the evidence spine, encryption, peer-to-peer sync, the standalone
> verifier, and a bilingual (EN/ES) web app with automated accessibility checks — is built and tested
> (`make verify` green, ~85% coverage). What it does not yet have is **outside eyes.**
> Until it does, **do not rely on habitable for a real legal matter.**

## Why this needs outside eyes

This is a tool that asks tenants under threat of retaliation to trust it with the
proof of their case — and "trust me" is exactly what such a tool should never ask. So
the project's posture is *verify, don't trust*: the design is documented and frozen,
the reviews are committed as artifacts, and the alpha caveat comes off only when
independent reviewers have checked the claims. That is the whole bargain, and it is
written down rather than restated here:

- **What's already prepared for you** — a frozen, hash-pinned threat-model baseline
  ([baseline **B1**](../audits/threat-model-baseline.md)), an
  [onboarding doc](../audits/onboarding.md) with scope tables and run instructions, the
  [audit-as-artifact](../audits/README.md) discipline, the
  [governance](../governance.md) model, and the honest
  [sustainability / bus-factor](../sustainability.md) account.
- **What removes the caveat** — the [v1.0 gate](../../ROADMAP.md#the-v10-gate-when-alpha-comes-off)
  in the roadmap names exactly the reviews recruited here. v1.0 is "not a feature
  count; it is a trust threshold," and an independent security + cryptographic review,
  a recorded human screen-reader pass, and an independent threat-model review are
  three of its required boxes. Nothing on this page is busywork: each role checks a box
  that keeps the project honestly labelled *alpha* until it is met.

The bus factor of one, the lack of funding, and the alpha label are stated plainly
because that honesty is the point — a tool for at-risk tenants has to say what it is
not yet, and external review is how it earns the right to drop the qualifier.

## Open roles at a glance

Three roles are recruited **here**. Each is a **fixed, small scope** so your volunteer
time is respected — a mini-engagement or a single recorded session, not an open-ended
commitment.

| Role | What you'd actually do | Time shape | Brief / intake |
| --- | --- | --- | --- |
| **Independent security + cryptographic auditor** | Check whether the code keeps its promises: vault-at-rest (scrypt-KEK + ChaCha20-Poly1305), X25519 sealed-box sync, Ed25519 signing, custody + fixity, the RFC 3161 path, and the standalone verifier. | A fixed-scope mini-engagement (e.g. ~2 weeks) | [role-auditor.md](role-auditor.md) · [offer a review](https://github.com/ChelseaKR/habitable/issues/new?template=reviewer-intake.yml) |
| **Accessibility tester who uses assistive technology** | A **recorded** NVDA + VoiceOver pass of `packet.html` and the local web app, in **English and Spanish**, against WCAG 2.2 AA. | One recorded session | [role-accessibility-tester.md](role-accessibility-tester.md) · [offer a pass](https://github.com/ChelseaKR/habitable/issues/new?template=reviewer-intake.yml) |
| **Independent threat-model reviewer** | Read [`threat-model.md`](../threat-model.md) against the frozen baseline B1: re-confirm or challenge the residual-risk list and the out-of-scope boundaries. | A short, bounded read | _brief in [onboarding §1](../audits/onboarding.md)_ · [offer a review](https://github.com/ChelseaKR/habitable/issues/new?template=reviewer-intake.yml) |

**Two more roles, with their own briefs** (currently scoped to **California**): a
**housing/tenant lawyer** to review the "not legal advice / no admissibility guarantee"
framing ([role-legal-reviewer.md](role-legal-reviewer.md)), and a **tenant-union or
legal-aid pilot partner** ([role-pilot-partner.md](role-pilot-partner.md)). Both are
external gate items on the
[v1.0 gate](../../ROADMAP.md#the-v10-gate-when-alpha-comes-off); use the **same**
[intake form](https://github.com/ChelseaKR/habitable/issues/new?template=reviewer-intake.yml)
and pick the matching role.

## Pick your path — one click to the right form

Interest should convert to a filed issue in one click, with no meeting. Pick the line
that fits you; the intake form captures fit and scope so the maintainer can say yes/no
async.

- **You audit security / cryptography** → file the
  [security + crypto reviewer form](https://github.com/ChelseaKR/habitable/issues/new?template=reviewer-intake.yml).
- **You use assistive technology and can record a screen-reader pass** → file the
  [accessibility reviewer form](https://github.com/ChelseaKR/habitable/issues/new?template=reviewer-intake.yml).
- **You model threats for at-risk or surveilled communities** → file the
  [threat-model reviewer form](https://github.com/ChelseaKR/habitable/issues/new?template=reviewer-intake.yml).

The forms route interest; they do not duplicate scope. The procedural depth — exact
scope, run instructions, synthetic-data rules, how findings get recorded — lives in
[onboarding.md](../audits/onboarding.md).

## What we can — and cannot — offer

Set expectations up front, so no one needs a call to ask "what's in it for me / how big
is this":

- **No payment, no bounty.** There is no paid bug bounty (see
  [SECURITY.md](../../SECURITY.md)) and no external funding behind the project (see
  [sustainability §4](../sustainability.md)). This is volunteer / pro-bono work.
- **Credit by default, anonymity on request.** Reviews are credited in
  [`docs/audits/`](../audits/) and the release notes by default; ask and we keep you
  anonymous.
- **Framing that fits how reviewers actually work** — pro-bono, a security
  clinic, an academic program, or an OSS-audit program are all welcome shapes; the
  intake form lets you say which.
- **A fixed, small scope.** A mini-engagement or one recorded session, bounded so your
  time is respected — not an open-ended commitment.
- **Public, diffable credit.** Because reviews are committed
  [as artifacts](../audits/README.md), your work is a citable, permanent part of the
  record rather than a line in a thank-you.

## How your review becomes a permanent artifact

habitable runs **audit-as-artifact**: a review is not a private assurance, it is a
committed file in version control. That means:

- Your review is **citable** and **diffable across releases** — a given release tag
  carries the audit state that was true for it. See
  [`docs/audits/README.md`](../audits/README.md) for the mechanics and
  [§4 of onboarding](../audits/onboarding.md) for how findings are recorded.
- For accessibility, your pass feeds the
  [Accessibility Conformance Report](../accessibility/ACR.md) and the per-release AT
  cadence.
- Most concretely: **your committed review is what removes the alpha caveat.** It is
  not symbolic. It checks a box on the
  [v1.0 gate](../../ROADMAP.md#the-v10-gate-when-alpha-comes-off).

## Before you start — the 60-second readiness check

A quick self-qualify before you file. If these are true, you're ready; the full run
instructions are in [onboarding.md](../audits/onboarding.md) (we don't repeat them
here):

- [ ] You can run `uv sync --all-extras` and get `make verify` **green** locally
      (ruff, `mypy --strict`, pytest).
- [ ] You've skimmed the frozen [baseline B1](../audits/threat-model-baseline.md) and
      the [out-of-scope list (threat model §5)](../threat-model.md) — we're not asking
      you to disprove claims the project never makes.
- [ ] You'll evaluate using `habitable demo` **synthetic data only** — never real
      tenant data, ever.

## Security disclosures go elsewhere

**This page is for *offering* to review.** It is **not** for reporting a vulnerability.

> If you have found an actual, unfixed weakness, **stop** and use GitHub's
> [private vulnerability reporting](https://github.com/ChelseaKR/habitable/security/advisories/new)
> per [SECURITY.md](../../SECURITY.md). Never put exploit detail in a public issue or an
> intake form. The reviewer forms include a required acknowledgment to this effect.

## Contributors welcome too — help lower the bus factor

You don't have to be a reviewer to help. The clearest mitigation for a bus factor of one
is more hands on the code and docs:

- Read [CONTRIBUTING.md](../../CONTRIBUTING.md) for setup, the `make verify` gate, and
  what a good change looks like.
- Good starter areas: **docs** (e.g. a usage guide for the standalone verifier, a
  `TRANSLATING.md` for localization, a support policy), **tests** (e.g. a guard that the
  Apache-2.0 verifier stays import-isolated from AGPL siblings), and
  **verifier-tooling**.
- Ground rules by reference: **DCO sign-off** (`git commit -s`), keep the verifier
  independent of vault/sync, and **synthetic data only** — see
  [CONTRIBUTING.md](../../CONTRIBUTING.md) and the
  [open issues](https://github.com/ChelseaKR/habitable/issues) to claim or propose a starter task (or use the intake
  form above and pick "Other").

## How to reach the maintainer — no meeting required

Async-first, by default:

1. **Preferred:** file the matching issue form above. That's the fastest path to a
   yes/no.
2. **Scoping questions** that aren't yet a filed offer: open a
   [GitHub Discussion](https://github.com/ChelseaKR/habitable/discussions).
3. **A call is opt-in**, only after scope is agreed in-thread — never the entry point.

This is a solo volunteer effort, so a realistic cadence: acknowledgment within a few
business days (echoing the [SECURITY.md](../../SECURITY.md) ack target). Silence isn't a
no — it's a bus factor of one, which is exactly what your help fixes.
