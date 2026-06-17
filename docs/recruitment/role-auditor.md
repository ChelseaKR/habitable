# Recruiting: independent security + cryptographic auditor

> **Status: alpha / concept-stage.** habitable is not to be relied on for a real legal
> matter yet. Removing that caveat is gated on exactly the external reviews this brief
> recruits for. This document is the scoped brief and outreach kit for the **independent
> security + cryptographic auditor** role.
>
> This is an **independent, personal, unfunded** open-source project (AGPL-3.0-or-later;
> the verification subset is additionally Apache-2.0). Single maintainer, **bus factor of
> one**. We have no cash for an audit today — the funding paths below are exactly how we
> would pay for, or get donated, the work. We would rather say that plainly than pretend
> otherwise.

habitable is a court-ready, offline-first, end-to-end-encrypted tool that lets tenants
document habitability problems as tamper-evident evidence. Its security *is* the product:
the design promise is "verify, don't trust." We are asking an external reviewer to check
whether the code keeps the promises the threat model makes — and to tell us, in public,
where it does not.

**Everything here runs offline on synthetic data. No real tenant data is needed, wanted,
or ever committed.** Evaluation is via `habitable demo` only.

---

## 1. Why this needs an external eye

We have done what a careful solo maintainer can do — a frozen threat model, a maintainer
re-review, a self-review, property-based and tamper-detection tests at ~86% coverage, and a
standalone verifier — but **no third-party security audit has been performed**, and a
self-review is not a substitute for one. The whole point of the alpha caveat is that an
independent reviewer has not yet confirmed the claims. This role removes that gap.

Concretely, an external audit lets us:

- validate the stated cryptographic and tamper-evidence claims (or refute them);
- confirm the residual-risk list in threat-model baseline **B1** is honest and complete;
- give tenants, unions, and legal-aid orgs a citable reason to trust the tool — committed
  in-repo under `docs/audits/`, per our audit-as-artifact discipline.

---

## 2. Scope of work — what to review

**Start here:** the reviewer onboarding doc — [`docs/audits/onboarding.md`](../audits/onboarding.md)
— has the run instructions, the synthetic-data rule, and the per-role scope table. Then the
frozen threat-model baseline — [`docs/audits/threat-model-baseline.md`](../audits/threat-model-baseline.md)
(**B1**) — and the threat model it pins, [`docs/threat-model.md`](../threat-model.md).

The audit target, in priority order:

1. **The cryptography and whether the code keeps its promises.** ChaCha20-Poly1305
   vault-at-rest with an scrypt-wrapped key; Ed25519 signing; X25519 sealed-box E2E sync;
   SHA-256 fixity. We have written **no novel cryptography** — primitives come from the
   `cryptography` library — so the review we want is **correct construction and use**: key
   derivation and wrapping, AEAD nonce/key handling, signing/verification flow, the
   sealed-box sync path, and anywhere a primitive could be misapplied. Theoretical breaks
   of the primitives themselves are out of scope (see §3).

2. **The residual risks in baseline B1.** B1 lists seven residual risks the project
   *states it does not protect against* (hostile keyholder rewriting the local custody
   chain before an external anchor exists; relay connection metadata; the limits of the
   duress-safe state; lost-key data loss; what a timestamp does and does not prove;
   endpoint compromise; no admissibility guarantee). We ask the reviewer to **confirm each
   is stated honestly and completely, and to surface any we missed.** A residual risk we
   failed to list is one of the most valuable things you can send us.

3. **The standalone verifier.** Offered under **Apache-2.0** as the "verification subset"
   (`src/habitable/verify.py` plus the pure helpers it relies on — see
   [`NOTICE`](../../NOTICE)) precisely so it can be embedded and audited as an independent
   artifact. The soundness question: can the verifier be made to **accept evidence it
   should reject, or reject evidence it should accept** — including backdating, a swapped
   sealed original, or a broken/forged custody chain that still verifies as intact.

4. **The hash-linked chain of custody and RFC 3161 timestamping.** SHA-256 fixity,
   the hash-linked custody chain, RFC 3161 trusted timestamping, and **archive
   re-timestamping** (keeping an existence proof durable past an authority's certificate or
   hash algorithm aging out). The interesting attack surface is tamper-evidence: any way to
   alter a sealed original, the custody chain, or a timestamp token such that
   `habitable verify` still reports the packet as intact.

5. **(Lower priority, if budget allows)** the local web app and the produced `packet.html`
   as an application attack surface (the relay stores only ciphertext sealed to recipient
   keys plus aggregate passthrough counts). The deep crypto/verifier review above is the
   priority; this is a stretch goal or a place a lighter-weight reviewer can help.

---

## 3. Out of scope

- **Theoretical breaks of the underlying primitives.** ChaCha20-Poly1305, Ed25519, X25519,
  scrypt, SHA-256, and RFC 3161 are taken as sound. Misuse of them is in scope; cracking
  them is not.
- **The adversaries the threat model explicitly excludes:** state-level adversaries, a
  targeted device-exploit attacker, and a capable forensic lab. The in-scope adversary is
  a retaliating landlord and their lawyer, device seizure, subpoena of third parties, and
  someone contesting the evidence (threat model §1).
- **The bundled development TSA (`DevTSA`)**, which is explicitly **non-production** and
  always reports an untrusted chain. That it is not a trusted timestamp source is by
  design, not a finding.
- **Admissibility / legal-weight questions** — handled by a separate housing-lawyer review,
  not this role.
- **Accessibility** — handled by a separate assistive-tech reviewer, not this role.
- **Real tenant data, ever.** Do not load real data to evaluate the tool. Evaluation is on
  synthetic data via `habitable demo` only.

---

## 4. What's provided

- **A frozen, hash-pinned baseline (B1)** so reviewer and maintainer are talking about the
  *same* threat model, and any later drift is detectable —
  [`docs/audits/threat-model-baseline.md`](../audits/threat-model-baseline.md).
- **Reviewer onboarding** with one-command setup (`uv sync --all-extras`), the full quality
  gate (`make verify`), integration/a11y/coverage targets, and the end-to-end synthetic
  demo + verify flow — [`docs/audits/onboarding.md`](../audits/onboarding.md).
- **The threat model, architecture, evidence method, key management, and a DPIA-style
  privacy statement** — [`docs/threat-model.md`](../threat-model.md),
  [`docs/ARCHITECTURE.md`](../ARCHITECTURE.md), [`docs/evidence-method.md`](../evidence-method.md),
  [`docs/key-management.md`](../key-management.md), [`docs/privacy.md`](../privacy.md).
- **A reproducible target.** `uv` pins Python 3.14; `make verify` runs ruff, `mypy --strict`,
  and pytest (~86% coverage, including property-based convergence tests and tamper-detection
  tests against clean, altered, and chain-broken fixtures). `make integration` exercises real
  public RFC 3161 authorities (DigiCert, FreeTSA).
- **The standalone verifier** as a bounded, independently-licensed (Apache-2.0) artifact —
  a small, self-contained thing to audit first.
- **A coordinated-disclosure path** for anything found mid-review —
  [`SECURITY.md`](../../SECURITY.md) (GitHub private vulnerability reporting).
- **A responsive single maintainer.** Bus factor is one, but that one person wrote all of
  it and can turn scoping questions around quickly.

---

## 5. Expected deliverable

An **audit report committed to the repository under `docs/audits/`** (audit-as-artifact:
reviews live in version control so anyone can diff them across releases, not as private
assurances). We ask for:

- **Findings** with severity, reproduction on synthetic data, impact, and suggested
  remediation, judged against the security contract in [`SECURITY.md`](../../SECURITY.md)
  (confidentiality at rest / in transit, tamper-evidence, unintended disclosure, verifier
  soundness).
- **An explicit verdict on the B1 residual-risk list** — each item confirmed honest/complete
  or corrected, plus any risk we omitted.
- A **scope/methodology statement** and the **commit/tag reviewed**, so the report is pinned
  to a specific release.

Unfixed vulnerabilities go through coordinated disclosure first ([`SECURITY.md`](../../SECURITY.md));
the public write-up under `docs/audits/` lands once a fix or an accepted-risk rationale exists.
Auditors are credited (unless they prefer anonymity). We are glad to support the auditor
**publishing their own report** as well.

---

## 6. How this gets paid for (three paths)

We have **no cash for an audit today**, so the brief includes how it would be funded. We are
pursuing the grant and pro-bono paths *in parallel*; the paid path is the shortlist if money
appears (a grant, a sponsor, or a donor). All program facts below were researched **2026-06-17**;
items we could not fully verify are marked.

### Path A — Grant / facilitated (best realistic free path)

- **OTF (Open Technology Fund) — Security Lab audit.** OTF directly facilitates and *pays
  for* independent third-party audits (secure code review, cryptographic review, pen
  testing, architecture review, validation of stated privacy/security claims). The project
  gets the audit, not cash. Projects that are **not** otherwise OTF-funded may apply
  specifically for an audit, via the project-side form at **apply.opentech.fund/security-lab/**.
  *How it would work for us:* lead with the threat model and baseline B1 and the fact that
  the alpha caveat is gated on exactly this review; emphasize the **at-risk-user + privacy-
  tool** angle (tenants facing landlord retaliation). **[Uncertain]** OTF's eligibility lens
  is "internet freedom" / repressive-environment users — habitable protecting at-risk *US*
  tenants is defensible but not a slam-dunk fit, and this is the chief risk for this channel.
  **[Uncertain]** Current queue depth / turnaround not verified; plan ~3–6+ months end to
  end. *(Note: a separate March 2026 RFP at the same Lab recruited auditors, not projects —
  not the form we want.)*

- **OSTIF (Open Source Technology Improvement Fund) — facilitated audit.** A non-profit that
  runs the whole audit lifecycle for a FOSS project: scoping, selecting a reputable firm
  (Quarkslab, Shielder, Ada Logics, etc.), managing the engagement, publishing the report —
  and **helping the project find/split funding** (they partner with ~10 funders incl.
  OpenSSF and the Sovereign Tech Agency Bug Resilience Program). *How it would work for us:*
  email **contactus@ostif.org** with the project, baseline B1, and our funding situation
  (unfunded, bus-factor-1, alpha); do their pre-audit self-checks first; ask whether they can
  slot us into a funded program or help raise the cost. This is the natural facilitator for a
  single-maintainer crypto-heavy project that cannot run an RFP alone. **[Uncertain]** OSTIF
  prioritizes critical/widely-deployed infrastructure, so an alpha solo tool may not be
  top-of-queue and may need to bring its own funder; whether they take it unprompted is the
  key unknown. ("Get an Audit": ostif.org/get-an-audit/.)

- **GitHub Secure Open Source Fund.** Cohort-based program ($5.5M committed) combining direct
  financial support + a ~3-week security education/mentorship program; funds can go toward an
  audit, plus tooling and Azure credits. *How it would work for us:* habitable already shows
  the security-maturity signals GitHub favors (CodeQL, pip-audit, Dependabot, SHA-pinned CI,
  signed-provenance + SBOM releases, ~86% coverage, a `make verify` gate); the narrative is "get
  to an external crypto/security review and remove the alpha caveat." Apply via the fund page
  with a written application, an interview, and a 45-second video pitch. **[Uncertain]** This is
  primarily a maintainer security-uplift program with funding, **not** a pure pay-a-third-party-
  audit grant — it complements rather than replaces an independent audit; exact 2026 cohort dates
  (a next cohort was noted ~September) and solo-alpha eligibility not confirmed.

- **Monitor, do not apply today:**
  - **NLnet / NGI Zero.** EUR 5k–50k grants, and grantees can access free security *and*
    accessibility audits. **[Uncertain fit]** The broad NGI Zero Commons Fund's 13th and
    **final** call closed **2026-06-01**; the only funds open now (NGI Taler, NGI Fediversity;
    deadline **2026-08-01**) are poor thematic matches for a tenant evidence tool, and the audit
    support is reserved for already-NGI-funded projects. Watch for a future broad NGI0 call.
  - **Sovereign Tech Fund / Agency (Bug Resilience Program).** **[Uncertain fit]** EUR 50k+
    minimum and a "critical base infrastructure" bar habitable almost certainly does not clear
    *directly*; its realistic value is **indirect** — as the funder behind an OSTIF engagement.
  - **Mozilla MOSS "Secure Open Source" track.** **[Unavailable]** On indefinite hiatus and
    not accepting applications since 2020; listed only for completeness.

### Path B — Pro bono / volunteer review

- **OSTIF as facilitator (even without a grant).** Closest thing to free expert audit
  *project management* for a solo maintainer — they will scope, help fundraise, select a
  firm, and publish, even if we do not already hold a grant. (Same contact as above:
  contactus@ostif.org.)
- **Consortium of Cybersecurity Clinics** (university student clinics; Google-funded
  network — cybersecurityclinics.org). Pro-bono vulnerability/risk assessments for
  under-resourced public-interest orgs. *How it would work:* contact a member clinic
  directly, framing habitable as a public-interest tool for at-risk tenants. **[Uncertain]**
  Most clinics do org-level/vuln-assessment work, **not** deep primitive-level crypto review —
  best as a complementary review or a warm-up, or aimed at the web-app / `packet.html` surface.
- **OWASP chapters + volunteer researcher communities** (owasp.org). Informal review,
  threat-model feedback, code review, and warm introductions to auditors. *How it would
  work:* post baseline B1 and the standalone verifier as a concrete, bounded review target.
  **[Uncertain]** Advisory, not a substitute for an independent audit; depth/availability vary.
- **Academic applied-crypto / security labs (e.g. Citizen Lab and university groups —
  citizenlab.ca).** Some publish on privacy/security tools for at-risk populations. *How it
  would work:* cold outreach to specific researchers with a tight scope — the
  custody-chain + timestamping + verifier story is the most academically interesting angle.
  **[Uncertain / speculative]** No intake process, no confirmed interest, long lead times.

### Path C — Paid specialist firm (shortlist if funded)

These are the firms to put on an RFP shortlist if a grant, sponsor, or donor materializes.
**[Uncertain]** Current pricing not verified for any; premium unless noted.

- **Trail of Bits** — dedicated cryptography service + open-source program; top-tier for the
  Ed25519 / X25519 / ChaCha20-Poly1305 / RFC 3161 design. (trailofbits.com)
- **Cure53** — Berlin; deep audits of crypto/privacy-critical software with thorough public
  reports; strong fit for both the crypto design and the web-app / `packet.html` surface.
  (cure53.de)
- **Radically Open Security** — Amsterdam; world's first **not-for-profit** security
  consultancy, channels ~90% of profits to NLnet; mission-aligned and often more affordable —
  a strong budget shortlist candidate. (radicallyopensecurity.com)
- **Quarkslab** — France; research-driven, already plugged into the OSTIF pipeline.
  (quarkslab.com)
- **NCC Group** — established firm with a dedicated cryptography-services practice and a long
  public open-source audit history; enterprise process/pricing. (nccgroup.com)
- **Shielder / Ada Logics** — smaller specialist firms that take OSTIF-facilitated FOSS
  engagements; often a better budget/scale match for a small project, still publishable
  reports. **[Uncertain]** Confirm advanced-crypto depth during RFP scoping. (shielder.com)

---

## 7. Outreach email template — auditor / pro-bono reviewer

> **Subject:** Independent crypto/security review of an open-source tenant-evidence tool (alpha, FOSS)
>
> Hi [name],
>
> I maintain **habitable** (github.com/ChelseaKR/habitable, AGPL-3.0; the verifier subset is
> also Apache-2.0) — an offline-first, end-to-end-encrypted tool that lets tenants document
> habitability problems as tamper-evident evidence, so they have something credible if they
> face landlord retaliation. It is a public-interest, single-maintainer project with **no
> funding**, and it is **alpha**: I tell people not to rely on it for a real legal matter yet,
> and I will not lift that caveat until an independent reviewer has checked the claims.
>
> I am looking for an **independent security + cryptographic reviewer**. The crypto is standard
> primitives via `cryptography` (ChaCha20-Poly1305 at rest, Ed25519, X25519 sealed-box sync,
> RFC 3161 timestamping, SHA-256 fixity, a hash-linked custody chain, a standalone verifier) —
> so the review I want is **correct construction/use and tamper-evidence soundness**, not
> primitive-breaking.
>
> I have tried to make this cheap to pick up: a **frozen, hash-pinned threat-model baseline**
> with an explicit residual-risk list to confirm or refute, a one-command setup, a `make verify`
> gate (ruff, mypy --strict, pytest ~86% cov), and **synthetic-data-only** evaluation via
> `habitable demo` — no real tenant data, ever. The reviewer onboarding is at
> docs/audits/onboarding.md and the baseline at docs/audits/threat-model-baseline.md.
>
> Findings would be committed in-repo under docs/audits/ (audit-as-artifact), and you are
> welcome to publish your own report. Would you be open to a look — or to pointing me toward the
> right channel?
>
> Thank you for considering it,
> Chelsea Kelly-Reif

---

## 8. Outreach email template — grant program (facilitated audit)

> **Subject:** Audit request — habitable, an open-source privacy tool for at-risk tenants
>
> Hello [OTF Security Lab / OSTIF / program] team,
>
> I am writing to request a **facilitated independent security + cryptographic audit** of
> **habitable** (github.com/ChelseaKR/habitable), an open-source (AGPL-3.0; verifier subset
> Apache-2.0), offline-first, end-to-end-encrypted tool that lets tenants document habitability
> problems as **tamper-evident evidence**. Its users are an **at-risk population** — tenants who
> may face retaliation from landlords for documenting conditions — and the project's entire value
> rests on **stated privacy and security claims** that have **not yet been independently
> validated**: ChaCha20-Poly1305 vault-at-rest, Ed25519 signing, X25519 sealed-box E2E sync,
> RFC 3161 timestamping with archive re-timestamping, a hash-linked chain of custody, and a
> standalone verifier.
>
> It is an **unfunded, single-maintainer (bus-factor-1), alpha** project, which is exactly why I
> am coming to you rather than running an RFP myself. I have prepared the engagement to be
> low-friction to scope: a **frozen, hash-pinned threat-model baseline (B1)** with an explicit
> residual-risk list for the auditor to confirm or refute (docs/audits/threat-model-baseline.md),
> a reviewer onboarding doc (docs/audits/onboarding.md), the full threat model
> (docs/threat-model.md), and **synthetic-data-only** evaluation via `habitable demo`. Quality
> signals already in place: CodeQL, pip-audit, Dependabot, SHA-pinned CI, signed-provenance + SBOM
> releases, and a `make verify` gate (ruff, mypy --strict, pytest ~86% coverage).
>
> The alpha "do not rely on this yet" caveat is **gated on exactly this review**. Could habitable
> be considered for a [Security Lab audit / facilitated engagement], or could you point me to the
> right intake? I am happy to complete any application form and to do the pre-audit self-checks
> first.
>
> With thanks,
> Chelsea Kelly-Reif — maintainer, habitable

---

*Program facts above were researched 2026-06-17 and are marked **[Uncertain]** where current
windows, queue depth, pricing, or eligibility for an alpha single-maintainer project could not be
fully verified. Roles 3 (housing/tenant lawyer) and 4 (pilot partner) are recruited separately.*
