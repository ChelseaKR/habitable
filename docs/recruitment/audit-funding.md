<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Audit funding playbook — getting habitable an independent security & crypto review

> **Status: working playbook, alpha project.** habitable is an independent,
> unfunded, bus-factor-1 FOSS project. The alpha caveat in the
> [README](../../README.md) and [threat model](../threat-model.md) stays until,
> among other things, an **independent security + cryptographic audit** is done.
> This document is how we go get that audit paid for. It covers all three paths —
> **grants**, **pro-bono**, and **paid** — and ends with reusable application and
> RFP drafts.
>
> **Scope.** This file covers recruiting/funding the **security & cryptographic
> auditor** (recruitment role 1) and, where a channel bundles it, the
> **accessibility tester** (role 2). The **housing/tenant lawyer** (role 3) and the
> **pilot partner** (role 4) are handled in separate recruitment docs and are out
> of scope here.
>
> **Research provenance.** The program facts below come from a funding-research pass
> dated **2026-06-17**. Anything that could move between then and when you actually
> hit *send* is tagged **`[RE-VERIFY]`**. Treat those as "check the live page first."
> See [§7 Re-verification checklist](#7-re-verification-checklist-do-this-before-sending-anything).

---

## 0. The thirty-second version

1. **Pursue the two channels actually built for us, in parallel, first:**
   **OTF Security Lab** (free, third-party audit they pay for) and **OSTIF**
   (free facilitation + fundraising for the audit). Both are designed for an
   unfunded, single-maintainer, crypto-heavy FOSS tool.
2. **Add GitHub Secure Open Source Fund** as a strong, lower-friction parallel bet —
   our existing security posture is exactly what it rewards — accepting that it is a
   cohort/uplift program whose money *goes toward* an audit rather than buying one
   outright.
3. **Treat NLnet, Sovereign Tech, and Mozilla MOSS as "monitor / indirect," not
   "apply today"** — eligibility mismatches are real and documented below.
4. **Keep a costed paid-firm RFP ready** so that if a funder (or OSTIF) says "yes,
   we'll fund it," we can scope and award within days, not months.
5. **Re-verify every program fact tagged `[RE-VERIFY]`** before sending.

The single asset that makes every one of these cheaper is already in the repo:
the frozen, hash-pinned **threat-model baseline B1**
([`../audits/threat-model-baseline.md`](../audits/threat-model-baseline.md)) plus the
reviewer **onboarding doc** ([`../audits/onboarding.md`](../audits/onboarding.md)).
Lead with those everywhere.

---

## 1. Comparison: grant vs pro-bono vs paid

| Dimension | **Grant / facilitated** (OTF, OSTIF, GitHub SOS, NLnet…) | **Pro-bono** (uni clinics, OWASP, academic labs) | **Paid firm** (Trail of Bits, Cure53, ROS, Quarkslab…) |
| --- | --- | --- | --- |
| **Cash out of our pocket** | $0 (they pay the auditor or pay us) | $0 | ~$30k–$200k for a real crypto+app audit (OSTIF's cited range) `[RE-VERIFY pricing]` |
| **Our effort to land it** | Medium–high: application, interview/video, scoping calls; eligibility framing matters | Low–medium per contact, but high volume of cold outreach; opportunistic | Low to *get a quote*; the cost is money, not effort, once funded |
| **Time application → report** | Long: ~3–6+ months end to end (intake + scope + auditor assignment + audit window) | Variable / unpredictable; can be a semester (clinics) or indefinite (labs) | Fast once funded: weeks to a few months for the engagement itself |
| **Certainty of landing it** | Medium. OTF's "internet-freedom" lens and OSTIF's "critical/widely-used" bias are the chief risks for a small alpha tool | Low–medium. Reachable, but depth on advanced primitives is the gap | High *if funded* — it's a contract |
| **Depth / credibility of result** | High (OTF/OSTIF route to top firms) to high-uplift (GitHub SOS is education+funding) | Usually **shallow on crypto**: org-level / vuln-assessment / web-surface, not Ed25519/X25519/RFC-3161 primitive review | Highest and most citable; publishable report |
| **Publishability** | Usually yes (OTF/OSTIF publish reports) | Sometimes (labs publish; clinics often don't) | Yes — that's the point |
| **Best use for habitable** | **Primary path.** Get the deep crypto+app audit paid for | **Complement / warm-up.** Web-app & `packet.html` surface; a second set of eyes before the deep review | **The thing the grant pays for.** Keep an RFP ready to execute on funding |

**Strategy that falls out of the table:** run **grant + pro-bono in parallel**
(they don't conflict and the pro-bono breadth can de-risk the paid scope), and keep
the **paid RFP costed and ready** so a "yes, funded" converts immediately. Reserve
the *deep cryptographic* review for an OTF/OSTIF-facilitated or paid specialist firm;
use pro-bono channels for breadth and the web-app/`packet.html` attack surface.

---

## 2. Per-program application checklist

Programs are ordered by **realistic fit for habitable today**, best first. Each has a
one-line verdict, the concrete steps, what to attach, and the honest fit risk.

### 2.1 OTF — Open Technology Fund, Security Lab (FREE audit) — **PRIMARY**

**Verdict:** Best-targeted free audit channel. They contract and pay an independent
auditor; we receive the audit, not cash. Projects that are *not* otherwise OTF-funded
may apply specifically for an audit.

- [ ] Open the **project-side audit application** at `apply.opentech.fund/security-lab/` `[RE-VERIFY URL + that project-side intake is open]`
- [ ] Lead with the **threat model** ([`../threat-model.md`](../threat-model.md)) and **baseline B1** ([`../audits/threat-model-baseline.md`](../audits/threat-model-baseline.md))
- [ ] State plainly that **the alpha caveat is gated on exactly this review** (a precondition on the [v1.0 gate](../../ROADMAP.md#the-v10-gate-when-alpha-comes-off))
- [ ] **Lean hard into the at-risk-user + privacy-claim-validation angle:** tenants documenting habitability problems who face **landlord retaliation**; the tool's job is tamper-evidence under an adversary. This is the framing that answers OTF's "internet freedom" lens.
- [ ] List the specific stated claims to validate (ChaCha20-Poly1305 at rest, scrypt-wrapped key, Ed25519 signing, X25519 sealed-box sync, RFC 3161 timestamping + archive re-timestamping, SHA-256 fixity, hash-linked custody chain, standalone verifier)
- [ ] Point to synthetic-data-only evaluation via `habitable demo` (no real tenant data, ever) and the onboarding doc
- [ ] Note expected turnaround and **do not** confuse this with the **March 2026 RFP that recruited auditors, not projects**

**Fit risk (state it, don't hide it):** OTF frames around *internet-freedom /
repressive-environment* users. A domestic US tenant tool is a **defensible but not
slam-dunk** fit. Mitigation = the at-risk-user + retaliation + privacy-tool framing
above. **Timeline:** rolling intake; plan **3–6+ months** end to end. **Confidence
in the facts:** high that the project-side form exists; the eligibility lens is the
real uncertainty. `[RE-VERIFY queue depth / turnaround]`

### 2.2 OSTIF — Open Source Technology Improvement Fund (FREE facilitation + fundraising) — **PRIMARY**

**Verdict:** The natural facilitator for a bus-factor-1 maintainer who can't run an
RFP alone. They scope, pick a reputable firm (Quarkslab, Shielder, Ada Logics, …),
run the engagement, publish the report — and help **find/split the funding** (Linux
Foundation/OpenSSF, Sovereign Tech Bug Resilience, CNCF, ~10 funders).

- [ ] Do their **pre-audit self-checks** (best-practices guide) first — we already pass much of it: `make verify` gate, CodeQL, pip-audit, Dependabot, SHA-pinned CI, SBOM+provenance releases
- [ ] Read the **"Get an Audit"** page: `ostif.org/get-an-audit/` `[RE-VERIFY page + intake]`
- [ ] Email **`contactus@ostif.org`** (use the sponsorship/`info@` contact for the funding conversation) `[RE-VERIFY addresses]`
- [ ] Be upfront about our situation: **unfunded, bus-factor-1, alpha** — and ask directly whether they can **slot habitable into a funded program** (e.g. Sovereign Tech **Bug Resilience Program**, which funds audits *through* OSTIF) **or help raise/split** the cost
- [ ] Attach **baseline B1** and the **onboarding doc** to make scoping cheap (that's literally why they exist)
- [ ] Give them a scoped target list (the standalone **verifier** and the crypto design are the cleanest bounded units)

**Fit risk:** OSTIF historically prioritizes **critical / widely-deployed**
infrastructure (OpenSSL, Kubernetes, git). A small alpha tool may not be top-of-queue
and **may need to bring its own funder** — which is exactly why the Sovereign-Tech-via-OSTIF
ask matters. **Timeline:** rolling intake; once funded, weeks to a few months; total
wall-clock often several months incl. fundraising. **Confidence:** high on the model;
the open question is whether they take an alpha solo project without a pre-identified
funder.

### 2.3 GitHub — Secure Open Source Fund (FUNDING + security uplift cohort) — **STRONG PARALLEL BET**

**Verdict:** Our existing posture is *exactly* what they reward. Lower friction than
OTF/OSTIF and a good fit for a solo maintainer who'd benefit from mentorship plus
money. Caveat: it's primarily a **cohort-based maintainer security-uplift + education**
program (~3 weeks) with funding — the money *can* go toward an audit, but it
**complements rather than replaces** an independent third-party one.

- [ ] Apply via the **Secure Open Source Fund** page: `github.com/open-source/github-secure-open-source-fund` `[RE-VERIFY URL + that a cohort is open]`
- [ ] Prepare the three deliverables: a **written application** about the OSS work, an **interview**, and a **45-second video pitch** `[RE-VERIFY format]`
- [ ] **Lead with the security-maturity signals** — these are real and already in-repo: `make verify` (ruff + `mypy --strict` + pytest at ~85% coverage), **CodeQL**, **pip-audit**, **Dependabot**, **SHA-pinned CI**, **signed-provenance + SBOM releases**
- [ ] Frame a **clear security-improvement outcome:** "fund and complete an external crypto/security review so the alpha caveat can be removed"
- [ ] Note: a next cohort was mentioned around **September** `[RE-VERIFY 2026 cohort dates]`

**Fit risk:** Low on posture; the only caveat is that it's an uplift program, so pair
it with OTF/OSTIF for the deep independent review. **Timeline:** cohort-based; weeks-to-months
to cohort start, then ~3 weeks. **Confidence:** medium-high.

### 2.4 NLnet Foundation — NGI Zero funds — **MONITOR, don't force a fit**

**Verdict:** EUR 5k–50k grants, and NGI Zero grantees can access **free security AND
accessibility audits** via the coalition — which would bundle *both* reviews we need
(roles 1 and 2). **But** the broad door is currently shut.

- [ ] Check `nlnet.nl/funding.html` for currently-open themes `[RE-VERIFY open calls]`
- [ ] Note the **flagship NGI Zero Commons Fund's 13th and FINAL call closed 2026-06-01** — that broad door is closed
- [ ] The only funds open mid-2026 — **NGI Taler** (privacy-preserving payments) and **NGI Fediversity** (federated hosting) — are **poor thematic matches** for a tenant evidence tool; the next deadline for those pilots is **2026-08-01** `[RE-VERIFY]`
- [ ] Remember the **audit support is reserved for projects already NGI-funded**, so there's no audit without first winning a grant
- [ ] **Action:** *monitor* for a future broad/Commons-style NGI0 successor call rather than forcing a fit into Taler/Fediversity now (NLnet's application is famously lightweight, 1–2 pages, so it's cheap when a real fit opens)

**Confidence:** high on facts, **medium-to-low on fit** for the currently-open themes.

### 2.5 Sovereign Tech Fund / Agency (incl. Bug Resilience Program) — **INDIRECT, via OSTIF**

**Verdict:** Our license satisfies their rule (AGPL-3.0-or-later + Apache-2.0 verifier
subset), but they fund **critical base infrastructure** with a **EUR 50k+ minimum**,
and a single-maintainer alpha **end-user app almost certainly does not clear that bar
directly.** The realistic value is as **the money behind an OSTIF Bug Resilience
engagement.**

- [ ] **Do not** lead here as a direct applicant — route via OSTIF (see §2.2) and ask OSTIF to tap the **Bug Resilience Program**
- [ ] If you still want to check direct eligibility: `apply.sovereigntechfund.de` (expect the EUR 50k+ / base-infrastructure bar) `[RE-VERIFY]`
- [ ] Watch the **Fellowship** (2026 cohort closed 2026-04-06) and **Standards** (pilot closed 2026-05-19) for future rounds `[RE-VERIFY next windows]`

**Confidence:** high on facts, **low on direct fit.**

### 2.6 Mozilla MOSS — Secure Open Source track — **DO NOT RELY ON (hiatus)**

**Verdict:** On paper an excellent audit-and-remediate model. In practice it has been
on **indefinite hiatus since the 2020 restructuring and is NOT accepting
applications.** Included only because it's commonly named.

- [ ] **Do not apply** — confirm status first if you must: `mozilla.org/en-US/moss/secure-open-source/` `[RE-VERIFY hiatus still in effect]`
- [ ] Monitor the **Mozilla Technology Fund** (thematic/cohort, historically *not* a general security-audit fund) in case SOS is revived

**Confidence:** high that it is on hiatus.

---

## 3. Pro-bono channels checklist (complement, not substitute)

Use these for **breadth and warm-up** — especially the **local web app + `packet.html`
attack surface** — and **reserve the deep crypto review** for an OTF/OSTIF-facilitated
or paid specialist firm. Most pro-bono channels do org-level / vulnerability-assessment
work, not primitive-level review of Ed25519 / X25519 / ChaCha20-Poly1305 / RFC 3161.

- **OSTIF as facilitator/matchmaker** — covered in §2.2; it doubles as a pro-bono
  *project-management* channel even before we hold a grant.
- **Consortium of Cybersecurity Clinics** (university student clinics, Google-funded
  network) — `cybersecurityclinics.org/about/our-members/`. Contact a clinic
  directly (ideally nearby or one that does application-level work). Frame habitable
  as a public-interest tool for at-risk tenants. **Expect a vuln/risk assessment from
  supervised students, not a deep crypto audit.** Best as a cheaper complementary
  review or warm-up. `[RE-VERIFY a member clinic is taking external orgs]`
- **OWASP chapters + volunteer researcher communities** — `owasp.org`. Post **baseline
  B1** and the **standalone verifier** as a concrete, bounded review target to a local
  chapter / relevant project list. Treat output as **advisory**, not an audit.
- **Academic applied-crypto / security labs (e.g. Citizen Lab and university groups)** —
  `citizenlab.ca`. No formal intake; opportunistic, topic-driven, long lead times, but
  potentially deep and citable at no cash cost. **The chain-of-custody + RFC 3161
  timestamping + verifier story is the most academically interesting angle** — lead
  with that in cold outreach. Speculative; not a reliable channel.

---

## 4. Generic grant-application draft (adapt per program)

> Reusable narrative. Trim/expand per program; swap in OTF's at-risk framing, GitHub's
> security-uplift framing, etc. Replace every `[…]` and re-verify program-specific
> facts before sending.

**Project:** habitable — github.com/ChelseaKR/habitable (public, AGPL-3.0-or-later;
verification subset additionally Apache-2.0). Maintainer: Chelsea Kelly-Reif.
Independent, unfunded, single-maintainer (bus factor 1). Currently **v0.2.0, alpha**.

**The problem we're asking you to help validate.**
Tenants documenting habitability problems — mold, no heat, leaks, pests — produce
evidence that a landlord has every incentive to dispute, and that a tenant may face
**retaliation** for collecting. habitable is an **offline-first, end-to-end-encrypted**
tool that turns those photos, videos, and notes into **tamper-evident** records:
sealed originals with SHA-256 fixity, a hash-linked chain of custody, Ed25519
signatures, and **RFC 3161 trusted timestamps** (with archive re-timestamping), all
checkable by a **standalone verifier**. The security *is* the product. We are not
asking you to take that on faith — we are asking for an **independent review to
validate it.**

**Who it protects.** People under threat of retaliation from a more powerful party
(a landlord), who often cannot afford a lawyer and whose evidence is only as good as
its integrity. The threat model treats the **adversary** (a landlord, or anyone who
can reach the device, the relay, or the timestamp authority) as the design center —
see [`docs/threat-model.md`](../threat-model.md).

**Why it's worth public-interest funding.** Fully FOSS and reproducible; AGPL-3.0-or-later
with an **Apache-2.0 verification subset specifically so courts and legal-aid orgs can
embed the verifier**; synthetic-data-only evaluation (`habitable demo`) so **no real
tenant data is ever needed to review it**; documented privacy posture (DPIA-style
statement, [`docs/privacy.md`](../privacy.md)). It serves an at-risk, under-resourced
population and asks nothing of them in return.

**Scope of the audit requested.** An independent **security + cryptographic review**
that validates the stated claims and probes the attack surface:
1. **Cryptographic design & implementation** — ChaCha20-Poly1305 vault-at-rest with a
   scrypt-wrapped key; Ed25519 signing; X25519 sealed-box E2E sync; SHA-256 fixity;
   correct, standards-conformant **RFC 3161** timestamping and archive re-timestamping.
2. **Tamper-evidence guarantees** — can a sealed original, a custody chain, or a
   timestamp token be altered such that the verifier still reports "intact" (e.g.
   undetected backdating)?
3. **The standalone verifier** — its trust assumptions and failure modes on hostile
   input (a deliberately bounded, high-value target).
4. **Local web app + `packet.html`** attack surface (this part is also a good fit for
   a complementary/cheaper review).
5. **Sync/relay** confidentiality and the documented **metadata exposure**.
6. **Validation of the residual risks** the maintainer has already enumerated in
   **threat-model baseline B1** — confirm or refute them independently.

**Budget sketch.** `[Tailor: for OTF the audit is contracted/paid by you; for OSTIF
we're seeking facilitation + a funder; for GitHub SOS we'd apply cohort funding +
program resources toward this review.]` Indicative market cost of a focused crypto +
app audit of a project this size is roughly **$30k–$200k** (OSTIF's cited range);
our scope is **deliberately bounded** (one maintainer, a small, well-documented
codebase, a frozen threat model, and synthetic test data) to keep it toward the
**lower end**. `[RE-VERIFY pricing before quoting a number.]`

**Project maturity / why this is a cheap, ready engagement (evidence, not claims).**
We treat our own assurance as **committed artifacts**, mirroring how the tool treats a
photo's hash and timestamp:
- **`make verify`** reproduces the full merge gate: **ruff**, **`mypy --strict`**, and
  **pytest** with property-based convergence tests and tamper-detection tests against
  clean, altered, and chain-broken fixtures, at **~85% coverage** (see the
  [`Makefile`](../../Makefile)).
- **CodeQL**, **pip-audit**, and **Dependabot** run in CI; CI actions are **SHA-pinned**;
  releases ship **signed provenance + an SBOM** (`.github/workflows/`).
- A **frozen, hash-pinned threat-model baseline B1**
  ([`docs/audits/threat-model-baseline.md`](../audits/threat-model-baseline.md)) so the
  reviewer and maintainer work from the *same* document and any later change is detectable.
- A reviewer **onboarding doc** ([`docs/audits/onboarding.md`](../audits/onboarding.md)),
  a DPIA-style **privacy statement** ([`docs/privacy.md`](../privacy.md)), an
  **audit-as-artifact** record ([`docs/audits/README.md`](../audits/README.md)) that
  already lists internally-found-and-fixed issues, and a private **vulnerability
  reporting** path ([`SECURITY.md`](../../SECURITY.md)).
- An honest self-review stating plainly that **no third-party audit has yet been
  performed** and that **no novel cryptography** was written (well-reviewed primitives
  via the `cryptography` library).

**What success looks like for us.** The **alpha caveat is gated on exactly this
review** (it's a stated precondition on the v1.0 gate). A completed,
publishable audit — and the remediation it drives — is what lets us responsibly tell
tenants and legal-aid orgs the tool can be relied on.

**Contact.** Chelsea Kelly-Reif — ckellyreif@gmail.com — github.com/ChelseaKR/habitable.

---

## 5. Paid-audit RFP skeleton

> Keep this costed and ready so a funder/OSTIF "yes" converts to an award in days.
> Send to specialist firms (see §6).

1. **About the project.** habitable, v0.2.0, alpha; FOSS (AGPL-3.0-or-later, Apache-2.0
   verifier subset); single maintainer; github.com/ChelseaKR/habitable. Security is the
   product; users are at-risk tenants.
2. **Why now.** Removing the alpha caveat is gated on this review. We have a **frozen,
   hash-pinned baseline (B1)** and reviewer onboarding ready, so scoping is cheap.
3. **In-scope (priority order).**
   (a) Cryptographic design + implementation: ChaCha20-Poly1305 at rest (scrypt-wrapped
   key), Ed25519, X25519 sealed-box sync, SHA-256 fixity, **RFC 3161** timestamping +
   archive re-timestamping.
   (b) Tamper-evidence: any path to alter a sealed original / custody chain / timestamp
   while the verifier still says "intact" (undetected backdating especially).
   (c) **Standalone verifier** (bounded, high-value).
   (d) Local web app + **`packet.html`** surface.
   (e) Sync/relay confidentiality + documented metadata exposure.
4. **Out of scope.** Real tenant data (none exists; evaluate on **`habitable demo`**
   synthetic data only). Roles 3–4 (legal framing, pilot) are handled elsewhere.
5. **Reference materials provided.** Threat model + **baseline B1**; onboarding doc;
   privacy statement; architecture + evidence-method docs; the full source.
6. **Deliverables.** A written report with severity-rated findings and reproductions
   on synthetic data; a remediation discussion; and a **re-test of fixes**. We intend
   to **publish** the report in [`docs/audits/`](../audits/) (raise any constraints).
7. **Engagement model.** Fixed scope; coordinate via the private path in
   [`SECURITY.md`](../../SECURITY.md) until fixes ship.
8. **Timeline.** Target an engagement window of **`[N] weeks`**; we can start within
   **`[N] days`** of award.
9. **Commercials.** Please quote **fixed price + estimated effort**; note any
   **FOSS / non-profit / public-interest rate**. Funding is **`[OTF-contracted /
   OSTIF-facilitated / grant-funded — specify]`**. `[RE-VERIFY firm pricing before
   committing a budget line.]`
10. **Selection criteria.** Demonstrated **applied-cryptography** depth (primitive +
    protocol review), public open-source audit track record, and willingness to
    publish.

---

## 6. Candidate paid firms (for the RFP shortlist)

Validate **crypto depth per engagement** during scoping; confirm current intake and
pricing — none of the pricing below is verified. `[RE-VERIFY all]`

| Firm | Why it fits habitable | Note |
| --- | --- | --- |
| **Trail of Bits** — `trailofbits.com/services/software-assurance/cryptography/` | Dedicated cryptography service + open-source program; top-tier for our primitive/protocol set | Premium pricing |
| **Cure53** — `cure53.de` | Deep, rigorous crypto + web-app audits; strong public-report reputation; fits both the crypto design and the `packet.html`/web surface | Premium pricing |
| **Radically Open Security** — `radicallyopensecurity.com` | World's first **non-profit** security consultancy; crypto analysis + code audit; mission-aligned (channels ~90% of profit to NLnet); often more affordable | Strong budget shortlist pick |
| **Quarkslab** — `quarkslab.com` | Research-driven; already executes **OSTIF-facilitated** FOSS audits; crypto/RE depth | Plugged into the OSTIF pipeline |
| **NCC Group** — `nccgroup.com` | Dedicated cryptography-services practice; long public open-source audit history | Enterprise pricing/process |
| **Shielder / Ada Logics** — `shielder.com` | Smaller specialist FOSS-audit firms that take OSTIF engagements; better budget/scale match for a small project; still publishable | Confirm advanced-crypto depth in scoping |

---

## 7. Re-verification checklist (do this before sending anything)

Research dated **2026-06-17**; the assistant's training cutoff predates it, so these
were re-verified by live search *then* — but verify again at send time.

- [ ] **OTF Security Lab** — that `apply.opentech.fund/security-lab/` **project-side**
      intake is open; current queue/turnaround; that we're not confusing it with the
      March 2026 *auditor*-recruiting RFP.
- [ ] **OSTIF** — `ostif.org/get-an-audit/` live; `contactus@ostif.org` (and the
      sponsorship/`info@` contact) current; whether they'll take an **alpha solo project
      without a pre-identified funder**.
- [ ] **GitHub Secure Open Source Fund** — that a **cohort is open**; the application
      format (written + interview + 45s video); the 2026 cohort dates (~September?).
- [ ] **NLnet** — confirm the **Commons Fund final (13th) call is closed (2026-06-01)**;
      that **Taler / Fediversity** are the only open funds (deadline **2026-08-01**);
      watch for a **successor broad NGI0 call**.
- [ ] **Sovereign Tech** — EUR 50k+ minimum / base-infrastructure bar still in effect;
      next **Fellowship / Standards** windows; that **Bug Resilience funds audits via
      OSTIF**.
- [ ] **Mozilla MOSS / SOS** — confirm **still on hiatus / not accepting applications**.
- [ ] **Paid firms** — current intake + **pricing** for every shortlisted firm; any
      FOSS/non-profit rate.
- [ ] **Pro-bono** — that a **Consortium of Cybersecurity Clinics** member is taking
      external public-interest orgs; reachable OWASP chapter / researcher community.

> **Honesty note to carry into every pitch.** habitable is alpha, unfunded, and
> bus-factor-1, and it protects **domestic US tenants** rather than the
> repressive-environment users some of these programs are framed around. Say so. The
> defensible, accurate frame — at-risk users facing retaliation, a privacy/tamper-evidence
> tool whose stated claims we want *independently validated* — is both true and our
> strongest argument.
