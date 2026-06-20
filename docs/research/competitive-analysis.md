<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# habitable — competitive market analysis & strategy

> **What this is.** A multi-source, cited competitive analysis and go-to-strategy for habitable,
> covering four landscapes (tenant-documentation apps, evidence-integrity/timestamping tech,
> legal-aid/access-to-justice tech, and privacy/local-first tools), the US/California evidentiary
> reality, and funding + partnership pathways for a non-commercial, AGPL, solo-maintainer project.
> Produced via a deep-research workflow (5 parallel search angles → claim extraction → verification →
> synthesis).
>
> **Confidence & method caveat.** Many authoritative primary pages (statutes, funders, tool sites)
> returned HTTP 403 to automated fetching, so a number of claims rest on search-engine summaries *of*
> those primaries plus reputable secondary sources. Confidence is tagged per claim in the source
> appendix; treat `medium`/`low` items as leads to confirm, not settled facts. This is market
> intelligence, not legal advice.

## 1. Executive summary

- **There is a real, specific market gap.** No tenant-facing tool today turns a renter's phone photos
  into **cryptographically verifiable, tamper-evident, court-ready** habitability evidence. Tenant
  tools generate *communications and forms* (JustFix, Tenant Power Toolkit, Rentervention, DoNotPay)
  or *organizing data* (Action Builder); the only tools that do evidence-integrity well serve
  **human-rights/atrocity** documentation (eyeWitness) or **general** activist/journalist use
  (ProofMode) — not housing. habitable sits in the empty intersection: *evidence-integrity ×
  housing-domain × open-source × offline/no-server*.
- **habitable's defensible niche** is the combination no competitor holds at once: **open-source +
  offline-first + no-server/no-account + independently verifiable packet + standalone verifier +
  tenant/housing focus + EN/ES + accessibility.** ProofMode is the closest peer (open-source, but
  general-purpose and notary/C2PA-leaning); eyeWitness is the legal-grade peer but is the *opposite*
  trust model (proprietary, server-mandatory, expert-gatekept).
- **The honest strategic constraint:** in California tenant court the bar to *admit* a photo is
  **low** (a photo is a "writing" authenticated under Evid. Code §1400; the best-evidence rule is
  abolished; *Goldsmith* imposes no special rule for machine images). So tamper-evidence is mostly
  **defensive** value — rebutting alteration/deepfake challenges, easing disputes, and anchoring the
  **notice timeline** — rather than a precondition to getting evidence in. **Notice to the landlord
  and the condition itself drive outcomes more than integrity does.** Positioning must lead with that
  honesty (it's also on-brand) and ride the **deepfake era** tailwind (FRE 902(14)'s hash pathway and
  the proposed FRE 901(c) burden-shift make integrity increasingly relevant).
- **Funding:** the cleanest fit is the **European open-source/digital-rights** ecosystem, led by
  **NLnet NGI Zero Commons Fund** (individuals eligible, AGPL fine, €5k–50k, *and a bundled free
  security/accessibility audit*) — which can fund development **and** the v1.0-gate audit in one move.
  US legal-aid money (LSC TIG) is **not** available to a solo project directly; it requires a
  legal-aid grantee co-applicant.
- **Partnerships:** **Tenant Power Toolkit** (California) and the **Docassemble/Suffolk LIT Lab
  Assembly Line** ecosystem are the highest-leverage integration targets — habitable supplies the
  *verified evidence + notice record* layer they lack. Tenant-union networks (TUF, ATUN locals) are
  distribution/credibility allies, not funders.

## 2. The market gap (white space)

Across all four landscapes, the recurring finding is the **absence of tenant-side evidence
integrity**. California legal-aid guidance tells tenants to "keep dated photos, texts, and a log in
one file" — with **no integrity layer**, and EXIF timestamps are explicitly editable and not
tamper-evident. Meanwhile the tools that *do* integrity (eyeWitness, ProofMode, Truepic) are aimed
elsewhere. habitable fills: **tenant-owned, verifiable, housing-specific evidence with no honeypot.**

## 3. Competitive landscape

### 3.1 Tenant-documentation & organizing tools
| Tool | Who/Model | Does | Evidence integrity? | Privacy |
| --- | --- | --- | --- | --- |
| **JustFix** | NYC nonprofit (2015) | Repair-demand **letters** (certified mail), Who Owns What, eviction screening | ❌ (creates a *notice record*, self-asserted) | Cloud/web |
| **Tenant Power Toolkit** | CA coalition (Inner City Law Center + Debt Collective + LA Tenants Union…) | E-files CA eviction **Answer (UD-105)**, fee waiver, jury demand; attorney connect | ❌ (forms, not evidence) | Web |
| **Rentervention** | Chicago nonprofit (LCBH) | AI chatbot, IL letters/forms/triage | ❌ | Web/SMS |
| **DoNotPay** | For-profit; FTC settlement Jan 2025 ($193k, barred "AI lawyer" claims) | Demand-letter generation | ❌ | Cloud |
| **Action Builder/Network** | Progressive-org SaaS | Tenant-union **organizing CRM** (buildings/units) | ❌ (different purpose) | Cloud, org-readable |
| **eyeWitness to Atrocities** | Int'l Bar Assoc. + LexisNexis | Capture metadata + hash, server chain-of-custody | ✅ (atrocity crimes) | Server (LexisNexis locker), proprietary |

**Takeaway:** every *tenant* tool is communications/forms/organizing; none does evidence integrity.

### 3.2 Evidence-integrity & trusted-timestamping (the technical peer group)
- **ProofMode** (Guardian Project + WITNESS) — **closest peer.** Open-source (GPL-3.0), mobile,
  SHA-256 + PGP signatures + sensor metadata + optional notarization (Filecoin/IPFS) and **C2PA**;
  framed for FRE 902(13)/(14). *General-purpose* (activists/journalists), notary/C2PA-leaning.
  habitable differs by: housing focus, offline-first/no-server, the **packet + standalone verifier**
  as the deliverable, and RFC 3161 trusted timestamps as the headline primitive. *(Whether ProofMode
  uses RFC 3161 specifically is unconfirmed.)*
- **eyeWitness** — **legal-grade peer, opposite architecture:** proprietary, server-mandatory,
  expert-gatekept (LexisNexis evidence locker). habitable is the inverse: open, no-server,
  self-service, independently verifiable by anyone.
- **Truepic** — proprietary C2PA capture SDK (B2B, TEE + cloud PKI). **Serelay** — **defunct
  (dissolved 2 Mar 2025).**
- **C2PA / Content Credentials** — dominant open *provenance standard* (Adobe/BBC/Microsoft/…);
  proves signing/edit-history, **not** that media depicts reality. **Complementary** to habitable — a
  fundable interop feature, not a competitor.
- **RFC 3161** (habitable's mechanism): proves a hash existed *at/before* time T and is unaltered
  since — an **upper bound on existence**, not authorship/truth. **OpenTimestamps** (Bitcoin-anchored)
  is a trust-minimized, free alternative (permanent but latency-bound) habitable could offer as an
  option.
- **Forensic suites** (Cellebrite, Magnet AXIOM, EnCase) validate habitable's primitives (SHA-256 +
  chain of custody are accepted forensic practice) but are examiner-operated/enterprise — orthogonal.

### 3.3 Legal-aid & access-to-justice tech (housing)
- **Tenant Power Toolkit** (CA) — flagship integration target; files Answers, **no conditions
  evidence**.
- **Docassemble** (open-source MIT, API-capable) + **Suffolk LIT Lab Document Assembly Line** (MIT) —
  the **integration substrate**; one connector reaches a broad ecosystem of court/legal-aid
  interviews.
- **Northeast Legal Aid** built an LSC-TIG-funded app guiding tenants to **notify landlords of
  substandard conditions** → demand letter → TRO — the closest functional precedent and a co-apply
  model.
- **LawHelp Interactive** (Pro Bono Net), **LegalServer** (proprietary case-management system of
  record), **Clio + Gavel** (Gavel already publishes a CA UD-105 guide) — adoption rails.
- **LSC Technology Initiative Grants** (~$4–5M/yr) — **grantee-only**; a solo project must partner.

### 3.4 Privacy / local-first peer group (positioning reference)
No direct competitor; this is where habitable borrows credibility patterns (Signal/SecureDrop/Guardian
Project: open-source + funded independent audits + no-honeypot architecture). Use these as the
*trust-model reference class* in funder and union pitches.

## 4. Evidentiary reality check (positioning guardrail)

- **Authentication is a low bar.** FRE 901 / Cal. Evid. Code §1400 require only "evidence sufficient
  to support a finding"; CA treats photos as "writings" (§250), abolished the best-evidence rule
  (Secondary Evidence Rule §1521), and imposes **no special rule for machine-generated images**
  (*People v. Goldsmith*, 2014).
- **Where integrity HELPS:** rebutting "this was edited/AI-generated" (maps to **FRE 902(14)** hash
  self-authentication and the proposed **FRE 901(c)** deepfake burden-shift); proving a file **existed
  by a date** (sequencing vs. the notice timeline); reducing authentication disputes.
- **Where it's IRRELEVANT/INSUFFICIENT:** it does **not** prove the photo depicts *this* unit, the
  *condition*, its materiality, or **landlord notice** (often dispositive) — and does not cure hearsay
  or guarantee admission/weight. habitable's "strengthens, does not guarantee" framing is accurate and
  should stay front-and-center.
- **Strategic read:** lead with the **notice timeline** and the **deepfake-era** value, not "gets your
  photo admitted." The tamper-evidence is insurance and future-proofing, plus a forcing function for
  landlords to settle.

## 5. Differentiation & positioning

**Where habitable uniquely wins** (no surveyed peer holds all): open-source · offline-first ·
no-server/no-account/no-telemetry (no honeypot, nothing to subpoena) · independently verifiable
packet + standalone Apache-2.0 verifier · housing-domain workflow (issues, rooms, timeline, notice) ·
EN/ES · WCAG 2.2 AA · retaliation threat model.

**Honest gaps to close:** (1) **alpha + unaudited** — the audit is the credibility gate; (2) **single
maintainer / bus-factor**; (3) **no real pilot yet**; (4) integrity ≠ depiction/notice — must be
communicated so advocates don't over-rely; (5) **no C2PA interop** yet (the dominant provenance
standard); (6) distribution — tenants don't know it exists.

**One-line positioning:** *"The tenant-owned, verifiable evidence layer for housing — open-source and
offline, so a landlord's lawyer can check it but no company can read, lose, or subpoena it."*

## 6. Funding strategy (prioritized)

1. **NLnet NGI Zero Commons Fund — #1.** Individuals eligible; AGPL fine; €5k–50k; light application;
   **bundles a free independent security/privacy/accessibility audit** → funds development *and* the
   v1.0-gate audit at once. Verify the live call deadline (rotates ~bi-monthly).
2. **Security audit path** (if not via NLnet's bundle): **OTF Red Team Lab** (free; non-OTF-funded
   tools may apply) or **OSTIF** (sponsor-funded; needs some adoption). Likely vendors: Radically Open
   Security, 7ASecurity, Trail of Bits.
3. **Open Source Collective fiscal host** — set up early to receive grants/donations and pay an audit
   vendor without incorporating (10% fee; not tax-deductible, c6).
4. **OTF Internet Freedom / FOSS Sustainability Fund** — larger ($50k–$300k) once mature (3+ yrs);
   frame around at-risk/surveilled tenants. *Risk: OTF funding stability is politically sensitive.*
5. **Legal-aid partner → LSC TIG / Pro Bono Net ("Scale Justice")** — partnership-gated; land a CA
   legal-aid org (via a Right-to-Counsel coalition) as adopter/co-applicant.
6. Lower priority: Sovereign Tech Fund (only if habitable ships reusable infra/libraries; €50k floor),
   Mozilla (on hiatus), Ford/Sloan (research-oriented), Digital Defenders (emergency-only).

## 7. Partnerships & ecosystem (prioritized)

1. **Tenant Power Toolkit (CA)** — propose an "attach your verified evidence packet" step to
   substantiate the §1941.1/§1174.2 habitability defense. Engage via **The Debt Collective** (tech) +
   **Inner City Law Center** (legal).
2. **Docassemble / Suffolk LIT Lab Assembly Line** — build one MIT/API connector to push a verified
   bundle into any guided interview; unlocks the broad court/legal-aid ecosystem.
3. **Northeast Legal Aid model** — partner or co-apply for an LSC TIG with a CA grantee, habitable as
   the verified-evidence/notice layer.
4. **JustFix** — competitor *and* partner: offer habitable as the **verification layer** behind a
   JustFix-style notice letter; complementary in the CA market where JustFix is NY-strong.
5. **Tenant Union Federation + ATUN locals (LA/Sacramento/Bay Area)** — distribution, credibility, and
   the pilot testimony that strengthens grant/audit applications. (ATUN rejects foundation/government
   money — treat as distribution only.)
6. **C2PA Content Credentials** — adopt as an interop feature (strong proposal line item; boosts
   credibility), not an org to join.
7. **Adoption rails** for scale: LegalServer connector + Clio/Gavel integration (Gavel already does CA
   UD-105) so packets land where advocates work.

## 8. Strategic risks

- **Over-claiming admissibility** → credibility loss with the exact lawyers habitable needs. Mitigation
  is already cultural (the honesty discipline) — keep it.
- **Bus-factor / alpha-unaudited** stalls adoption and funding. Mitigation: NLnet-bundled audit +
  contributor onramp.
- **ProofMode + C2PA could enter housing** (C2PA-native capture becomes commodity). Mitigation: own the
  *housing workflow + no-server/no-honeypot + verifiable packet*, and interoperate with C2PA rather
  than compete on provenance primitives.
- **Adoption cold-start**: tenants document under stress with whatever's on their phone. Mitigation:
  ride existing channels (TPT, legal-aid, unions) instead of direct-to-tenant.
- **Marginal legal value in low-bar CA courts** could make "why bother" the objection. Mitigation:
  lead with notice-timeline + deepfake-era + landlord-settlement leverage, not admission.
- **OTF/geopolitical funding volatility** → don't over-index on any single US-internet-freedom funder;
  NLnet/EU diversification helps.

## 9. Prioritized recommendations

1. **Reframe the pitch around "notice timeline + tamper-proof in the deepfake era," not "admissible."**
   Update README/site copy and the legal docs accordingly. (Cheap, high-leverage, on-brand.)
2. **Apply to NLnet NGI Zero Commons Fund** in the next call — one ask funds development *and* the
   v1.0-gate audit; set up an **Open Source Collective** fiscal host first.
3. **Land one California pilot through a tenant-union/legal-aid channel** (LA/Sacramento/Bay Area
   ATUN local or a Right-to-Counsel-linked legal-aid org). The written pilot outcome is the unlock for
   both the v1.0 gate and every funder.
4. **Build the Tenant Power Toolkit integration** (or a clean "export a verified packet a TPT user can
   attach") — the fastest path to real, in-court use in CA.
5. **Ship a Docassemble/Assembly Line connector** so one integration reaches the broader A2J ecosystem.
6. **Pursue the independent security + crypto audit** via NLnet's bundled service or OTF Red Team Lab —
   it is simultaneously the v1.0 gate, the top adoption blocker, and a funder requirement.
7. **Add C2PA Content Credentials interop** as a funded feature — aligns with where provenance is
   standardizing and strengthens the deepfake-rebuttal story.
8. **Differentiate explicitly against ProofMode and eyeWitness** in positioning materials (housing
   focus + no-server + verifiable packet) so funders/advocates understand the niche.
9. **Recruit a second maintainer / co-stewards** (bus-factor is a named funder risk) via the
   good-first-issues onramp already in the repo.
10. **Treat tenant-union federations as distribution, not funding**, and keep the no-honeypot/no-telemetry
    architecture as the trust anchor that the whole strategy rests on.

## 10. Source & confidence appendix

High-confidence, cross-corroborated: the four-segment competitor set and their models; ProofMode
(GPL, SHA-256+PGP+C2PA) and eyeWitness (IBA+LexisNexis, server chain-of-custody) as the bracketing
analogues; Serelay dissolved (2025-03-02); RFC 3161 upper-bound semantics; C2PA "not a truth machine";
FRE 902(13)/(14) + Cal. Evid. Code §§250/1400/1521 + *Green*/*Goldsmith* framework; CA habitability
elements (notice + condition); NLnet eligibility/€5k–50k/bundled audit; LSC TIG grantee-only;
Open Source Collective terms; TUF (Aug 2024) and ATUN (41 unions) including ATUN's rejection of
foundation/government funding.

Treat cautiously (medium/low or single-source): Tenant Power Toolkit's "~1 in 5 LA Answers" scale and
its exact tech stack/whether its code is open; whether ProofMode uses RFC 3161 specifically; eyeWitness
being formally closed-source (strong inference, not a quoted license); exact LSC-TIG year/amount for
the Northeast Legal Aid app; current NLnet/OTF call deadlines and OTF budget continuity; DoNotPay's
post-FTC housing features; JustFix's current California availability. Many primary pages (statutes,
funders, tool sites) 403'd, so verify specifics against the live primary source before relying on them.

*Not legal advice. Confirm all legal and funding specifics with counsel and the funders' live pages.*
