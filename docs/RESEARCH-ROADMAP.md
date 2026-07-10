<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Research-Backed Roadmap

> **Framing.** This roadmap is derived from two inputs: the **synthetic persona panel**
> in [`USER-RESEARCH.md`](USER-RESEARCH.md) (clearly labelled synthetic — *not* real
> interviews and *not* evidence of demand), and **external, citable research** on
> housing law, digital-evidence standards, the tenant-organizing movement, comparable
> tools, and the access realities of low-income tenants (full reference list below, all
> URLs accessed **2026-06-30**). It **complements and does not replace** the strategic
> [`ROADMAP.md`](../ROADMAP.md) at the repo root or the prior backlog in
> [`docs/research/synthetic-personas-feedback.md`](research/synthetic-personas-feedback.md)
> (and its [`execution-log.md`](research/execution-log.md)). Its job is to add the
> *evidence layer* the prior study lacked — tying each need to a documented external
> finding — and to re-sequence accordingly. Where an item restates something the existing
> roadmap or backlog already holds, it is tagged **[corroborates …]** with the source;
> where it is not in the existing roadmap, it is tagged **[NET-NEW]**. Nothing here may
> violate the project's invariants (no server-side personal data; no telemetry; no
> central authority; mandatory tamper-evidence; the retaliating-landlord threat model;
> honesty about limits; non-optional accessibility/bilingual reach).
>
> **Last assembled: 2026-06-30.** Priorities: **P0** now · **P1** next · **P2** soon ·
> **P3** opportunistic. Effort: **S** ≈ afternoon · **M** ≈ a few days · **L** ≈ a week+.

---

## Research basis / evidence

> Cross-checked: every high-stakes legal or technical claim below is corroborated by
> **≥2 sources**, mixing **primary** sources (Cornell LII rule text, HUD, DOJ, Pew, CA
> OAG) with **practitioner/secondary commentary** (forensics vendors, legal blogs,
> advocacy orgs). Treat the secondary sources as *signposts to confirm against primary
> law*, not as authority. All legal claims are **jurisdiction-dependent and change over
> time**; volatile items are flagged. Nothing here is legal advice.

### A. Habitability law and how housing court treats condition evidence
- **The implied warranty of habitability is now recognized in every U.S. state** (by
  statute or case law; Arkansas was last, in 2021), but **remedies, written-notice
  requirements, and cure periods vary by state and city** — so a tool can frame, but must
  not assert, a given jurisdiction's rules. [L1] [L2] *(Volatile / jurisdiction-specific.)*
- **Tenants are told to document conditions over time, give written notice, and that
  time-stamped photos plus a dated timeline and an official inspection report are the
  persuasive evidence.** This is exactly habitable's capture + timeline + packet shape.
  [L3] [L4]

### B. Admissibility of digital photos: authentication, metadata, chain of custody, timestamps
- **Authentication (FRE 901)** requires "evidence sufficient to support a finding" that
  an item is what it's claimed to be; photos are authenticated by testimony that the
  image "fairly and accurately depicts" the scene, or by circumstantial evidence. This is
  why a **witness-foundation declaration** is half the product. [E1] [E2]
- **Bare EXIF is weak evidence.** Device-clock timestamps and GPS in EXIF are
  user-editable and, once disputed, "collapse to a weak indication" — they are *not* an
  independent, tamper-evident anchor. This is the precise gap habitable closes with
  hashing + trusted timestamps. [M1] [M2]
- **Hash values + certified electronic processes are treated as self-authenticating**
  under **FRE 902(13)–(14)**: identical hash values "reliably attest" that a copy is an
  exact duplicate, and a qualified certification can substitute for a foundation witness.
  This underwrites the `bundle.json` + standalone-verifier design and the value of a
  recipient being able to check a hash without trusting the producer. [E3] [E4] [E5]
- **RFC 3161 trusted timestamps** are recognized (and, as eIDAS "qualified" timestamps in
  the EU, have explicit legal weight) as strong corroborating evidence that exact content
  existed **no later than** a given time — an *upper bound*, not proof of authorship or
  depiction. habitable's semantics and honest-limits framing track this exactly. [T1]
  [T2] [T3]

### C. The tenant-union / organizing movement (the realistic distribution channel)
- **Tenants overwhelmingly face eviction without counsel** — roughly **3% of tenants are
  represented nationally vs ~81% of landlords**, and even right-to-counsel cities have
  seen representation fall amid funding gaps. The packet's recipient is therefore often a
  *pro se* tenant and the bench — strengthening the case for zero-install, plain-language
  verification. [A1] [A2]
- **Tenant unions are a growing, organizing-led infrastructure** (the Tenant Union
  Federation formed in 2024; multi-building rent strikes have won concessions; building
  card-drive unionization is spreading) — i.e., the org-level adopters habitable is built
  for. [U1] [U2] [U3]

### D. Comparable verifiable-capture tools (what exists, and the gaps)
- **ProofMode** (WITNESS + Guardian Project) cryptographically signs and timestamps
  captures for chain-of-custody and aligns to **C2PA** content provenance — validating
  habitable's hashing/timestamp approach, but it is capture-and-share, not a local-first
  case file with court packets. [C1] [C2]
- **eyeWitness to Atrocities** embeds rich sensor metadata and **uploads to a controlled
  server reviewed by lawyers** — a *centralized custody* model habitable deliberately
  rejects to avoid a subpoena/honeypot target. [C3] [C4]
- **Tella** encrypts on-device and can disguise itself; **DV-documentation tools**
  (DocuSAFE, VictimsVoice) surface the **shared-device / abuser-monitoring** threat and
  often store **off-device** — a different privacy bet that informs habitable's
  shared-phone and duress concerns. [C4] [C5] [C6]

### E. Why local-first + E2E (not the cloud) is the right bet here
- A cloud provider holding **both ciphertext and keys** can be **compelled to produce
  data — sometimes without notice** — under the CLOUD Act / Stored Communications Act;
  E2E encryption where only end users hold keys is the documented mitigation. This is the
  legal grounding for habitable's "nothing to subpoena from the project" design and its
  AGPL hosted-service clause. [S1] [S2]

### F. Access realities of the protected users
- **Smartphone-dependence:** ~**26% of sub-$30k households** rely on a phone with no home
  broadband (vs ~5% of $100k+) — offline-first and data-frugality are necessities, not
  niceties. [P1] [P2]
- **Language access:** Spanish speakers are ~**65% of the U.S. LEP population**, and
  meaningful language access in federally assisted housing is a **Title VI** obligation
  and a documented failure point — grounding EN/ES-in-v1 and more languages next. [G1]
  [G2] [G3]
- **Disability:** disabled renters are disproportionately cost-burdened and
  eviction-exposed; an evidence tool a disabled tenant can't operate fails its purpose —
  grounding the WCAG 2.2 AA gate and the recorded-AT-pass v1.0 requirement. [D1] [D2]

### Reference list (accessed 2026-06-30)

| Key | Source | URL | Type |
| --- | --- | --- | --- |
| L1 | Cornell LII — Implied warranty of habitability | https://www.law.cornell.edu/wex/implied_warranty_of_habitability | Primary/encyclopedic |
| L2 | Nolo — Tenant Rights to a Livable Place | https://www.nolo.com/legal-encyclopedia/free-books/renters-rights-book/chapter7-2.html | Practitioner |
| L3 | CA OAG — Know Your Rights as a California Tenant (Habitability) | https://oag.ca.gov/system/files/media/Know-Your-Rights-Habitability-English.pdf | Primary (gov) |
| L4 | tenant-rights.com — NY Housing Court HP Action for Repairs | https://tenant-rights.com/new-york/housing-court-hp-action-for-repairs | Practitioner |
| R1 | Cornell LII — Retaliatory eviction | https://www.law.cornell.edu/wex/retaliatory_eviction | Primary/encyclopedic |
| R2 | Nolo — State Laws Prohibiting Landlord Retaliation | https://www.nolo.com/legal-encyclopedia/state-laws-prohibiting-landlord-retaliation.html | Practitioner |
| R3 | iPropertyManagement — Landlord Retaliation Laws by State | https://ipropertymanagement.com/laws/landlord-retaliation | Secondary |
| E1 | Cornell LII — FRE 901 (Authenticating evidence) | https://www.law.cornell.edu/rules/fre/rule_901 | Primary (rule text) |
| E2 | Expert Institute — Federal Rule 901 | https://www.expertinstitute.com/resources/insights/federal-rule-901-authentication/ | Practitioner |
| E3 | Cornell LII — FRE 902 (Self-authenticating evidence) | https://www.law.cornell.edu/rules/fre/rule_902 | Primary (rule text) |
| E4 | U.S. Courts (G. Joseph) — Self-Authentication of Electronic Evidence (902(13)–(14)) | https://www.txs.uscourts.gov/sites/txs/files/Self-Authentication%20of%20Electronic%20Evidence%20-%20New%20Rules%20-%20G.Joseph.pdf | Primary (gov) |
| E5 | ABA — New Rules for Self-Authenticating Electronic Evidence | https://www.americanbar.org/groups/litigation/resources/newsletters/trial-evidence/new-rules-self-authenticating-electronic-evidence/ | Practitioner |
| M1 | TrueScreen — EXIF Metadata: Proving the Date of a Photo in Court | https://truescreen.io/insights/exif-metadata-photo-date-court-evidence/ | Secondary |
| M2 | Factually — Verifying photo timestamps/geolocation/edits | https://factually.co/fact-checks/media/verify-photo-timestamps-geolocation-edits-0d389a | Secondary |
| T1 | Evidency — RFC 3161 timestamping & reliable digital evidence | https://evidency.io/en/rfc-3161-timestamping/ | Secondary |
| T2 | Forensic Notes — Trusted Timestamps (RFC 3161) | https://www.forensicnotes.com/trusted-timestamps/ | Secondary |
| T3 | TrueScreen — Qualified Electronic Timestamps (eIDAS) | https://truescreen.io/articles/qualified-electronic-timestamps-legal-value/ | Secondary |
| C1 | WITNESS Library — ProofMode | https://library.witness.org/product/proofmode/ | NGO/primary |
| C2 | ProofMode — ProofMode and C2PA | https://proofmode.org/c2pa | Project/primary |
| C3 | eyeWitness to Atrocities | https://www.eyewitness.global/ | Project/primary |
| C4 | WITNESS Blog — Should I Use This Documentation App? | https://blog.witness.org/2020/02/use-documentation-app/ | NGO/primary |
| C5 | NNEDV Safety Net — Choosing and Using Apps | https://www.techsafety.org/choosingapps | NGO/primary |
| C6 | DomesticShelters — Lifesaving Apps for Survivors of DV | https://www.domesticshelters.org/articles/technology/lifesaving-apps-for-survivors-of-domestic-violence | NGO/secondary |
| A1 | NLIHC — Advancing Tenant Protections: Right to Counsel | https://nlihc.org/resource/14-1-advancing-tenant-protections-right-counsel-tenants-facing-eviction | NGO/primary |
| A2 | NYC Comptroller — Evictions Up, Representation Down | https://comptroller.nyc.gov/reports/evictions-up-representation-down/ | Primary (gov) |
| U1 | Shelterforce — Tenant Organizing Beyond Legislative Campaigns | https://shelterforce.org/2026/05/06/stalled-in-state-houses-tenant-unions-organize-against-landlords-directly/ | Journalism |
| U2 | In These Times — The Future of Housing Organizing: Tenant Unions | https://inthesetimes.com/article/housing-crisis-tenant-unions-debt-collective | Journalism |
| U3 | Truthout — Rising Tenant-Led Movement | https://truthout.org/articles/rising-tenant-led-movement-aims-to-bring-down-corporate-landlords/ | Journalism |
| G1 | NHLP — Language Access | https://www.nhlp.org/initiatives/fair-housing-housing-for-people-with-disabilities/language-access/ | NGO/primary |
| G2 | HUD — Limited English Proficiency | https://www.hud.gov/program_offices/fair_housing_equal_opp/limited_english_proficiency_0 | Primary (gov) |
| G3 | NLIHC — HUD Issues LEP Fair Housing Guidance | https://nlihc.org/resource/hud-issues-limited-english-proficiency-fair-housing-guidance | NGO/primary |
| D1 | Center for American Progress — Housing Insecurity for Disabled Renters | https://www.americanprogress.org/article/recognizing-addressing-housing-insecurity-disabled-renters/ | Policy |
| D2 | NHLP — Fair Housing & Housing for People with Disabilities | https://www.nhlp.org/initiatives/fair-housing-housing-for-people-with-disabilities/ | NGO/primary |
| P1 | Pew Research — Digital divide persists (2021) | https://www.pewresearch.org/short-reads/2021/06/22/digital-divide-persists-even-as-americans-with-lower-incomes-make-gains-in-tech-adoption/ | Primary (research) |
| P2 | Pew Research — Internet use, smartphone ownership, digital divides (2026) | https://www.pewresearch.org/short-reads/2026/01/08/internet-use-smartphone-ownership-digital-divides-in-u-s/ | Primary (research) |
| S1 | DOJ — CLOUD Act White Paper (2019) | https://www.justice.gov/d9/press-releases/attachments/2019/04/10/department_of_justice_cloud_act_white_paper_2019_04_10_final_0.pdf | Primary (gov) |
| S2 | Wikipedia — CLOUD Act | https://en.wikipedia.org/wiki/CLOUD_Act | Tertiary |

---

## Remediation backlog (strengthen what exists)

> Ranked by user-harm-if-unfixed × evidence strength. "Personas" reference
> [`USER-RESEARCH.md`](USER-RESEARCH.md). Tags are relative to the repo's existing
> [`ROADMAP.md`](../ROADMAP.md); overlaps with the prior backlog cite its `R-/E-` IDs.

| ID | Remediation | Personas | Pri | Effort | Evidence / tag |
| --- | --- | --- | --- | --- | --- |
| RR-01 | **Plain-language, reassuring evidence-status copy (EN+ES)** — "awaiting timestamp" = the photo is *already safe*; what to do next; no dead-end screens | DU1,DU5,DU6,AA4,OR1 | P0 | M | [P1][G2][M1] · **[corroborates ROADMAP ws B]** (also feedback R-01/R-02/R-04) · ✅ Implemented 2026-06-30 (working tree, uncommitted) |
| RR-02 | **Make honest "what this proves / does not" + upper-bound timestamp semantics unmissable** — a one-page "for the court" cover sheet on every packet, and the same disclosure surfaced in-app at the moment it matters | VA1,VA3,AD1,DU2 | P0 | S | [M1][M2][E1][T1] · **[corroborates ROADMAP risks/honest-limits]** — extends shipped packet disclosure · ✅ Implemented 2026-06-30 (working tree, uncommitted) |
| RR-03 | **Recorded human NVDA+VoiceOver pass + AT-completable capture flow + ARIA live-regions** for async transitions; recurring each release | DU5,AA2 | P0 | L | [D1][D2] + §508 FPC · **[corroborates ROADMAP ws B / v1.0 gate]** (needs paid human) |
| RR-04 | **Independent security + cryptographic audit** using the crypto spec / decision table / red-team doc; findings remediated or accepted; finish reproducible builds + signed provenance | AA1,DU4,AD1 | P0 | L | [S1][S2][T2] · **[corroborates ROADMAP ws A / v1.0 gate]** (needs funding) |
| RR-05 | **Multi-state, lawyer-vetted legal scaffolding** beyond CA — declaration/foundation templates, evidence-rule notes, hedged notice/cure framing, per state | OR3,DU2,VA1 | P1 | L | [E1][L1][L2][R1] · **[corroborates ROADMAP ws D]** — extends shipped CA pack |
| RR-06 | **Keep multiple-TSA redundancy a default** (now shipped) **and document the integrity meaning of a long "awaiting-timestamp" gap** (hash anchors content at capture) | DU6,AA1,VA3 | P1 | S | [T1][T2] · **[corroborates ROADMAP ws A]** — shipped (feedback R-16); add the doc · ✅ Implemented 2026-06-30 (working tree, uncommitted) |
| RR-07 | **Sync-confirmation receipt + legible peer-sync redundancy** ("you are in sync as of X; this case is on N devices") | OR1 | P1 | M | [U1] · **[NET-NEW]** (also feedback R-21/R-22) |
| RR-08 | **Storage-footprint UX on low-end devices** — show case size; safe offload of sealed originals without breaking the chain | DU1 | P1 | M | [P1][P2] · **[NET-NEW]** (also feedback R-03) |
| RR-09 | **Fix recurrence modeling** — a relapse links to the *same* issue's timeline, not a new orphan issue | DU1,OR3 | P1 | M | [L3][L4] · **[NET-NEW]** (also feedback R-05) |
| RR-10 | **Confirm + undo on destructive actions; non-auditory equivalents for sound cues; tolerate imprecise pointers** | DU3,AA4 | P1 | M | [D1] · **[corroborates ROADMAP ws B]** (also feedback R-09/R-10) |
| RR-11 | **Recovery UX** — communicate by-design unrecoverability *before* it bites; guided backup at setup; printable recovery card | DU3,OR2 | P1 | M | threat-model + [C6] · **[corroborates ROADMAP ws C]** |
| RR-12 | **Shared-device hardening** — surface duress-mode forensic/coercion limits *at point of use*; audit notification/recents leakage; reduce discreet-presence leakage | DU4,AD1 | P1 | M | [C5][C4][R1] · **[NET-NEW]** (also feedback R-12/R-14/R-15) |
| RR-13 | **Data-cost transparency + Wi-Fi-only/metered options** for sync and timestamp fetch | DU6 | P2 | S | [P1][P2] · **[NET-NEW]** (also feedback R-18/R-19) |
| RR-14 | **Jurisdiction templates speak the inspector's code/citation vocabulary**, not only our 6 categories | VA2,OR3 | P2 | M | [L4][L3] · **[corroborates ROADMAP ws C]** (also feedback R-28) |
| RR-15 | **Minimal-disclosure export scoping**, documented and defensible against over-broad discovery | OR3,AD1 | P2 | M | [E3] · **[NET-NEW]** (also feedback R-35) |
| RR-16 | **Relay operator no-log self-audit + observability matrix kept current; advance metadata resistance** | OS2,AD1 | P2 | L | [S1][S2] · **[corroborates ROADMAP ws C]** — partly shipped (feedback R-45/R-46) |
| RR-17 | **Localization workflow + legally-sensitive-string flagging + RTL/expansion readiness; ≥1 language beyond EN/ES** | AA3 | P2 | M | [G1][G2][G3] · **[corroborates ROADMAP ws B]** (also feedback R-47/R-48) |
| RR-18 | **Publish a verifier fuzz/adversarial test report** (no accept-on-tamper, no crash) + keep the documented general-tool cross-check current | VA3,AA1,DU5 | P1 | M | [E4][T2] · **[corroborates ROADMAP ws A]** — `--json` + cross-check shipped (feedback R-08/R-31/R-32); add the report |

## Expansion backlog (new capability)

| ID | Expansion | Personas | Pri | Effort | Evidence / tag |
| --- | --- | --- | --- | --- | --- |
| RE-01 | **Zero-install, offline-capable recipient verifier** — drag a packet onto a static page (served from the user's own device); confirm integrity with no install; project still hosts no case data | VA1,VA3,DU2,OR3 | P0 | L | [A1][A2][E3] · **[NET-NEW]** (also feedback E-15) — **highest leverage** |
| RE-02 | **Real tenant-union / legal-aid pilot (CA first)** with written outcomes incl. whether a packet was usable in its forum | OR1,OR3,OS3 | P0 | L | [U1][U2][A1] · **[corroborates ROADMAP ws D / v1.0 gate]** (needs partners) |
| RE-03 | **"This happened again"** — link a new capture to an existing issue as a recurrence on one timeline (pairs with RR-09) | DU1,OR3 | P1 | M | [L3][L4] · **[NET-NEW]** (also feedback E-01) |
| RE-04 | **First-class sneakernet sync** — export/import an encrypted delta via USB/SD; no relay, no data plan (surface the existing shared-directory transport as a documented tenant flow) | DU6,OR1 | P1 | M | [P1][P2] · **[corroborates ROADMAP ws C]** (also feedback E-09) |
| RE-05 | **Local multi-case organizer "campaign view"** with per-unit evidence-health badges, entirely on-device | OR1 | P1 | L | [U1] · **[NET-NEW]** (also feedback E-11) |
| RE-06 | **Co-custodian survivability** so a case survives any one tenant losing a phone — no central store | OR1,DU3 | P1 | L | threat-model + [P1] · **[NET-NEW]** (also feedback E-12) |
| RE-07 | **Capture-time alt-text authoring** so tenant-produced packets are accessible downstream | DU5,AA2 | P2 | M | [D1] + §508 · **[NET-NEW]** (also feedback E-03) |
| RE-08 | **"Assisted / calm mode"** — large-type, high-contrast, one-task-at-a-time capture for stressed/low-vision/low-dexterity users | DU3,AA4,DU5 | P2 | M | [D1][P1] · **[NET-NEW]** (also feedback E-04) |
| RE-09 | **Recovery-drill mode** (rehearse a restore on a throwaway case) + threshold/split "key custody for unions" practice | OR2 | P2 | M | threat-model · **[NET-NEW]** — playbook shipped (feedback E-13/E-14); add the drill |
| RE-10 | **Operationalize the adoption kit** — run a real workshop from the shipped facilitator guide + EN/ES quick-start + board risk briefing; iterate from it | OR1,OS3 | P1 | M | [U1][U3] · **[corroborates ROADMAP ws D]** — docs shipped; now use them |
| RE-11 | **Funder-facing artifact/outcome impact framework** (audits done, pilots run, languages shipped) with **no** user surveillance | OS3,OS1 | P2 | S | [U2] + ROADMAP "measuring without surveillance" · **[corroborates ROADMAP]** — brief shipped; extend |
| RE-12 | **Inspector view** — room → condition → timeline rollup | VA2 | P2 | M | [L4] · **[NET-NEW]** (also feedback E-17) |
| RE-13 | **Hardened relay profile** (padding/batching) for metadata resistance + operator self-audit command | OS2,AD1 | P2 | L | [S1][S2] · **[corroborates ROADMAP ws C]** (also feedback E-23) |
| RE-14 | **Maintain the bundle JSON Schema + semver stability contract + verifier-embedding cookbook** against the real code | OS4 | P2 | M | [E4][E5] · **[corroborates ROADMAP ws C interop]** — shipped; keep stable (feedback E-26/E-27) |
| RE-15 | **Per-case / per-user separation on a shared device** so a roommate can't see another's case | DU4 | P1 | L | [C5][C6] · **[NET-NEW]** (also feedback R-13) |
| RE-16 | **On-device, telemetry-free "data-flow X-ray"** + externally demonstrable "no plaintext to relay" — show exactly what each component would expose externally | DU4,AA1,OS2 | P3 | M | [S1][S2] · **[NET-NEW]** (also feedback E-07/E-08) |

---

## Sequenced roadmap (tied to the existing release horizons)

Anchored to [`ROADMAP.md`](../ROADMAP.md#release-horizons). This re-sequences the items
above; it does not move the existing horizon dates.

### Now — *v0.1.x → v0.2 (alpha hardening / assurance groundwork)*
Mostly copy, disclosure, and documentation that cut the top cross-cutting frictions and
feed the v1.0 gate:
- **RR-02** honest "for the court" cover + point-of-use framing *(S; extends shipped)*
- **RR-01** plain-language EN/ES status copy + no dead-ends *(the #1 tenant friction)*
- **RR-06** keep multiple-TSA default + document the awaiting-timestamp-gap semantics
- **RR-18** publish the verifier fuzz/adversarial report; keep the cross-check current
- **RE-10** run one real adoption workshop from the shipped kit
- **Prep the gate:** fund/schedule **RR-03** (recorded AT pass) and **RR-04** (audit),
  handing reviewers the already-written crypto spec, decision table, and red-team doc.

### Next — *v0.3 → v0.5 beta (accessible packet + pilot-ready)*
Validate the big bets with the real pilot *before* heavy build:
- **RE-01** zero-install recipient verifier *(spike → validate with a real clerk/attorney → build)*
- **RE-02** real CA tenant-union / legal-aid pilot *(gate item; also validates RE-01, RR-05, RR-09/RE-03)*
- **RR-05** multi-state legal scaffolding *(CA done; expand as lawyers vet each state)*
- **RR-09 + RE-03** recurrence modeling on one timeline
- **RR-07** sync receipt + **RE-04** sneakernet + **RE-05** organizer campaign view
- **RR-11** recovery UX + **RR-12 / RE-15** shared-device hardening & separation
- **RR-08** low-end storage UX · **RR-10** undo/confirm + non-auditory cues · **RR-13** data-cost controls

### Later — *v1.0 → v2.x (trustworthy → reach & resilience)*
- **RR-14 + RE-12** inspector code-taxonomy templates + inspector view
- **RR-16 + RE-13** metadata-resistant relay + operator self-audit
- **RR-17** languages beyond EN/ES + RTL · **RE-07** capture-time alt-text · **RE-08** calm mode
- **RE-06** co-custodian survivability · **RE-09** recovery drill · **RE-16** data-flow X-ray
- **RR-15** discovery-scoped export · **RE-11** funder impact framework · **RE-14** keep interop contract stable

---

## Recommended first sprint

Highest-leverage, mostly small, mostly already-built-on infrastructure — and it tees up
the gate. Each maps to a top cross-cutting theme and a cited finding:

1. **RR-02 — honest "for the court" cover + point-of-use framing.** Cheapest credibility
   lever; turns the tool's biggest legal risk (overclaiming) into its shield. *Evidence:
   EXIF collapses once disputed [M1][M2]; FRE 901 is a skeptic's bar [E1]; RFC 3161 is an
   upper bound [T1].*
2. **RR-01 — plain-language EN/ES status copy + no dead-ends.** Kills the #1 tenant
   friction (status legibility) for the actual audience. *Evidence: smartphone-dependent,
   LEP, stress-loaded users [P1][G2].*
3. **RE-01 (spike) — prototype the zero-install recipient verifier and put it in front of
   one real clerk/legal-aid attorney *before* building it.** This is the load-bearing gap
   and the riskiest assumption. *Evidence: ~3% of tenants represented [A1][A2];
   hash-based self-authentication [E3][E4].*
4. **RR-06 — keep multiple-TSA-by-default and document the offline-gap semantics.** Small,
   reassures offline/low-data tenants and skeptical reviewers. *Evidence: single-TSA risk
   [T1][T2]; smartphone-dependence [P1].*
5. **RR-18 — publish the verifier fuzz/adversarial report.** Converts the existing
   standalone verifier into demonstrated, not asserted, robustness. *Evidence: hostile
   review (VA3); FRE 901 challenge [E1].*

In parallel (people/money, not code): **fund RR-03 (recorded AT pass) and RR-04
(security/crypto audit)**, and **line up RE-02 (the CA pilot)** — the three human v1.0-gate
items, all unblocked by materials the repo already ships.

---

## Traceability matrix (persona → findings)

| Persona | Remediations | Expansions |
| --- | --- | --- |
| DU1 Marisol (ES, low-end, mold) | RR-01, RR-08, RR-09 | RE-03 |
| DU2 Eddie (rent-withholding heater) | RR-02, RR-05 | RE-01 |
| DU3 Gloria (elderly, dexterity) | RR-10, RR-11 | RE-06, RE-08, RE-09 |
| DU4 Daniel (undocumented, shared phone) | RR-12 | RE-15, RE-16 |
| DU5 Aisha (blind, AT) | RR-01, RR-03, RR-18 | RE-07 |
| DU6 Wesley (prepaid data, dead zone) | RR-06, RR-13 | RE-04 |
| OR1 Renata (organizer) | RR-07 | RE-04, RE-05, RE-06, RE-10 |
| OR2 Marcus (tech steward) | RR-11 | RE-09 |
| OR3 Alondra (legal aid) | RR-05, RR-09, RR-14, RR-15 | RE-01, RE-02, RE-03 |
| VA1 Judge/Clerk | RR-02 | RE-01 |
| VA2 Inspector Nguyen | RR-14 | RE-12 |
| VA3 Harlan (opposing counsel) | RR-02, RR-15, RR-18 | RE-01 |
| AA1 Dr. Variyam (auditor) | RR-04, RR-06, RR-18 | RE-16 |
| AA2 Priya (AT tester) | RR-03 | RE-07 |
| AA3 Thuy (localization) | RR-17 | — |
| AA4 Sahar (plain-language) | RR-01, RR-10 | RE-08 |
| AD1 Landlord (adversary) | RR-02, RR-12, RR-15, RR-16 | RE-13, RE-16 |
| OS1 Chelsea (maintainer) | — | RE-11, RE-14 |
| OS2 Tomas (relay self-hoster) | RR-16 | RE-13, RE-16 |
| OS3 Della (funder) | — | RE-02, RE-10, RE-11 |
| OS4 Priyanka (integrator) | — | RE-14 |

---

## What to validate with real users / risks

Synthetic work can name plausible needs; only real people can tell you which are real.
Validate these *before* committing L-effort build — ideally inside the CA pilot (RE-02):

- **Will a real clerk/judge actually accept a drag-onto-a-page verifier** — or do local
  filing rules, e-filing portals, or chambers practice demand something else? Test the
  *exact* recipient workflow before building RE-01. *(Riskiest assumption.)*
- **Does the witness-foundation declaration actually authenticate the photos in a real
  CA courtroom**, and does the framing generalize to other states? Confirm with a
  licensed attorney per jurisdiction before extending RR-05. *(FRE 901 is "sufficient to
  support a finding" — a judge-by-judge call.)* [E1]
- **Does recurrence modeling (RR-09/RE-03) match how attorneys frame persistence and
  repeat-notice** in habitability cases, or does it create a structure courts don't use?
- **Is multiple-TSA-by-default (RR-06) a burden for offline / metered-data tenants
  (DU6)?** Tune the default against real data-cost behavior. [P1]
- **Does the honest upper-bound framing help or hurt a *pro se* tenant** in front of a
  skeptical judge — does candor read as weakness? Test the copy with real recipients.
- **Are inspectors' code taxonomies stable and public enough to template (RR-14/RE-12)?**
  Confirm with a real code-enforcement office.
- **On a shared phone, is per-case separation (RE-15) the real mitigation, or is the
  honest answer "use a separate device"?** Don't overpromise a safety feature. [C5]
- **Jurisdiction + recency risk.** Every legal claim cited here is jurisdiction-dependent
  and dated 2026-06-30; re-verify against primary law for the target forum before relying
  on it. Retaliation coverage, right-to-counsel funding, and evidence-rule interpretation
  all shift. [R1][R2][A2]
- **Framing risk.** A recipient verifier or a polished packet could be *misread* as
  "habitable certifies admissibility." Every surface must keep the honest "not legal
  advice / no admissibility guarantee" framing — this is an invariant, not a nicety.

---

## Honest limits

- **Synthetic, not real, and not demand.** The persona panel is model-generated; the
  citations establish the *problems* are documented, **not** that habitable is the tool
  people will adopt. No user count, conversion, or willingness-to-use is shown here.
- **Mixed source quality.** High-stakes legal/technical claims are corroborated by ≥2
  sources, but several are practitioner or vendor commentary (flagged "Secondary" in the
  reference table). Confirm against primary rule text and the governing jurisdiction's
  law before relying on any of it. Nothing here is legal advice.
- **Priorities and effort are estimates** pending real scoping by the (single)
  maintainer; the bus-factor constraint means even "Now" items compete for one person's
  time, and config-/community-extensible surfaces are preferred over bespoke code.
- **This roadmap defers to the existing ones.** Where it disagrees with
  [`ROADMAP.md`](../ROADMAP.md) on *ordering*, the existing roadmap and its ADRs win until
  a real pilot or audit says otherwise; this document's contribution is the *evidence* and
  the re-prioritization argument, not a new mandate.
- **Close the loop honestly.** If/when real interviews, the audit, the AT pass, and the
  pilot happen, this file should be updated to mark which findings were *confirmed*,
  *refuted*, or *reframed* — the same discipline the project applies to audit findings.

---

*Companion: the synthetic persona panel is in [`USER-RESEARCH.md`](USER-RESEARCH.md).
Prior backlog: [`research/synthetic-personas-feedback.md`](research/synthetic-personas-feedback.md).
Strategic plan: [`../ROADMAP.md`](../ROADMAP.md).*
