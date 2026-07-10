# Role: CA legal reviewer (framing & habitability-reference review)

> **Status: alpha / concept stage.** This is a recruitment brief and outreach kit for a
> volunteer California housing/tenant lawyer (or law-school housing clinic) to do a short,
> bounded **review of framing**, on **synthetic data only**. It is **not** a request for
> legal representation and **does not** create an attorney–client relationship. Nothing in
> this file is legal advice. The California habitability background in §6 is drawn from
> secondary sources and is included **to be validated by the reviewer**, not relied upon.

habitable is an alpha, offline-first, end-to-end-encrypted tool intended to help tenants
document habitability problems as tamper-evident evidence (photos with RFC 3161 timestamps,
SHA-256 fixity, a hash-linked chain of custody, a standalone verifier, location-stripped
shareable packets). It is an independent personal project, no funding, AGPL-3.0 (the
verifier subset is also Apache-2.0), and it is **alpha — not for real legal use yet.**
Evaluation uses synthetic data only (`habitable demo`); no real tenant data, ever.

The project runs **audit-as-artifact**: reviews are committed to the public repo so anyone
can diff them across releases. A legal-framing review fits that model — see §4 for what we
ask, and §5 for how findings get recorded (with optional attribution credit).

---

## 1. The ask, in one paragraph

We are looking for a CA housing/tenant attorney or housing clinic to spend a few hours
checking two narrow things: (a) that habitable's **"not legal advice / no guarantee of
admissibility"** disclaimers are honest and adequate, and (b) that any **California
habitability references** in the tool's surfaces are accurate and current — in **both the
English and the Spanish** copy. That's it. This is a review of how the tool *talks about
itself and about CA law*, not a review of whether the tool should be used in a case, and not
representation of anyone.

---

## 2. Scope

**In scope**

- Review the **"not legal advice / no guarantee of admissibility" framing** wherever it
  appears: README *Honest limits*, [`docs/privacy.md`](../privacy.md),
  [`docs/threat-model.md`](../threat-model.md), the local web app UI, and the produced
  `packet.html`. The current README language reviewers should weigh in on reads:
  > *"Not legal advice, and no guarantee of admissibility. habitable produces
  > well-documented evidence. Whether a court or agency admits it, or how much weight it
  > carries, is a legal question this tool cannot answer."*
  Is that honest? Is it adequate? Is it placed where a tenant will actually see it before
  relying on the tool?
- **Sanity-check the CA habitability references** the tool surfaces (statutory citations,
  remedy descriptions, forum framing) for accuracy and currency. The candidate references
  are gathered in §6 **specifically so they can be checked.** Flagging anything stale,
  wrong, or oversimplified is the highest-value outcome.
- Check that the **English and Spanish** surfaces say the **same** thing — that the Spanish
  copy is not a softer, stronger, or differently-scoped claim than the English (or vice
  versa), and that legal terms translate correctly.
- Note where the framing should be **more conservative** (e.g., admissibility, chain of
  custody, what an RFC 3161 timestamp does and does not prove).

**Explicitly out of scope**

- **No representation, no advice to any tenant, no client relationship.** This review does
  not certify the tool, opine on any real matter, or vouch for admissibility in any forum.
- Not a security or accessibility review (those have separate reviewer tracks — see
  [`docs/audits/onboarding.md`](../audits/onboarding.md)).
- Not jurisdiction-by-jurisdiction local-ordinance research. A single "these local overlays
  exist and the tool should not pretend to track them" note is plenty; exhaustive
  city-by-city analysis is not expected.
- **No real tenant data is involved.** Evaluation is on synthetic data only.

**What this review explicitly is not, for the record:** it is a framing/reference review
consistent with [`docs/privacy.md`](../privacy.md)'s statement that the project is **not a
data controller or processor** and holds no tenant data. The reviewer is checking honesty of
disclaimers and accuracy of references — not providing legal services.

---

## 3. What's provided

| Document | Why it matters to this review |
| --- | --- |
| [`docs/audits/onboarding.md`](../audits/onboarding.md) | The reviewer/pilot scope table and the synthetic-data, audit-as-artifact model. **Start here.** |
| [`docs/privacy.md`](../privacy.md) | DPIA-style statement; the "not a data controller/processor, no admissibility guarantee" posture in writing. |
| [`docs/threat-model.md`](../threat-model.md) | What is and is not protected; "what a timestamp does and does not prove." Grounds the conservative claims. |
| [`docs/evidence-method.md`](../evidence-method.md) | How fixity, timestamping, and chain of custody actually work — useful for judging whether the integrity claims are stated honestly. |
| README *Honest limits* | The current disclaimer language to react to (quoted in §2). |

You do **not** need to install or run anything to do this review. If you want to see the
exact strings in context, the whole flow runs offline on synthetic data:

```sh
git clone https://github.com/ChelseaKR/habitable.git
cd habitable
uv sync --all-extras
uv run habitable demo                          # builds a synthetic case + packet
uv run habitable app --vault <demo-vault>      # the local web app, EN/ES, in a browser
```

---

## 4. Expected output (low-burden)

Whatever is easiest for you:

- **Inline notes / a marked-up doc / an email** listing each thing that is wrong, stale,
  oversimplified, or missing — the maintainer turns those into a PR.
- **Or a PR / GitHub issue** directly, if you prefer.

A useful note looks like: *"§X says ‘repair-and-deduct up to one month's rent'; confirm the
cap and the twice-in-12-months limit against current Civil Code §1942 — and the EN/ES copy
differ on whether notice is required."* Pointed and specific beats comprehensive.

The single most valuable finding is **a place where the framing overclaims** — e.g., implies
admissibility, or states a CA rule that is no longer accurate. The second most valuable is a
**CA reference that is wrong or out of date.**

---

## 5. How findings are recorded (audit-as-artifact)

Per [`docs/audits/onboarding.md`](../audits/onboarding.md), reviews are **committed to the
public repo**, not kept as private assurances, so anyone can diff them across releases. A
legal-framing review would be written up under [`docs/audits/`](../audits/) alongside its
resolution.

- **Attribution is your choice.** We are glad to credit you or your org by name (a credible
  CA housing reviewer strengthens the project), or to keep the review anonymous — your call.
- This is a **framing review of an alpha tool**, recorded as such. It does not bind you, does
  not represent that you endorse the tool for real use, and explicitly is not legal advice to
  any tenant.

---

## 6. CA habitability background — **to be validated by the reviewer (NOT legal advice)**

> This section exists **so it can be checked**, not relied on. It mirrors the project's own
> framing ([`docs/privacy.md`](../privacy.md), [`docs/audits/onboarding.md`](../audits/onboarding.md)):
> alpha, synthetic data only, no guarantee of admissibility. The statutory citations and
> dollar/time thresholds below come from **secondary sources and were not each independently
> re-confirmed against the codes.** **Verifying these is the reviewer's first job.**

**Implied warranty of habitability (verify before relying):**

- California recognizes an **implied warranty of habitability** in residential leases,
  established by case law (*Green v. Superior Court* (1974) 10 Cal.3d 616) and reflected in
  statute. **Civil Code §1941** requires a landlord to keep a dwelling fit for human
  occupancy; **§1941.1** enumerates conditions that render a unit untenantable (effective
  waterproofing/weatherproofing; working plumbing/gas with hot and cold running water;
  working heat; safe electrical/wiring/lighting; clean, sanitary premises free of
  rodents/vermin/garbage; adequate trash receptacles; working floors, stairways, railings).
  Health & Safety Code provisions and local building/housing codes also feed the standard.
  **Civil Code §1942.4** restricts collecting rent where serious, noticed defects go
  unrepaired.
- **Tenant remedies commonly cited** (all with notice/reasonableness/procedural
  preconditions to confirm): (1) **repair-and-deduct** under §1942 (up to one month's rent
  after notice and a reasonable time, generally capped at twice in 12 months); (2) the
  **habitability defense / rent-withholding** theory in eviction; (3) **damages / rent
  abatement**; (4) **reporting to code enforcement.** Exact dollar/time limits and notice
  forms are fact-dependent and change.
- **Retaliation:** CA presumes retaliatory motive if, after a tenant's good-faith
  habitability complaint or exercise of rights, the landlord raises rent, decreases
  services, or moves to evict — commonly within a **6-month window** (**Civil Code §1942.5**).
  Triggers/durations to confirm.
- **Overlays:** the **Tenant Protection Act (AB 1482)** adds statewide rent-cap and
  just-cause rules on top of local ordinances; local rent boards and just-cause rules vary
  by city and change over time. The tool should not pretend to track these.

**How habitability evidence is used across CA forums (validate per forum/county):**

- **Code enforcement** (city/county building/health dept): dated photos, descriptions, and a
  documented timeline support inspection requests and citations; an official inspection
  report can become independent corroboration. Value turns on showing condition + date +
  location credibly.
- **Rent boards** (rent-controlled jurisdictions — e.g. LA, SF, Oakland, Berkeley, Santa
  Monica): tenants may petition for rent reductions for decreased housing services;
  contemporaneous dated photo evidence and notice-to-landlord records are central.
  Procedures and admissibility norms vary by board.
- **Small claims:** informal (no attorneys at the hearing, relaxed evidence rules), so clear,
  organized, dated photographic evidence and proof of landlord notice are persuasive.
- **Unlawful detainer (UD) defense:** habitability is a recognized affirmative defense to
  nonpayment evictions (per *Green*); the tenant typically must prove the defect existed, was
  material, the landlord had notice, and a reasonable repair time passed. UD is
  summary/expedited with **formal** evidence rules — authentication, chain of custody, and
  photo metadata can matter, which is exactly where a tamper-evident tool aims to help **but
  where "no guarantee of admissibility" must be stated honestly**: a judge decides
  weight/admissibility case-by-case; RFC 3161 timestamps and SHA-256 fixity support
  integrity/authentication arguments but do **not** guarantee a court will admit or credit the
  evidence.

**Reviewer's first checks, in priority order:** (1) the citations and thresholds above;
(2) AB 1482 / local rent-board and just-cause overlays; (3) whether the tool's own copy
overclaims anywhere relative to the honest forum-by-forum reality above.

---

## 7. Where to find a reviewer (CA target list)

Each entry below is a **lead to qualify, not a commitment** — existence and mission fit were
verified (WebSearch/WebFetch, June 2026); willingness/capacity for a volunteer review was
**not**. **Pitch hygiene:** legal-aid and clinic **intake lines are for clients seeking
representation — do not use them for this ask.** Route to **pro-bono / volunteer
coordinators, communications, support-center attorneys, or clinic program offices**, and
state up front this is a **framing review on synthetic data, not representation.** Lead with
[`docs/audits/onboarding.md`](../audits/onboarding.md) and the audit-as-artifact model.

### Best starting points (maintained, county-searchable directories)

| Source | Type | How to approach | Confidence |
| --- | --- | --- | --- |
| **[LawHelpCA.org](https://www.lawhelpca.org/)** — LAAC-operated statewide legal-aid directory | directory | Search **Housing > Landlord/Tenant / Safe and Healthy Housing** by county; build a shortlist of local legal-aid housing units; contact each org's intake/communications or **pro-bono coordinator** (not client intake) with the bounded synthetic-data review ask. Lead with the onboarding scope table. | **high** |
| **[LAAC member directory](https://www.laaconline.org/laacmembers/)** — ~115 IOLTA-funded nonprofits | coalition | Pick direct-service orgs with a housing practice in the target region **plus any housing-focused support center** (technical assistance is their stated role — a natural fit). Contact the housing-unit managing attorney or volunteer coordinator. | **high** |

### Statewide / targeted parallel outreach

| Source | Type | How to approach | Confidence |
| --- | --- | --- | --- |
| **[Tenants Together — Tenant Lawyer Network (TLN)](https://www.tenantstogether.org/tenant-lawyer-network-california)** | tenant-union / lawyer network | Email Tenants Together to ask whether a TLN member would volunteer a short framing review; offer to present at a TLN webinar or post in member channels. **TLN is not a fee-sharing referral service — position as volunteer/pro-bono.** Do not assume a contact name. | **high** |
| **[Western Center on Law & Poverty (WCLP)](https://wclp.org/affordable-housing/)** — statewide housing/community-stability team | legal-aid support center | Contact via the general/housing-team channel proposing a brief pro-bono review of framing + CA references; emphasize synthetic-data-only and the public committed artifact. They may point to a local affiliate. Capacity unverified. | **high (org); capacity unverified** |
| **[UCLA Law — Housing Justice Clinic](https://law.ucla.edu/academics/experiential-program/law-clinic-courses/housing-justice-clinic)** | law-school clinic | Email **HJC@law.ucla.edu** proposing a clinic project: bounded review of framing + CA references on synthetic data. Frame as community-org collaboration; note the FOSS posture and public findings. **Time to the academic calendar.** | **high (contact); acceptance unverified** |
| **[UC Berkeley Law — La Alianza Workers' & Tenants' Rights Clinic](https://www.law.berkeley.edu/experiential/pro-bono-program/slps/current-slps-projects/la-alianza-workers-and-tenants-rights-clinic/)** | law-school clinic | Reach out via the **Berkeley Law pro-bono / SLPS program office** (not students directly) to ask whether a supervising attorney would sponsor a short synthetic-data review. Align to the term. | **high (exists); supervisor availability unverified** |
| **[Stanford Law — Community Law Clinic (Housing)](https://law.stanford.edu/community-law-clinic/housing/)** | law-school clinic | Contact via Stanford Law's clinic channels; pitch as a low-burden, well-scoped **research/policy-style** review (a stated clinic activity). Faculty-supervised, so a steadier contact. Ask the clinic, not an individual. | **medium-high** |
| **[State Bar of CA — Pro Bono Opportunities Directory](https://www.calbar.ca.gov/legal-professionals/volunteer/pro-bono-opportunities)** | bar pro-bono | Use the directory to locate regional **housing pro-bono programs**; contact their volunteer coordinators. Program questions: **PBPP@calbar.ca.gov / 415-538-2252**. Note: the Bar **routes attorneys to providers** — frame the ask through a provider org, not the Bar itself. | **high** |
| **Regional legal-aid housing units** — e.g. LAFLA, Bay Area Legal Aid, LSNC, Community Legal Aid SoCal | legal-aid | Contact each org's **housing-unit managing attorney or volunteer coordinator (not general intake)**. Reference onboarding's reviewer scope. **Confirm current focus/contacts via LawHelpCA/LAAC first** — capacity shifts. | **medium (orgs real; volunteer capacity unverified)** |

### Reference only (to fact-check CA framing, not a reviewer source)

| Source | Type | Use |
| --- | --- | --- |
| **[California Courts Self-Help](https://selfhelp.courts.ca.gov/)** — Housing / Landlord–Tenant | directory | Fact-check CA habitability and forum references before sending them to a reviewer; follow "find legal help" links to local self-help centers and ask which local legal-aid/clinic contacts handle habitability. **Confirm the live URL** — the courts site reorganizes periodically. |

**Two published intake channels** appeared in verified sources and are included only as such:
**HJC@law.ucla.edu** (UCLA Housing Justice Clinic, community-org partnerships) and
**PBPP@calbar.ca.gov / 415-538-2252** (State Bar Pro Bono Practice Program). No individual
lawyer names are asserted as contacts — **approach the program/clinic, not the person.**

---

## 8. Outreach email template (pro-bono, framing review)

> Adjust the bracketed bits per recipient. Keep it short, concrete, and non-salesy. Send to a
> **pro-bono / volunteer coordinator, communications, support-center attorney, or clinic
> program office** — **not** a client-intake line.

**Subject:** Short pro-bono ask — review legal-framing copy for a tenant-evidence tool (synthetic data, not representation)

Hi [org / clinic / coordinator],

I'm Chelsea Kelly-Reif, the maintainer of **habitable** — an independent, open-source,
offline-first tool that helps tenants document habitability problems as tamper-evident
evidence (dated, integrity-checked photos and a verifiable packet). It's an unfunded personal
project, currently **alpha and explicitly not for real legal use**, and it targets
California.

I'm looking for a CA housing/tenant attorney (or a housing clinic) to do a **short, bounded,
volunteer review of framing** — specifically two things:

1. Whether the tool's **"not legal advice / no guarantee of admissibility" disclaimers** are
   honest and adequate, and
2. Whether the **California habitability references** it shows users are accurate and current
   — in **both English and Spanish**.

To be clear about scope: this is **a review of how the tool talks about itself and about CA
law — not legal representation, not advice to any tenant, and it would not create an
attorney–client relationship.** All evaluation is on **synthetic data only**; the project
holds no real tenant data by design.

The project runs "audit-as-artifact," so a review would be **committed to the public repo**,
diffable across releases — and I'm glad to **credit you/your org by name, or keep it
anonymous**, whichever you prefer.

You don't need to install anything. The reviewer scope and run-it-yourself instructions are
here:
- Scope and onboarding: https://github.com/ChelseaKR/habitable/blob/main/docs/audits/onboarding.md
- Privacy / DPIA statement: https://github.com/ChelseaKR/habitable/blob/main/docs/privacy.md
- Threat model: https://github.com/ChelseaKR/habitable/blob/main/docs/threat-model.md

It's a few hours at most, and a single "this overclaims" or "this citation is stale" note
would be genuinely valuable. Would someone on your team be open to it — or could you point me
to the right person? [For clinics: I know clinics scope projects by term, so happy to fit the
academic calendar.]

Thank you for the work you do.

Chelsea Kelly-Reif
ckellyreif@gmail.com · https://github.com/ChelseaKR/habitable

---

## 9. Notes for the maintainer

- Start with **LawHelpCA** and the **LAAC member directory** (maintained, pre-screened,
  county-searchable), and run **TLN, WCLP, and the law-school clinics** as targeted parallel
  outreach.
- Every org above is a **lead, not a commitment** — existence and fit verified June 2026;
  willingness/capacity not.
- **Never use client-intake lines.** Route to pro-bono/volunteer/communications/clinic-program
  channels, and lead with the synthetic-data, not-representation framing.
- Re-confirm live URLs (especially California Courts Self-Help) before sending.
- The §6 CA background is **secondary-source background to be validated** — say so explicitly
  to any reviewer; the reviewer's first job is verifying citations, thresholds, and AB 1482 /
  local-ordinance overlays.
