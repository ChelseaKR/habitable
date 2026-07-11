# Pilot partner — scoped brief & outreach kit (California)

> **Status: alpha / concept stage.** habitable is unaudited software. This brief recruits
> a California tenant union or legal-aid organization to **pilot the workflow on synthetic
> data only**, and — *much later, and only after an external security audit lands* — on a
> real matter. The entire point of the staged design below is that **no real tenant is ever
> put at risk to evaluate an alpha tool.** This is a request to test and report, not a
> service procurement, and there is no funding ask.

habitable is an alpha, offline-first, end-to-end-encrypted tool intended to help tenants document
habitability problems with tamper-evident media: photos with RFC 3161 timestamp tokens,
SHA-256 fixity, a hash-linked chain of custody, a standalone verifier, and packets whose
shared media is metadata-stripped by default. It is a free and open-source ([AGPL-3.0](../../LICENSE); the verifier is
also Apache-2.0), independent personal project by Chelsea Kelly-Reif, with **no funding**.

This document is a companion to the role brief for the **legal reviewer** (a CA housing/tenant
lawyer who validates the "not legal advice / no guarantee of admissibility" framing in EN and
ES). The two roles are distinct: a pilot partner tells us *whether the workflow and packet fit
a real CA forum*; a legal reviewer tells us *whether the legal framing is accurate*. A pilot
partner is welcome to do both, but neither implies representation of the project.

---

## What we are asking for

A few organizers, counselors, or clinic students run habitable on **generated, synthetic
data**, build and open a packet, try to verify it, and tell us — in writing — **what broke,
what was confusing (in English and Spanish), and whether the produced packet looks usable in
your forum** (local code enforcement, a rent board "decrease in housing services" petition,
small claims, or unlawful-detainer (UD) defense). That is the whole ask for Phase 1. Real
matters come later and are explicitly gated (see [Phase 2](#phase-2--real-matter-after-the-audit-lands)).

This maps to the roadmap's pilot / beta phase (see [`ROADMAP.md`](../../ROADMAP.md)).

---

## Why this fits a CA tenant org's real needs

A CA tenant org evaluating a documentation tool realistically needs five things; habitable is
built around them, and the pilot is how we find out whether the build actually delivers:

- **Workflow fit for non-lawyers/organizers** — capture a defect fast on a cheap phone,
  offline, in EN or ES, without training.
- **Output your forum accepts** — a clean, dated, printable packet a code inspector, rent-board
  clerk, small-claims judge, or UD-defense attorney can actually read, with a plain-English
  explanation of what the timestamp and fixity do and *do not* prove.
- **Tenant-safety boundaries** — no central plaintext data; packet shared-media metadata is
  stripped by default; sealed originals and public custody commitments are disclosed honestly,
  because the data subjects face retaliation.
  This is the project's privacy posture, set out in [`../privacy.md`](../privacy.md) (DPIA-style)
  and [`../threat-model.md`](../threat-model.md).
- **Low operational burden** — no servers to run, no accounts, no funding required; FOSS, so
  you are not locked in.
- **Honesty about maturity** — an org with limited capacity cannot absorb an alpha tool on live
  matters, so the **synthetic-only gate is a feature, not a limitation.**

### CA legal framing this pilot helps test (context only — NOT legal advice)

For an organizer's mental model, and for the legal reviewer to validate: California's implied
warranty of habitability is the backbone, with statutory tenant remedies mainly in Civil Code
§§ 1941–1942 (landlord duty to maintain; repair-and-deduct), the warranty established as a
defense to eviction in *Green v. Superior Court* (1974) 10 Cal.3d 616, and retaliatory-eviction
protection in Civil Code § 1942.5; cities layer on more (e.g., SF Housing/Health Codes and
rent-board petitions). A packet's usefulness differs by forum — (1) **code enforcement /
housing inspection**: photos + dates drive an inspection; (2) **rent board** (rent-controlled
cities): documenting reduced services to win a rent reduction; (3) **small claims**: a tenant
affirmatively suing for habitability damages; (4) **UD defense**: habitability raised as an
affirmative defense under *Green*. In every forum, admissibility turns on authentication and
relevance under the CA Evidence Code, and **a judge — not the tool — decides weight.** Trusted
timestamps and SHA-256 fixity support authentication but **guarantee nothing.** That is exactly
why habitable's "not legal advice / no guarantee of admissibility" framing is load-bearing, and
why the EN and ES surfaces must say the same thing. *None of this paragraph is legal advice; it
is framing for a legal reviewer to confirm.*

---

## Phased pilot design

The pilot is staged so risk only ever rises after a verifiable gate is met.

### Phase 1 — synthetic-data dry run (no real data, no risk)

A few of your people run the demo flow on **generated data only** — no network, no real tenant
information, nothing read off a real device.

```sh
git clone https://github.com/ChelseaKR/habitable.git
cd habitable
uv sync --all-extras
uv run habitable demo                          # builds a synthetic case + signed packet, offline
uv run habitable verify <packet-dir>           # verify it with the independent verifier
uv run habitable app --vault <demo-vault>      # the local web app, EN/ES, to test in a browser
```

(Full instructions, prerequisites, and optional deeper checks are in
[`../audits/onboarding.md`](../audits/onboarding.md) §2–§3 and [`../setup-guide.md`](../setup-guide.md).)

**What you do:** build a packet, open it, try to verify it, and look at it the way your forum
would. **What you report:** what broke, what was confusing in EN *and* ES, and — critically —
whether the produced packet looks usable in your specific forum.

There is **no real tenant data in Phase 1, ever.** It is impossible to harm a tenant by doing
this, which is the point: you can stress an alpha tool with zero exposure.

### Phase 2 — real matter, only after the audit lands

A real matter is touched **only after** all of the following are committed to the repo:

- an external **security + cryptographic audit** with findings remediated or formally accepted
  and re-tested (the roadmap's assurance phase);
- a recorded human **NVDA + VoiceOver accessibility pass**;
- the **legal reviewer's sign-off** on the "not legal advice / no admissibility" framing,
  applied to EN + ES (Phase 2, task 2.5);
- a **signed lightweight MOU** for the pilot (see below).

Until every one of those is true, the alpha caveat stays and habitable **must not be relied on
for a real matter.** We would rather lose a pilot than rush this gate.

### Lightweight MOU note

For Phase 1 a one-page written understanding is enough — and for a decentralized, consensus-run
union it can be a community agreement rather than a formal MOU. It records that:

- the pilot is **synthetic-data-only** unless and until the Phase 2 gate above is met;
- the tool is **unaudited alpha**, used at the partner's discretion;
- the project **holds no tenant data** and operates no service that could (see
  [`../privacy.md`](../privacy.md));
- findings are committed to the public repo under [`../audits/`](../audits/) as
  **audit-as-artifact**, so anyone can diff them across releases; and
- **either side can stop at any time, for any reason.**

We are happy to start from your template or provide a draft.

---

## What we provide

- **Onboarding without a meeting** — [`../audits/onboarding.md`](../audits/onboarding.md) is
  written so you can start cold; §3 covers the synthetic demo specifically.
- **A synthetic demo and the local app** — `habitable demo` and `habitable app`, EN/ES,
  offline, no accounts, no setup beyond `uv`.
- **The standalone verifier** — offered under Apache-2.0 so you (or anyone) can verify a packet
  independently of this project; see [`../evidence-method.md`](../evidence-method.md) and
  [`../../NOTICE`](../../NOTICE).
- **Maintainer support** — direct help during the dry run, on a schedule that fits a volunteer
  or capacity-constrained team.
- **The supporting docs** — [`../privacy.md`](../privacy.md) (DPIA-style),
  [`../threat-model.md`](../threat-model.md), and the frozen baseline B1
  ([`../audits/threat-model-baseline.md`](../audits/threat-model-baseline.md)).

## What we ask in return

**Written outcomes, committed to the repo** (with nothing proprietary or sensitive — synthetic
data only):

- **What broke** — bugs, dead ends, crashes, confusing steps.
- **What was confusing in EN and ES** — wording, flow, accessibility friction.
- **Whether a produced packet was usable in your forum** — would a code inspector, rent-board
  clerk, small-claims judge, or UD-defense attorney be able to read and use it? What is missing?

A finding that contradicts a stated protection, or a forum requirement we missed, is the most
valuable thing you can send us. Pilot outcomes are written up and committed under
[`../audits/`](../audits/) per the project's audit-as-artifact discipline.

---

## CA target list — how to approach each

Drawn from CA pilot research (verified via web search as of 2026-06). **Confidence reflects
that the org and its relevant program exist and fit — not that they will say yes.** Honest
caveats first:

- We did **not** invent people, emails, or phone numbers. Engage each org through the public
  channels on **its own site**, and confirm a current staff contact there before naming anyone.
- Decentralized unions (LATU, TANC) have **no central staff** and run by consensus — approach a
  **specific local chapter**, expect informal engagement, and accept that a formal MOU may come
  late or be replaced by a community agreement.
- Legal-aid orgs and clinics are **capacity- and semester-constrained** — approach **2–3 in
  parallel** and lead with the synthetic-only, no-funding, no-real-data framing to lower their
  risk.
- Some best entry points (ACCE's regional office, the Stay Housed LA coordination contact) must
  still be pinned down on the orgs' own pages.
- Knowledge cutoff is 2026-01 and today is 2026-06 — **re-verify before outreach.**

### Tenant unions & organizing coalitions

| Org | Type | How to approach | Confidence |
| --- | --- | --- | --- |
| **[Tenants Together](https://www.tenantstogether.org/)** | Statewide tenant union (hub) | CA's only statewide renters'-rights org; good *first* conversation to be **routed to a willing local member group** rather than the front-line provider itself. Use the public contact / "Get Involved" channels; lead with: alpha, FOSS, synthetic-data-only, no funding ask. | **high** (org + statewide role confirmed) |
| **[ACCE Action / ACCE Institute](https://www.acceaction.org/)** | Coalition | Grassroots, member-led, 15,000+ members; building- and neighborhood-level organizers are exactly the front-line testers. Contact via general or **regional-office** channels; frame as a volunteer tool evaluation, not procurement. **Confirm which regional office on-site first.** | **medium-high** (role confirmed; best entry point needs confirming) |
| **[Los Angeles Tenants Union (LATU)](https://latenantsunion.org/)** | Tenant union (bilingual, decentralized) | Largest autonomous bilingual (EN/ES) tenants union in the US; building-association repair organizing is a natural fit and its bilingual base **directly stresses the ES surfaces.** Approach a **specific local chapter** ([locals list](https://latenantsunion.org/en/locals)), not a head office; propose a synthetic-data workshop; expect consensus-based, informal engagement. | **high** (structure + bilingual base confirmed) |
| **[San Francisco Tenants Union (SFTU)](https://sftu.org/repairs/)** | Tenant union (counseling + organizing) | Since 1970, explicit habitability/repairs practice; routes tenants to SF Rent Board "decrease in housing services" petitions and code-enforcement complaints — **concrete, forum-specific feedback.** Ask a counselor (via sftu.org) whether the workflow maps to how they advise tenants to document, on synthetic data only. | **high** (habitability focus + rent-board routing confirmed) |
| **[Tenant and Neighborhood Councils (TANC)](https://baytanc.com/)** | Tenant union (Bay Area, decentralized) | Member-run, East Bay focus; volunteer, organizing-first culture suits a synthetic dry run and offers a Bay Area counterpart to LATU for the building-association case. Reach out via general/organizing channels; expect a horizontal, consensus-driven group; confirm the contact route on-site. | **medium** (org + model confirmed; pilot responsiveness unknown) |

### Legal aid, pro bono, and law-school clinics

| Org | Type | How to approach | Confidence |
| --- | --- | --- | --- |
| **[Bay Area Legal Aid (BayLegal)](https://baylegal.org/legal-areas/housing/)** | Legal aid | Housing unit handles evictions, discrimination, and habitability; can evaluate **both** the workflow and whether a packet is usable in UD defense / habitability claims, and credibly co-sign whether the framing holds in CA forums. Approach via **partnerships channels (not client intake)**; lightweight MOU; explicitly no real client data pre-audit. | **high** (housing/habitability practice confirmed) |
| **[Legal Aid Foundation of LA (LAFLA)](https://lafla.org/get-help/housing-homelessness/)** | Legal aid | Eviction Defense Center framed around the right to a safe, habitable home; member of the **Stay Housed L.A.** collaborative. Strong for UD-defense / habitability forum-usability feedback and a gateway to the broader collaborative. Contact via partnerships/communications; synthetic-data review; no real client data until the audit lands. | **high** (eviction-defense work + collaborative membership confirmed) |
| **[Public Counsel — Housing Justice / Eviction Defense](https://publiccounsel.org/issues/housing-justice/eviction-defense/)** | Pro bono law office | Bridges legal-aid and pro-bono-bar worlds; can supply **both** pilot feedback **and** a credible review of CA habitability references and admissibility framing. Reach the Housing Justice team via publiccounsel.org; frame as synthetic-data evaluation + possible pro-bono framing review (distinct from representation). | **high** (housing-justice/eviction-defense practice confirmed) |
| **[Stanford Community Law Clinic — Housing](https://law.stanford.edu/community-law-clinic/housing/)** | Law-school clinic | San Mateo County; represents tenants in eviction, works habitability defects as affirmative defenses; **ideal low-stakes pilot/review partner** — supervised, academic, motivated to test new tools, and can review CA framing in EN (and recruit Spanish-speaking students for ES). Email the director/supervising attorney; propose a **semester-bounded** synthetic-data evaluation + framing review as a teaching artifact. Confirm the current director on-page. | **high** (habitability-as-affirmative-defense work confirmed) |
| **[UCLA Law Housing Justice Clinic](https://law.ucla.edu/academics/experiential-program/law-clinic-courses/housing-justice-clinic)** (+ USC Gould, UC Irvine CED, UC Law SF, Loyola LA) | Law-school clinics | A cluster taking limited-scope and full UD-defense cases — multiple low-risk options, bilingual student capacity for ES, and academic interest in evidence tooling and the admissibility question. **Approach 2–3 in parallel** since availability is semester-dependent. | **medium-high** (clinics exist; each clinic's capacity must be confirmed individually) |

### Discovery & coalition layers (find the right local org)

| Resource | Type | How to use | Confidence |
| --- | --- | --- | --- |
| **[LawHelpCA legal-aid directory](https://www.lawhelpca.org/)** (maintained by Legal Aid Association of California) | Directory | Authoritative county-by-county directory of legal-aid offices and lawyer-referral services. Use the "Search legal directory" / by-service-area tool to find the housing/landlord-tenant provider in a **target county**, then contact those orgs via their own sites. A **discovery and verification layer**, not a pilot partner. | **high** (LAAC maintenance + active directory confirmed) |
| **[Stay Housed L.A. County collaborative](https://dcba.lacounty.gov/trtc/)** | Coalition | LA County + tenant orgs + legal providers (LAFLA, Bet Tzedek, Community Legal Aid SoCal, Housing Rights Center, Inner City Law Center, Neighborhood Legal Services LA, Public Counsel, BASTA, Eviction Defense Network). **One entry point reaches many UD-defense / code-enforcement-adjacent orgs.** Identify the coordination contact via LA County DCBA pages; treat as a referral network and engage individual members for the actual pilot. | **medium** (collaborative + member list confirmed; best single contact needs confirming via DCBA) |

---

## Ready-to-send outreach email template

Lead with the no-risk dry run. Adapt the bracketed parts; confirm a current contact on the
org's own site before sending. Keep the alpha caveat explicit.

> **Subject:** A no-risk, synthetic-data dry run of a free tenant-evidence tool — would [ORG] take a look?
>
> Hi [NAME / "[ORG] team"],
>
> I'm Chelsea Kelly-Reif, an independent developer. I built **habitable**, a free and
> open-source tool that helps tenants document habitability problems as well-organized,
> tamper-evident evidence — photos with trusted timestamps, integrity hashes, a chain of
> custody, and a printable packet anyone can verify independently. It runs offline on a phone,
> in **English and Spanish**, with no accounts and no central server.
>
> I'm reaching out to ask whether a few of your organizers, counselors, or clinic students would
> be willing to **try it on synthetic (made-up) data and tell me what breaks** — and, most
> importantly, whether a packet it produces would look usable in your forum (code enforcement, a
> rent-board petition, small claims, or UD defense).
>
> **Three things up front, because they should lower your risk to near zero:**
>
> 1. **It's alpha and unaudited.** The dry run uses **only generated, synthetic data — never a
>    real tenant's information.** It's impossible to expose a real tenant by doing this. Real
>    matters are explicitly off the table until an external security audit and a lawyer review of
>    the legal framing are completed and published.
> 2. **There's no funding ask and no service to buy.** It's a volunteer tool evaluation. The
>    project holds **no tenant data** and operates no service that could — I can't see, store, or
>    leak anything.
> 3. **Either side can stop anytime.** For Phase 1 a one-page understanding (or a community
>    agreement) is plenty.
>
> What I'd provide: a short onboarding you can start without a meeting, the demo and local app,
> the standalone verifier, and direct help on your schedule. What I'd ask back: a brief written
> note on what broke, what was confusing in EN and ES, and whether the packet fits your forum —
> committed to the public repo (synthetic data only, nothing sensitive).
>
> The project is here: https://github.com/ChelseaKR/habitable — onboarding at
> `docs/audits/onboarding.md`, privacy posture at `docs/privacy.md`.
>
> One caveat in plain terms: habitable produces well-documented evidence, but it is **not legal
> advice and guarantees nothing about admissibility** — a judge decides weight, not the tool.
> Validating exactly that framing is part of why I want experienced eyes on it.
>
> Would a low-stakes synthetic dry run be of interest? Happy to work entirely around your
> capacity.
>
> Thank you for the work you do,
> Chelsea Kelly-Reif
> [contact]

---

## Related

- [`../audits/onboarding.md`](../audits/onboarding.md) — reviewer & pilot onboarding (start here)
- [`../privacy.md`](../privacy.md) — DPIA-style privacy statement
- [`../threat-model.md`](../threat-model.md) and baseline B1
  ([`../audits/threat-model-baseline.md`](../audits/threat-model-baseline.md))
- [`ROADMAP.md`](../../ROADMAP.md) — the assurance and pilot gates this brief depends on
- [`../evidence-method.md`](../evidence-method.md) — what a packet is and how the verifier checks it
