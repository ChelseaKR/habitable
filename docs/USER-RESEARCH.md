<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# User Research — Synthetic Persona Panel & Simulated Interviews

> [!WARNING]
> **These personas and interviews are synthetic.** They were generated as a
> structured research-and-design device — *not* conducted with real people. No real
> tenant, organizer, lawyer, judge, inspector, auditor, or funder said any of this.
> The panel is a way to pressure-test habitable from many standpoints at once against
> the **actual** implementation (per [`README.md`](../README.md),
> [`ROADMAP.md`](../ROADMAP.md), and the docs) and against **external, citable
> research** on housing law, digital-evidence standards, the tenant-organizing
> movement, comparable tools, and the access realities of low-income tenants. It is
> **not** evidence of demand and does **not** substitute for the real screen-reader
> pass, the real security/cryptographic audit, or the real tenant-union/legal-aid
> pilot named in the [v1.0 gate](../ROADMAP.md#the-v10-gate-when-alpha-comes-off).
> Treat every "quote" as a *hypothesis to validate with real people*, never as a
> finding. Saying so plainly is the same discipline the README's *Honest limits*
> applies to the product itself.
>
> **Last assembled: 2026-06-30.**

## Relationship to other research in this repo

This document is a **complement**, not a replacement, to the prior synthetic study at
[`docs/research/synthetic-personas-feedback.md`](research/synthetic-personas-feedback.md)
and its [`execution-log.md`](research/execution-log.md). That study built a 23-persona
roster and a detailed `R-##`/`E-##` backlog, much of which has since shipped as
documentation and code (see the execution log). **What is new here** is the *external
evidence layer*: every theme is anchored to cited research on warranty-of-habitability
law, the admissibility of digital photos (FRE 901/902, chain of custody, metadata
reliability, RFC 3161 trusted timestamps), landlord retaliation, comparable
evidence-capture tools (ProofMode, eyeWitness, Tella, DV-documentation apps), the
tenant-union movement, language access, disability and housing, and the digital divide.
The companion deliverable, [`RESEARCH-ROADMAP.md`](RESEARCH-ROADMAP.md), carries the
full reference list and a research-backed, re-prioritized backlog. Where this panel
re-raises a need the prior study already logged, the roadmap says so and cites it
rather than claiming novelty.

---

## Method

- **Sampling frame.** Everyone a court-ready, retaliation-aware evidence tool touches:
  the tenants who **document and use** it (across language, age, disability, immigration
  status, device, and connectivity constraints — deliberately over-sampling the
  margins, because that is where this tool earns its purpose or fails it); the people
  who **organize and represent** (tenant-union organizers, a union "tech steward,"
  legal-aid attorneys); the people who **verify and adjudicate** (a housing-court judge
  and clerk, a code inspector, and opposing counsel as a hostile reviewer); the people
  who **assure and audit** (a security/cryptographic reviewer, an assistive-technology
  tester, a localization contributor, a plain-language/trauma-informed reviewer); the
  **adversary** the design must defeat (a retaliating landlord and their lawyer); and
  the people who **operate and sustain** (the solo maintainer, a relay self-hoster, a
  funder, and a downstream interop integrator).
- **Protocol.** Each persona was role-played in two passes: (1) *current implementation*
  — "walk your real task with what habitable does today; where does it help, confuse,
  frustrate, or scare you, and what would stop you using it?"; and (2) *future* — "for
  your goal, what is missing, and what would make you trust, recommend, or fund it?"
  Each card is compressed to five lines: **goal · values today** (grounded only in
  features that *actually exist*) **· gets stuck · wants next · adopts-if / walks-if.**
- **Synthesis.** Frictions become *remediations*; wishes become *expansions*; both are
  triaged, tied back to personas, and — in the roadmap — to external evidence and to the
  project's existing plans. Every candidate was checked against habitable's
  **invariants** (no server-side personal data; no telemetry; no central authority;
  mandatory tamper-evidence; the retaliating-landlord threat model; honesty about
  limits; non-optional accessibility and bilingual reach). Items that *violate* an
  invariant are not built — they are recorded as declined, with an honest alternative.
- **Effort scale (used in the roadmap).** S ≈ an afternoon · M ≈ a few days · L ≈ a week+.

### Research basis (why these personas, and why these frictions are plausible)

The standpoints and stress points below are chosen because external evidence says they
are where habitability documentation actually breaks down:

- **Proof is the tenant's core disadvantage, and bare phone photos are weak.** Courts
  authenticate photographs under [FRE 901](https://www.law.cornell.edu/rules/fre/rule_901)
  by testimony that the image "fairly and accurately depicts" the scene or by
  circumstantial evidence; self-declared **EXIF timestamps are alterable and, on their
  own, rarely clear that bar** once disputed
  ([TrueScreen](https://truescreen.io/insights/exif-metadata-photo-date-court-evidence/),
  [Factually](https://factually.co/fact-checks/media/verify-photo-timestamps-geolocation-edits-0d389a)).
  Hash values and certified electronic processes are what newer rules
  ([FRE 902(13)–(14)](https://www.law.cornell.edu/rules/fre/rule_902)) treat as
  self-authenticating, and **RFC 3161 trusted timestamps** are recognized as strong
  corroborating temporal evidence
  ([Evidency](https://evidency.io/en/rfc-3161-timestamping/),
  [Forensic Notes](https://www.forensicnotes.com/trusted-timestamps/)). This is exactly
  habitable's evidence spine — so the personas' demands cluster on *whether that spine is
  legible and checkable by non-technical recipients*.
- **The warranty of habitability is near-universal but jurisdiction-specific, and notice
  matters.** Every U.S. state now recognizes an implied warranty of habitability by
  statute or case law (Arkansas last, in 2021), but remedies, notice rules, and cure
  periods vary by state and city
  ([Cornell LII](https://www.law.cornell.edu/wex/implied_warranty_of_habitability),
  [Nolo](https://www.nolo.com/legal-encyclopedia/free-books/renters-rights-book/chapter7-2.html)).
  Tenants must usually give **written notice** and document conditions over time
  ([CA OAG habitability guide](https://oag.ca.gov/system/files/media/Know-Your-Rights-Habitability-English.pdf)).
- **Retaliation is a real, structured risk — which is the threat model.** Most states
  prohibit retaliation against tenants who complain or organize, often with a *rebuttable
  presumption* within a 3–6 month window, but Arkansas, Oklahoma, and Wyoming offer no
  protection ([Nolo](https://www.nolo.com/legal-encyclopedia/state-laws-prohibiting-landlord-retaliation.html),
  [Cornell LII](https://www.law.cornell.edu/wex/retaliatory_eviction)).
- **Tenants overwhelmingly face this alone.** Nationally only ~3% of tenants facing
  eviction are represented, versus ~81% of landlords; even in right-to-counsel cities
  funding gaps have driven representation down sharply
  ([NLIHC](https://nlihc.org/resource/14-1-advancing-tenant-protections-right-counsel-tenants-facing-eviction),
  [NYC Comptroller](https://comptroller.nyc.gov/reports/evictions-up-representation-down/)).
  So the realistic distribution channel is **tenant unions and legal aid**, a movement
  that has grown markedly (the Tenant Union Federation formed in 2024; multi-building
  rent strikes have won concessions)
  ([Shelterforce](https://shelterforce.org/2026/05/06/stalled-in-state-houses-tenant-unions-organize-against-landlords-directly/),
  [In These Times](https://inthesetimes.com/article/housing-crisis-tenant-unions-debt-collective)).
- **The protected users sit at the hard end of the access spectrum.** Lower-income adults
  are far more likely to be **smartphone-dependent** with no home broadband (~26% of
  sub-$30k households vs ~5% of $100k+)
  ([Pew](https://www.pewresearch.org/short-reads/2021/06/22/digital-divide-persists-even-as-americans-with-lower-incomes-make-gains-in-tech-adoption/)).
  Spanish speakers are ~65% of the U.S. limited-English-proficiency population, and
  language access in housing is both a civil-rights obligation and a documented failure
  point ([NHLP](https://www.nhlp.org/initiatives/fair-housing-housing-for-people-with-disabilities/language-access/),
  [HUD](https://www.hud.gov/program_offices/fair_housing_equal_opp/limited_english_proficiency_0)).
  Disabled renters are disproportionately cost-burdened and eviction-exposed
  ([Center for American Progress](https://www.americanprogress.org/article/recognizing-addressing-housing-insecurity-disabled-renters/)).
- **Comparable tools validate the pattern and reveal the gaps.** ProofMode (WITNESS +
  Guardian Project) cryptographically signs and timestamps captures for chain-of-custody
  and aligns to C2PA ([WITNESS](https://library.witness.org/product/proofmode/),
  [ProofMode/C2PA](https://proofmode.org/c2pa)); eyeWitness embeds sensor metadata and
  *uploads to a controlled server* reviewed by lawyers
  ([eyeWitness](https://www.eyewitness.global/)); Tella encrypts on-device and can hide
  itself ([WITNESS app guide](https://blog.witness.org/2020/02/use-documentation-app/)).
  DV-documentation tools surface the shared-device / abuser-monitoring threat and often
  store **off-device** — a different privacy bet than habitable's
  ([Safety Net Project](https://www.techsafety.org/choosingapps),
  [DomesticShelters](https://www.domesticshelters.org/articles/technology/lifesaving-apps-for-survivors-of-domestic-violence)).
  And the reason habitable rejects the cloud-honeypot model: a provider holding both
  ciphertext and keys can be compelled to produce data, sometimes silently, under the
  CLOUD Act / Stored Communications Act
  ([DOJ CLOUD Act white paper](https://www.justice.gov/d9/press-releases/attachments/2019/04/10/department_of_justice_cloud_act_white_paper_2019_04_10_final_0.pdf),
  [Wikipedia](https://en.wikipedia.org/wiki/CLOUD_Act)).

> **Jurisdiction caveat.** Every legal statement above is **jurisdiction-dependent and
> changes over time.** Habitability standards, notice and cure rules, retaliation
> presumptions, right-to-counsel coverage, and what a given court will admit vary by
> state, city, and forum. Nothing here is legal advice, and habitable's own
> jurisdiction guidance is currently scoped to California
> (see [`docs/legal/`](legal/README.md)).

---

## Persona roster

| # | Persona | Group | Primary goal | Top friction |
| --- | --- | --- | --- | --- |
| DU1 | **Marisol** — Spanish-dominant, 2018 Android, recurring winter mold | Document & Use | Document a relapsing condition her landlord blames on her | Status jargon in "lawyerly" Spanish; storage pressure |
| DU2 | **Eddie** — withholding rent over a dead heater, mid-winter | Document & Use | Build a notice + timeline that survives an eviction filing | Unsure the record is "court-strong"; what counts as notice |
| DU3 | **Gloria** — 71, hard of hearing, limited dexterity, ceiling leak | Document & Use | Document without "breaking" anything | Fear of irreversible taps; sound-only cues; lost-key dread |
| DU4 | **Daniel** — undocumented, shared phone, max retaliation fear | Document & Use | Document without exposing himself or his household | App is visible/openable by roommates; duress-mode limits |
| DU5 | **Aisha** — blind, screen-reader (VoiceOver/NVDA), no-heat case | Document & Use | Complete a case start-to-finish with assistive tech | Can't *confirm* a capture fired/sealed by ear; verifier output |
| DU6 | **Wesley** — exurban, prepaid data cap, dead zone at home | Document & Use | Document offline and not burn his data plan | Long "awaiting timestamp"; sync data cost; no Wi-Fi-only |
| OR1 | **Renata** — volunteer organizer, 24-unit building campaign | Organize & Represent | Keep ~10 tenants' cases in step and export packets | Onboarding non-tech tenants; "did the sync actually work?" |
| OR2 | **Marcus** — union "tech steward," holds keys + runs relay | Organize & Represent | Not be the single point of failure (or the honeypot) | Where to store recovery blobs; untested restore; rotation |
| OR3 | **Alondra** — legal-aid housing attorney (CA), over capacity | Organize & Represent | Move a packet into evidence; hand it to a paralegal | Needs declaration/foundation scaffolding; discovery scope |
| VA1 | **Hon. R. / Clerk K.** — housing-court pro tem + filing clerk | Verify & Adjudicate | Decide an exhibit's integrity in minutes, no install | Won't run a CLI; a hash table means nothing to the bench |
| VA2 | **Inspector Nguyen** — municipal housing/code inspector | Verify & Adjudicate | Map rooms + dates to code citations | App categories ≠ his code's taxonomy; wants per-room rollup |
| VA3 | **Harlan** — landlord's attorney (hostile reviewer) | Verify & Adjudicate | Discredit the evidence | Will attack timestamp semantics + chain self-authentication |
| AA1 | **Dr. Variyam** — independent security + crypto auditor | Assure & Audit | Verify the claims without trusting the project | Needs spec'd crypto + verifier failure-mode truth table |
| AA2 | **Priya** — AT tester, daily NVDA/VoiceOver user (paid) | Assure & Audit | Confirm a *flow* is completable with AT, not just static axe | No recorded pass yet; PDF not PDF/UA; live-region gaps |
| AA3 | **Thuy** — localization contributor (Vietnamese / Haitian Creole) | Assure & Audit | Add a language without mistranslating the law | Which strings are legally load-bearing; RTL/expansion |
| AA4 | **Sahar** — plain-language / trauma-informed reviewer | Assure & Audit | Make it usable under stress and at low reading levels | "Fixity," "chain of custody," "awaiting timestamp" jargon |
| AD1 | **The retaliating landlord** (and their lawyer) | Adversary | Surveil, deter, and discredit the tenant | Where's the metadata, the duress gap, the forensic trail |
| OS1 | **Chelsea** — solo maintainer / steward | Operate & Sustain | Keep it alive and honest without a team | Every feature is hers to maintain; bus-factor |
| OS2 | **Tomas** — relay self-hoster (union sysadmin) | Operate & Sustain | Run a relay that provably sees nothing sensitive | Prove "no logs"; what metadata can he still see? |
| OS3 | **Della** — mutual-aid / privacy-tech grantmaker | Operate & Sustain | Fund real harm reduction, sustainably | Impact "without surveillance"; bus-factor; sustainability |
| OS4 | **Priyanka** — legal-aid tool integrator (ingests `bundle.json`) | Operate & Sustain | Verify a habitable bundle inside her own app | Is the bundle a stable, documented contract? |

---

## Group 1 — Document & Use (tenants, the protected user)

> The people the threat model exists to protect. Over-sampled at the margins on purpose:
> language, age, disability, immigration status, device, and connectivity.

### DU1 · Marisol — Spanish-dominant, old Android, recurring winter mold
- **Goal:** prove the bathroom mold *keeps coming back* after she reports it, against a landlord who blames her "ventilation."
- **Values today:** the app is genuinely bilingual (EN/ES ships in v1, axe-gated in both languages); the photo-and-note flow is familiar; **no account to create**; the offline demo made sense; packet shared-media metadata is stripped by default.
- **Gets stuck:** *esperando sello de tiempo* ("awaiting timestamp") reads like an error — she left the screen open for a day, afraid to close it; the correct Spanish "sounds like a lawyer"; her phone warns *almacenamiento lleno* because sealed original + shared copy roughly double the footprint.
- **Wants next:** plain, reassuring status copy that says the photo is *already safe*; a "this happened again" action that links a relapse to the **same** issue's timeline (not a new orphan issue); a way to see and safely offload case size.
- **Adopts if:** she can document a winter of mold without the phone filling up or a status scaring her. **Walks if:** "awaiting timestamp" makes her think it failed and she gives up. *(Evidence: Spanish = ~65% of U.S. LEP population — [HUD](https://www.hud.gov/program_offices/fair_housing_equal_opp/limited_english_proficiency_0); persistence/repeat-notice is the substance of a warranty claim — [CA OAG](https://oag.ca.gov/system/files/media/Know-Your-Rights-Habitability-English.pdf).)*

### DU2 · Eddie — withholding rent over a dead heater, mid-winter
- **Goal:** assemble notice + a dated timeline strong enough to defend a rent-withholding position if the landlord files to evict.
- **Values today:** the timeline logs repair requests, landlord silence, and worsening conditions, each hashed and (once online) RFC 3161-timestamped; `habitable letter` drafts a dated repair-request/notice letter with hedged, framing-only language and a standing "not legal advice" disclaimer; one command exports a court/inspector packet with a chain-of-custody/integrity summary.
- **Gets stuck:** he can't tell whether his record is "court-strong" or just neat; he isn't sure his letter satisfies *his state's* written-notice rule; he doesn't know withholding is even available where he lives.
- **Wants next:** a plain "what this proves / what it does not" page on the packet **and** a clear statement that the tool frames, but does not assert, his jurisdiction's notice/withholding rules; pointers to local legal aid.
- **Adopts if:** the packet visibly strengthens his notice-and-timeline story. **Walks if:** he mistakes the letter for legal advice and relies on a wrong deadline. *(Evidence: warranty + written-notice + remedy rules are jurisdiction-specific — [Cornell LII](https://www.law.cornell.edu/wex/implied_warranty_of_habitability), [Nolo](https://www.nolo.com/legal-encyclopedia/free-books/renters-rights-book/chapter7-2.html); the generator is deliberately framing-only — [`letter-generator.md`](letter-generator.md).)*

### DU3 · Gloria — 71, hard of hearing, limited dexterity, ceiling leak
- **Goal:** document a leak from the unit above without "pressing the wrong thing."
- **Values today:** capture is designed to tolerate imprecise pointers and to avoid time limits; every visual status has a text equivalent; there is no stressful account setup.
- **Gets stuck:** "every button feels like a trap" — she wants confirmation and **undo**; any success *chime* she can't hear excludes her; the by-design unrecoverability ("if you forget the passphrase it's just *gone*") terrifies her after her grandson set it up.
- **Wants next:** confirm-and-undo on destructive actions; haptic/visual equivalents for sound cues; a large-type, high-contrast, one-task-at-a-time "assisted mode"; a printed recovery card the organizer can keep for her.
- **Adopts if:** she's reassured she "can't break this." **Walks if:** one mistaken tap looks irreversible. *(Evidence: disabled renters face elevated eviction exposure — [CAP](https://www.americanprogress.org/article/recognizing-addressing-housing-insecurity-disabled-renters/); unrecoverability is intentional — [`threat-model.md`](threat-model.md) §5.)*

### DU4 · Daniel — undocumented, shared phone, maximum retaliation fear
- **Goal:** document conditions without exposing himself or his household to a landlord who has threatened to "call someone."
- **Values today:** the *entire premise* — no central plaintext service, end-to-end encryption at rest and in sync, and default metadata stripping for packet shared media — is why he'd consider it at all; he still needs the planned duress-safe state and clear warnings that sync/share or embedded originals carry metadata.
- **Gets stuck:** the app **icon is right there** on a shared phone; a roommate opening the app might see his case; he fears the case name leaking via notifications or the recents switcher; the docs admit duress mode "is not a guarantee against a coercing or forensic adversary" — he needs that limit *at the moment he turns it on*, not buried in a doc.
- **Wants next:** per-case/per-user separation on a shared device; a discreet-presence option; a "this device is shared" setup that hardens defaults; an honest, plain-language explainer of what duress mode can and cannot stop.
- **Adopts if:** discovery on a shared phone is genuinely unlikely **and** the limits are honest. **Walks if:** the tool implies a safety guarantee it can't keep. *(Evidence: retaliation is a structured, real risk — [Cornell LII](https://www.law.cornell.edu/wex/retaliatory_eviction); shared-device/abuser-monitoring is a known threat class — [Safety Net Project](https://www.techsafety.org/choosingapps); some tools deliberately hide themselves — [WITNESS](https://blog.witness.org/2020/02/use-documentation-app/).)*

### DU5 · Aisha — blind, screen-reader user, no-heat case
- **Goal:** capture → seal → export → verify a no-heat case end to end with assistive technology, with no sighted help.
- **Values today:** accessibility is a **merge-blocking gate**; axe-core passes in EN+ES with keyboard-nav and 320px-reflow tests; the packet ships an accessible `packet.html`; the PDF declares its language and carries an outline; `habitable verify --json` emits a structured report.
- **Gets stuck:** automated axe is necessary, not sufficient — does the *capture* step announce when a photo actually fired and sealed? Is the awaiting-timestamp→timestamped transition an ARIA live-region announcement or does she have to go hunting? Can she read the verifier's verdict structurally?
- **Wants next:** the **recorded** NVDA + VoiceOver pass that's a v1.0 gate item; live-region announcements for async transitions; alt-text authoring at capture so *her* packet is accessible to the next AT user downstream.
- **Adopts if:** she can finish a case start-to-finish by ear. **Walks if:** the camera step gives no confirmation she can perceive. *(Evidence: Section 508 functional-performance criteria target use without vision — [`README` §508](../README.md#accessibility-and-section-508-conformance); the recorded pass is an open v1.0 gate item — [`ROADMAP.md`](../ROADMAP.md#the-v10-gate-when-alpha-comes-off).)*

### DU6 · Wesley — exurban, prepaid data cap, dead zone at home
- **Goal:** document a broken furnace where there's no signal and ration a prepaid data plan.
- **Values today:** offline-first capture is exactly right — the item is hashed and sealed instantly and the timestamp request queues; sync can run over a shared directory / USB with **no relay at all**.
- **Gets stuck:** how long can an item stay "awaiting timestamp" before the evidence is "weaker"? Does sync over the relay eat his data? Might a timestamp fetch fire on cellular and cost him?
- **Wants next:** a clear statement that the hash anchors content **at capture** (the timestamp is an upper bound added later, not the thing that makes it safe); first-class, documented **sneakernet** sync (export an encrypted delta to a USB/SD card handed to the organizer); Wi-Fi-only / metered options and data-cost transparency.
- **Adopts if:** he can document entirely offline and control when bytes move. **Walks if:** he thinks an offline gap silently degrades his evidence. *(Evidence: low-income renters are disproportionately smartphone-dependent with no home broadband — [Pew](https://www.pewresearch.org/short-reads/2021/06/22/digital-divide-persists-even-as-americans-with-lower-incomes-make-gains-in-tech-adoption/); RFC 3161 bounds existence "no later than" gen_time — [`evidence-method.md`](evidence-method.md).)*

---

## Group 2 — Organize & Represent (organizers and legal aid)

> The realistic distribution channel: with ~3% of tenants represented nationally,
> unions and legal aid are how this reaches people
> ([NLIHC](https://nlihc.org/resource/14-1-advancing-tenant-protections-right-counsel-tenants-facing-eviction)).

### OR1 · Renata — volunteer organizer, 24-unit building campaign
- **Goal:** keep ~10 tenants of wildly varying tech comfort in step, and export whole-unit packets for a campaign.
- **Values today:** one command exports a whole-unit packet; the CRDT "just merges" when she and a tenant both edited offline; sharing seals a case to a verified organizer key; the optional relay only ever moves ciphertext.
- **Gets stuck:** onboarding ten non-technical tenants in church-basement Wi-Fi is the actual job, and the setup guide is a *document*, not a workshop; a **silent sync** is a sync she can't trust the night before a hearing; she loses track of which units still need a timestamp or have a broken chain; if a tenant's phone dies, did her sync save the case?
- **Wants next:** a 20-minute workshop kit and printable EN/ES quick-start (these now exist under [`docs/adoption/`](adoption/README.md) — surface them); a sync-confirmation receipt ("you are in sync as of X; received N items"); a local, multi-case "campaign view" with per-unit evidence-health badges; legible peer-sync redundancy ("this case is on 3 devices").
- **Adopts if:** she can onboard a building and *see* that cases are synced and healthy. **Walks if:** she can't tell whether a tenant's evidence is safe. *(Evidence: building-level union drives are the live organizing model — [Shelterforce](https://shelterforce.org/2026/05/06/stalled-in-state-houses-tenant-unions-organize-against-landlords-directly/).)*

### OR2 · Marcus — union "tech steward," holds keys and backups
- **Goal:** make cases survive a lost phone without becoming the single point of failure the project warns against.
- **Values today:** `habitable key rotate | backup | restore` exists with a non-technical walkthrough; the recovery blob uses an **independent** passphrase; there's a published key-custody playbook and a relay operator self-audit.
- **Gets stuck:** where does he store ten families' recovery blobs without becoming "the honeypot the whole project says not to build"? If he rotates keys, what breaks for a tenant offline for a month? He's never tested a restore and is scared to.
- **Wants next:** threshold/split backup guidance so no one person is the honeypot (started in [`key-custody-playbook.md`](key-custody-playbook.md)); a **recovery-drill** mode on a throwaway case; multi-device rotation that degrades gracefully under partial connectivity.
- **Adopts if:** he can be useful without being a liability. **Walks if:** being the steward means being the breach. *(Evidence: the project's own design forbids a central store of secrets — [`threat-model.md`](threat-model.md); custodial key material is the classic re-centralization trap.)*

### OR3 · Alondra — legal-aid housing attorney (California pilot), over capacity
- **Goal:** move a tenant's packet into evidence and hand the routine parts to a paralegal.
- **Values today:** the "not legal advice / no admissibility guarantee" honesty earns her trust; the structured `bundle.json` could plug into her case tooling; CA-scoped legal notes, a declaration/foundation template, and a "what to expect on cross" guide now exist under [`docs/legal/`](legal/README.md).
- **Gets stuck:** the tech is half the job — she needs the **witness-foundation declaration** a tenant signs so a photo "fairly and accurately depicts" the condition (the FRE 901 route); evidence rules differ by state, and she won't extrapolate CA guidance elsewhere; **discovery cuts both ways** — if she produces a packet, can opposing counsel demand the whole union vault?
- **Wants next:** lawyer-vetted, multi-state jurisdiction packs over time; a defensibly **scoped, minimal-disclosure** export; a paralegal-runnable batch mode.
- **Adopts if:** the legal scaffolding makes the tech usable in her forum. **Walks if:** producing a packet exposes more than the issue at hand. *(Evidence: authentication via "fairly and accurately depicts" testimony — [FRE 901](https://www.law.cornell.edu/rules/fre/rule_901); jurisdiction variance — [Nolo](https://www.nolo.com/legal-encyclopedia/free-books/renters-rights-book/chapter7-2.html).)*

---

## Group 3 — Verify & Adjudicate (recipients of the packet)

> The whole value proposition is "the *other side* can verify." These personas test
> whether that's true for people who will never run a CLI.

### VA1 · Hon. R. / Clerk K. — housing-court pro tem and filing clerk
- **Goal:** judge an exhibit's integrity in the minutes available, with no install and no terminal.
- **Values today:** the packet's plain-language "what this proves / what it does not" cover section (now rendered at the top of `packet.html` and the PDF) speaks to the bench; default packet shared-media metadata stripping reduces PII-at-filing risk; the accessible HTML packet is readable.
- **Gets stuck:** "a packet that says *run `habitable verify`* is a packet I will not verify"; an appendix that's "a table of hashes" means nothing without a one-sentence "what a court should conclude, and what it should not."
- **Wants next:** a **zero-install, offline-capable** verification — drag the packet onto a static page (served from the user's own device), confirm integrity with no install, project still hosts nothing; a one-page "for the court" summary stating the **upper-bound** timestamp semantics in plain words.
- **Adopts if:** integrity is confirmable in under a minute without IT. **Walks if:** verification requires a command line. *(Evidence: hash-based self-authentication is what newer rules contemplate — [FRE 902(14)](https://www.law.cornell.edu/rules/fre/rule_902); most tenants are unrepresented, so the bench often *is* the audience — [NLIHC](https://nlihc.org/resource/14-1-advancing-tenant-protections-right-counsel-tenants-facing-eviction).)*

### VA2 · Inspector Nguyen — municipal housing/code inspector
- **Goal:** map a tenant's evidence to rooms, dates, and his jurisdiction's code citations.
- **Values today:** room, category (heat/mold/pests/water/electrical/structural), and a dated, tamper-evident timeline map well to how he works; an official inspection record is itself strong evidence.
- **Gets stuck:** the six built-in categories are "close but not my *code's* categories"; he'd prefer a per-room rollup ("unit 4B, bathroom: 3 issues across 4 months") over a flat issue list.
- **Wants next:** the jurisdiction template library extended to a code/citation **vocabulary**, not just layout; an optional inspector view organized room → condition → timeline.
- **Adopts if:** the packet speaks his code's language. **Walks if:** he has to re-translate every item. *(Evidence: government inspection reports are "highly persuasive" and tenants are told to involve code enforcement — [tenant-rights.com HP action](https://tenant-rights.com/new-york/housing-court-hp-action-for-repairs); template config exists today — [`ROADMAP.md` ws C](../ROADMAP.md#c-apps-sync--platform).)*

### VA3 · Harlan — landlord's attorney (hostile reviewer)
- **Goal:** discredit the evidence in front of the judge. *The most useful persona in the set — every attack he names is a remediation.*
- **Reviews:** "Your timestamp bounds *existence*, not authorship or that the photo is *this* unit on *that* day — I'll argue it's somewhere else." "Your chain shows the *tenant* held the device the whole time — that's self-authentication, not independent proof." "How do I know your verifier isn't cooked?" "Show me one altered pixel that slipped through."
- **Where habitable already answers him:** the packet itself now states authorship/depiction are **not** proven; the verifier is standalone and Apache-2.0 and can be cross-checked with general RFC 3161/hashing tools; there's a published "[how to attack a habitable packet](audits/packet-attack-redteam.md)" red-team doc and a [verifier decision table](verifier-decision-table.md).
- **Wants next (i.e., what the design must keep doing):** the honest upper-bound framing made *unmissable* on the packet so it's the tenant's shield, not a gap; foundation guidance for counsel introducing it; a published fuzz/adversarial test report; an airtight, prominent relay-metadata disclosure that can't be spun as hidden.
- **Defeated if:** the framing is honest and the verifier is independently reproducible. **Wins if:** the tool overclaims and he catches it overclaiming. *(Evidence: EXIF-only dating collapses once disputed — [Factually](https://factually.co/fact-checks/media/verify-photo-timestamps-geolocation-edits-0d389a); authentication is a "sufficient to support a finding" bar a skeptic will probe — [FRE 901](https://www.law.cornell.edu/rules/fre/rule_901).)*

---

## Group 4 — Assure & Audit (independent scrutiny)

> A "verify, don't trust" tool only earns the label after outsiders check it. These are
> the reviewers whose sign-off is the v1.0 gate.

### AA1 · Dr. Variyam — independent security + cryptographic auditor
- **Goal:** confirm the cryptographic claims without trusting the project.
- **Values today:** an "unusually reviewable alpha" — a frozen threat-model baseline, a standalone [`crypto-spec.md`](crypto-spec.md) (KDF/AEAD/sealed-box handshake/salted custody commitments), a [verifier decision table](verifier-decision-table.md), SHA-pinned CI, CodeQL, pip-audit, and a standalone verifier to attack.
- **Gets stuck:** he wants the security *argument* for the custody-commitment scheme, not just the construction; a key-handling narrative (rotation, recovery-blob independent passphrase, in-memory lifetime, device-compromise impact); and a fuzz corpus matched to the decision table.
- **Wants next:** a **funded** independent security + cryptographic audit with findings remediated or formally accepted in `docs/audits/`; reproducible builds finished so a binary can be matched to source; a coordinated-disclosure track record.
- **Adopts if:** the crypto survives his review and the verifier never accepts tampered input. **Walks if:** the spec and the code disagree. *(Evidence: the no-honeypot promise is the safety case — defeating it via compelled cloud production is exactly what local-first + E2E avoids — [DOJ CLOUD Act](https://www.justice.gov/d9/press-releases/attachments/2019/04/10/department_of_justice_cloud_act_white_paper_2019_04_10_final_0.pdf); audit is a v1.0 gate — [`ROADMAP.md`](../ROADMAP.md#a-evidence--cryptographic-assurance).)*

### AA2 · Priya — accessibility tester, daily NVDA/VoiceOver user (paid reviewer)
- **Goal:** confirm a *flow* is completable with AT — capture → seal → export → verify — not just that static pages pass axe.
- **Values today:** axe-gated EN+ES, keyboard-nav and 320px-reflow tests, an accessible HTML packet, a language-declared PDF with an outline — "better than 95% of what I'm hired to test."
- **Gets stuck:** automation can't certify completability; the PDF isn't PDF/UA-tagged (a documented reportlab limit — the HTML packet is the conformant rendering); async transitions and error messages need live-region testing, not static-page axe.
- **Wants next:** the **recorded** end-to-end AT pass as a *recurring* gate (not a one-time pass); recipient guidance pointing AT users to the accessible HTML; capture-time alt-text authoring.
- **Adopts if:** she can complete a whole case by ear and it stays that way each release. **Walks if:** it green-lights a flow she personally can't finish. *(Evidence: disabled tenants are disproportionately housing-insecure, so an unusable tool fails its purpose — [CAP](https://www.americanprogress.org/article/recognizing-addressing-housing-insecurity-disabled-renters/); PDF/UA decision recorded in [`docs/adr/0004`](adr/0004-accessible-html-packet-as-conformant-rendering.md).)*

### AA3 · Thuy — localization contributor (Vietnamese / Haitian Creole)
- **Goal:** add a language to reach her community without mistranslating something legally load-bearing.
- **Values today:** strings live in per-language bundles; an i18n parity test guards completeness; a [localization guide](localization-guide.md) flags legally-sensitive strings.
- **Gets stuck:** which strings (e.g., "not legal advice," the upper-bound disclosure) must **not** be casually translated? Will RTL, date/number formats, and text expansion break layouts?
- **Wants next:** a clean contributor workflow with a pseudo-locale test; an RTL-readiness pass; a per-language glossary of terms-of-art; ≥1 added language with enforced parity.
- **Adopts if:** she can ship a correct locale safely. **Walks if:** a well-meaning translation weakens a legal disclaimer. *(Evidence: LEP need extends well beyond Spanish; meaningful access is a civil-rights obligation under Title VI — [NHLP](https://www.nhlp.org/initiatives/fair-housing-housing-for-people-with-disabilities/language-access/), [NLIHC LEP guidance](https://nlihc.org/resource/hud-issues-limited-english-proficiency-fair-housing-guidance).)*

### AA4 · Sahar — plain-language / trauma-informed reviewer
- **Goal:** make the tool usable by someone documenting at midnight after a fight with a landlord.
- **Values today:** the project avoids time limits; the packet disclosure is written in plainer language than most; quick-starts exist in EN/ES.
- **Gets stuck:** the in-app copy is precise but high reading-level — "fixity," "chain of custody," "awaiting timestamp" are jargon, and stress lowers effective reading age; irreversible actions plus anxious users is a bad combination.
- **Wants next:** a full plain-language pass (EN+ES) with a reading-level target and an in-app glossary; confirm-and-undo and "you can't break this" reassurance throughout; a "calm mode" that strips everything but the next action.
- **Adopts if:** a stressed, low-literacy user can finish a case. **Walks if:** jargon stalls them at the first status screen. *(Evidence: smartphone-dependent, low-income, multilingual users are the core audience — [Pew](https://www.pewresearch.org/short-reads/2021/06/22/digital-divide-persists-even-as-americans-with-lower-incomes-make-gains-in-tech-adoption/).)*

---

## Group 5 — Adversary (the threat the design must defeat)

### AD1 · The retaliating landlord (and their lawyer) — red-team lens
- **Not interviewed sympathetically; modeled to surface remediations.** Where would a resourced, motivated adversary push?
- **Device seizure / forensics.** Image a seized phone, find the vault and the app's traces. → duress mode hides contents but is *not* forensic-proof (documented); the response is point-of-use disclosure (DU4) and hardened at-rest defaults, **not** a false guarantee.
- **Coercion.** Force the tenant to open the app. → the duress state's honest limits; any decoy/duress-data design only if it can be built without overpromising.
- **Metadata at the relay.** Subpoena the relay operator. → pure peer-to-peer needs no relay; no-log, self-hostable relay; metadata-resistance is roadmapped; the disclosure must stay prominent so it can't be spun as hidden.
- **Discrediting in court.** (See VA3.) Attack the semantics and the chain. → honest packet framing + the published red-team doc.
- **Supply chain / social.** Compromise a dependency or pose as a "reviewer/pilot partner." → pinned/hashed deps, CodeQL, pip-audit, planned signed provenance and reproducible builds; private security disclosures; **no central access exists to grant anyway.**
- **Net:** the adversary lens mostly **confirms the architecture** and converts documented limits into *point-of-use disclosure* and *default-hardening*, not new mechanisms. *(Evidence: retaliation is a real, presumed risk in most states — [Cornell LII](https://www.law.cornell.edu/wex/retaliatory_eviction); the cloud-honeypot a competitor would build is precisely the subpoena target habitable refuses — [Wikipedia: CLOUD Act](https://en.wikipedia.org/wiki/CLOUD_Act).)*

---

## Group 6 — Operate & Sustain

### OS1 · Chelsea — solo maintainer / steward (bus-factor)
- **Goal:** keep the project alive and honest without a team.
- **Values today:** `make verify` reproduces the full gate; ADRs capture rationale; the pluggable layers (TSA, transport, templates, locales) let the community extend without growing the core; the sustainability doc names a bus-factor minimum.
- **Gets stuck:** every expansion in this panel is something she alone must keep alive; some popular requests (cloud backup, a login dashboard, analytics) would violate invariants if built as asked.
- **Wants next:** weight every backlog item by maintenance cost; prefer config-/community-extensible surfaces; a `good first issue` lane and a devcontainer to lower the bus-factor; governance evolution as contributors arrive.
- **Adopts if:** the backlog is scoped so the community can carry it. **Walks if:** features each become a permanent maintenance anchor. *(Evidence: sustainability without paid infra is the stated model — [`sustainability.md`](sustainability.md), [`ROADMAP.md` ws D](../ROADMAP.md#d-governance-community-partnerships--sustainability).)*

### OS2 · Tomas — relay self-hoster (union sysadmin)
- **Goal:** run a relay that provably sees nothing sensitive, and tell the union so honestly.
- **Values today:** the relay ships a runbook and a health endpoint; IaC stands one up; it stores ciphertext only and logs only aggregate passthrough counts; there's an operator self-audit and an observability matrix.
- **Gets stuck:** he wants to *prove* to the union he's logging nothing sensitive, and to state precisely what metadata he can still see (who syncs with whom, sizes, timing).
- **Wants next:** a no-log self-audit command and a documented log schema he can attest to; a hardened relay profile (padding/batching) that shrinks observable metadata; the published "what a relay operator can and cannot observe" matrix kept current.
- **Adopts if:** he can run it and honestly attest its limits. **Walks if:** he can't tell the union what he can see. *(Evidence: a relay is a subpoena target unless it holds nothing readable — [`threat-model.md`](threat-model.md) §3.2; metadata resistance is roadmapped — [`ROADMAP.md` ws C](../ROADMAP.md#c-apps-sync--platform).)*

### OS3 · Della — mutual-aid / privacy-tech grantmaker
- **Goal:** fund real harm reduction that will still exist in three years.
- **Values today:** the no-paid-infra, no-vendor-lock-in, no-honeypot thesis is exactly the harm-reduction story she funds; there's a funder-facing impact + sustainability brief.
- **Gets stuck:** "how do you show me it *works* when you measure nothing about users?"; the single-maintainer bus-factor is her biggest risk.
- **Wants next:** an artifact/outcome impact framework (audits completed, pilots run, languages shipped) that requires **no** user surveillance; a scoped audit-funding ask; a contributor-growth plan that fires the shared-governance trigger.
- **Adopts if:** impact is legible without telemetry and the bus-factor is shrinking. **Walks if:** "impact" can only be shown by instrumenting users (which the project forbids). *(Evidence: the tenant movement is a fundable, growing infrastructure need — [In These Times](https://inthesetimes.com/article/housing-crisis-tenant-unions-debt-collective); measuring without surveillance is a stated principle — [`ROADMAP.md`](../ROADMAP.md#measuring-progress-without-surveillance).)*

### OS4 · Priyanka — legal-aid tool integrator (ingests `bundle.json`)
- **Goal:** verify a habitable bundle inside her own legal-aid case-management app.
- **Values today:** the structured bundle is plain, verifiable data; the verifier is Apache-2.0 and embeddable; a formal [`packet-bundle.schema.json`](packet-bundle.schema.json) and [`bundle-schema.md`](bundle-schema.md) with a stability contract now exist, plus a [verifier-embedding cookbook](embedding-the-verifier.md).
- **Gets stuck:** she needs the bundle to be a documented, **versioned** contract with a stability policy, not internal structure she reverse-engineers at her peril.
- **Wants next:** the schema and its semver contract kept stable; a tiny "verify a habitable bundle in ~20 lines" example maintained against the real code.
- **Adopts if:** the bundle is a stable machine contract she can build on. **Walks if:** the format shifts under her. *(Evidence: hash-based self-authentication lets a downstream tool certify a process — [FRE 902(14)](https://www.law.cornell.edu/rules/fre/rule_902); interop is roadmapped — [`ROADMAP.md` ws C](../ROADMAP.md#c-apps-sync--platform).)*

---

## Cross-cutting themes

Patterns raised by many personas at once — where investment pays the broadest dividend.
Each is grounded in external evidence in [`RESEARCH-ROADMAP.md`](RESEARCH-ROADMAP.md).

1. **Recipient verification is the load-bearing gap.** The entire thesis is "the other
   side can verify," yet the people who *receive* packets (VA1, VA3) won't run a CLI, and
   most tenants have no lawyer to do it for them. A **zero-install, offline-capable
   recipient verifier** is the single highest-leverage expansion. *(NLIHC; NYC
   Comptroller; FRE 902(14).)*
2. **Honest limits must live at the point of use.** EXIF-only dating is legally weak and
   a timestamp only bounds *existence*; the tool's credibility depends on saying so *on
   the packet* (VA1, VA3, AD1) and *in the app* when it matters (DU4, DU6). This is
   already partly shipped — keep extending it. *(Factually; FRE 901; RFC 3161 semantics.)*
3. **Status legibility + plain language, in both languages, is the #1 tenant friction.**
   "Awaiting timestamp," "did it save," "am I in sync," "am I safe now" stall tenants
   (DU1, DU5, DU6), organizers (OR1), and AT users (AA2). Reassuring, accessible,
   low-reading-level state communication cuts across every interaction. *(Pew; HUD/NHLP
   LEP.)*
4. **The legal scaffolding is half the product.** Declarations, foundation guidance,
   jurisdiction packs, and a plain "what this proves" page (OR3, VA1, VA3) determine
   whether the evidence is *usable* — non-code work as decisive as the crypto. *(FRE 901;
   jurisdiction variance.)*
5. **Recovery, custody, and shared devices terrify non-technical and high-risk users.**
   By-design unrecoverability is correct but under-supported in UX (DU3, OR2), and shared
   phones are a real exposure surface (DU4). Drills, custody playbooks, co-custodianship,
   and per-case separation are needed — *without* reintroducing a honeypot. *(Safety Net
   Project; threat-model invariants.)*
6. **The protected users are at the hard end of access.** Old devices, prepaid data, dead
   zones, low vision, low literacy, and English-as-a-wall are the norm, not the edge
   (DU1, DU3, DU5, DU6, AA4). Offline-first and accessibility are not features here; they
   are the product. *(Pew; CAP; NHLP.)*
7. **Adoption ≠ documentation; sustainability ≠ a server.** Organizers and funders (OR1,
   OS3) need workshop kits and surveillance-free impact metrics; the maintainer (OS1)
   needs config-/community-driven surfaces over bespoke code. *(Shelterforce; ROADMAP
   "measuring without surveillance.")*

---

## Honest limits of this exercise

- **Synthetic ≠ real.** These are *hypotheses generated by a model role-playing
  personas*, not data from real tenants, organizers, lawyers, judges, inspectors,
  auditors, AT users, or funders. Some findings will evaporate on contact with a real
  user; others no synthetic persona imagined will dominate a real pilot. Use this to
  *widen* the search and *seed* the backlog — then run the real screen-reader pass, the
  real security/cryptographic audit, and the real tenant-union/legal-aid pilot named in
  the [v1.0 gate](../ROADMAP.md#the-v10-gate-when-alpha-comes-off).
- **No demand is demonstrated.** A persona "wanting" something is not a market, a user
  count, or evidence anyone will adopt the tool. The external citations establish that
  the *problems* are real and documented; they do **not** establish that habitable is the
  solution people will choose.
- **Legal claims are jurisdiction-dependent and dated (accessed 2026-06-30).**
  Habitability standards, notice/cure rules, retaliation presumptions, right-to-counsel
  coverage, evidence rules, and admissibility all vary by forum and change over time.
  Nothing here is legal advice; the project's own legal guidance is CA-scoped.
- **Some "personas" are standpoints, not customers.** Opposing counsel (VA3) and the
  landlord (AD1) are adversarial lenses; their value is the remediations they expose, not
  in being served.
- **No telemetry was or should be added to "validate" this.** Validation means talking to
  real people, not instrumenting them — consistent with the project's no-analytics
  invariant.

---

**Next:** the research-backed, triaged backlog and sequencing — with the full external
reference list — is in **[`RESEARCH-ROADMAP.md`](RESEARCH-ROADMAP.md)**.
