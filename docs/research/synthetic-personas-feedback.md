<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Synthetic-persona research: interviews, remediations, and expansions

> **What this is.** A structured, broad-spectrum *synthetic* user-research exercise for
> habitable. It assembles a wide roster of personas across everyone the tool touches —
> tenants, organizers, packet recipients, adversaries, reviewers, builders, and funders —
> "interviews" each on the **current** implementation and on **future** possibilities, and
> distills the result into a single prioritized backlog of **remediations** (fix what
> exists) and **expansions** (build what doesn't).
>
> **What this is NOT — read this first.** These personas are *invented*. No real tenant,
> organizer, lawyer, or auditor was interviewed for this document. Synthetic personas are a
> useful way to widen the search for problems and to pressure-test a design against many
> standpoints at once, but they are **not evidence about real users** and they cannot
> substitute for the real screen-reader pass, the real security/crypto audit, or the real
> tenant-union pilot named in the [v1.0 gate](../../ROADMAP.md#the-v10-gate-when-alpha-comes-off).
> Treat every finding here as a *hypothesis to validate with real people*, never as a
> validated requirement. Saying that plainly is the same discipline the
> [README's "Honest limits"](../../README.md#honest-limits--what-habitable-does-not-do)
> applies to the product itself.
>
> **Status:** working document · generated for the `claude/synthetic-personas-feedback`
> workstream · cross-referenced to `ROADMAP.md` (v0.2.0) and `docs/threat-model.md`.
>
> **What was acted on:** see [`execution-log.md`](execution-log.md) for an honest, per-ID ledger of
> which backlog items were executed (shipped as documentation), which are deferred pending the test
> gate (code/UX), and which need real people (audit, pilot, recorded AT pass, funding).

## Contents

- [Method](#method)
- [How to read the backlog](#how-to-read-the-backlog)
- [Persona roster](#persona-roster)
- [The interviews](#the-interviews)
  - [Cluster A — Tenants (the protected user)](#cluster-a--tenants-the-protected-user)
  - [Cluster B — Organizers and the union](#cluster-b--organizers-and-the-union)
  - [Cluster C — Recipients of the packet](#cluster-c--recipients-of-the-packet)
  - [Cluster D — Legal-aid and pilot partners](#cluster-d--legal-aid-and-pilot-partners)
  - [Cluster E — Assurance reviewers](#cluster-e--assurance-reviewers)
  - [Cluster F — Builders and sustainers](#cluster-f--builders-and-sustainers)
  - [Cluster G — The adversary lens](#cluster-g--the-adversary-lens)
  - [Cluster H — Interoperability consumers](#cluster-h--interoperability-consumers)
- [Cross-cutting themes](#cross-cutting-themes)
- [Master backlog — remediations](#master-backlog--remediations)
- [Master backlog — expansions](#master-backlog--expansions)
- [Requests we should decline (invariant conflicts)](#requests-we-should-decline-invariant-conflicts)
- [Coverage map against the roadmap](#coverage-map-against-the-roadmap)
- [Suggested next steps](#suggested-next-steps)
- [Limits of this exercise](#limits-of-this-exercise)

## Method

Each persona was given a short, consistent script in two passes:

1. **Current implementation.** "Here is what habitable does today (per `README.md`,
   `ROADMAP.md` v0.2.0, and the docs). Walk through your real task with it. Where does it
   help, confuse, frustrate, or scare you? What would stop you using it?"
2. **Future possibilities.** "Forget what exists. For *your* goal, what would the ideal
   version do? What is missing? What would make you trust it / recommend it / fund it?"

Personas were chosen to maximize *coverage of standpoints*, not to be statistically
representative — deliberately over-sampling the margins (high-retaliation risk, assistive
technology, low-end devices, non-English, non-technical, and adversarial reviewers) because
those are where this tool either earns its purpose or fails it.

Every resulting item was then checked against the project's **guiding principles**
(no server-side personal data; no telemetry; no central authority; mandatory
tamper-evidence; retaliating-landlord threat model; honesty about limits; accessibility and
bilingual reach are not optional). Items that *violate* an invariant are not silently
dropped — they are recorded in
[Requests we should decline](#requests-we-should-decline-invariant-conflicts), because the
*reason* a popular request is refused is itself a design artifact worth keeping.

## How to read the backlog

Every backlog item carries:

- **ID** — `R-##` (remediation) or `E-##` (expansion), stable for cross-reference.
- **Sources** — which personas raised it (P-codes from the roster).
- **Severity / Value** — `critical` · `high` · `medium` · `low` (remediations rank by
  user-harm-if-unfixed; expansions by value × reach).
- **Effort** — rough `S/M/L/XL`, a guess pending real scoping.
- **Workstream** — `A` evidence/crypto · `B` a11y/localization · `C` apps/sync/platform ·
  `D` governance/community · `X` cross-cutting / new.
- **Roadmap status** — `planned` (already in `ROADMAP.md`), `implied`, or `net-new`.
- **Invariant check** — `clean`, or a note where the item must be shaped to stay inside the
  principles.

## Persona roster

| P-code | Persona | Cluster | One-line standpoint |
| --- | --- | --- | --- |
| P-01 | **Maritza** — monolingual Spanish speaker, 7-year-old Android, documenting recurring mold | A Tenant | "I just want to take the picture and not break anything." |
| P-02 | **James** — tenant with low vision, screen-reader + large text, no-heat case | A Tenant | "If I can't hear what state the evidence is in, it doesn't exist for me." |
| P-03 | **Dorothy** — 74, hard of hearing, limited dexterity, high stress, water-damage case | A Tenant | "I tapped something and now I'm afraid I deleted it." |
| P-04 | **Tobias** — undocumented tenant, maximum retaliation fear, shares a phone | A Tenant | "If the wrong person opens this phone, I could lose everything." |
| P-05 | **Priya** — software-comfortable tenant, privacy-skeptical, electrical-hazard case | A Tenant | "Prove to me the company can't read it. Don't tell me — show me." |
| P-06 | **Marcus** — rural/exurban tenant, prepaid data cap, dead zone at home | A Tenant | "The 'as soon as you're online' part is the whole problem for me." |
| P-07 | **Renee** — volunteer tenant-union organizer, runs a 30-unit building campaign | B Organizer | "I'm syncing with twelve people who've never used this." |
| P-08 | **Sam** — union's de-facto IT steward, holds backups and keys | B Organizer | "I'm one dropped phone away from losing a family's whole case." |
| P-09 | **Hon. R. / Clerk K.** — housing-court pro tem and filing clerk (recipient) | C Recipient | "I have four minutes per exhibit. Make verification trivial or it won't happen." |
| P-10 | **Inspector Diaz** — municipal code/housing inspector (recipient) | C Recipient | "I need to map your rooms and dates to my code citations." |
| P-11 | **Opposing counsel** — landlord's attorney, hostile reviewer of the evidence | C Recipient | "I will try to break your chain of custody in front of the judge." |
| P-12 | **Alejandra** — legal-aid housing attorney, California pilot partner | D Partner | "Admissibility, foundation, and what I can hand a paralegal to run." |
| P-13 | **Devon** — tenant-union pilot coordinator (org adoption) | D Partner | "Can I roll this out to 40 members in one workshop?" |
| P-14 | **Dr. Okonkwo** — independent security + cryptographic auditor | E Reviewer | "Show me the threat model, the key handling, and the verifier's failure modes." |
| P-15 | **Lena** — accessibility tester who uses NVDA/VoiceOver daily (paid reviewer) | E Reviewer | "Automated axe is table stakes. Can I *finish a case* with AT?" |
| P-16 | **Cognitive/plain-language reviewer** — literacy & trauma-informed UX | E Reviewer | "Reading level, jargon, and what stress does to comprehension." |
| P-17 | **Outside contributor** — new developer, first OSS patch | F Builder | "Can I get the test suite green and find a good first issue?" |
| P-18 | **Maintainer/steward** — solo maintainer carrying bus-factor risk | F Builder | "Every feature I add, I have to keep alive alone." |
| P-19 | **Relay self-hoster** — sysadmin standing up a no-log relay for a union | F Builder | "Operate it safely, prove it logs nothing, and never see plaintext." |
| P-20 | **Localization contributor** — Haitian Creole / Vietnamese translator | F Builder | "Give me a clean string workflow and tell me what I can't translate." |
| P-21 | **Grantmaker** — mutual-aid / privacy-tech funder | F/D Funder | "What's the impact, the sustainability, and the harm-reduction story?" |
| P-22 | **The adversary** — retaliating landlord with resources (red-team lens) | G Adversary | "Where's the metadata, the duress gap, and the forensic trail I can exploit?" |
| P-23 | **Civic/legal-aid tool integrator** — ingests `bundle.json` downstream | H Interop | "Is your bundle a stable, documented, machine contract or a moving target?" |

## The interviews

> Interviews are condensed to: **Profile**, **On the current implementation** (✅ works /
> ⚠️ friction / ❌ blocker), and **On the future** (wishes). Backlog IDs in brackets link
> the quote to the consolidated lists below.

### Cluster A — Tenants (the protected user)

#### P-01 · Maritza — monolingual Spanish speaker, old Android, recurring mold

**Profile.** Speaks and reads Spanish; English is a wall under stress. Phone is a 2018
budget Android with little free storage. Documents bathroom mold that returns every winter;
the landlord blames her "ventilation."

- ✅ **Current.** "The app is in Spanish — *de verdad*, the whole thing, not half." The
  photo-and-note flow is familiar; she doesn't have to make an account. The demo made sense.
- ⚠️ "It says *esperando sello de tiempo* (awaiting timestamp). I don't know if that's bad.
  Did it work or not? I left it on that screen for a day, afraid to close it." → status
  language needs plain-language, reassuring, *what-to-do-next* copy. [R-01, R-02]
- ⚠️ "My phone said *almacenamiento lleno* (storage full). Sealing the original keeps two
  copies? My phone can't do that for a whole winter of photos." → storage pressure on
  low-end devices; sealed-original + shared-copy doubling needs a footprint story. [R-03]
- ⚠️ The Spanish is correct but "sounds like a lawyer." Wants it to sound like a person.
  [R-04 plain-language ES pass]
- ❌ "When the mold came back in January, I had last year's photos but I couldn't tell the
  app *this is the same problem, again*. I made a new issue and now it looks like two small
  problems instead of one that never got fixed." → recurrence/relapse modeling is the core
  of her legal story and the timeline doesn't capture it well. [R-05, E-01]

**On the future.** A "this happened again" button that links a new capture to an existing
issue's timeline. A one-screen, picture-based "what does each status mean" help. A way to
see *how much space* a case is using and safely offload sealed originals to her SD card or
the organizer's phone without breaking the chain. [E-01, E-02, R-03]

#### P-02 · James — low vision, screen reader, no-heat case

**Profile.** Uses VoiceOver on iOS and TalkBack on Android plus large text. Documenting a
dead radiator in winter.

- ✅ **Current.** Encouraged that accessibility is a *merge-blocking gate* and that every
  visual status has a text equivalent by design, and that the packet ships an accessible
  HTML rendering. "Most 'evidence' apps are unusable to me. This one at least tried."
- ⚠️ "axe-core passing is necessary, not sufficient. Does the *capture* step announce when a
  photo is actually taken and sealed? A camera I can't confirm fired is useless." → needs an
  explicit, audited AT walkthrough of the *capture* moment, not just static pages. [R-06]
- ⚠️ The *awaiting-timestamp → timestamped* transition: is it an ARIA live-region
  announcement, or do I have to go hunting? [R-07]
- ❌ "I can't verify a packet myself with AT if `habitable verify`'s output is a wall of
  text with no structure." → verifier output accessibility / structured summary. [R-08]

**On the future.** A recorded NVDA + VoiceOver pass published (he knows it's the v1.0 gate,
wants it prioritized). A "describe this photo" prompt so *he* can add alt text to his own
evidence at capture, making his packet accessible to the *next* AT user downstream. [E-03]

#### P-03 · Dorothy — 74, hard of hearing, limited dexterity, water damage

**Profile.** Arthritis makes precise taps hard. Anxious about technology; terrified of
"pressing the wrong thing." Ceiling leak from the unit above.

- ⚠️ **Current.** "I'm afraid every button is a trap." Wants confirmation and, above all,
  *undo*. "Can I take it back if I tap delete?" → destructive actions need confirm + undo;
  capture must tolerate imprecise pointers (already a stated goal — verify it holds). [R-09]
- ⚠️ Hard of hearing: any reliance on sound (shutter, success chime) excludes her; needs
  haptic/visual equivalents. [R-10]
- ⚠️ "The words are small and there are a lot of them." Wants a stripped, large, one-task
  -at-a-time "assisted mode." [E-04]
- ❌ "My grandson set it up. If he's not here and I forget the passphrase, the lawyer told me
  it's just *gone*?" The by-design unrecoverability terrifies her. → recovery UX and a
  social/assisted backup path that doesn't reintroduce a server. [R-11, E-05]

**On the future.** A guided, large-type, high-contrast "assisted capture" mode; a printed
"in case of trouble" card the organizer can hand her with her recovery blob stored safely.
[E-04, E-05]

#### P-04 · Tobias — undocumented tenant, maximum retaliation fear, shared phone

**Profile.** Shares a phone with two roommates. A landlord who has threatened to "call
someone" if tenants complain. For him, discovery isn't embarrassment — it's existential.

- ✅ **Current.** The whole premise — no server, nothing to subpoena, duress-safe open
  state, location stripped from shared copies — is *why* he'd consider it at all.
- ⚠️ "Duress mode hides the cases. But the *app icon is right there* on a shared phone.
  Someone sees 'habitable,' asks what it is, and now I'm explaining." → app
  disguise / discreet presence, and honest documentation of its limits. [R-12, E-06]
- ⚠️ "If a roommate opens the app, do they see my stuff? We share the phone but not the
  case." → per-case / per-user separation on a shared device. [R-13]
- ⚠️ Worried about the *notification* and *recent-apps* surface leaking a case name. [R-14]
- ❌ Most afraid of the gap the docs admit: duress mode is "not a guarantee against a
  coercing or forensic adversary." He needs that limit in *plain language at the moment he
  turns it on*, not only in the threat-model doc. [R-15]

**On the future.** A panic action that does more than hide (configurable, with documented
limits); a "this device is shared" setup path that hardens defaults; a clear, scary-honest
explainer of exactly what duress mode can and cannot stop. [E-06, R-15]

#### P-05 · Priya — software-comfortable, privacy-skeptical, electrical hazard

**Profile.** Reads threat models for fun. Will not trust a privacy claim she can't check.
Exposed wiring in a kitchen.

- ✅ **Current.** Loves that `verify` is standalone and Apache-2.0, that deps are pinned and
  hashed, that there's an invariant guard test proving no plaintext hits the relay, and that
  it's AGPL to close the hosted-service loophole. "This is the first one that didn't insult
  my intelligence."
- ✅ **Shipped [E-07].** "I want to *see* the ciphertext-only claim myself, not just read that a
  test asserts it. Give me a `--prove-no-plaintext` or a documented packet capture I can run against
  a relay." → `habitable prove-no-plaintext` now runs a real sync through an in-process relay,
  captures every byte on the wire verbatim, and greps it for planted plaintext markers (failing on
  any hit); [`docs/prove-no-plaintext.md`](../prove-no-plaintext.md) documents the equivalent
  `tcpdump`/`tshark` procedure against a self-hosted relay. The invariant is now externally
  demonstrable, not only internally tested.
- ⚠️ Wants reproducible builds finished so she can verify the binary matches source. (Knows
  it's roadmapped.) [planned, E-coverage]
- ⚠️ "Multiple TSAs by default — is it on by default or do I have to know to configure it?
  Defaults are the only thing most people get." [R-16]

**On the future.** A "transparency dashboard" *local to her device* (no telemetry) that
shows, for her own case, exactly what each component would expose externally — a personal
data-flow X-ray. [E-08] — ✅ **shipped** as `habitable status --xray`: a fully-local,
telemetry-free per-component table (capture → nothing, TSA → a hash, relay → sealed blobs + a
mailbox id, export → a plaintext packet you initiate) derived from her own vault, with no network
calls.

#### P-06 · Marcus — prepaid data, dead zone at home, exurban

**Profile.** No home broadband; cell signal drops at the apartment. Prepaid data he rations.
Broken furnace.

- ✅ **Current.** Offline-first capture is exactly right; he can document with no signal and
  the timestamp queues.
- ⚠️ "How long can it stay *awaiting timestamp*? If I'm offline for two weeks, is my
  evidence weaker? Does the queue expire?" → clarity on the integrity meaning of a long
  awaiting-timestamp gap, and reassurance the hash still anchors content at capture. [R-17]
- ⚠️ "Sync over a relay — does that eat my data plan? How much?" → data-cost transparency /
  a low-bandwidth or sneakernet sync path. [R-18, E-09]
- ⚠️ Worried a timestamp fetch fires on cellular and costs him. Wants Wi-Fi-only options.
  [R-19]

**On the future.** "Sneakernet" sync — export an encrypted delta to a file he hands to the
organizer on a USB stick or SD card when they meet, no relay, no data. (Notes the CRDT
already syncs "over a shared directory" — wants that surfaced as a first-class, documented
tenant workflow.) [E-09]

### Cluster B — Organizers and the union

#### P-07 · Renee — volunteer organizer, 30-unit building campaign

**Profile.** Coordinates a rent-strike-adjacent habitability campaign. Syncs with ~12
tenants of wildly varying tech comfort. Burned out, no budget.

- ✅ **Current.** One command to export a whole-unit packet is a superpower. CRDT merge
  "just working" when she and a tenant both edited offline is the dream.
- ⚠️ "Onboarding twelve people who've never done this, in church-basement Wi-Fi, is the
  actual job. The setup guide is good but it's a *document*. I need a 20-minute workshop kit."
  → adoption materials, not just reference docs. [R-20, E-10]
- ⚠️ "When I sync with a tenant, how do I *know* it worked? Did I get their new photos? A
  sync that's silent is a sync I don't trust the night before a hearing." → sync status /
  confirmation / 'you are in sync as of X' receipt. [R-21]
- ⚠️ "I manage many cases. The CLI is fine for me but I lose track of *which units still
  need a timestamp*, which are export-ready, which have a broken chain." → an
  organizer dashboard view (local, multi-case) of evidence health. [E-11]
- ❌ "If a tenant's phone dies, is their case gone, or did my sync save it? I can't tell, and
  that's the thing that keeps me up." → make peer-sync's redundancy *legible* as a safety
  guarantee. [R-22]

**On the future.** A "campaign view": all units, each with an evidence-health badge
(captured / timestamped / chain intact / export-ready), entirely on her device. A
"co-custodian" model so a case survives any one tenant losing their phone. Merge/conflict
review so she can see who changed what without fearing data loss (roadmapped). [E-11, E-12]

#### P-08 · Sam — union IT steward, holds keys and backups

**Profile.** The "computer person." Ends up holding recovery blobs and running the relay.
Not actually a sysadmin.

- ✅ **Current.** `habitable key rotate | backup | restore` exists with a non-technical
  walkthrough; the recovery blob uses an independent passphrase. Relieved this is real.
- ⚠️ "Where do I *store* twelve families' recovery blobs safely? If they're all on my laptop,
  I'm the honeypot the whole project says not to build." → guidance (and tooling) for
  custodial key material without recreating a central point of compromise. [R-23]
- ⚠️ "Rotation across multiple devices — if I rotate, does every tenant's device need to do
  something? What breaks if one is offline for a month?" → multi-device key-lifecycle UX
  under partial connectivity (roadmapped, needs hardening). [R-24]
- ⚠️ "Restore: I've never tested it for real and I'm scared to. I need a *drill* mode —
  practice a recovery on a throwaway case." → a safe recovery-rehearsal path. [E-13]

**On the future.** A documented, opinionated "key custody for unions" playbook (threshold /
split backups so no single person is the honeypot); a recovery-drill command; a clear
"who-can-recover-what" map. [E-13, E-14]

### Cluster C — Recipients of the packet

#### P-09 · Hon. R. / Clerk K. — housing-court pro tem and filing clerk

**Profile.** Sees hundreds of exhibits. Minutes per item. Not technical; will not install a
tool or run a CLI.

- ⚠️ **Current.** "A packet that says 'run `habitable verify`' is a packet I will not
  verify. I don't have a terminal and wouldn't use one." → verification must be possible for
  a non-technical recipient with no install. [R-25 → E-15]
- ⚠️ "Your evidence appendix is a table of hashes. That means nothing to me. *Tell me, in
  one sentence, what a court should conclude and what it should not.*" → a plain-language
  "what this proves / what it does not" cover page (the upper-bound semantics, for a judge).
  [R-26]
- ⚠️ Filing systems often want specific formats/redaction. "Can I file this? Is there a PII
  problem if the original has GPS?" (Shared copies strip location — surface that clearly to
  the recipient.) [R-27]

**On the future.** A recipient-facing verification that's a *drag-the-file-onto-a-web-page*
experience (served from the user's own device or a static, offline-capable verifier page),
so a clerk can confirm integrity with zero install and the project still hosts no case data.
A one-page "for the court" summary at the front of every packet. [E-15, R-26]

#### P-10 · Inspector Diaz — municipal housing/code inspector

**Profile.** Cites code violations. Needs to map evidence to rooms, dates, and code sections.

- ✅ **Current.** Room, category, and dated timeline map well to how he thinks.
- ⚠️ "Your categories (heat, mold, pests, water, electrical, structural) are close but not my
  *code's* categories. Can the packet speak my jurisdiction's language?" → jurisdiction
  template library extends to category/citation vocabulary, not just layout. [R-28, E-16]
- ✅ **Shipped.** Wants a per-room rollup ("unit 4B, bathroom: 3 issues across 4 months") rather
  than a flat issue list. `habitable export --inspector-view` now writes `inspector.html`
  organized room → condition → chronological timeline. [E-17]

**On the future.** Templates that emit a jurisdiction's citation taxonomy; an optional
inspector view organized by room→condition→timeline. [E-16, E-17]

#### P-11 · Opposing counsel — landlord's attorney (hostile reviewer)

**Profile.** Paid to discredit the evidence. The most useful persona in the set — every
attack he names is a remediation.

- 🔎 **Attacks he'll try.**
  - "The timestamp only bounds *existence*, not authorship or that the photo depicts *this*
    unit on *that* day. I'll argue the photo is of somewhere else." → the tool already states
    upper-bound semantics; the *packet* must state it too, prominently, so the tenant isn't
    blindsided — and so the honest framing is the tenant's shield, not a gap. [R-26, R-29]
  - "The chain of custody shows the *tenant* controlled the device the whole time — that's
    self-authentication, not independent proof." → document foundation guidance for counsel
    introducing it; this is a legal-framing gap, not a code bug. [R-30]
  - "How do I know the verifier itself isn't cooked?" → standalone, Apache-2.0, reproducible
    verifier + the ability to cross-check with general RFC 3161/hashing tools answers this;
    make that cross-check a *documented procedure* a skeptic can follow. [R-31]
  - "Show me a single altered pixel slipped through." → fuzzing/property hardening of the
    verifier (roadmapped); publish an adversarial test report. [planned, R-32]
- ⚠️ Will subpoena *something*. The honest answer (relay sees metadata) must be airtight and
  documented so it can't be spun as hidden. [R-33]

**On the future.** A published "how to attack a habitable packet" red-team document — the
project naming its own evidentiary weaknesses before opposing counsel does. That candor is
credibility. [E-18]

### Cluster D — Legal-aid and pilot partners

#### P-12 · Alejandra — legal-aid housing attorney (CA pilot)

**Profile.** Represents tenants for free; chronically over capacity. Cares about
admissibility foundation and what a paralegal can operate.

- ✅ **Current.** The "not legal advice / no admissibility guarantee" honesty earns trust;
  the structured `bundle.json` could plug into her case tooling.
- ⚠️ "I need a **declaration template** — the witness foundation a tenant signs so I can move
  the packet into evidence. The tech is half of it; the legal scaffolding is the other half."
  [E-19]
- ⚠️ "Evidence rules vary by state. California isn't New York. Where's the
  jurisdiction-specific guidance, vetted by a lawyer in that state?" (Pilot is CA-scoped —
  good; document the boundary.) [R-34, E-20]
- ⚠️ "Discovery cuts both ways. If we produce a packet, can opposing counsel demand the
  *whole* union vault? I need the export to be *scoped* and that scoping to be defensible."
  → minimal-disclosure export scoping + documentation. [R-35] ✅ **Done** — each packet now
  self-documents its scope (`scope.statement`/`scope.exclusions` in the signed bundle, rendered
  localized in the packet) and ships [`legal/minimal-disclosure.md`](../legal/minimal-disclosure.md)
  on responding to over-broad discovery.

**On the future.** A jurisdiction pack (CA first): declaration/foundation templates, an
evidence-rule cheat-sheet, and a "what to expect on cross" guide for the tenant. A
paralegal-runnable batch mode. [E-19, E-20]

#### P-13 · Devon — tenant-union pilot coordinator (adoption)

**Profile.** Decides whether an org adopts the tool across dozens of members.

- ⚠️ "I can't train 40 people from a README. I need a workshop deck, a one-pager, and a
  'train-the-trainer' kit." [E-10]
- ⚠️ "What happens when a member quits the union mid-case? Whose data is it? How do we hand
  off custodianship?" → membership-churn / custody-transfer story. [R-36]
- ⚠️ "I need to tell my board what could go wrong, in plain English, before we bet members'
  safety on it." → a plain-language risk briefing for org decision-makers, drawn from the
  threat model. [E-21]

**On the future.** An "adopt habitable" kit: slides, a facilitator script, a printable quick
-start in EN/ES, and a board-level risk/benefit one-pager. [E-10, E-21]

### Cluster E — Assurance reviewers

#### P-14 · Dr. Okonkwo — independent security + cryptographic auditor

**Profile.** Will perform the review that's a v1.0 gate. Skeptical by trade.

- ✅ **Current.** A frozen, content-pinned threat-model baseline (B1), an onboarding doc, a
  DPIA-style privacy doc, SHA-pinned CI, SBOM, signed provenance, invariant guard tests, and
  a standalone verifier to attack. "This is an unusually reviewable alpha."
- ⚠️ "I want the **crypto specification** written down independent of the code: KDF and
  parameters, AEAD construction, the sealed-box sync handshake, the custody-commitment
  scheme (salted actor commitments — show me the construction and its security argument)."
  → a standalone cryptographic design spec, not just source. [R-37]
- ⚠️ "Key handling: rotation, the recovery blob's independent passphrase, what's in memory
  and for how long, and what a device compromise yields." → a key-management security
  narrative beyond the user walkthrough. [R-38]
- ⚠️ "Verifier failure modes: enumerate every way a token/chain/hash can be malformed and the
  *exact* verdict. I want a truth table, then I'll fuzz against it." → a documented
  verifier decision table + the fuzz corpus. [R-39, R-32]

**On the future.** A funded audit (the recruitment + funding playbook exists); a published
report with findings remediated/accepted in `docs/audits/`. A bug-bounty or
coordinated-disclosure track record. [planned]

#### P-15 · Lena — accessibility tester who uses AT daily (paid reviewer)

**Profile.** Blind NVDA/VoiceOver user. Will do the recorded pass that's a v1.0 gate.

- ✅ **Current.** axe-gated EN+ES, keyboard-nav and 320px-reflow tests, accessible HTML
  packet, PDF with language + outline. "Better than 95% of what I'm hired to test."
- ⚠️ "Automated checks can't tell you if a *flow* is completable. Can I, blind, go capture →
  seal → export → verify start to finish without sighted help? That's the test." → fund and
  publish the recorded end-to-end AT pass (gate item). [R-06, planned]
- ⚠️ "The PDF isn't PDF/UA tagged (reportlab limit, I see the ADR). The HTML packet is my
  path — make sure *recipients* know to open the HTML, not just the PDF." → recipient
  guidance to the accessible artifact. [R-40]
- ⚠️ "Error messages and the awaiting-timestamp transitions need live-region testing, not
  just static-page axe." [R-07]

**On the future.** AT-completability as a *recurring* gate, not a one-time pass; alt-text
authoring at capture so tenant-produced packets are accessible downstream. [E-03]

#### P-16 · Cognitive / plain-language reviewer

**Profile.** Specialist in literacy, cognitive load, and trauma-informed design.

- ⚠️ "Your copy is precise but *high reading level*. Tenants documenting under threat are
  cognitively loaded — stress drops effective reading age. 'Awaiting timestamp,'
  'chain of custody,' 'fixity' are jargon." → a full plain-language pass (EN+ES), reading-
  level target, jargon glossary in-app. [R-04, R-41]
- ⚠️ "Irreversible actions + anxious users = disaster. Confirmations, undo, and 'you can't
  break this' reassurance throughout." [R-09]
- ⚠️ "Time pressure: people document at midnight after a fight with a landlord. Avoid time
  limits (you do) and avoid dead-ends with no next step." [R-02]

**On the future.** A trauma-informed content style guide for the project; a "calm mode" that
strips everything but the next action. [E-04, R-41]

### Cluster F — Builders and sustainers

#### P-17 · Outside contributor — first OSS patch

- ✅ `make verify` reproduces the gate; CONTRIBUTING, conventional commits, ADRs present.
- ⚠️ "No `good first issue` set; I don't know where to start or what's wanted." (Roadmapped
  under contributor growth.) [R-42]
- ✅ "Python 3.14 is bleeding-edge — getting the toolchain right took a while. A devcontainer
  or a one-command bootstrap would help." [R-43] — shipped: `./scripts/bootstrap.sh`
  (`make bootstrap`) and a `.devcontainer/` for VS Code / Codespaces.

**Future.** A curated starter-issue lane, a devcontainer, an architecture walkthrough for
newcomers. [R-42, R-43, E-22]

#### P-18 · Maintainer / solo steward (bus-factor)

- ⚠️ "Every expansion here is something I alone keep alive. The sustainability doc names a
  bus-factor minimum — I need features scoped so they don't each become a maintenance
  anchor." → weight every backlog item by maintenance cost; prefer config-driven, community
  -contributable surfaces (templates, locales) over bespoke code. [R-44]
- ⚠️ "Shared governance is triggered by sustained contributors — I need the onramp (R-42) to
  actually fire that trigger." [link]

**Future.** Governance evolution as contributors arrive; ruthless scoping; lean on the
pluggable layers (TSA, transport, templates, locales) so the community can extend without
the core growing. [E-22]

#### P-19 · Relay self-hoster — sysadmin

- ✅ Relay ships a runbook and health endpoint; IaC stands one up; it sees ciphertext only.
- ⚠️ "Prove to *me*, the operator, that I'm logging nothing sensitive — give me a
  no-log self-audit / a log schema doc so I can attest it to the union." [R-45]
- ⚠️ "Metadata resistance (who-syncs-with-whom, sizes, timing) — what can I, the operator,
  see? I want to minimize it and tell the union honestly." (Roadmapped.) [R-46, planned]

**Future.** A hardened relay profile (padding/batching), an operator self-audit command, and
a published "what a relay operator can and cannot observe" matrix. [E-23]

#### P-20 · Localization contributor — Haitian Creole / Vietnamese

- ✅ Strings in per-language bundles; an i18n parity test guards completeness.
- ⚠️ "What's the contributor workflow? How do I test my locale? What strings are *legal* and
  must not be casually translated (e.g., 'not legal advice')?" → a documented localization
  process + a flag for legally-sensitive strings. [R-47]
- ⚠️ "RTL languages, date/number formats, and text expansion will break layouts — is the UI
  ready?" [R-48]

**Future.** A localization-contributor guide, a pseudo-locale test, an RTL-readiness pass,
and a glossary of terms-of-art per language. [E-24]

#### P-21 · Grantmaker — mutual-aid / privacy-tech funder

- ⚠️ "Impact without surveillance — how do you show me it *works* when you measure nothing
  about users?" → an outcomes/artifact-based impact framework (audits done, pilots run,
  languages shipped) packaged for funders. [E-25]
- ⚠️ "Sustainability: who keeps it alive? The bus-factor is my biggest risk as a funder."
  [R-44]
- ✅ The no-paid-infra, no-vendor-lock-in, no-honeypot story is exactly the harm-reduction
  thesis they fund.

**Future.** A funder-facing impact + sustainability brief; a scoped audit-funding ask (the
playbook exists). [E-25]

### Cluster G — The adversary lens

#### P-22 · The retaliating landlord (red-team)

Not interviewed sympathetically — modeled to surface remediations. Where would a resourced,
motivated adversary push?

- **Device seizure / forensics.** Duress mode hides contents but isn't forensic-proof
  (documented). Attack: image the phone, find the vault, find the app's traces. → surface
  the limit at the moment of use (R-15); harden at-rest defaults; document residual risk.
  [R-15, R-49]
- **Coercion.** Force the tenant to open the app. → duress state's honest limits; consider a
  decoy/duress-data design *only if* it can be done without overpromising. [E-06, caution]
- **Metadata at the relay.** Subpoena the relay operator. → pure-P2P needs no relay;
  metadata-resistance workstream; no-log + self-hostable. [R-46, planned]
- **Discrediting in court.** (Covered by P-11.) Attack the semantics and the chain. → honest
  packet framing + red-team doc. [R-26, E-18]
- **Supply chain.** Compromise a dependency or the build. → pinned/hashed deps, CodeQL,
  pip-audit, signed provenance, reproducible builds (in progress). [planned]
- **Social.** Pose as a "reviewer" or "pilot partner" to get access. → vet partners;
  security disclosures go private; no central access exists to grant anyway. [R-50]

**Net.** The adversary lens mostly *confirms* the architecture and converts the documented
limits into **point-of-use disclosure** and **default-hardening** remediations rather than
new mechanisms.

### Cluster H — Interoperability consumers

#### P-23 · Civic / legal-aid tool integrator

**Profile.** Builds a legal-aid case-management tool; wants to ingest `bundle.json`.

- ✅ The structured bundle is plain, verifiable data; the verifier is Apache-2.0 and
  embeddable.
- ⚠️ "Is the bundle a **documented, versioned schema** with a stability contract, or
  internal structure I'm reverse-engineering at my peril?" → publish a formal
  packet/bundle schema + a compatibility policy (the verifier already enforces a versioned
  contract internally — expose it). [R-51, E-26]
- ⚠️ "Give me a tiny embedding example: 'here's how to verify a habitable bundle in 20 lines
  in your app.'" [E-27]

**Future.** A published JSON Schema for the bundle, a semver contract for it, and a
verifier-embedding cookbook. [E-26, E-27]

## Cross-cutting themes

Patterns that surfaced from *many* personas at once — these are where investment pays the
broadest dividend:

1. **Status legibility is the #1 friction.** "Awaiting timestamp," sync state, evidence
   health, "did it save," "am I safe now" — across tenants (P-01, P-06), organizers (P-07),
   and AT users (P-02, P-15). Plain-language, accessible, reassuring *state communication* is
   the single highest-leverage fix. → R-01, R-02, R-07, R-21, E-11.
2. **Verification by the recipient is a missing link.** The whole value is "the other side
   can verify," yet the people who *receive* packets (P-09, P-11) can't run a CLI. A
   zero-install, offline-capable recipient verifier is arguably the biggest expansion gap.
   → E-15.
3. **The legal scaffolding is half the product.** Personas P-12, P-09, P-11 want
   declarations, foundation guidance, jurisdiction packs, and a plain "what this proves" page
   — non-code work that determines whether the evidence is *usable*. → E-19, E-20, R-26.
4. **Plain language + trauma-informed design, in both languages.** P-01, P-03, P-04, P-16
   all hit jargon and anxiety. A reading-level + calm-mode + glossary pass cuts across every
   tenant interaction. → R-04, R-41, E-04.
5. **Honest limits must move to the point of use.** The docs are admirably candid; personas
   need that candor *in the moment* — when turning on duress mode (P-04), when offline a long
   time (P-06), when handing a packet to a court (P-09, P-11). → R-15, R-17, R-26.
6. **Recovery and custody terrify non-technical users.** By-design unrecoverability is
   correct but under-supported in UX (P-03, P-08, P-13). Drills, playbooks, and custody-
   transfer flows are needed — without reintroducing a honeypot. → R-11, E-13, E-14, R-36.
7. **Adoption ≠ documentation.** Organizers and coordinators (P-07, P-13) need workshop
   kits, not just reference docs. → E-10, E-21.
8. **Extensibility is the maintainer's survival strategy.** The steward (P-18) and funder
   (P-21) both point at bus-factor; the answer is config-/community-driven surfaces
   (templates, locales, jurisdiction packs) over bespoke code. → R-44, E-22.

## Master backlog — remediations

> Fixes and hardening of what already exists. Ranked by user-harm-if-unfixed.

| ID | Remediation | Sources | Sev | Effort | WS | Roadmap | Invariant check |
| --- | --- | --- | --- | --- | --- | --- | --- |
| R-01 | Rewrite evidence-status labels in plain, reassuring language (EN+ES): what "awaiting timestamp" means, that the photo is *already safe*, what to do next — **✅ shipped in-app** | P-01,P-06,P-16 | critical | S | B | implied | clean |
| R-02 | Eliminate dead-end screens: every state shows a clear next action; no screen leaves a stressed user stuck — **✅ shipped in-app** | P-01,P-16 | high | S | B | implied | clean |
| R-03 | ✅ **Done.** Storage-footprint UX on low-end devices: show case size; document sealed-original + shared-copy doubling; safe offload path (`Vault.storage_footprint`, `status` storage line, app + docs) | P-01 | high | M | C | done | clean |
| R-04 | Plain-language Spanish pass — correct but human, not "lawyerly"; reading-level target | P-01,P-16 | high | M | B | planned | clean |
| R-05 | Fix recurrence modeling so a relapse links to the *same* issue's timeline, not a new orphan issue | P-01 | critical | M | C | net-new | clean |
| R-06 | Audited AT walkthrough of the *capture* moment (photo fired + sealed announced), not just static pages | P-02,P-15 | critical | M | B | planned | clean |
| R-07 | ARIA live-region announcements for awaiting-timestamp→timestamped and all async transitions; test with AT — **✅ shipped in-app** | P-02,P-15 | high | S | B | implied | clean |
| R-08 | Structure `habitable verify` output (and a summary line) so it's parseable and AT-readable | P-02 | medium | S | A | implied | clean |
| R-09 | Confirm + **undo** on all destructive actions; tolerate imprecise pointers (verify the stated goal holds) | P-03,P-16 | high | M | B/C | implied | clean |
| R-10 | Non-auditory equivalents (haptic/visual) for every sound cue (shutter/success) — **✅ shipped in-app** (success cue) | P-03 | medium | S | B | implied | clean |
| R-11 | Recovery UX: communicate by-design unrecoverability *before* it bites; guided backup at setup | P-03,P-08 | high | M | C | planned | clean (no server) |
| R-12 | Reduce discreet-presence leakage on shared phones: review app name/icon visibility; document limits | P-04 | high | M | C | net-new | clean |
| R-13 | Per-case/per-user separation on a shared device so a roommate can't see another's case | P-04 | high | L | C | net-new | clean |
| R-14 | Audit notification + recents/app-switcher surfaces for case-name leakage | P-04 | high | S | C | net-new | clean |
| R-15 | Surface duress-mode's forensic/coercion limits *in plain language at the moment it's enabled* | P-04,P-22 | critical | S | B/C | implied | clean (honesty) |
| R-16 | Make multiple-TSA redundancy a sane **default**, not opt-in-if-you-know | P-05 | high | M | A | planned | clean |
| R-17 | Document the integrity meaning of a long awaiting-timestamp gap; reassure the hash anchors content at capture — **✅ shipped in-app** (status reassurance copy) | P-06 | medium | S | A | implied | clean |
| R-18 | ✅ **Done.** Data-cost transparency for sync/timestamp over cellular (`SyncResult` byte counters; `sync`/`resolve`/`retimestamp` report bytes used; docs note per-timestamp ~few KB) | P-06 | medium | S | C | done | clean |
| R-19 | ✅ **Done.** Wi-Fi-only / metered-connection options for sync and timestamp fetch (`[network] allow_metered`; `--wifi-only`/`--allow-metered` gate; exposed read-only in the app) | P-06 | medium | S | C | done | clean |
| R-20 | Turn the setup guide into a workshop-ready quick-start (printable, EN/ES) | P-07,P-13 | high | M | D | planned | clean |
| R-21 | Sync confirmation: a clear "you are in sync as of X / you received N new items" receipt | P-07 | high | M | C | planned | clean |
| R-22 | Make peer-sync redundancy legible as a safety guarantee ("this case is backed up on 3 devices") | P-07 | high | M | C | net-new | clean |
| R-23 | Guidance + tooling for custodial recovery-blob storage that doesn't recreate a honeypot | P-08 | high | M | C/D | net-new | shape: must avoid central store |
| R-24 | Multi-device key rotation/lifecycle under partial connectivity — harden and document | P-08 | high | L | C | planned | clean |
| R-25 | Stop assuming recipients can run a CLI; provide a non-technical verification path (→ E-15) | P-09 | critical | — | C | net-new | clean |
| R-26 | Plain-language "what this proves / what it does not" cover page on every packet (upper-bound semantics for a judge) | P-09,P-11,P-22 | critical | S | A/D | implied | clean (honesty) |
| R-27 | Tell recipients clearly that shared copies strip location; flag any residual PII before filing | P-09 | high | S | A | implied | clean |
| R-28 | Let jurisdiction templates speak the recipient's code/citation vocabulary, not just our 6 categories | P-10 | medium | M | C | planned | clean |
| R-29 | Ensure the packet itself (not just the docs) states authorship/depiction are *not* proven | P-11 | high | S | A | implied | clean (honesty) |
| R-30 | Document evidentiary-foundation guidance for counsel introducing a packet (self-auth vs independent proof) | P-11,P-12 | high | M | D | net-new | clean |
| R-31 | Publish a documented cross-check procedure: verify a packet with general RFC 3161/hashing tools | P-11,P-05 | medium | S | A | implied | clean |
| R-32 | Publish an adversarial/fuzz test report for the verifier (no accept-on-tamper, no crash) | P-11,P-14 | high | M | A | planned | clean |
| R-33 | Make the relay-metadata disclosure airtight and prominent so it can't be spun as hidden | P-11,P-22 | medium | S | A/D | planned | clean |
| R-34 | Document the CA-only scope of legal guidance; warn against extrapolation to other states | P-12 | high | S | D | implied | clean |
| R-35 | Minimal-disclosure export scoping + documentation defensible against over-broad discovery | P-12,P-22 | high | M | A | net-new | clean |
| R-36 | Custody-transfer / membership-churn flow: handing off a case when a member leaves | P-13 | medium | M | C/D | net-new | clean |
| R-37 | Write a standalone **cryptographic design spec** (KDF, AEAD, sync handshake, custody commitments) | P-14 | high | M | A | net-new | clean |
| R-38 | Key-management security narrative (rotation, recovery blob, memory lifetime, device-compromise impact) | P-14 | high | M | A | net-new | clean |
| R-39 | Document the verifier decision/truth table for every malformed token/chain/hash case | P-14 | high | M | A | net-new | clean |
| R-40 | Recipient guidance pointing AT users to the accessible HTML packet (not only the PDF) | P-15 | medium | S | B | implied | clean |
| R-41 | Full plain-language pass (EN+ES) with a reading-level target and an in-app jargon glossary | P-16,P-01 | high | M | B | planned | clean |
| R-42 | Curate a `good first issue` set + newcomer architecture walkthrough | P-17,P-18 | medium | S | D | planned | clean |
| R-43 | One-command dev bootstrap / devcontainer for the Python 3.14 toolchain | P-17 | low | S | D | done | clean |
| R-44 | Weight every backlog item by maintenance cost; prefer config/community-extensible surfaces | P-18,P-21 | high | S | D | planned | clean |
| R-45 | Relay operator no-log self-audit + a documented log schema to attest to the union | P-19 | medium | M | C | net-new | clean |
| R-46 | Document precisely what a relay operator can/cannot observe; advance metadata resistance | P-19,P-22 | medium | L | C | planned | clean |
| R-47 | Localization-contributor workflow + flag legally-sensitive strings that must not be casually translated | P-20 | medium | S | B | planned | clean |
| R-48 | ✅ **done** — RTL readiness, date/number formats, and text-expansion layout robustness (CSS logical properties only; `dir` flipped per language via `RTL_LANGS`; `Intl`-keyed date/number formatting; wrap-tolerant chrome; static guards in `tests/test_app_i18n.py`) | P-20 | medium | M | B | net-new | clean |
| R-49 | Harden at-rest defaults against device-forensic recovery; document residual risk | P-22 | high | M | A/C | implied | clean |
| R-50 | Partner/reviewer vetting guidance; keep security disclosures private; confirm no central access to grant | P-22 | low | S | D | implied | clean |
| R-51 | Publish the packet/bundle as a documented, versioned schema with a stability contract | P-23 | medium | M | A | implied | clean |

## Master backlog — expansions

> New capability. Ranked by value × reach. Several directly serve a v1.0-gate item.

| ID | Expansion | Sources | Value | Effort | WS | Roadmap | Invariant check |
| --- | --- | --- | --- | --- | --- | --- | --- |
| E-01 | "This happened again" — link a new capture to an existing issue as a recurrence on one timeline | P-01 | high | M | C | net-new | clean |
| E-02 | Picture-based, plain-language in-app help: "what each status means" | P-01,P-16 | high | S | B | net-new | clean |
| E-03 | Alt-text authoring at capture so tenant-produced packets are accessible downstream | P-02,P-15 | high | M | B | net-new | clean |
| E-04 | "Assisted / calm mode": large-type, high-contrast, one-task-at-a-time capture for stressed/low-vision/low-dexterity users | P-03,P-16 | high | M | B | net-new | clean |
| E-05 | Assisted/social backup path + printable recovery card — no server, no honeypot | P-03,P-08 | high | M | C | net-new | shape: no central store |
| E-06 | Stronger panic/duress action (configurable) + "shared device" hardening setup, with documented limits | P-04,P-22 | high | L | C | net-new | shape: never overpromise |
| E-07 | ✅ **done** — Externally demonstrable "no plaintext to relay": `habitable prove-no-plaintext` (real sync through an in-process relay + verbatim wire capture + marker grep) and a `tcpdump`/`tshark` procedure in [`prove-no-plaintext.md`](../prove-no-plaintext.md) | P-05 | medium | M | A | shipped | clean |
| E-08 | ✅ **done** — On-device, telemetry-free "data-flow X-ray": `habitable status --xray` prints a per-component account (capture → nothing, TSA → hash, relay → sealed blobs + mailbox id, export → plaintext, user-initiated) from the user's own vault, no network | P-05 | medium | M | A | shipped | clean (local only) |
| E-09 | First-class **sneakernet sync**: export/import an encrypted delta via USB/SD, no relay, no data plan | P-06 | high | M | C | implied | clean |
| E-10 | "Adopt habitable" workshop kit: slides, facilitator script, EN/ES quick-start, train-the-trainer | P-07,P-13 | high | M | D | planned | clean |
| E-11 | Local multi-case **campaign/organizer view** with per-unit evidence-health badges | P-07 | high | L | C | net-new | clean (on-device) |
| E-12 | Co-custodian model so a case survives any one tenant losing their device | P-07 | high | L | C | net-new | clean |
| E-13 | Recovery-**drill** mode: rehearse a restore on a throwaway case | P-08 | medium | S | C | net-new | clean |
| E-14 | "Key custody for unions" playbook (threshold/split backups; no single honeypot) | P-08 | high | M | D | net-new | clean |
| E-15 | **Zero-install recipient verifier**: drag a packet onto an offline-capable static page; project still hosts no case data | P-09,P-11,P-25→R-25 | critical | L | A/C | net-new | shape: must host no case data |
| E-16 | Jurisdiction template library extended to citation/category taxonomies | P-10,P-12 | high | M | C | planned | clean |
| E-17 | Inspector view: room → condition → timeline rollup | P-10 | medium | M | C | shipped ✅ | clean |
| E-18 | Published "how to attack a habitable packet" red-team document (name our own weaknesses first) | P-11,P-22 | high | M | A/D | net-new | clean (honesty) |
| E-19 | Declaration / witness-foundation templates a tenant signs to move a packet into evidence | P-12 | high | M | D | net-new | clean |
| E-20 | Jurisdiction pack (CA first): evidence-rule cheat-sheet + "what to expect on cross" tenant guide | P-12,P-13 | high | L | D | planned | clean |
| E-21 | Plain-language board/decision-maker risk-and-benefit briefing drawn from the threat model | P-13 | medium | S | D | net-new | clean |
| E-22 | Lean on pluggable layers (TSA, transport, templates, locales) so the community extends without growing the core | P-18 | high | M | D | planned | clean |
| E-23 | Hardened relay profile (padding/batching) + operator self-audit + observability matrix | P-19,P-22 | medium | L | C | planned | clean |
| E-24 | Localization-contributor guide + pseudo-locale test + RTL-readiness pass + per-language glossary | P-20 | medium | M | B | planned | clean |
| E-25 | Funder-facing impact + sustainability brief (artifact/outcome metrics, no user surveillance) | P-21 | medium | S | D | implied | clean (no telemetry) |
| E-26 | Publish a formal JSON Schema for `bundle.json` with a semver stability contract | P-23 | medium | M | A | implied | clean |
| E-27 | Verifier-embedding cookbook: "verify a habitable bundle in ~20 lines" | P-23 | low | S | A | net-new | clean |

## Requests we should decline (invariant conflicts)

Recording *why* a tempting request is refused is itself a design artifact. These came up
(implicitly or explicitly) and **must not** be built as asked:

| Tempting request | Raised via | Why it's declined | Honest alternative |
| --- | --- | --- | --- |
| "A web dashboard where I can log in and see all my union's cases from anywhere" | organizer/funder convenience | Violates **no server-side personal data** + **no central authority**; creates the exact honeypot the tool exists to avoid | Local multi-case view (E-11) on the organizer's own device |
| "Cloud backup so a lost phone doesn't lose data" | tenants, steward | A project-run cloud is a subpoena target and a honeypot | Peer-sync redundancy (R-22, E-12) + self-custody backups (E-05, E-14) |
| "Anonymous usage analytics so you know what to fix" | funder/impact | Violates **no telemetry, ever** | Artifact/outcome metrics (E-25); this synthetic study + real pilots |
| "A live impact dashboard that streams building-condition stats to funders" | funder/impact (EXP-14) | Any *automatic* upstream flow is telemetry and a central store, no matter how aggregated | The **opt-in aggregate commons** (EXP-14, [`docs/commons.md`](../commons.md)): a union *chooses* to compute a k-anonymous, on-device summary and *manually* decides whether to publish the file — nothing streams, nothing phones home |
| "Password reset / account recovery if I forget my passphrase" | non-technical tenants | Recoverability-by-operator means an operator who can read data; contradicts the whole model | Pre-emptive guided backup + recovery card (R-11, E-05); communicate unrecoverability honestly |
| "Make duress mode guarantee safety against a forensic search" | high-risk tenant | Overpromising in a safety feature can get someone hurt; the limit is real | Disclose the limit at point of use (R-15); harden defaults (R-49) without claiming a guarantee |
| "Auto-detect and flag fake/edited landlord photos" | wishful | The tool proves *our* item wasn't altered after capture; it can't adjudicate truth of depiction | Restate scope honestly (R-26, R-29); the timestamp/hash semantics, not content judgment |
| "Promise this is admissible / will win the case" | adoption pressure | Explicit **non-goal**; legal outcomes aren't ours to promise | Foundation templates + jurisdiction guidance (E-19, E-20), framed as documentation not advice |

## Coverage map against the roadmap

How the synthetic findings line up with `ROADMAP.md` (v0.2.0):

- **Strongly confirms existing roadmap items** — recorded AT pass (R-06), verifier fuzzing
  (R-32), multiple-TSA default (R-16), metadata-resistant relay (R-46), jurisdiction
  templates (R-28/E-16), multi-device key lifecycle (R-24), `good first issue`/onboarding
  (R-42), plain-language pass (R-41/R-04), reproducible/signed builds (Priya, P-05).
- **Sharpens / re-prioritizes existing items** — the personas push **status legibility**
  (R-01/R-07/R-21) and **recipient verification** (E-15) *up* the priority order relative to
  the current roadmap, which under-weights both.
- **Net-new, principle-clean candidates worth adding to the roadmap** — zero-install
  recipient verifier (E-15), recurrence modeling (R-05/E-01), sneakernet sync as a
  first-class tenant flow (E-09), declaration/foundation templates (E-19), the standalone
  crypto spec (R-37), shared-device separation (R-13), co-custodian survivability (E-12),
  and the published red-team packet-attack doc (E-18).
- **Net-new but must be declined** — see the table above; useful to log so they aren't
  re-proposed.

## Suggested next steps

A pragmatic ordering that maximizes harm-reduction per unit of (single-maintainer) effort
and respects the bus-factor constraint (R-44):

1. **Quick, high-leverage remediations (S effort, broad reach):** R-01, R-02, R-07, R-15,
   R-26, R-29 — mostly copy, disclosure, and live-region work that cuts the top cross-cutting
   frictions (status legibility + honest limits at point of use).
2. **Validate the big bets with the real pilot before building:** E-15 (recipient verifier),
   E-19 (declarations), E-01/R-05 (recurrence) — confirm with Alejandra/Devon-type *real*
   partners that these match courtroom reality before investing L effort.
3. **Feed the v1.0 gate:** fund/schedule the recorded AT pass (R-06) and the security/crypto
   audit, supplying the auditor the new artifacts they asked for (R-37, R-38, R-39).
4. **Lower the bus-factor in parallel:** R-42/R-43/E-22 so the rest of this backlog can be
   carried by more than one person.

## Limits of this exercise

- **Synthetic ≠ real.** Re-stating the opening caveat because it's the most important
  sentence here: these findings are *hypotheses generated by an LLM role-playing personas*,
  not data from real tenants, lawyers, auditors, or AT users. Several "findings" may
  evaporate on contact with a real user; others that no synthetic persona imagined will
  dominate a real pilot. Use this to *widen* the search and *seed* the backlog — then go run
  the real screen-reader pass, the real audit, and the real union pilot named in the v1.0
  gate.
- **No new telemetry was or should be introduced** to "validate" this — the project measures
  outcomes and artifacts, not users (E-25). Validation means talking to real people, not
  instrumenting them.
- **Some "personas" are really standpoints.** Opposing counsel and the adversary aren't
  customers; they're lenses. Their value is in the remediations they expose, not in being
  served.
- **Severities and effort are guesses** pending real scoping by the maintainer.
- **This document is itself a remediation candidate:** if/when real interviews happen, this
  file should be updated to mark which synthetic findings were *confirmed*, *refuted*, or
  *reframed* by real users — closing the loop honestly, the same way the project closes audit
  findings.
