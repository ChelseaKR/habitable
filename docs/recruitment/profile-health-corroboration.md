# Profile review: `health_corroboration` — for a clinician who has written housing letters

> **Bounded, unpaid, synthetic data only.** A review of *framing* — what a workflow says and
> in what order — not medical advice, not a privacy-law opinion, not an endorsement. Shared
> terms (what a profile is, what the review is not, credit, conflicts) are in
> [profile-reviews.md](profile-reviews.md); this page is only what is specific to
> `health_corroboration`. **One profile is a complete contribution.**

habitable is an alpha, offline-first tool that helps a tenant document housing conditions as
tamper-evident evidence. This profile is the "the tenant is also carrying something a
clinician wrote" case. It ships implemented and marked `external_review_required`: the
project's own plan said to build it only with a clinical or legal partner, and it was built
without one.

## Who this is for

Someone who has **actually written a letter about a patient's housing**: a primary-care or
pediatric clinician, a community-health-center provider, a public-health nurse or
environmental-health worker, a social worker or case manager who drafts these for a
clinician's signature, a medical-legal-partnership clinician. The specific expertise wanted
is what you put in such a letter, what you refuse to put in it, and why.

You do not need to know anything about the software. Nothing here asks you to evaluate
security, storage, or encryption.

## What the profile actually asserts

Verbatim from [`src/habitable/usecases.py`](../../src/habitable/usecases.py):

- **Name:** "Health corroboration handoff" (Spanish: "Entrega de corroboración de salud")
- **Summary:** *"Preserve tenant-chosen supporting material without inferring medical
  causation."*
- **Document types it declares:** `clinician_letter`, `supporting_letter`
- **Relationship types it declares:** `supports`, `documents_condition`
- **Reading order it declares:** `condition` → `tenant_statement` → `optional_support` →
  `limits`
- **Its disclosure, which travels with the export and cannot be suppressed:**
  *"Habitable is not a medical record and does not infer diagnosis or causation."*

What it does, precisely:

- **It stores a file the tenant already has.** A letter is hashed, timestamped, and sealed
  into the tenant's own encrypted case. The "issuer" is a free-text string the tool never
  verifies — nothing authenticates that a clinician wrote it, and the tool says so.
- **It never contacts a provider.** There is no clinician-facing screen, no portal, no
  request sent to a practice, and no interface to any health record system. "Handoff" here
  means the tenant carries something, in both directions.
- **It infers nothing.** No symptom fields, no diagnosis fields, no exposure model, no
  scoring, and no statement anywhere connecting a housing condition to a health outcome.
  The tenant's own account is kept as a tenant statement, presented distinctly from what the
  tool can actually check.
- **What goes in, goes everywhere the case goes.** Packets export the whole case; scoped
  export is deliberately blocked. A letter sealed into a case travels with every later
  export of that case, to whoever the tenant sends it — and a packet already sent cannot be
  recalled.
- **It has had no health-privacy analysis.** The project's own plan says one is needed even
  though habitable is not acting as a covered entity, and it has never been done. **This
  brief does not tell you what any health-privacy rule requires, and the project does not
  claim to know.** If your answer is "get that analysis before shipping this", that is a
  legitimate outcome of the review.

## The questions this profile needs answered

1. **When you write a housing letter, what is in it — and what do you deliberately leave
   out?** That answer alone is most of what this profile is missing.
2. **Would you write it differently knowing what happens to it here?** The letter is hashed,
   timestamped, sealed into a tenant-controlled record, and may be forwarded to a landlord,
   an agency, or a court inside a packet, permanently and without a way to withdraw it.
   Does that change what you would sign?
3. **Is "corroboration" the right word?** It implies the letter confirms something. Does a
   clinician's housing letter corroborate a condition, or does it only report what a patient
   said and what the clinician observed clinically? If the word overstates, what would you
   use?
4. **Does the reading order match how such a letter is read?** condition → tenant statement
   → optional support → limits.
5. **Is there anything here that would push a tenant to ask you for something you should not
   write?** A causation opinion linking a condition to an illness is the obvious risk. Does
   the profile's language invite it, and if so, where?
6. **What should the tool tell a tenant before they attach your letter?** Today it says
   nothing at the moment of attaching. What is the one sentence that would prevent the most
   harm — about who will see it, about what cannot be taken back, or about something else?
7. **Should the tool hold clinical material at all?** A defensible answer is no: keep the
   housing record and the medical letter apart, and let the tenant carry the letter
   separately. If that is your view, say so — it is the most useful finding this review
   could produce.

### If you only have twenty minutes

Answer 1 and 5. What you actually write, and what this might wrongly invite you to write.

## What would make this fail review

- The framing invites, implies, or rewards a causation claim a clinician should not make.
- "Corroboration" or "handoff" misdescribes the letter's role or implies a clinical channel
  that does not exist.
- The workflow would foreseeably move health information further than the housing matter
  requires — especially given whole-case export and the impossibility of recalling a sent
  packet — and the tool does nothing to slow that down.
- The honest conclusion is that a health-privacy analysis has to happen before this ships to
  anyone, in which case the profile stays gated on that rather than on wording.
- Clinicians would not write these letters at all under these conditions, which makes the
  workflow a burden on patients rather than a support.

## What this review is not

Not medical advice, not an opinion about any real patient, not a privacy-law or regulatory
opinion, and not a certification of habitable, which stays alpha regardless. Not a review of
the tool's storage or encryption — that is the security track. **No real patient material,
chart, or letter is involved at any point**, and none should be: the demo generates its own
synthetic case.

## How your answer is recorded

A dated entry for `health_corroboration` in the public capability ledger
([`docs/capabilities.md`](../capabilities.md)), the profile's `reviewer` and `reviewed_at`
fields filled in, and an expiry date if your read depends on practice norms that shift.
Credit or anonymity is your call
([profile-reviews.md](profile-reviews.md#credit-and-conflicts-of-interest)) — role-only
credit ("a primary-care clinician, 2026-09") is common and completely fine here.

## Finding this reviewer (maintainer note)

No verified leads; channel types only. **Never a clinical intake line, a patient portal, or
a practice's appointment channel.**

- **Medical-legal partnerships** — clinicians there write housing letters as part of the
  work and already think about the legal recipient; the likeliest yes.
- **Community health centers' population-health, quality, or advocacy staff**, rather than
  clinical scheduling.
- **Public-health environmental-health programs** (housing, lead, asthma-home-visiting), where
  the housing–health link is the job.
- **Academic clinicians** in family medicine, pediatrics, or public health who publish on
  housing and health.
- **Professional-association housing or health-equity committees**, which review materials as
  a matter of course.

Lead with: twenty minutes, one page, unpaid, synthetic data, no patient, no clinical
opinion, credit optional.

## Outreach note

> **Subject:** 20 minutes from a clinician who writes housing letters (unpaid, no patient
> data)
>
> Hi Dr. [name],
>
> I maintain **habitable**, an open-source, offline tool that helps tenants keep a
> tamper-evident record of housing conditions — dated photos, hashes, timestamps. Unfunded
> personal project, **alpha, explicitly not for real use yet**.
>
> One of its workflows lets a tenant keep a clinician's housing letter alongside that record.
> It has no diagnosis fields and makes no causation claims, but **no clinician has ever read
> it**, so it ships marked as needing outside review rather than pretending otherwise.
>
> The ask: one page, and two questions — when you write a housing letter, what do you
> deliberately leave out? And is there anything in this workflow's language that would push a
> patient to ask you for something you should not write?
>
> Unpaid, **no patient data of any kind** (the demo generates synthetic cases), not a
> clinical opinion, not a privacy-law question, and nothing you would be answerable for. I
> can credit you by name, credit the role only, or record it anonymously.
>
> A completely legitimate answer is "this should not hold clinical material at all" — that
> would be the most useful thing I could hear.
>
> The brief:
> https://github.com/ChelseaKR/habitable/blob/main/docs/recruitment/profile-health-corroboration.md
>
> Chelsea Kelly-Reif · ckellyreif@gmail.com · https://github.com/ChelseaKR/habitable
