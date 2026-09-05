# Profile review: `inspector_handoff` — for a code-enforcement or housing inspector

> **Bounded, unpaid, synthetic data only.** This is a review of *framing* — what a workflow
> says and in what order — not legal advice, not a code determination, and not an
> endorsement of anything. The shared terms (what a profile is, what the review is not, how
> credit and conflicts are handled) are in
> [profile-reviews.md](profile-reviews.md); this page is only what is specific to
> `inspector_handoff`. **One profile is a complete contribution.**

habitable is an alpha, offline-first tool that helps a tenant document a habitability
problem as tamper-evident evidence — dated photos, hashes, timestamps, a chain of custody —
and hand it to somebody. This profile is the "somebody is an inspector" case. It ships
implemented and marked `external_review_required`, because no inspector has ever read it.

## Who this is for

Someone who **receives tenant-supplied documentation and has to decide what to do with
it**: a municipal or county code-enforcement officer, a housing or building inspector, a
health-department sanitarian, or someone who trains or supervises them. Retired or former
counts, and may be easier — you can say what the job is like without asking your employer.

You do not need to know anything about software, cryptography, or this project. The
question is entirely about your side of the counter.

## What the profile actually asserts

Verbatim from [`src/habitable/usecases.py`](../../src/habitable/usecases.py):

- **Name:** "Inspector handoff" (Spanish: "Entrega para inspección")
- **Summary:** *"Organize room, condition, chronology, and support for an inspector."*
- **Document types it declares:** `inspection_report`, `repair_request`, `delivery_receipt`
- **Relationship types it declares:** `inspection_finding_for`, `documents_condition`,
  `supports`

Those two lists are the workflow's published vocabulary, not a restriction: nothing stops a
tenant attaching any of the tool's other document types to a case using this profile.
- **Reading order it declares:** `rooms` → `conditions` → `chronology` →
  `supporting_artifacts`
- **Its disclosure, which travels with the export and cannot be suppressed:**
  *"This profile is not an inspector finding or code determination."*

Two things it deliberately does **not** assert, so you are not reviewing them: it names no
statute, code section, or ordinance anywhere, and it makes no claim about whether anything
in the packet is admissible or sufficient.

## What you would actually be looking at

Exporting a synthetic packet with this profile produces a page,
`handoff-inspector_handoff.html`, whose full body is a heading, the summary sentence, the
external-review warning, a whole-packet count, the four section headings — **empty, with
nothing filed under them** — and the disclosures. Here is the real rendered text from a
two-photo demo case, complete:

> **Inspector handoff**
> Organize room, condition, chronology, and support for an inspector.
> **External review required.** This workflow is implemented for synthetic evaluation; it
> is not a legal, medical, inspector, or accessibility approval.
> **This handoff as a whole** — 2 evidence item(s), of which 0 document(s), across 1
> condition(s), with 0 stated relationship(s). These totals cover the whole packet.
> The headings below are the order this recipient is expected to read in. This packet does
> not record which record belongs to which heading, so no heading claims a count of its
> own; `bundle.json` lists every record.
> **Rooms · Conditions · Chronology · Supporting Artifacts**
> **Limits and disclosures** — Scope: the whole unit — every issue recorded in this vault
> is included. · 2 media item(s) included as shared copies · all embedded metadata stripped
> from supported shared media · custody identities not exported · This profile is not an
> inspector finding or code determination.

The evidence itself is in the packet's main page (`packet.html`) and in the signed
`bundle.json` — which, note, do not mention the profile at all. Behind those headings, the
tenant's own record uses a free-text **room** field, a short condition vocabulary (heat,
mold, pests, water, electrical, structural, and an "other" escape hatch), and a severity
scale (low, moderate, severe, emergency, other) that the code describes as habitable's own
operational vocabulary carrying no legal meaning.

That is the whole thing. It is a small object, and the review is correspondingly small.

## The questions this profile needs answered

1. **Is that reading order yours?** The profile asserts room → condition → chronology →
   supporting documents. Is that how you actually work through a complaint, or do you start
   somewhere else — address and unit, prior complaint history, the reporting party, access?
2. **Can you accept a thing like this at all?** Does your department take tenant-supplied
   documentation, in what form, and what happens to it when you do — does receiving it open
   a record, create a disclosure obligation, or oblige a response? A workflow that produces
   something you must refuse is worse than nothing.
3. **Does the name mislead?** "Inspector handoff" describes who it is *for*. Could a tenant,
   a landlord, or a court read it as something an inspector produced, endorsed, or accepted?
   Is the disclosure sentence enough to prevent that, and is it the right sentence?
4. **What do you always need that is not here?** Unit or parcel identifiers, access
   instructions, a prior case or complaint number, who was present, contact details,
   the date the landlord was told — name the things whose absence would make you set this
   aside.
5. **Does any of this vocabulary collide with a term of art?** `inspection_report`,
   `inspection_finding_for`, "finding", "condition", the severity words — if any of these
   already mean something specific in your work, and this use of them would confuse or
   mislead, that is the highest-value thing you can tell us.
6. **Does arriving with a packet help the tenant or hurt them?** Honestly. Does an
   organized, timestamped, hash-verified submission read as prepared, or as coached and
   adversarial? Does it change how the complaint is handled, for better or worse?
7. **Should this profile let a tenant record your report at all?** It offers
   `inspection_report` as a document type — the tenant's own copy of an inspection result,
   with the issuer as a free-text assertion the tool never verifies. Is that useful, or is
   it an invitation to misrepresent an official document?

### If you only have twenty minutes

Answer 1, 2, and 5. Those three carry most of the risk.

## What would make this fail review

Any of these is a good outcome for the review and a bad one for the profile:

- The name or the summary implies an official product, and the disclosure does not fix it.
- The reading order is simply not how inspections work, so the "handoff" organizes nothing.
- The profile would lead tenants to prepare and present something an inspector must decline,
  redirect, or log in a way that harms the tenant.
- A word in the vocabulary is a term of art in code enforcement and is used here to mean
  something else.
- Something essential is missing badly enough that the handoff is not usable — in which case
  the profile should stay gated until it is added.

Any of those and the honest response is to change the profile or withdraw it, not to ship
it with a caveat.

## What this review is not

Not a code determination, not a compliance opinion, not an assessment of any real property,
and not your department speaking. Not an endorsement of habitable, which stays alpha
regardless. Not a review of the cryptography or the accessibility — separate tracks, in
[profile-reviews.md](profile-reviews.md). And it involves **no real complaint, property, or
tenant** — the demo builds its own synthetic case.

## How your answer is recorded

A dated entry for `inspector_handoff` in the public capability ledger
([`docs/capabilities.md`](../capabilities.md)), the profile's `reviewer` and `reviewed_at`
fields filled in from your review, and — if your answer is jurisdiction-specific — a
`jurisdiction` and an expiry date after which the profile stops presenting itself as
reviewed. Credit or anonymity is your call; see
[profile-reviews.md](profile-reviews.md#credit-and-conflicts-of-interest).

## Finding this reviewer (maintainer note)

No leads here are verified, so none are named. The channel types worth trying, in rough
order of likely willingness:

- **Retired or former inspectors**, reachable through professional associations, training
  bodies, and code-official certification communities — no employer to clear it with.
- **Trainers and curriculum staff** at code-official associations and municipal training
  programs; they read documents like this for a living.
- **A department's public-information or community-outreach contact** — never a complaint
  hotline, which is for reporting conditions.
- **Housing-court or nuisance-abatement program staff** who work alongside inspectors.
- **Tenant-side organizers and legal-aid housing units**, who can often name a
  code-enforcement contact who would take the question.

Ask for one person's read of one page, name the twenty-minute version, and say plainly that
nothing will be published under their employer's name.

## Outreach note

> **Subject:** 20-minute ask — does this read like an inspector's workflow? (unpaid,
> synthetic data)
>
> Hi [name],
>
> I maintain **habitable**, an open-source, offline tool that helps tenants document
> habitability problems as dated, tamper-evident evidence. It is an unfunded personal
> project, currently **alpha and explicitly not for real use**.
>
> It ships a workflow called "Inspector handoff" that claims to organize a tenant's
> evidence as room → condition → chronology → supporting documents. **No inspector has ever
> read it**, so it ships marked as needing outside review, and I would rather withdraw it
> than ship something that looks naive to the person receiving it.
>
> The ask is small and specific: read one page (about 40 lines) and tell me whether that
> order is how you actually work, whether your department could accept a submission like
> this at all, and whether any of the words I use already mean something different in code
> enforcement.
>
> To be clear: unpaid, no real case or property involved, **not** a request for a code
> determination or any opinion you would be answerable for, and nothing published under
> your employer's name — I can credit you, credit the role only, or record it anonymously.
>
> The brief:
> https://github.com/ChelseaKR/habitable/blob/main/docs/recruitment/profile-inspector-handoff.md
>
> If it is not for you, is there someone you would point me to?
>
> Chelsea Kelly-Reif · ckellyreif@gmail.com · https://github.com/ChelseaKR/habitable
