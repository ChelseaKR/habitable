# Profile review: `partner_capsule` — for an organization that receives evidence from outside

> **Bounded, unpaid, synthetic data only.** A review of *framing* and of an exchange format —
> not legal advice, not an integration commitment, not an endorsement. Shared terms (what a
> profile is, what the review is not, credit, conflicts) are in
> [profile-reviews.md](profile-reviews.md); this page is only what is specific to
> `partner_capsule`. **One profile is a complete contribution.**

habitable is an alpha, offline-first tool that helps a tenant document housing conditions as
tamper-evident evidence. This profile is the "somebody else's tool, or somebody else's
office, has to take one record out of it" case. It ships implemented and marked
`external_review_required` for a plain reason: the project's own plan said step one was to
**secure a named adopter and write the contract with them**, and there is no adopter. It is
an exchange format with nobody on the other end.

## Who this is for

Someone who **receives evidence from outside their own systems and has to do something with
it**: an intake or case-management lead at a legal-aid or tenant-advocacy organization, a
paralegal or intake coordinator who processes what clients and partner orgs send, a
technologist or data lead at a civic-tech or housing-justice organization, a court
self-help-center staffer. Someone at an organization that has already been handed a folder of
phone photos and had to make it into a file.

You do not need to be able to read the code. The useful expertise is **what arrives at your
door today and what happens to it next.**

## What the profile actually asserts

Verbatim from [`src/habitable/usecases.py`](../../src/habitable/usecases.py):

- **Name:** "Partner evidence capsule" (Spanish: "Cápsula de evidencia para organizaciones")
- **Summary:** *"Exchange a small conforming evidence object with another civic tool."*
- **Document types it declares:** `partner_export`, `other_document`
- **Relationship types it declares:** `supports`, `documents_condition`
- **Reading order it declares:** `source_tool` → `evidence` → `verification` → `limits`
- **Its disclosure, which travels with the export and cannot be suppressed:**
  *"A conforming capsule does not imply the partner or source is authenticated."*

And the object itself, from [`src/habitable/capsule.py`](../../src/habitable/capsule.py)
(kernel background in [`docs/evidence-kernel.md`](../evidence-kernel.md)):

- **A capsule is one JSON file** holding one evidence record's own fields, any relationships
  that touch it, optionally the original file base64-encoded inside, a producer key and
  signature, and three disclosures carried in the payload:
  - *"The producer signature proves capsule integrity, not authorship of the source file."*
  - *"Issuer, source, chronology, and relationship labels remain assertions."*
  - *"No legal, medical, code-compliance, or admissibility conclusion is made."*
- **`habitable capsule verify` needs nothing** — no vault, no account, no network, no
  service. It checks the payload hash, the producer signature, the declared kind and schema
  version, and that any embedded original matches its stated hash, with an 80 MiB ceiling.
- **Here is the sharp edge.** The producer's key travels *inside the same file* it signs. So
  "verified" means **these bytes are internally consistent and unmodified since they were
  signed** — it does **not** mean the sender is who they say they are, that a real person
  took the photo, or that anything in the record is true.
- **Importing keeps the capsule as received.** `habitable capsule import` seals the capsule
  file itself as a `partner_export` document rather than re-authoring its contents into your
  case, records the producer's key fingerprint as the issuer, and attaches the description
  *"source assertions remain unverified."*
- **Schema version 1, and no stability promised** beyond the documented surface. There is no
  hosted verification service and none is planned.

## The questions this profile needs answered

1. **What actually arrives at your organization today?** When a tenant or a partner sends you
   evidence, what is it — email with attachments, a phone-photo album link, a shared drive, a
   printed packet — and what does your staff do with it in the first ten minutes?
2. **Could you use a signed JSON file?** Honestly. Would it reach a case file, or would it be
   the attachment nobody can open? What would have to be true for it to be better than a PDF
   and an email — and is "better for the sender" quietly being traded against "worse for the
   receiver"?
3. **Does the word "verified" mislead?** `capsule verify` prints a verdict on an object whose
   signing key came in the same file. Read as a person on intake, not as an engineer: what
   would your staff think that verdict means, and what would they then tell a client?
4. **What would you need before treating a capsule as trustworthy?** Who sent it, through
   which channel, on what date, matched to which client — name the things that do the real
   work, and say whether any file format can supply them.
5. **Does receiving evidence this way create obligations for you?** Retention, conflict
   checking, records or discovery exposure, a duty to act once you hold something. If
   adopting this format quietly creates work or risk for a receiving organization, that is
   the finding.
6. **Is "partner" the right frame at all?** The workflow assumes an organization on the other
   side that has agreed to something. There is no such organization. Should the profile stay
   gated until there is a real named adopter, or is a documented format useful even with
   nobody using it?
7. **Would you rather have the whole packet?** habitable's main output is a full packet with
   an accessible HTML rendering, a PDF, and a standalone verifier. The capsule is a single
   record. Which one would your office actually want, and when?

### If you only have twenty minutes

Answer 2 and 3. Whether the object is usable at your door, and whether "verified" would
mislead the person who reads it.

## What would make this fail review

- "Verified" reads as "authenticated" to the people who would actually see it, and no wording
  fixes it — in which case the verdict language has to change before this ships.
- The object is unusable in a real intake, so the workflow serves the sender at the receiver's
  expense.
- Receiving capsules creates an obligation or a risk for organizations that nobody flagged.
- The whole premise is wrong: organizations want a complete, human-readable packet, not a
  machine-readable single record — which would mean the profile should be withdrawn rather
  than reworded.
- The format cannot be judged at all without a named adopter, which is itself the answer:
  the gate stays until step one of the plan actually happens.

## What this review is not

Not legal advice, not an integration commitment, and not an ask to adopt anything or change a
system. Not an endorsement of habitable, which stays alpha regardless. Not a security review
of the signing scheme — that is the [auditor track](role-auditor.md). **No client data is
involved**: everything is evaluated on generated synthetic cases.

If your answer is "we would need funding and a scoped project to even evaluate this
properly", that is a fine answer and it is worth recording as one.

## How your answer is recorded

A dated entry for `partner_capsule` in the public capability ledger
([`docs/capabilities.md`](../capabilities.md)), the profile's `reviewer` and `reviewed_at`
fields filled in, and — if a receiving organization is willing to be named — that is the
closest thing this profile has to the named adopter its plan asked for. Credit or anonymity
is your call
([profile-reviews.md](profile-reviews.md#credit-and-conflicts-of-interest)); organizational
credit is meaningful here and entirely optional.

## Finding this reviewer (maintainer note)

No verified leads; channel types only. **Never a client-intake line.**

- **Intake and case-management leads** at legal-aid and tenant-advocacy organizations —
  reachable through operations, technology, or volunteer coordinators.
- **Legal-aid technology staff and statewide legal-aid technology projects**, whose job is
  exactly "what do we do with the thing the client sent".
- **Civic-tech and housing-justice tool builders**, who can answer the format question and
  might be the missing adopter.
- **Court self-help centers**, on what a self-represented litigant can actually hand over.
- **Document- and evidence-format communities** in the public-interest technology world.

The [pilot-partner brief](role-pilot-partner.md) reaches some of the same organizations for a
much larger ask; do not send both at once — this one is deliberately the small ask.

## Outreach note

> **Subject:** 20 minutes on intake — would your office be able to use this file? (unpaid,
> synthetic data)
>
> Hi [name],
>
> I maintain **habitable**, an open-source, offline tool that helps tenants document housing
> conditions as dated, tamper-evident evidence. Unfunded personal project, **alpha, not for
> real use yet**.
>
> It can export a single evidence record as a small signed file — a "capsule" — that another
> tool or organization can check without any account, service, or network. **Nobody on the
> receiving side has ever reviewed it.** My own plan said step one was to find a real adopter
> and design it with them; I built it first, so it ships marked as needing outside review.
>
> The ask is one page and two questions: could a signed JSON file with a photo inside it
> actually reach a case file in your office, or is it the attachment nobody can open? And
> when the checker says "verified" — which only means the bytes are intact and signed by a key
> that shipped in the same file — would your intake staff read that as something stronger?
>
> Unpaid, synthetic data only, no client data, **not** an ask to adopt or integrate anything.
> Credit, role-only credit, or anonymous, your choice.
>
> The brief:
> https://github.com/ChelseaKR/habitable/blob/main/docs/recruitment/profile-partner-capsule.md
>
> "We would never use this" is a genuinely useful answer and I would rather hear it now.
>
> Chelsea Kelly-Reif · ckellyreif@gmail.com · https://github.com/ChelseaKR/habitable
