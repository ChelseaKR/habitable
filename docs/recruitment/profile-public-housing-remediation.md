# Profile review: `public_housing_remediation` — for someone who has worked a housing-authority remediation

> **Bounded, unpaid, synthetic data only.** A review of *framing* — what a workflow says and
> in what order — not legal advice, not a compliance opinion, not an endorsement. Shared
> terms (what a profile is, what the review is not, credit, conflicts) are in
> [profile-reviews.md](profile-reviews.md); this page is only what is specific to
> `public_housing_remediation`. **One profile is a complete contribution.**

habitable is an alpha, offline-first tool that helps a tenant document housing conditions as
tamper-evident evidence. This profile is the "the repair is moving through a public or
subsidized housing process, and the tenant is keeping their own parallel record" case. It
ships implemented and marked `external_review_required`, because the project's own plan
required a housing-authority or advocacy reviewer to supply the real workflow, and no such
person was ever found.

## Who this is for

Someone who has been **inside a remediation cycle in public or subsidized housing**: a
housing-authority employee (current or former) in inspections, maintenance coordination, or
resident services; a resident-council or tenant-association leader who has pushed a work
order through; an advocate or legal-aid worker whose caseload is authority-managed or
voucher housing; a HUD- or state-program monitor.

What is needed is somebody who knows **what actually happens between "an inspection found
something" and "somebody says it is fixed"** — including how often that loop repeats.

## What the profile actually asserts

Verbatim from [`src/habitable/usecases.py`](../../src/habitable/usecases.py):

- **Name:** "Public-housing remediation trail" (Spanish: "Seguimiento de reparación en
  vivienda pública")
- **Summary:** *"Connect an inspection finding, repairs, tenant observations, and
  reinspection."*
- **Document types it declares:** `inspection_report`, `landlord_response`, `repair_request`
- **Relationship types it declares:** `inspection_finding_for`, `repair_claim_for`,
  `supports`
- **Reading order it declares:** `finding` → `repair` → `tenant_observation` →
  `reinspection`
- **Its disclosure, which travels with the export and cannot be suppressed:**
  *"Agency status is reported or imported, never silently refreshed."*

Mechanics behind those words:

- **`repair_claim_for` means somebody else's claim that a repair happened.** In the code it
  deliberately has the same shape as a landlord's deduction claim: it points from a document
  (or the timeline entry recording its arrival) at the condition it is a claim about.
  Recording it is not agreeing with it, and the tenant's disagreement is a separate record
  joined with `supports`.
- **`inspection_report` is the tenant's own copy.** Any inspection document in a case is a
  file the tenant supplied, with a free-text issuer string the tool never verifies. The
  timestamp proves when the tenant's copy existed, not that an agency issued it.
- **"Agency status is reported or imported" means the tool has no integration with anybody.**
  habitable does not connect to any authority system, does not fetch a work-order state, and
  will never silently update one. Everything an agency "says" in a case is there because a
  person typed or attached it.
- **There is no work-order field, no inspection identifier, no development or unit code, and
  no case number** anywhere in the model. Conditions carry a free-text room, a short category
  vocabulary, and a severity word that is habitable's own, with no regulatory meaning.
- **`landlord_response` is the only word the profile has** for the counterparty's answer.

## The questions this profile needs answered

1. **Who is the "landlord" in your setting?** The vocabulary assumes one counterparty. In
   authority-managed, contracted-management, and voucher housing the answer can be the
   authority, a private manager, an owner, or two of those at once — with the authority also
   being the inspector. Does one word for all of that mislead, and what would you call it?
2. **Is finding → repair → tenant observation → reinspection the real shape?** Or does a
   real remediation loop, stall, get closed without a reinspection, get re-opened under a new
   number, or run several conditions on different clocks at the same time? A four-step
   "trail" that does not loop may be the profile's core error.
3. **What identifiers does an authority need before your record is usable to them?** If a
   tenant hands you a packet with no work-order number, no inspection ID, and no development
   or unit code, can it be matched to anything on your side? Which one identifier would do
   the most work?
4. **Is a tenant's parallel record welcome, useless, or risky?** Honestly. Does an organized
   tenant-side trail help move a stalled repair, or does it read as escalation and make the
   tenant a problem resident? Is there a retaliation exposure here that the tool should
   warn about?
5. **Should a tenant be recording an agency's inspection result at all?** The profile offers
   `inspection_report` as a document type. Given the copy is unverified and the tool says so,
   is that useful corroboration or an invitation to present an official-looking document
   that is not one?
6. **Does "remediation trail" mean something specific in your world?** If it is a term with a
   defined meaning in a program, a monitoring framework, or a settlement, using it loosely is
   a problem worth catching.
7. **Is the disclosure the right disclosure?** "Agency status is reported or imported, never
   silently refreshed" is written for a reader who suspects the tool of scraping. Is that the
   confusion that would actually arise, or is the real risk that a reader assumes the
   inspection document itself is authenticated?

### If you only have twenty minutes

Answer 1 and 2. If the counterparty vocabulary and the shape of the cycle are wrong, nothing
else in the profile can be right.

## What would make this fail review

- The remediation cycle does not have this shape, so the trail organizes a process that does
  not exist.
- "Landlord" is the wrong frame for public or subsidized housing badly enough to confuse the
  recipient about who is being asked for what.
- A term here is a term of art in an authority process and is used to mean something else.
- Without at least one matching identifier, a packet is unusable by the agency it is aimed
  at — a workflow producing something its recipient cannot act on should not ship.
- The tenant-side risk (retaliation, being marked difficult) outweighs the benefit and the
  tool says nothing about it.

## What this review is not

Not legal advice, not a compliance or program-monitoring opinion, not a statement on behalf
of any authority, and not a review of any real unit, work order, or resident. Not a
certification of habitable, which stays alpha regardless. Not a security or accessibility
review — separate tracks, in [profile-reviews.md](profile-reviews.md). No real case data is
involved: the demo builds its own.

If you work for an authority, note that this asks about **the tool's copy**, never about
your employer's process or performance, and nothing is recorded under your employer's name
unless you ask for that.

## How your answer is recorded

A dated entry for `public_housing_remediation` in the public capability ledger
([`docs/capabilities.md`](../capabilities.md)), the profile's `reviewer` and `reviewed_at`
fields filled in, plus a `jurisdiction` and an expiry date — this is the profile most likely
to need one, since program rules and local practice move. Credit or anonymity is your call
([profile-reviews.md](profile-reviews.md#credit-and-conflicts-of-interest)).

## Finding this reviewer (maintainer note)

No verified leads; channel types only.

- **Resident councils and resident-advisory boards** — often the fastest route to someone who
  has run the loop from the tenant side, and no employer to clear it with.
- **Former authority staff**, reachable through professional associations for housing
  agencies and through university housing-policy programs.
- **Legal-aid and advocacy housing units** whose caseload is subsidized housing; approach the
  supervising attorney or a policy staffer, never client intake.
- **Tenant organizing coalitions in authority-managed developments.**
- **Academic housing-policy researchers** who have done fieldwork inside authorities — good
  readers, and used to reviewing instruments.

## Outreach note

> **Subject:** 20 minutes — does this describe a real remediation cycle? (unpaid, synthetic
> data)
>
> Hi [name],
>
> I maintain **habitable**, an open-source, offline tool that helps tenants keep their own
> tamper-evident record of housing conditions. Unfunded personal project, **alpha, explicitly
> not for real use yet**.
>
> One of its workflows claims to connect an inspection finding, repairs, tenant observations,
> and reinspection into a "public-housing remediation trail". **Nobody who has worked one of
> those cycles has ever read it** — my own plan said a housing-authority or advocacy reviewer
> had to supply the real workflow, and that never happened. So it ships marked as needing
> outside review.
>
> The ask is one page and two questions: is that four-step shape what actually happens, and
> is "landlord" the wrong word for the counterparty in public or subsidized housing?
>
> Unpaid, synthetic data only, no real unit or resident involved, **not** a request for a
> compliance opinion or anything you would answer for professionally, and nothing published
> under your employer's name — credit, role-only credit, or anonymous, your choice.
>
> The brief:
> https://github.com/ChelseaKR/habitable/blob/main/docs/recruitment/profile-public-housing-remediation.md
>
> If it is not for you, is there someone you would point me to?
>
> Chelsea Kelly-Reif · ckellyreif@gmail.com · https://github.com/ChelseaKR/habitable
