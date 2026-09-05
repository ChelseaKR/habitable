# Profile review: `accommodation_request` — for a disability-rights advocate or fair-housing worker

> **Bounded, unpaid, synthetic data only.** This is a review of *framing* — what a workflow
> says and in what order — not legal advice, not representation, and not an endorsement of
> anything. Shared terms (what a profile is, what the review is not, credit, conflicts) are
> in [profile-reviews.md](profile-reviews.md); this page is only what is specific to
> `accommodation_request`. **One profile is a complete contribution.**

habitable is an alpha, offline-first tool that helps a tenant document housing problems as
tamper-evident evidence and keep their own copy of what they sent and what came back. This
profile is the "the thing being documented is an accommodation request" case. It ships
implemented and marked `external_review_required`: the project's own plan says this data
model needed a disability-rights reviewer **before** it was built, and it was built without
one.

## Who this is for

Someone who has **helped tenants make, document, and follow up on accommodation requests**:
a fair-housing advocate or tester-program staffer, an independent-living-center housing
advocate, a disability-rights legal-aid worker, a tenants'-rights counselor who handles
these regularly. Someone who has watched requests go wrong is more useful here than someone
who has read about them.

**One thing to say directly.** This project's stated position is that it does not ask
disabled people for free accessibility labor — its screen-reader testing role is a paid
engagement ([role-accessibility-tester.md](role-accessibility-tester.md)). This ask is a
different thing: a domain read of record-keeping vocabulary, not assistive-technology
testing. But you are the judge of whether that distinction holds for you, and if this reads
as unpaid disability labor, say so and decline — that answer is itself useful.

## What the profile actually asserts

Verbatim from [`src/habitable/usecases.py`](../../src/habitable/usecases.py):

- **Name:** "Accommodation request record" (Spanish: "Registro de solicitud de adaptación")
- **Summary:** *"Preserve a request, optional support, delivery, response, and follow-up."*
- **Document types it declares:** `accommodation_request`, `supporting_letter`,
  `delivery_receipt`
- **Relationship types it declares:** `sent_via`, `delivery_receipt_for`, `response_to`,
  `supports`
- **Reading order it declares:** `request` → `optional_support` → `delivery` → `response`
- **Its disclosure, which travels with the export and cannot be suppressed:**
  *"Technical integrity does not establish disability, entitlement, receipt, or
  compliance."*

What it deliberately does not do: there is **no diagnosis field, no eligibility score, and
no required medical upload** anywhere in the data model, and the tool names no statute,
regulation, or agency process. It does not decide whether a request was reasonable, whether
a response was adequate, or whether anybody is entitled to anything.

Three mechanics that matter more than the vocabulary:

1. **"Optional support" is genuinely optional and unverified.** A supporting or clinician
   letter is stored as a sealed document with a free-text issuer string the tool never
   checks. The tool hashes and timestamps whatever file the tenant hands it; it has no idea
   who wrote it.
2. **Export is whole-case, always.** A packet covers the entire unit — every issue in that
   vault. Scoped or issue-by-issue export is deliberately blocked, because the packet's
   custody proof would leak the identifiers of whatever was left out. So a supporting letter
   sealed into a case travels with **every** later export of that case, whoever the
   recipient is.
3. **Nothing warns the tenant about that.** The project's own plan called for
   "user-controlled neutral labels and a high-sensitivity warning" for this workflow. No
   such warning is implemented. A tenant attaching a clinician's letter is told nothing
   special at the moment they attach it.

## The questions this profile needs answered

1. **Is the name and the vocabulary right?** Is "accommodation request record" what your
   field calls this, and do `accommodation_request`, `supporting_letter`, and
   `delivery_receipt` map onto the documents that actually exist in one of these matters?
2. **Is the disclosure sentence the right one?** It names four things technical integrity
   does *not* establish: disability, entitlement, receipt, compliance. Are those the right
   four? Is one of them wrong, or is something missing that a tenant or a landlord could
   misread?
3. **Is the reading order the real shape?** request → optional support → delivery →
   response. Real requests often involve an interactive back-and-forth, a landlord asking
   for more information, a partial grant, a verbal request months before a written one, and
   a renewal. Does a four-step record flatten that into something misleading?
4. **The whole-case export is the sharpest question here.** A tenant who wants to show a
   landlord "I asked, on this date, and you did not answer" can only send the whole case —
   including any supporting letter. Is that a real hazard in your experience? Should the
   tool warn at attachment time, refuse medical documents in this workflow entirely, or
   stay out of the tenant's way? What would you want it to say?
5. **Does no-diagnosis-field help or hinder?** The model refuses to hold a diagnosis. Does
   that protect tenants, or does it push the sensitive material into the free-text title and
   description fields, where it is less visible and just as exported?
6. **What does this fail to preserve that always matters?** The date the request was first
   made verbally? The landlord's request for more information and the tenant's reply? A
   partial or conditional grant? Withdrawal of an accommodation later? Name what you would
   need in a file six months on.
7. **Is a tamper-evident record the right instinct here at all?** Documentation is not
   always neutral for a tenant with a disability. Does building a hash-and-timestamp record
   of an accommodation request change the dynamic with a landlord in ways that could hurt?

### If you only have twenty minutes

Answer 2 and 4. The disclosure sentence is what a recipient reads, and the whole-case
export is the design decision most likely to hurt somebody.

## What would make this fail review

- The disclosure sentence is wrong or incomplete in a way that lets the record be read as
  proof of entitlement or of a landlord's non-compliance.
- The vocabulary pushes tenants to disclose medical information they should not disclose, or
  to ask a clinician for something a clinician should not write.
- The four-step order misdescribes the process badly enough that a tenant following it
  ends up with a record that undercuts them.
- Whole-case export plus an attached medical letter is a foreseeable disclosure harm and the
  tool does nothing about it — in which case the profile should stay gated until it does.
- The workflow is simply not something a tenant should be doing alone, and the honest answer
  is that it needs an advocate in the loop, not a better data model.

## What this review is not

Not legal advice, not representation, not an opinion on any real tenant's request, and not
a compliance or fair-housing determination. Not a certification of habitable, which stays
alpha regardless. Not an accessibility or assistive-technology review — that is a separate,
paid role. No real tenant material is involved at any point.

## How your answer is recorded

A dated entry for `accommodation_request` in the public capability ledger
([`docs/capabilities.md`](../capabilities.md)), the profile's `reviewer` and `reviewed_at`
fields filled in, and a `jurisdiction` plus an expiry date if your read depends on where
you practice. Credit or anonymity is your call
([profile-reviews.md](profile-reviews.md#credit-and-conflicts-of-interest)).

## Finding this reviewer (maintainer note)

Nothing below is a verified lead; these are channel types, not names.

- **Independent living centers** — housing advocates there do this work daily and are often
  reachable through program or outreach staff.
- **Fair-housing organizations' education, outreach, or testing-program staff** — not the
  intake or complaint line, which is for people seeking help.
- **Disability-rights legal organizations' communications or policy staff**, who are used to
  reviewing materials rather than taking cases.
- **Law-school disability-rights or housing clinics**, timed to the academic term.
- **Peer and cross-disability advocacy networks**, where an advocate with lived experience
  may be the best reader of question 7.

Lead with: twenty minutes, one page, synthetic data, no case, no representation, unpaid,
and the option to be credited or not.

## Outreach note

> **Subject:** Short unpaid ask — does this accommodation-request workflow read as naive?
> (synthetic data, not representation)
>
> Hi [name],
>
> I maintain **habitable**, an open-source, offline tool that helps tenants keep a
> tamper-evident record of housing problems and of what they sent a landlord. It is an
> unfunded personal project, **alpha and explicitly not for real use yet**.
>
> One of its workflows is an "accommodation request record". It has no diagnosis field and
> makes no legal claims, but **no disability-rights or fair-housing worker has ever read
> it** — my own plan said one should have, before it was built. So it ships marked as
> needing outside review, and I would rather change or withdraw it than leave something
> naive in front of tenants.
>
> The ask: read one page and tell me (a) whether the disclosure sentence — "technical
> integrity does not establish disability, entitlement, receipt, or compliance" — is the
> right sentence, and (b) whether it is a problem that a packet can only be exported for
> the whole case, so an attached clinician letter travels with everything the tenant later
> sends anyone.
>
> Unpaid, synthetic data only, no real tenant involved, not representation and not a legal
> opinion. I can credit you, credit the role only, or record it anonymously.
>
> The brief:
> https://github.com/ChelseaKR/habitable/blob/main/docs/recruitment/profile-accommodation-request.md
>
> If this reads to you as asking a disabled advocate for unpaid labor, tell me and I will
> take the note seriously — the project's accessibility testing role is paid for exactly
> that reason.
>
> Chelsea Kelly-Reif · ckellyreif@gmail.com · https://github.com/ChelseaKR/habitable
