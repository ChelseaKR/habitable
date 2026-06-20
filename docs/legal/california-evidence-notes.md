<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# California evidence notes — educational cheat-sheet (item E-20)

> **This is not legal advice, and it is California-scoped general education only.** Nothing
> here is advice, a guarantee, or a substitute for a licensed California attorney. Evidence law
> changes, and the specifics turn on the facts, the court, and the judge. **A licensed
> California attorney must check current law and adapt anything here before relying on it.**
> Do **not** apply these California-flavored notes to any other state — the rules differ (item
> R-34).

This is a plain-language orientation for a California tenant, organizer, or advocate to what
*kinds* of rules and objections come up when introducing digital photographs and records like a
habitable packet. It deliberately describes the **type** of rule rather than citing specific
statutes or cases, so it cannot mislead by quoting something out of date or out of context.
Your attorney will supply the current, exact authority.

## The kinds of rules that come up

California, like other jurisdictions, has general rules covering roughly these areas. Ask your
attorney how each applies to your case:

- **Authentication of writings and photographs.** Before a photo or record comes in, the
  proponent generally has to show it is what they claim it is. For a photograph, the classic
  route is a witness with personal knowledge testifying it *fairly and accurately depicts* what
  they saw. A habitable packet *supports* this — it shows the file was not altered after capture
  — but the tenant's own testimony is still the foundation for what the photo shows.
- **Authentication of digital / electronic records.** Courts have general rules for
  authenticating electronically stored information; this is where the content hash, the trusted
  timestamp, and the integrity of the chain are most useful, because they speak to *this is the
  unaltered file, and it existed by this date*. Ask your attorney how California treats
  authentication of electronic records and what showing the court will expect.
- **The "best evidence" / secondary evidence concept.** There are general rules about proving
  the content of a writing or recording. Discuss with your attorney whether a packet's
  rendering, the bundle, and the sealed original satisfy them and which form to offer.
- **Hearsay and its exceptions.** A photograph itself is usually not hearsay, but *statements*
  in a record (notes, the timeline text) might be, and there are general exceptions (for example,
  the kinds of exceptions that apply to records made in the regular course of an activity). Your
  attorney decides what is offered for its truth and what is not.
- **Relevance and prejudice.** Standard rules let a court weigh whether evidence is relevant and
  whether its value is outweighed by other concerns. Usually straightforward for habitability
  photos, but worth anticipating.

> None of the above is a citation. Treat each as a *category* to raise with your attorney, who
> will identify the current California authority by section or case name.

## Objections to anticipate (and the honest response)

- **"Lack of foundation / not authenticated."** Met by the tenant's testimony plus the
  packet's integrity showing (hash, timestamp, custody). See
  [`foundation-guidance.md`](./foundation-guidance.md) and
  [`declaration-template.md`](./declaration-template.md).
- **"The image could have been altered / the date is unreliable."** This is precisely what the
  content hash and RFC 3161 timestamp address: the file was not changed after capture and existed
  by a stated date. Be ready to explain, accurately, that the timestamp is an *upper bound* — it
  does not prove authorship or depiction.
- **"This just proves the tenant controlled their own device — it's self-serving."** Concede the
  point honestly: the record's integrity is not the same as independent proof of the condition.
  The condition is proven by the tenant's testimony; the technology defeats the *separate* claim
  that the evidence was fabricated after the fact.
- **"How do we know the software is trustworthy?"** The verifier is standalone and the format is
  checkable with general-purpose RFC 3161 / SHA-256 tools — the other side can verify it
  themselves. (See foundation guidance.)
- **Hearsay objections to text/notes.** Anticipate and let your attorney decide the purpose for
  which each statement is offered.

## What to expect on cross-examination (for the tenant, plain language)

If you are the tenant who took the photos and you testify, the landlord's lawyer may try to
make your evidence look weak. This is normal. Here is the kind of thing they may ask, and the
honest truth behind it. **Always tell the truth; never guess.** If you don't know or don't
remember, say so.

- **"Did you take this photo yourself?"** Answer truthfully. The strongest evidence is that you
  saw the condition with your own eyes and photographed it.
- **"How do we know you didn't edit this photo?"** You don't have to be a computer expert. The
  honest answer is that the app saved the original when you took it and you did not change it.
  The tool's job is to back that up; your job is to tell the truth about what you did.
- **"This timestamp doesn't prove you took the picture in *this* apartment, does it?"** Correct
  — and that's fine. The timestamp shows *when* the file existed. *You* are the one who tells the
  court it was your bathroom, on that day. Don't claim the technology proves more than it does.
- **"You could have taken this anytime."** The timestamp limits how late the photo could have
  been made — it could not have been created or edited after the stamped date. Say what you know:
  when you saw the condition and when you photographed it.
- **"You're the one who controlled the phone the whole time."** Yes — and that is honest. The
  records show nothing was secretly inserted or reordered. They do not pretend you were a neutral
  outsider; you are a witness to your own home.

Stay calm, answer only what is asked, and don't volunteer technical claims you're unsure about.
Your attorney can handle the technical foundation; you handle what you saw.

## Reminders

- This is **general California educational information**, not advice and not a guarantee of any
  outcome.
- **Current law must be confirmed by a licensed California attorney**, who will supply the exact,
  up-to-date authority for anything described here by category.
- habitable produces well-documented, verifiable evidence; whether a court admits it or how much
  weight it gives it is a legal question this tool — and this document — cannot answer.
