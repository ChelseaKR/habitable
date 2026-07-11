<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Foundation guidance for introducing a habitable packet (item R-30)

> **This is not legal advice.** This is **educational background** for an attorney or trained
> advocate who is introducing a habitable packet, written to explain what the technology does
> and does not establish. It is not a brief, not a script for your court, and not a guarantee
> of admissibility. You are responsible for the law in your jurisdiction and for how you frame
> the evidence in your case.

This document exists because opposing counsel will (correctly) point out that the chain of
custody shows the *tenant* controlled the device — that the record is largely
*self-authenticating*, not independent third-party proof of the condition. That is not a flaw
to hide; it is a boundary to state plainly. Getting the framing right is the tenant's shield.

## The central distinction: two different things to prove

Keep these two questions separate in your own mind, in your foundation, and in argument:

**(a) Authenticity and integrity of the digital record.** *Is this the file that was captured,
unaltered, and did it exist by the date claimed?* This is what habitable's machinery
establishes:

- **Content hash + fixity (SHA-256):** the item's bytes have not changed since capture. Any
  alteration after capture is detectable.
- **RFC 3161 trusted timestamp:** an independent authority attests the exact content existed
  *no later than* a stated time — an **upper bound** on creation.
- **Append-only, hash-linked chain of custody:** the recorded events were not inserted, deleted,
  or reordered. Exported in identity-stripped form, it shows the tenant/union controlled the
  device throughout, without disclosing who did what.
- **Signed bundle + standalone verifier:** the whole packet is bound by a signature and can be
  re-checked by anyone.

**(b) Proof of the underlying habitability condition.** *Was there really mold? Was the heat
really out? Does this photo depict this unit on this day?* habitable does **not** prove any of
this. This rests on the **tenant's testimony and the depiction in the photographs** — the
ordinary foundation for any photograph: a witness with personal knowledge testifying that it
fairly and accurately depicts what they saw. The cryptography makes that testimony harder to
impeach as "edited later," but it does not substitute for it.

If you blur (a) and (b), you will overclaim — and overclaiming in a courtroom is exactly the
failure this project is built to avoid.

## How to lay foundation (general shape)

1. **The condition, through the tenant.** The tenant testifies (or declares) to what they
   personally observed, where, and when, and that the photo/video fairly and accurately depicts
   it. This is what carries question (b). See
   [`declaration-template.md`](./declaration-template.md).
2. **Capture and integrity, through the tenant and/or custodian.** Establish that the media was
   captured with habitable on a described device; that the app sealed the original and computed
   a content hash at capture; that the declarant did not alter it; and that a trusted timestamp
   was obtained over the hash. The tenant can testify to this as a lay user ("when I took the
   photo, the app saved it and I couldn't change it"); the technical detail can come from the
   evidence-method documentation or a knowledgeable witness if the court requires it.
3. **Production and verification, through the custodian/organizer.** Who assembled the packet,
   that the export was a single automated step (no hand-editing), and that verification reported
   the items intact and the chain unbroken.
4. **Independent verifiability, as the backstop.** The other side does not have to take your
   word for any of it — they can re-run verification themselves (see below).

## Explaining RFC 3161 to a judge in one or two sentences

Plain, accurate, no overclaim:

> "An independent timestamp authority confirmed that this exact file existed no later than
> [date]. It is proof the photo could not have been created or edited *after* that date — it is
> not proof of who took it or what it shows; that comes from the tenant's testimony."

If pressed on what "no later than" means:

> "The timestamp sets an outer limit: the file existed by that moment. It doesn't say the file
> couldn't have existed earlier, and it doesn't speak to authorship or content."

That single concession — *upper bound, not authorship, not depiction* — is what makes the rest
of your foundation credible.

## "How do we know the tool isn't cooked?" — the standalone verifier

This is the strongest objection and habitable has a direct answer: **the evidence is not
"trust the app," it is independently checkable.**

- The verifier is **standalone and offered under Apache-2.0**, separate from the rest of the
  codebase, so the other side (or their expert) can read it, run it, or embed it in their own
  software without any license entanglement.
- Verification uses **standard primitives** — SHA-256 hashing and RFC 3161 timestamp tokens —
  so a skeptic does not even need habitable's verifier: a packet can be **cross-checked with
  general-purpose RFC 3161 and SHA-256 tools** (item R-31). The timestamp token can be validated
  against the issuing authority's certificate the same way any RFC 3161 token is.
- Because verification is deterministic, **the same packet yields the same verdict on any
  machine.** Invite the other side to verify it themselves; an integrity claim that the
  opponent can confirm is far stronger than one they must accept on faith.

Frame it as: *"You don't have to trust this tool. Here is how to check it yourself."*

## The evidentiary limits opposing counsel will (legitimately) raise

Anticipate these and concede the honest ones; do not let them be "discovered" as if hidden:

- **"The timestamp only bounds existence, not authorship or depiction — that photo could be of
  somewhere else."** True as to the cryptography. The answer is the tenant's testimony tying the
  photo to the unit and the condition; the timestamp/hash defeat the *separate* attack that the
  photo was fabricated or edited after the fact.
- **"The chain of custody shows the tenant controlled the device the whole time — that's
  self-authentication, not independent proof."** Also true. The chain proves the *record* was
  not tampered with; it does not turn the tenant into a neutral third party. Present it for what
  it is: integrity of the record, supporting the tenant's own testimony.
- **"The custody log is tamper-*evident*, not tamper-*proof* — the device holder could have
  discarded the whole log and written a fresh one."** Honest limit (see
  [`threat-model.md`](../threat-model.md) §5). Detection of that depends on an external anchor —
  e.g., the trusted timestamp over the content, or a counterpart who already held the chain head.
  Do not claim the chain binds a hostile keyholder; it does not.
- **"How do we know the tool isn't cooked?"** Answered above — standalone verifier, standard
  primitives, cross-checkable.
- **"What about metadata / where did this sync through?"** habitable holds no central server; a
  relay, if used, sees only ciphertext plus connection metadata, never contents. Be ready to
  state this plainly so it cannot be spun as concealment (item R-33).
- **"Is any of this admissible?"** That is the court's call under your jurisdiction's rules.
  habitable makes **no admissibility guarantee.** Your foundation, not the tool, is what gets it
  in.

## Discovery caution

A produced packet should disclose no more than counsel decides is appropriate. The current safe
export is a **whole-unit** packet, not an issue/date subset. `--issue` and `--since` fail before
output because packet v3's complete custody chain can reveal identifiers outside a filtered item
list. Do not bypass that guard or manually delete custody entries and call the result complete.
Discuss whether the whole-unit artifact is suitable and whether a protective order is needed. The
current status and planned versioned scoped-custody design are in
[`minimal-disclosure.md`](./minimal-disclosure.md).
