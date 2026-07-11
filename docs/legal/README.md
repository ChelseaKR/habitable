<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Legal-support materials for a habitable packet

> **This is not legal advice.** Nothing in this directory is legal advice, creates an
> attorney–client relationship, or guarantees that any court or agency will admit a packet
> or give it weight. These are **educational templates and background notes**. Have a
> licensed attorney in the relevant jurisdiction review and adapt anything here before it is
> used in a real matter.

These materials are the *legal scaffolding* around a habitable packet — the human and
procedural half of what makes the evidence usable. The tool produces a verifiable record
(SHA-256 content hashes, RFC 3161 trusted timestamps, an append-only chain of custody, and a
signed bundle); these documents help a tenant, an organizer, and an attorney *introduce* that
record and explain, honestly, what it does and does not prove.

They realize backlog items **E-19**, **R-30**, **E-20**, and **R-34** from
[`docs/research/synthetic-personas-feedback.md`](../research/synthetic-personas-feedback.md).
As that study says of its own findings: treat everything here as a starting point to validate
with real attorneys and real courts, never as a settled requirement.

## What habitable's evidence actually proves (the one thing to get right)

Everything in this directory rests on being precise about the boundary, because overclaiming
in a courtroom fails the people relying on the tool. In short:

- A **SHA-256 content hash + fixity check** shows an item was **not altered after capture**.
- An **RFC 3161 timestamp** proves the content **existed no later than** a given time — an
  *upper bound* on when it was created. It does **not** prove authorship, that a photo depicts
  a particular unit, or that the underlying condition was as described.
- The **chain of custody** (exported in identity-stripped form) shows the recorded events were
  **not inserted, deleted, or reordered** — i.e., that the tenant/union controlled the device.
  That makes the record largely **self-authenticating**, not independent third-party proof of
  the condition.
- The **packet is independently verifiable** by anyone, using the standalone Apache-2.0
  verifier *or* general-purpose RFC 3161 / SHA-256 tools.

The full method is in [`docs/evidence-method.md`](../evidence-method.md); the limits are in
[`docs/threat-model.md`](../threat-model.md) and the README's *Honest limits* section.

## Jurisdiction scope: CALIFORNIA ONLY (item R-34)

> **Any jurisdiction-specific guidance in this directory is scoped to California, and even
> that is general educational background, not advice.** Evidence law varies by state (and
> between state and federal court). **Do not extrapolate** California-flavored notes to New
> York, Texas, or anywhere else; the rules on authentication, hearsay, and admissibility
> differ, sometimes sharply. The habitable pilot is currently scoped to California, which is
> why CA is the only jurisdiction addressed at all.

The **declaration template** and **foundation guidance** below are written to be largely
jurisdiction-neutral (they describe the technology and general foundation concepts), but they
still must be reviewed by a licensed attorney in your jurisdiction before use.

## The files

- **[`declaration-template.md`](./declaration-template.md)** — (E-19) a fill-in-the-blank
  declaration a tenant/witness can sign to lay foundation for moving a packet into evidence,
  plus an optional custodian/organizer variant for chain-of-custody foundation.
- **[`foundation-guidance.md`](./foundation-guidance.md)** — (R-30) guidance *for an attorney
  or advocate* introducing a packet: authenticity/integrity of the digital record vs. proof of
  the underlying condition, how to lay foundation, how to explain timestamp semantics to a
  judge, the standalone verifier as the answer to "how do we know the tool isn't cooked," and
  the evidentiary limits opposing counsel will raise.
- **[`california-evidence-notes.md`](./california-evidence-notes.md)** — (E-20) a
  California-scoped, **educational** cheat-sheet on authenticating digital photographs and
  records and the objections to anticipate, plus a plain-language "what to expect on
  cross-examination" section for tenants.
- **[`minimal-disclosure.md`](./minimal-disclosure.md)** — (R-35) what a produced packet
  contains and, just as importantly, what it deliberately omits; the current whole-unit boundary
  and optional originals/metadata choices; and guidance on responding to an over-broad discovery
  demand (scope statement, protective orders, and that the disclosure decision is a legal one).

## How to use these responsibly

1. Read [`docs/evidence-method.md`](../evidence-method.md) so you can describe accurately what
   the packet contains and what each component proves.
2. Have a **licensed attorney in your jurisdiction** review and adapt the declaration and
   tailor the foundation to the specific case and court.
3. Never tell a tenant the packet "guarantees" anything. The honest framing — *this record was
   not altered after capture and existed by this date* — is the tenant's shield, not a weakness
   to hide.
