<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# ADR 0016: Authority seal over the joint submission index

- Status: Accepted
- Date: 2026-08-27
- Supersedes: the deferred authentication decision in
  [ADR 0015](0015-joint-multi-tenant-submission-index.md). ADR 0015 itself
  stands; only the two rows it recorded as *deferred, not rejected* are settled
  here.

## Context

ADR 0015 shipped the joint submission index and was explicit about the one thing
it could not do:

> It proves no *listed* member was substituted, because the digest is
> recomputed. It does not prove the list is the list the organizer wrote: anyone
> who can write the file can add or drop a row, and no field inside an
> attacker-controlled file can prevent that.

Half of that gap was already closed by construction: `check_joint_index` reports
packet directories present beside the index that the index does not name, so
silently *adding* a member fails the check. The other half was not. A submission
that arrives with a household quietly removed leaves every remaining packet
valid, every remaining digest correct, and nothing unlisted on disk. Nothing in
the format disagrees. For a building-wide submission that is the damaging
direction: the packet a landlord would most like missing is the one that is
missing, and the recipient has no way to know.

ADR 0015 named two candidate mechanisms and deliberately declined to choose
between them in the same change:

- an **organizer signing key**, which needs an answer to whose key it is, and
- an **RFC 3161 seal over the index**, which needs no identity at all.

This ADR chooses the second.

## Decision

1. **The finished index is sealed the way ADR 0011 seals a packet.** At build
   time, if the organizer names an authority, `joint` timestamps the SHA-256 of
   the canonical `joint_index.json` bytes and writes the token to a sidecar,
   `joint_index.sig.json`, carrying `index_sha256` and an `index_seal`
   `{kind, tsa_name, token_b64}` record in exactly the shape `bundle.sig.json`
   already uses. The sidecar sits outside the index for the same reason
   `bundle.sig.json` sits outside `bundle.json`: a token over the index's own
   digest cannot live inside the bytes it covers.
2. **The index still carries no signature of its own,** and `index_signed` stays
   `false`. That field means "a key speaks for this presentation", and none
   does. A seal and a signature are different claims and this project has kept
   them apart since ADR 0008; conflating them here to make a field read better
   would be the first place that separation slipped.
3. **ADR 0011's three rules are inherited unchanged, because the situation is
   identical.** A present seal is always checked against the index in front of
   it, so a retained, foreign, or malformed seal fails with nothing asserted. An
   absent seal is reported rather than fatal until the recipient passes
   `--require-seal`. Every assertion fails closed: an unparseable
   `--seal-not-after`, or either assertion made against an unsealed index, is a
   problem rather than a quietly skipped check. A `dev`-kind seal verifies and is
   never trusted.
4. **Seal problems flow into the existing `problems` tuple.** No new verdict, no
   new status field, no redefinition of `JointCheck.ok`. This is ADR 0011's rule
   and it is why an existing reader of a joint check does not have to learn
   anything to benefit.
5. **Sealing never fails the build.** An unreachable authority costs the index
   its seal, not its existence, and the operator is told which of the three
   things happened: no authority was named, the authority answered, or the
   authority could not be reached. A message that misstates its own cause is a
   defect.
6. **Rebuilding without an authority deletes a stale sidecar.** A token beside
   bytes it no longer covers is a false claim. `check_joint_index` would
   correctly call it one, but the honest place to prevent it is the writer.
7. **The seal is reported at check time and appears in no rendering.** Not in
   `index.html`, not in the `disclosures` list, not as a field inside the index.
   ADR 0011 reached the same conclusion for packets: a document that announces
   its own seal makes a claim an attacker removes by deleting one file. The
   standing disclosure is reworded instead to be true in every state: the
   packets are signed, the index carries no signature of its own,
   `habitable joint check` recomputes every digest, `--require-seal` refuses a
   list no authority countersigned, and without that flag anyone who can edit
   the file can add or remove a row.
8. **The authority is named on the command line, not read from config.** `joint`
   has no vault, so there is no `[tsa]` section to inherit. `--seal-tsa URL`
   (with `--seal-tsa-name`) or `--dev-tsa`; nothing is sealed by default,
   because sealing is the one part of this command that touches the network and
   an organizer should be the one to decide that.

## Options considered

| Option | Assessment |
| --- | --- |
| Sign the index with the organizer's device key | Rejected, and this is the substantive choice. It would require inventing an organizer identity: a key, a distribution story, a compromise story, and a name attached to a document that travels to a landlord's lawyer. ADR 0011 already rejected a producer certificate on exactly that ground ("names tenants, rejected on safety"). A seal buys the property we actually need, which is *this list, at this time*, and buys it without naming anyone. |
| Do both: sign and seal | Rejected for now. The signature adds nothing the seal does not, until there is a reason to bind a presentation to a person, and adding an identity mechanism "while we are here" is how identity mechanisms arrive unexamined. If an organizer identity is ever justified on its own merits, it supersedes this ADR rather than hiding inside it. |
| Put the seal inside `joint_index.json` | Impossible as stated, and the impossibility is instructive: the seal covers the index bytes, so it cannot be one of them. The sidecar is not a workaround, it is the only shape this can have. |
| Make `--require-seal` the default | Rejected, following ADR 0011 exactly. It would fail every index built offline and every index built before this change, in exchange for a guarantee an attacker sidesteps by deleting one file. The judgement belongs with the recipient, who is the one who knows whether they expected a sealed submission. |
| Record the seal in `disclosures` or in `index.html` so a reader sees it without running a command | Rejected. Those bytes are exactly what a seal-stripping attacker keeps. A page that says "this list is sealed" beside a deleted sidecar is worse than a page that says nothing, because it is confidently wrong. |
| Seal each member packet as part of `joint build` | Rejected: it would mean modifying member packets, which ADR 0015 forbids, and it would put the organizer's authority over a tenant's evidence. Members are sealed by their own producers at their own export, or not at all. |
| Read the authority from a vault the organizer happens to have | Rejected: it would make the command's behaviour depend on whether an unrelated vault exists, and it would quietly make a network call the organizer did not ask for. |

## Consequences

- **A dropped member is now detectable, and that is the whole point.** Removing a
  household from the list changes the index bytes, and the old token no longer
  covers them. The attacker must produce a fresh token from an authority, which
  they cannot do without reaching one, and if they can reach one they still
  cannot backdate it, which is what `--seal-not-after` catches.
- **What is still not covered, stated rather than argued away.** An unsealed
  index is exactly as strong as ADR 0015 left it. An attacker who deletes the
  sidecar downgrades the submission to that state, and only a recipient passing
  `--require-seal` notices. An attacker who can obtain a token from an authority
  the recipient anchors can re-seal a rewritten list; they cannot backdate it, so
  `--seal-not-after <the day it reached you>` catches that, and without that flag
  it is a documented miss. These are ADR 0011's residuals, unchanged, because
  this is ADR 0011's mechanism.
- **Threat-model delta: one new network path, opt in.** `joint build` reaches an
  authority only when the organizer names one, and only to send a hash. The
  authority learns a digest and never the list, the packets, or who is in them.
  No new key material, no change to what is encrypted, nothing a relay can see.
  Unlike `export`, `joint` has no metered-link policy to consult because it has
  no vault to read one from; the mitigation is that sealing is off by default
  rather than on.
- **Old indexes keep checking.** `joint_index_version` stays 1: the sidecar is a
  new file, not a new field, so an index written before this change parses
  identically and reports an absent seal, which is the truth about it.
- **Rollback:** delete `joint_index.sig.json`. The submission returns to exactly
  ADR 0015's guarantees, and `check` says so.
- **ISO 25010:** integrity, and analysability again: the property that was
  previously a paragraph explaining what the format could not do is now a flag
  the recipient can pass.
- **What this does not do:** it does not establish who assembled the submission,
  that the list is complete, that the households have a joint claim, or anything
  about the merits. A seal proves a list of packets existed in this exact form at
  a time an authority attests to. That is all it has ever proved about a packet
  either.

## Action items

- [x] Seal the canonical index at build time, into a sidecar, with the same token
      record shape `bundle.sig.json` uses.
- [x] `--seal-tsa` / `--seal-tsa-name` / `--dev-tsa` on `joint build`;
      `--require-seal` / `--seal-not-after` on `joint check`.
- [x] Verify a present seal always; report an absent one; fail closed on every
      assertion.
- [x] Delete a stale sidecar when a rebuild produces no seal.
- [x] Reword the standing disclosure so it is true sealed and unsealed.
- [x] Tests: a dropped row, an added row, a stripped seal, a dev seal, a
      backdating assertion, an unparseable date, a date asserted against an
      unsealed index, a malformed sidecar, and a corrupt index that still reports
      its broken seal.
- [x] Extend the same treatment to `campaign export`, whose sub-packets were
      built with no authority and therefore carried no seal at all. Named as
      unfinished in ADR 0011; done as a separate change because it is a separate
      surface, sealing per vault with that vault's own configured authority under
      that vault's own metered-link policy. It needed no decision of its own:
      `campaign.py` already promised a unit's packet is exactly what
      `habitable export` produces, and since ADR 0011 that promise included a
      seal.
