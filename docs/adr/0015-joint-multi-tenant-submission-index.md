<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# ADR 0015: Joint multi-tenant submission index

- Status: Accepted
- Date: 2026-08-27

## Context

`docs/novel-use-cases-plan.md`'s *Beyond the current portfolio* table ranks a
**joint multi-tenant case bundle** (#13) as value 4, fit 5, confidence 3, effort
M, and decides it *"Next: prototype presentation-only bundling over existing
signed packets."* `ROADMAP.md`'s v0.5 row names the same item. The plan also
writes down the shape it must take, and the reason:

> **#13** is presentation over facts that already exist and verify
> independently, it must not create a new merged-custody artifact (that would
> reopen the scoped/rehashed-custody-view gate workstream A is still closing).
> A safe version is closer to a signed table of contents over N already-signed
> `bundle.json` files than a new packet shape.

The organizer job is concrete and is not the one `campaign` already serves.
`campaign` (`src/habitable/campaign.py`) rolls up several vaults **an organizer
already holds the keys to**. The joint submission is the other situation, and
the commoner one in a tenant union: six households each exported their own
packet on their own device and handed the organizer a folder. The organizer has
no key to any of them, cannot open a vault, and should not need to. What they
need is to hand a court, an inspector, or a housing agency one navigable
submission instead of six unrelated folders with no stated relationship.

Today the only honest way to do that is a covering email, which the recipient
has no reason to trust and no way to check.

## Decision

1. **A new module, `src/habitable/joint.py`, that merges nothing.** It writes a
   table of contents beside packets it does not modify: `joint_index.json` plus
   an accessible `index.html`. It reads no vault, needs no key, and opens no
   network connection. The member packets are opened read-only and are never
   rewritten, re-signed, re-hashed, or copied.
2. **Membership is bound by the member's own bundle digest.** Each row records
   the SHA-256 of that packet's exact `bundle.json` bytes. That is the same
   digest the member's own `bundle.sig.json` signs and the same one an authority
   seals under ADR 0011, so a substituted or edited member is a mismatch the
   index catches before its signature is even consulted.
3. **The index is never a trust root.** Every claim it records is one
   `check_joint_index` recomputes from the packets themselves: the digest is
   re-derived from bytes on disk, and readiness is thrown away and re-obtained
   from `verify_packet`. A doctored index therefore cannot talk its way to a
   passing verdict; the worst it can do is claim things the check disagrees
   with.
4. **Additions are reported, not absorbed.** `check_joint_index` also lists
   packet directories present beside the index that the index does not name, and
   an unlisted member makes the verdict fail. An index that quietly ignored a
   folder someone dropped into the submission would present a
   complete-looking table of contents over a set it never saw.
5. **Build refuses rather than skips.** A subdirectory of the submission folder
   with no `bundle.json` is an error naming that folder, not a silent omission.
   An empty submission folder is an error too.
6. **The index is not itself signed or sealed, and every rendering says so.**
   Three disclosures ride in the JSON and in the HTML: the index is presentation
   only, the index itself is unsigned while its members are signed, and listing
   households together neither makes them one case nor says anything about a
   shared cause. Authenticating the index is deferred to its own decision,
   below.
7. **No protocol surface moves.** `packet_version` stays 4, `bundle.json` and
   `bundle.sig.json` are untouched, the verifier is unchanged, and
   `habitable.verify` gains no new import. The index carries its own
   `joint_index_version`, starting at 1, because it is not a packet and must not
   be versioned as if it were.
8. **The fail-closed direction is not softened by bulk.** Without a
   `--trusted-cert` anchor no member is evidence-ready, exactly as with
   `habitable verify` under ADR 0008, and `habitable joint build` exits non-zero
   rather than presenting a batch as ready. A joint index over unready packets
   is a true index of an unready submission.

## Options considered

| Option | Assessment |
| --- | --- |
| Merge the member cases into one packet with one custody chain | Rejected, and it is the reason this ADR exists. It would reopen the scoped/rehashed custody-view problem workstream A is still closing, it would replace N independently checkable proofs with one the recipient must take on faith, and it would put six households' identifiers into a single chain none of them signed. |
| Extend `campaign export` to cover packets instead of vaults | Rejected: `campaign` is defined by holding the keys, and its whole capability row says so. Bending it to also mean "packets from people whose keys you do not hold" would make one command's privacy story two different stories. |
| Copy each member's `case_id` into the index | Rejected. The index is the file most likely to be forwarded on its own, and a per-household identifier in it buys the reader nothing: the recorded digest already identifies a member unambiguously, and the directory name locates it. The fields that are copied (`unit`, `generated_at`, `language`, `producer_fingerprint`) are already in the member's own `bundle.json`, which travels with it. |
| Compute a combined readiness verdict for the submission | Rejected as stated, kept as a count. "This building's evidence is ready" is one sentence away from "this building's claim is good," which the plan's fit filter excludes. The index reports how many members were ready and names each one; it draws no conclusion about the submission. |
| Sign the index with the organizer's device key | Deferred, not rejected, and deferred for a reason that is not engineering: this project has no notion of an organizer identity, and ADR 0011 already rejected a producer certificate on the ground that naming people in evidence is a safety problem. A key that speaks for an organizer's presentation is a decision about who that key belongs to and what its compromise costs, and it deserves its own record. |
| Seal the index with an RFC 3161 token, as ADR 0011 does for a packet | Deferred to a separate decision for the same reason, and it is the likelier answer: it needs no identity, no key distribution, and no new primitive. It is deliberately not folded in here, because ADR 0011's seal is a decision with recorded rejected alternatives and residual gaps, and extending it to a document that is not a packet should be recorded the same way rather than inherited by assumption. |
| Say nothing about the index being unsigned | Rejected outright. A table of contents that looks authoritative and is not is worse than no table of contents. The limitation is a disclosure in the JSON, a paragraph in the HTML, and a field (`index_signed: false`) a machine can read. |

## Consequences

- **Nothing about existing packets changes.** The golden corpus is untouched,
  `packet_version` does not move, and no verifier anywhere needs to learn a new
  term. A joint index is an ordinary file beside packets; a recipient who
  ignores it verifies exactly what they verified before.
- **What the index does and does not prove is now precise.** It proves no
  *listed* member was substituted, because the digest is recomputed. It does not
  prove the list is the list the organizer wrote: anyone who can write the file
  can add or drop a row, and no field inside an attacker-controlled file can
  prevent that. The mitigation available today is that `check` reports unlisted
  packets and refuses to pass while any exist, so silently *adding* a member is
  caught even though the file is unauthenticated. Silently *dropping* one is
  not, and that is the gap the deferred decision above closes.
- **Threat-model delta: one item, and it is about linkage, not integrity.** The
  index is a document that names several households together. Every field it
  copies is already in the member packet sitting next to it, so it creates no
  new disclosure where it is stored, and it is written only where the organizer
  ran the command. It is still, by design, the artifact whose whole job is to
  associate households, and an organizer who did not want that association
  should not build one. No new network path, no new key material, no change to
  what is encrypted, and nothing a relay can see.
- **Rollback/migration:** none. Deleting `joint_index.json` and `index.html`
  returns the submission folder to a plain directory of packets. No vault, no
  packet, and no protocol version is involved, so there is nothing to migrate
  forward or back.
- **ISO 25010:** functional appropriateness (an organizer job the tool could not
  express) and, principally, analysability: the index turns "trust my covering
  email" into a command the recipient runs.
- **What this does not do:** it does not decide that the listed conditions share
  a cause, that the households have a joint claim, that a court will accept the
  submission, or that the submission is complete. It makes no legal claim of any
  kind, and `docs/capabilities.md`'s "Independent legal/court/inspector fitness"
  row is unchanged and still reads *externally unvalidated*.

## Action items

- [x] `src/habitable/joint.py`: build, check, and an accessible EN/ES index page.
- [x] `habitable joint build` and `habitable joint check`, with the same
      `--trusted-cert` anchor policy and exit-code contract as `habitable verify`.
- [x] EN/ES strings at key parity for every reader-visible string.
- [x] Tamper tests: an edited member, a swapped member, a removed member, an
      added member, a doctored index, and an index naming a path outside the
      submission.
- [x] Fail-closed tests: an unreadable, unparseable, newer-versioned, or
      memberless index, and a submission with nothing in it.
- [ ] Authenticate the index itself. Recorded as a decision to make, not a task
      to schedule; see the two deferred rows above.
