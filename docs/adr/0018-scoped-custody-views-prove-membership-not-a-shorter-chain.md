<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# ADR 0018: A scoped custody view proves membership in the whole chain; it is never a shorter chain

- Status: Proposed
- Date: 2026-09-05

## Context

Issue-scoped and date-scoped packets, and issue-subset organizer shares, are blocked.
`packet.build_packet` raises before it stages anything if `issue_id` or `since` is set;
`share.export_share` raises before state attestation if `issue_ids` is set;
`sync.export_message` raises before a message id is minted if `capture_ids` is set. The
CLI keeps `--issue`, `--since`, and `share --issue` as reserved flags naming issue #262,
and the app says the same thing in `export_scope_help`. Whole-unit and full-case
operations are unaffected.

That hold is correct and this ADR does not lift it. It answers the prior question: what
would have to be true for a scoped disclosure to be *honest*, specified closely enough
that a cryptographer can disagree with it in detail.

**Why this is `Proposed` and not `Accepted`.**
[ADR 0017](0017-corrections-and-edit-history-need-one-append-only-change-log.md) could be
accepted the day it was written because it decided *not* to ship something; the cost of
being wrong was a feature that stayed absent. This one proposes a cryptographic
construction that would carry a tenant's partial disclosure into a courtroom, and the
roadmap makes independent crypto review a precondition of restoring the selectors
([`../../ROADMAP.md`](../../ROADMAP.md), workstream A). A construction this project has
only reviewed itself is not a decided one. Marking it `Accepted` before #265 would be
exactly the overclaim the rest of these documents exist to refuse. It becomes `Accepted`
when that review is done and its findings are remediated or recorded in
[`../audits/`](../audits/).

### What the code actually does today

Five facts, each verified in the tree rather than assumed, decide the shape of this
design.

1. **The chain has no way to express a gap.** `CustodyLog.verify` requires
   `entry.seq == index + 1` for every entry. A subset that keeps its entries' original
   `seq` values raises `CustodyError: custody chain out of order at position 1: seq 3
   (expected 2)` — checked against a six-entry log. The only *representable* subset is
   one that renumbers, which is fact 2. The format does not merely make honest partial
   disclosure awkward; it makes it unsayable.
2. **A renumbered, re-linked subset verifies as a complete chain.** Taking three of six
   entries, renumbering them `1..3`, re-linking each `prev_hash` from the 64-zero
   genesis and recomputing each `entry_hash` produces a log that `CustodyLog.verify`
   accepts (`ok=True, length=3`) and that `verify._verify_custody` accepts
   (`(True, 3)`). Nothing in the packet distinguishes it from a case that only ever had
   three custody entries. This is the packet that "looks whole while silently omitting
   entries", and it is one loop away from existing.
3. **A subset that kept the excluded entries would name the excluded records, everywhere
   it could.** A custody entry's `item_id` *is* the capture, artifact, relationship, or
   timeline-entry id, and its hashed `details` carry that record's `content_hash`,
   `shared_hash`, `artifact_commitment`, `relationship_commitment`, or `timeline_sha256`
   (`capture.py`, `artifact.py`, `vault.py`, `packet.py`). `integrity_proof` then repeats
   every `item_id` in its `items` summary. Beyond the chain: a timeline entry's
   `links.capture_ids` and a relationship's `source_id`/`target_id` sit inside the
   commitments `verify.py` recomputes, so a scoped export cannot strip them without
   failing verification — [`../bundle-schema.md`](../bundle-schema.md) already records
   that historical scoped packets "may retain an opaque reference to a capture omitted
   from that old packet". `_verify_v4_relationship` reports `relationship points to a
   missing endpoint`, so a date-scoped packet that filtered captures by `captured_at`
   while keeping its issue's relationships would fail verification outright. The share
   path has its own: `CaseDocument.subset_state` filters issues, timeline, captures, and
   artifacts by the selected set, but passes `self._issues.removes` through unfiltered —
   those are raw HLC add-tags for removed issues — while `meta` carries `case_salt`, the
   HMAC key `opaque_id` uses. A recipient holding both could re-derive the opaque ids of
   issues removed outside their scope.
4. **The exported chain is already a derived, rehashed chain, and the tree contains two
   different derivations.** `CustodyLog.integrity_proof(hlc_map=…)` calls
   `_rehash_with_hlc`, which redacts every entry, rewrites each `hlc` through the
   per-case opaque mapping, re-links from genesis, and recomputes every hash — so a
   packet's `custody_proof.head_hash` is *not* the vault's head. A sync message calls
   `integrity_proof()` with no mapping, so its head is the raw one. For one chain the two
   values are never equal. Rehashing a derived custody structure is not a new idea here;
   it is what a packet already does.
5. **The tree already binds a derived chain to a source head, and that is the shape of
   the answer.** On import, `sync._apply_captures` appends an `imported` custody entry
   whose `details` carry `source_custody_head` and `source_custody_sha256` — the sender's
   head and the digest of the sender's whole proof. The receiving device's chain
   *states, inside its own hashed material, which foreign chain state it came from*. A
   scoped view needs the same move, made checkable rather than merely stated.

One more thing the new format has to fix. `verify._verify_custody` compares only the
declared `head_hash` against the walked chain; it ignores `custody_proof.length` and
`custody_proof.items`, and `bundleview.py` renders that unchecked `length` to a human.
`sync._custody_from_proof` does check `length`. The two verifiers do not agree today
about which summary fields are load-bearing, and a scoped format cannot afford that.

### Why the cheap paths were rejected

- **Filter the entries, renumber, re-link.** The tempting one: a dozen lines, and every
  existing test passes. Rejected on fact 2 — it is the artifact the hold exists to
  prevent, and it is worse than a leak, because a leak is visible to the person harmed
  while this is invisible to everyone.
- **Keep the original `seq` values and let the chain have holes.** Rejected on fact 1:
  today's verifier calls that `custody chain out of order`, the same verdict it gives a
  tampered chain, so a reader cannot tell honest partial disclosure from attack.
  Teaching the verifier to accept holes is a verifier change, therefore a version bump,
  so this option buys none of the compatibility it appears to buy while giving up any
  ability to prove what the holes contained.
- **Add a `custody_view` member beside `custody_proof` inside packet v4.** Rejected, and
  this is the sharpest of the rejections. [`../bundle-schema.md`](../bundle-schema.md)'s
  stability contract requires consumers to **ignore unknown fields**. An old verifier
  handed such a packet would ignore the member that exists to warn it and verify the
  `custody_proof` beside it. The additive rule that makes ordinary format growth safe is
  exactly what makes this unsafe: the warning is the one thing an old reader is required
  to skip.
- **Keep every entry but blank the excluded ones' `item_id` and `details`.** Rejected:
  `entry_hash` covers both fields, so a blanked entry no longer recomputes and the reader
  holds an entry they cannot verify.
- **Keep every position, replacing each excluded entry with its `entry_hash` as an
  opaque link, and re-walk the chain to the declared head.** This is the design this ADR
  reached first, and it is wrong. Because a withheld position contributes a
  producer-chosen 32-byte value and no constraint, an adversary grafts freely: place a
  withheld link with any value `P`, follow it with a fabricated disclosed entry whose
  `prev_hash` is `P`, then another withheld link set to the *real* chain's value at that
  point, and the walk still terminates at the real head. The reconstruction proves only
  that disclosed entries chain to their immediate disclosed neighbours. Recording it
  here because it is the obvious reading of "never delete a link", it looks like a proof,
  and it is not one.
- **Restore the selectors now and document the risk.** Rejected: a disclosure the reader
  cannot audit is not made safe by a paragraph the reader does not get.

## Decision

1. **A scoped disclosure is a derived artifact with its own name, schema, and hash
   domain: a *custody view*.** It is never a `custody_proof`. A packet or message
   carries exactly one of the two members — never both, never neither.
2. **A view proves membership, not adjacency.** Every custody entry is accumulated into
   a Merkle tree over the chain's entry hashes; a view carries, for each disclosed entry,
   its position and an inclusion proof against that tree's root. Given the root, a
   disclosed entry cannot be fabricated or moved, and the number of entries the case holds
   cannot be understated — each of those changes the root. This replaces the
   grafting-vulnerable design in the last rejection above.
3. **The disclosed entries are rehashed into a second chain under their own domain and
   labels, rooted at a commitment to the view's scope.** Three independent separations,
   so no verifier holding one artifact can mistake it for the other.
4. **The accumulator is added to the full-case proof too**, so a whole-unit packet and a
   scoped view of the same case are comparable, and so anyone holding a full export can
   compute the root a view claims without any new anchor being published.
5. **This is a new packet version and a new sync protocol version.** Not a field addition
   (see the third rejection). This ADR deliberately does **not** reserve a number: ADR
   0017 named `packet_version` 5 for the append-only change log and neither design has
   shipped, so whichever reaches implementation first takes 5 and the other takes 6. The
   sync protocol string becomes `habitable-sync-v3`, which a v2 peer already rejects
   before merge — `_validate_message` compares that string for equality and raises before
   any state is touched.
6. **Scope is closed under links, never trimmed to fit.** If a disclosed record commits
   to a link whose endpoint is outside the requested scope, the exported scope is the
   *closure* of the request, the bundle records what the closure added, and the operator
   is told before publication. Silently dropping the link is forbidden by fact 3;
   silently widening the disclosure is a decision only the tenant may make.
7. **A device that imports from a view records that its source was scoped.** The
   `imported` custody entry gains `source_custody_kind: "view"` and the view's scope
   commitment beside the existing `source_custody_head`. Without it, a device that
   received partial provenance would go on to present it as unqualified provenance.
8. **Nothing ships before the checklist below is complete** — not the CLI selectors, not
   the app control, not a preview behind a flag.

### The construction

`custody_view` replaces `custody_proof` in a scoped bundle and in a scoped sync message:

```json
{
  "view_schema": 1,
  "domain": "habitable-custody-view-v1",
  "algorithm": "sha256",
  "scope": {"type": "issue", "issue_ids": ["issue-…"], "since": "", "until": "",
            "requested_issue_ids": ["issue-…"], "closure_added": 0},
  "scope_commitment": "<hex>",
  "source": {"algorithm": "sha256", "length": 41, "head_hash": "<hex>",
             "entries_root": "<hex>", "hlc_mapping": "opaque-per-case"},
  "disclosed": 12,
  "withheld": 29,
  "entries": ["… 12 disclosed entries, source_index strictly increasing …"],
  "items": {"cap-…": {"entries": 3, "last_action": "included_in_packet",
                      "head_hash": "<view entry hash>"}},
  "view_head": "<hex>",
  "view_root": "<hex>"
}
```

A disclosed entry carries the source payload verbatim, its position, its inclusion proof,
and its links in the view chain:

```json
{"view_seq": 3, "source_seq": 7,
 "action": "captured", "item_id": "cap-…", "hlc": "<mapped>",
 "actor_commitment": "<hex>", "details": {},
 "source_prev_hash": "<hex>", "source_entry_hash": "<hex>",
 "audit_path": [{"side": "right", "hash": "<hex>"}, {"side": "left", "hash": "<hex>"}],
 "prev_view_hash": "<hex>", "view_entry_hash": "<hex>"}
```

`source_seq` is the entry's own 1-based `seq` in the chain, so it is already inside the
hashed payload; the entry's leaf index in the accumulator is `source_seq - 1`. There is
deliberately no second position field to drift out of step with it.

- `source_entry_hash` must equal `CustodyEntry(seq=source_seq, …,
  prev_hash=source_prev_hash).recompute_hash()` — the existing payload shape, unchanged,
  so the Apache-2.0 verifier reuses `habitable.evidence` and gains no dependency.
- The accumulator is RFC 6962-shaped over the 32-byte decodings of the entry hashes, with
  `D = "habitable-custody-view-v1"`:

  ```text
  leaf(h)      = SHA-256(0x00 || D || h)
  node(l, r)   = SHA-256(0x01 || D || l || r)
  root([])     = SHA-256(0x02 || D)
  root([h])    = leaf(h)
  root(hs)     = node(root(hs[:k]), root(hs[k:])),  k = largest power of two < len(hs)
  ```

  The distinct leaf and interior prefixes, and the no-promotion split, are not decoration:
  without them two different entry lists can share a root, which would let a view move an
  entry without moving the root.
- `scope_commitment = SHA-256(canonical_json({domain, view_schema, scope}))`.
- `view_entry_hash = SHA-256(canonical_json({domain, view_schema, view_seq, source_seq,
  action, item_id, hlc, actor_commitment, details(sorted), prev_view_hash}))`, and the
  first disclosed entry's `prev_view_hash` is the **scope commitment**, not 64 zeros.
- `view_root = SHA-256(canonical_json({domain, view_schema, scope_commitment, source,
  disclosed, withheld, view_head}))` — the single value the bundle signature covers and
  an authority seal ([ADR 0011](0011-authority-seal-over-the-whole-packet.md)) can
  countersign.

**The three separations.** (i) The view payload's key set differs from the chain
payload's — it lacks `seq` and `prev_hash` and adds `domain`, `view_schema`, `view_seq`,
and `prev_view_hash` — so under canonical JSON, which is injective over key/value
structure, no view preimage can equal a chain preimage, and `CustodyEntry.from_dict`
raises on a view entry rather than quietly accepting one.
(ii) The domain string is inside every preimage, including every Merkle node. (iii) The
view chain's genesis is the scope commitment, so even a walker that ignored field names
entirely computes a different head. Any one suffices; all three are cheap.

**What a verifier checks, in order.** Ordering matters here as it does in
[`../sync-protocol-v2.md`](../sync-protocol-v2.md) §3: every structural check precedes any
claim derived from the contents.

1. Exactly one of `custody_proof` and `custody_view` is present.
2. `disclosed == len(entries)`, `disclosed + withheld == source.length`, and `source_seq`
   is strictly increasing within `1 .. source.length`.
3. Each disclosed entry's payload recomputes to its `source_entry_hash`.
4. Each `audit_path` folds that hash to `source.entries_root` at leaf `source_seq - 1` in
   a tree of exactly `source.length` leaves — path length and sibling sides are determined
   by the index and the size, so a path of the wrong shape is a failure, not a shrug.
5. Walk the view chain from `scope_commitment`: `view_seq` dense from 1, each
   `prev_view_hash` equal to the running value, each `view_entry_hash` recomputed. The
   final value must equal `view_head`.
6. Recompute `scope_commitment` and `view_root`, and require the bundle's own `scope`
   member to agree with `custody_view.scope`.
7. Recompute `items` from the disclosed entries and compare exactly — closing the gap
   where `verify._verify_custody` checks only `head_hash` while `bundleview.py` renders
   `length`.
8. Every item binding, timeline commitment, and relationship commitment must resolve
   against a disclosed entry. A withheld position can never satisfy a binding.

### What a reader can conclude, and what is honestly lost

**What a view commits to.** Its scope; the exact entries it discloses and where each sits
in the source chain; how many entries the source chain has and therefore how many are
withheld; the head and the accumulator root of the chain it was cut from — all under one
`view_root`.

**How a reader tells a view from a truncated chain.** By the member name and
`view_schema`, by the entry grammar, by the non-zero genesis, by the domain string. But
the load-bearing answer is not a marker: **a truncated chain is not expressible.** There
is no field that says "this is all of it"; there is `source.length`, which every inclusion
proof is checked against, and a producer who understates it changes the root and breaks
every path.

**What survives to the source proof, and what does not.** Three tiers; the third is the
honest limit behind the roadmap's "where possible".

- *Given the root — from a full export of the same case, a counterpart's sync receipt, or
  a sealed earlier bundle:* every disclosed entry is **proved** to be the entry at that
  index of a chain of exactly that length. Not asserted. Fabrication, reordering,
  insertion, and understated length are all excluded by collision resistance.
- *Given only the view:* internal consistency, and a self-describing claim about which
  chain state it came from. A reader with no anchor learns the shape of the disclosure but
  cannot confirm the chain existed.
- *With no anchor and a hostile keyholder:* nothing. Someone who rewrites the whole chain
  before any counterpart or timestamp has seen it produces a coherent view of a fictional
  case. That is not new here — it is the residual [`../threat-model.md`](../threat-model.md)
  §5 already states for the full chain — but it is exactly the boundary of what a view can
  promise, and the artifact must not read as promising more.

Two things are lost outright, and the packet must say both rather than let a reader assume
them:

- **A view cannot prove its scope filter was applied faithfully.** It proves that what it
  shows is real and that nothing was deleted from the count. It cannot prove that every
  in-scope entry was shown: a producer may withhold an in-scope custody entry that no
  other record references. Check 8 catches a withheld entry some binding needs; it cannot
  catch a withheld `viewed` or a second `fixity_checked`. "These records are genuine" is
  provable; "this is all of them for this issue" is not.
- **A packet view and a sync view of the same chain are not comparable.** Because a packet
  rehashes under the opaque per-case HLC mapping and a sync message does not (fact 4),
  their heads and roots differ for one chain. `source.hlc_mapping` names the derivation so
  two artifacts are only ever compared when comparison means something.

### Compatibility

- **Today's verifier, handed a new-version packet:** it refuses cleanly. The v4 golden
  packet with `packet_version` set to 5 yields exactly one problem — `packet_version 5 is
  newer than supported 4; upgrade habitable to verify this packet` — with
  `custody_ok=False`, zero items, `structurally_intact=False`. No partial verification, no
  crash.
- **A version-downgrade attack fails closed.** A scoped packet carries no `custody_proof`,
  so editing `packet_version` back to 4 to coax an old verifier into accepting it yields
  `_verify_custody → (False, 0)`: a missing proof reads as a broken chain, not an absent
  check.
- **The new verifier, handed an old packet:** versions 1–4 keep verifying with their
  historical meanings per the stability contract; the view path is reached only at the new
  version.
- **The corpus does not yet test the case that matters.** All four committed golden
  packets (`tests/golden/packet-v1` … `packet-v4`) are whole-unit — `scope.type == "unit"`,
  empty `issue_id` and `since`. Historical *scoped* v1/v2 packets are described in
  [`../bundle-schema.md`](../bundle-schema.md) and are precisely the artifact this ADR
  replaces, but nothing pins their behaviour. "Old scoped packets keep verifying" is an
  untested claim until such a fixture is committed.
- **Sync:** a v2 peer rejects a v3 message on the protocol string before any merge; a v3
  peer accepts a v2 message unchanged.

### Threat model: what a scoped packet reveals that a whole-unit one does not

A scoped packet is a narrower disclosure of *contents* and a wider one of the *existence
of a remainder*. That trade is not incidental — it is the price of refusing to present a
truncation as complete — and the tenant must be told it before they choose.

- **The size of the case they did not show you.** `source.length` and `withheld` say how
  many custody entries exist beyond this disclosure; an inspector shown one issue learns
  the vault holds far more. There is no construction that proves a packet is untruncated
  while hiding how much was withheld: they are the same fact.
- **Where the withheld activity sits.** Disclosed `source_seq` values reveal the
  interleaving — that a run of undisclosed custody activity falls between two disclosed
  captures. Against someone who also holds a full export of the case this adds nothing,
  because `scope` is declared in the clear and a full packet names every record; to a
  recipient who holds only the scoped packet it is a real disclosure.
- **Linkability across exports.** Under the same case salt and mapping, entry hashes are
  stable, so audit paths in two scoped packets of one case are linkable and their
  withheld sets partially intersectable. Blinding the sibling hashes would forfeit the
  inclusion proofs that make tier one work. A reviewer may reasonably prefer that trade in
  the other direction; it is stated here as a choice, not an oversight.
- **That a scope was chosen at all.** Which issue a tenant showed a court and which they
  did not is metadata about a legal strategy. `scope.statement` says as much in ordinary
  language today; the view adds the arithmetic that makes it precise.
- **Not disclosed:** the ids, content hashes, actions, or timing of withheld records. Every
  entry hash is a digest over a payload containing a fresh 128-bit actor salt, so a hash on
  an audit path is not a membership oracle for a guessed record.

Hiding the counts was considered and rejected: it re-creates the truncation lie this ADR
exists to refuse. What remains is informed consent — the export path must state, in the
operator's language and through `disclosure.py` rather than as hand-written English in the
bundle, what a scoped packet reveals about the remainder, before it is published.

### Before the CLI and app selectors come back

Executable, in order. Every item, not a subset.

1. Independent crypto review of this construction (#265), findings remediated or formally
   accepted in [`../audits/`](../audits/). This ADR moves to `Accepted` here and not
   before.
2. [`../crypto-spec.md`](../crypto-spec.md) §6 gains the view construction and the
   accumulator *before* the code, per that document's own rule that the spec is what gets
   reviewed.
3. A new `packet_version`, a new sync protocol version, and a migration note beside
   [`../migrations/packet-v4-workflows.md`](../migrations/packet-v4-workflows.md).
4. Golden corpus: a whole-unit packet at the new version, a scoped packet at the new
   version, and a scoped v1/v2/v3 fixture, which the corpus does not contain today.
5. Verifier work: exactly-one-of enforcement, the eight ordered checks, recomputed
   summaries, bindings resolvable only against disclosed entries, and no new dependency in
   the Apache-2.0 verification subset
   ([`../embedding-the-verifier.md`](../embedding-the-verifier.md)).
6. Adversarial privacy tests: for every scope, no id, content hash, commitment, or mapped
   `hlc` belonging to an excluded record appears anywhere in the published bytes —
   extending the pattern `tests/test_share.py` already uses for the unit label.
7. Adversarial integrity tests: a fabricated disclosed entry, a moved `source_seq`, an
   understated `source.length`, a malformed or wrong-length `audit_path`, a duplicated
   leaf, a relabelled scope, and a view chain re-rooted at 64 zeros each fail — and the
   view joins the stateful hostile-packet harness, since the defects that matter here are
   compositional.
8. Atomic-publication tests: a scoped export that fails after appending
   `copied_for_sharing` entries leaves neither a packet directory nor those entries, and
   two exports from one vault do not lose each other's custody entries, since
   `build_packet` restores a whole snapshot on failure.
9. Sync v3 tests: a v2 peer rejects a v3 message before merge, and an import from a view
   records `source_custody_kind: "view"` in the importing device's own chain (decision 7).
10. `subset_state` fixes: filter `_issues.removes` to the selected set, and apply
    closure-or-refuse to relationships instead of today's silent cross-scope drop.
11. Localized (EN/ES) scope and remainder copy through `disclosure.py`, rendered in
    `packet.html` and `packet.pdf`.
12. Only then: `export --issue`, `export --since`, `share --issue`, and the app's export
    scope control.

## Consequences

- **Easier or safer.** The dangerous artifact stops being expressible rather than being
  discouraged: `source.length` is not a free variable once every inclusion proof is
  checked against it. A reader gets a partial disclosure whose completeness they can audit
  without holding the case. The two verifiers stop disagreeing about which summary fields
  are load-bearing, and the accumulator gives the project a per-case value worth anchoring
  in future work.
- **Costs.** A view is larger than a proof by roughly `disclosed × log2(source.length)`
  hashes — about ten kilobytes to disclose twelve entries from a four-thousand-entry chain,
  before deduplicating shared path prefixes. Every full export must now compute the
  accumulator. A scoped packet permanently reveals the size and timing shape of what it
  withholds. Old verifiers cannot read scoped packets at all, which lands hardest on
  exactly the embedded Apache-2.0 deployments a court or legal-aid group is least able to
  upgrade.
- **What stays blocked.** #242 and the export-scoping half of #203 remain blocked until
  the checklist is complete. That is the honest state: this ADR does not restore scoping,
  it says what restoring it costs and refuses the version that would have looked like a
  restoration.
- **Follow-up outside this file.** Once accepted, this decision needs a row in
  [`../../ROADMAP.md`](../../ROADMAP.md) workstream A, a residual-risk row in
  [`../threat-model.md`](../threat-model.md) §6 for the remainder disclosure, an update to
  [`../sharing-trust-model.md`](../sharing-trust-model.md)'s "safe restoration path"
  paragraph, and a `docs/capabilities.md` entry. None are written yet, and none should be
  until the review in step 1 has had its say.

## References

- Issues #262 (this restoration), #265 (independent crypto review), #242 and #203 (the
  scoping friction it blocks)
- [`../../ROADMAP.md`](../../ROADMAP.md) workstream A, "Versioned scoped/rehashed custody
  views (P0 restoration)" — the exit criteria this design is written against, including
  the note that the chain proves a *prefix* and suffix truncation is caught only by a
  separately committed head
- [`../crypto-spec.md`](../crypto-spec.md) §6.2 (the chain), §6.5 (the seal that would
  cover a `view_root`); [`../bundle-schema.md`](../bundle-schema.md) (`custody_proof`, the
  stability contract, historical scoped packets)
- [`../sync-protocol-v2.md`](../sync-protocol-v2.md) §2 (why v2 cannot represent a scoped
  original-bearing share), [`../sharing-trust-model.md`](../sharing-trust-model.md)
- [`../threat-model.md`](../threat-model.md) §5 (tamper-evident, not tamper-proof, against
  the keyholder), [`../verifier-decision-table.md`](../verifier-decision-table.md) §3
- [ADR 0011](0011-authority-seal-over-the-whole-packet.md) — binding an artifact as a
  whole, and naming the residual instead of hiding it
- [ADR 0017](0017-corrections-and-edit-history-need-one-append-only-change-log.md) — the
  `packet_version` 5 reservation this ADR sequences against
- [ADR 0008](0008-separate-integrity-timestamp-trust-and-readiness.md) — keeping distinct
  claims distinct, which is why a view head is not a chain head
