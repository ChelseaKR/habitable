<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# ADR 0017: Corrections and edit history need one append-only change log, and it is a packet-format decision

- Status: Accepted
- Date: 2026-09-04

## Context

Two issues arrived separately and turn out to be one question.

**Issue #241** (split from the #203 umbrella, surfaced by the organizer workflow
review task #123): after a mistyped `habitable issue`, no subcommand offers an
edit, delete, or correct path. Append-only custody is intentional, but a
stressed person at 11pm who fat-fingers a room name has nothing to do about it,
and — because export scoping is blocked (#242) — the typo rides into the
exported packet.

**Issue #261**: the roadmap lists merge/conflict surfacing as *partial*.
Authenticated per-field provenance and a CLI view identify the winning value's
device and time; the history of what it beat is gone, because the state-based
CRDT does not retain overwritten values.

They are the same gap seen from two directions: **the case's own edit history is
not recoverable.** A correction is an edit somebody meant to make; a merge
conflict is an edit two devices made at once. Neither is reconstructible, and a
mechanism that fixed one without the other would be built twice.

### What the code actually does today

Four facts, each verified in the tree rather than assumed, decide this ADR.

1. **`CaseDocument.update_issue()` already exists** (`model.py`), already
   validates the field name against `_ISSUE_FIELDS`, and already stamps each
   write through `_stamp()` — so an edit carries a signed `FieldProvenance`
   naming the device and the time. The storage layer is not the blocker.
2. **That provenance is local-only.** `packet.py`'s `_issue_json()` exports the
   six flat fields and nothing else; neither `packet.py` nor `verify.py`
   mentions provenance at all. `habitable provenance` reads it from the vault on
   the device. **A correction made through `update_issue` today would be
   completely invisible to the person the packet is written for.**
3. **The LWW register does not keep what it overwrote.** Once a field merges,
   the losing value is gone from the state. No UI can display it, and no export
   can carry it, because it no longer exists to carry.
4. **There is exactly one caller of `update_issue` in `src/`, and it is safe for
   a reason worth generalising.** `vault.py`'s timeline path reopens an issue's
   `status` when a `recurrence` event is recorded. That mutation is invisible in
   `_issue_json` — the packet shows `status: open` with no sign it was ever
   otherwise — but it is *accompanied by an append-only timeline entry that
   explains it*, and that entry does export. A reader can reconstruct why the
   status changed from the record they were given.

Fact 4 is the shape of the answer. The one mutation the codebase permits itself
is permitted because an append-only record travels beside it.

### Why the cheap paths were rejected

- **Ship `update_issue` behind a `habitable issue correct` command.** This is
  the tempting one — the storage works, the provenance is signed, it could land
  this week. It is rejected because of fact 2: the correction would be a
  **silent edit** in every artifact that leaves the device. A packet whose
  fields quietly differ from what was first recorded, with nothing saying so, is
  precisely the artifact a skeptical reader is entitled to reject, and shipping
  one would trade a visible typo for an invisible edit. That is a worse record,
  not a better one.
- **Record the correction as a timeline entry.** `EVENT_TYPES` already has an
  `other` escape hatch with a required label, so this needs no vocabulary change
  and no format change, and old verifiers would accept it. Rejected anyway: the
  timeline is the narrative of *the dwelling* — condition observed, notice sent,
  repair attempted. A correction is metadata about the case file, not something
  that happened in the home. Filing one there puts case-file bookkeeping into
  the chronology a court reads as the history of the housing problem, and
  degrades the artifact this project's central claim rests on.
- **Delete or rewrite the entry.** Defeats the chain. Not considered further.
- **Widen `EVENT_TYPES` with a `record_corrected` member.** `verify.py` imports
  `EVENT_TYPES` from `timeline.py` and rejects an unknown value, and the
  verifier subset is redistributed independently under Apache-2.0. Adding a
  member means packets that older verifiers refuse — a format break wearing the
  costume of a one-line change.

## Decision

1. **Corrections and complete edit history are one mechanism: a versioned,
   append-only change log**, carried beside the CRDT state rather than derived
   from it. Every field write is retained with its existing signed provenance
   instead of being collapsed. A correction is an ordinary entry in it; a merge
   conflict is two.
2. **It is packet surface, and therefore a packet-version decision.** The change
   log has to reach the packet, because a correction nobody outside the device
   can see is the silent edit this ADR exists to refuse. That means
   `packet_version` 5, golden fixtures, a migration note, and a verifier that
   understands the new record — the full protocol path, not a field addition.
3. **The rule the design must satisfy, stated now so the implementation is
   judged against it:** *a stored field may be mutated only alongside an
   append-only record, exported with the packet, that says it was.* This
   generalises the one mutation already in the tree (fact 4) rather than
   inventing a new principle.
4. **Superseded values stay visible in the packet.** Hiding them is what a
   skeptic would object to, and a correction the reader can see is stronger
   evidence of good faith than a record that was always right.
5. **Nothing ships before that ADR-and-version work.** Specifically, no
   `habitable issue correct`, and no app edit affordance, until the change log
   exists. The current absence of a correction path is a known cost, recorded
   here, not an oversight.
6. **Two guards pin the facts this decision rests on**
   (`tests/test_record_corrections.py`), so the reasoning cannot rot silently:
   the exported issue payload carries no provenance, and `update_issue` gains no
   new caller without someone revisiting this file.

### The three questions issue #261 asked, answered

- **Does the change log enter the packet?** Yes — see decision 2. That is what
  makes it protocol work rather than a local convenience.
- **Retention.** Unbounded growth is a real cost on the target device. The bound
  is deferred to the implementing ADR, which must state one; "keep everything
  forever" is a decision that has to be made deliberately, not by omission.
- **Privacy.** An edit history is a behavioural record of the tenant — when they
  were awake, how often they revised, what they took back. It is a new exposure
  *inside the vault* and a larger one in an exported packet. The implementing
  ADR must carry a threat-model section before any code, and the default should
  be that the log reaches the packet only where a correction actually occurred,
  not as a complete keystroke history.

## Consequences

- **Easier/safer.** Two issues become one design with one rule to satisfy. The
  rule is testable, and is now tested. The reason the cheap version was refused
  is on the record, so the next person to reach for `update_issue` finds an
  argument rather than silence.
- **Costs.** #241 and #261 both stay open, and the typo #203 described still
  reaches the packet. That is the honest state: this ADR does not fix it, it
  says what fixing it requires and refuses the version that would have looked
  like a fix.
- **Follow-up.** (a) The implementing ADR — packet v5, retention bound, threat
  model, migration. (b) The app and CLI should say what a tenant should do about
  a mistake *today*, at the point of pain, rather than leaving them to discover
  there is no path; that is copy work and does not wait for the protocol.
  (c) `habitable demo` already provides a synthetic case to practise on — the
  "scratch/practice mode" half of #241 — and is simply not offered where someone
  needs it.

## References

- Issues #241 (correction path), #261 (change log), #203 (umbrella), #123
  (organizer workflow review task), #242 (export scoping, blocked behind #262)
- `ROADMAP.md` workstream C, "Merge/conflict surfacing" (*partial*)
- ADR 0002 (state-based CRDT and HLC) — why the register does not retain history
- ADR 0008 (separate integrity, timestamp trust, and readiness) — the precedent
  for keeping distinct claims distinct rather than collapsing them
