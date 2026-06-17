# 2. A state-based CRDT with hybrid logical clocks for offline-first cases

Status: Accepted (2026-06-17)

## Context

An organizer and the tenants on a case routinely edit the same case on different
devices with no network — documentation happens in an apartment, often on the only
phone a tenant has. When those devices reconnect, their edits must converge: no
lost data, no merge that silently drops an observation, and an event order that is
defensible if a landlord's lawyer contests it.

Two constraints make this harder than ordinary offline sync:

- **The threat model forbids a central server.** There is no authoritative replica
  to arbitrate conflicts, and no server may hold plaintext (see
  `../threat-model.md`). Convergence has to be a property of the data itself.
- **Wall clocks disagree.** Phones drift, are set wrong, or sit offline for days.
  We cannot order events by `datetime.now()` across devices and call it a timeline
  a court should trust.

## Decision

Model a case as a single **state-based CRDT** document (a CvRDT), so that merging
two replicas' full states is commutative, associative, and idempotent and the
result is independent of sync order. Three CRDT shapes cover the domain
(`src/habitable/model.py`):

- **LWW registers** for scalar fields — a unit label, an issue's category, room,
  status, severity, description. Last write wins, ordered by timestamp, with a
  deterministic tiebreaker on equal timestamps.
- **An OR-Set** (observed-remove, add-wins) for the set of issue ids, so a
  concurrent add/remove of the same issue resolves to present rather than losing
  the issue.
- **Grow-only / append-only logs** (`GrowLog`) for the timeline and the captures.
  These entries are immutable evidence — a photo's hash, a timeline observation —
  so by construction they never need conflict resolution; merge is set union.

Order events with a **hybrid logical clock** (HLC, `src/habitable/clock.py`) per
device. The HLC tracks physical time closely enough to be meaningful to a court,
never runs backwards, and produces a total order over `(wall_ms, counter,
node_id)` so LWW ties break identically on every device. Each device advances its
clock past every timestamp it merges in, preserving causality despite clock skew.

## Consequences

- Replicas converge with no central server and no conflict-resolution authority,
  which is exactly what the threat model requires.
- Sync messages are **full document state**, which is simple and idempotent:
  applying the same state twice is harmless, and a peer can recover by re-sending
  everything. The honest trade-off is bandwidth — full-state sync sends more than
  a delta-based CRDT would. For case-sized documents over peer-to-peer sync this is
  acceptable for now; a delta-state encoding is a possible future optimization and
  would warrant its own ADR.
- LWW can drop one side of a *true concurrent* conflict on the same scalar field
  (two organizers editing the same issue's status offline at the same instant — one
  value wins deterministically, the other is discarded). We accept this for this
  domain: scalar-field collisions are rare, low-stakes, and recoverable by re-edit,
  whereas the evidence that must never be lost — captures and timeline entries —
  lives in append-only logs that cannot drop data.
- Convergence (commutativity, associativity, idempotence) is guarded by
  property-based tests rather than asserted, since these laws are easy to state and
  easy to break in a refactor.
