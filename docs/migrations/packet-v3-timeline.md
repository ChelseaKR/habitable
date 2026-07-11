<!-- SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0 -->
# Packet v3 and Timeline 2.0 migration

Packet v3 is a deliberate format bump. It introduces sourced, dated, linked, custody-bound timeline
events without changing the historical meaning of any packet-v1 or packet-v2 field.

## Compatibility promise

- Current verification accepts packet versions 1, 2, and 3.
- The committed fixtures under `tests/golden/packet-v1`, `packet-v2`, and `packet-v3` run through the
  same current verifier in CI.
- Packet v1 keeps its raw `timeline[].hlc`; packet v2 keeps its opaque `timeline[].hlc`. Neither is
  interpreted as v3 `occurred_at` or `recorded_at`.
- New exports use packet v3 and `timeline[].order_token`; they do not emit v2 `kind` or `hlc` fields.

## Case-state migration

The encrypted case schema is now version 2. Opening a schema-v1 case is read-compatible and does not
rewrite its append-only grow-log entries. When an old free-form timeline entry is exported:

1. its `kind` is preserved as the v3 `other_label`;
2. `event_type` becomes `other`;
3. `occurred_at` stays empty and `source` becomes `unspecified`—the migration does not invent facts;
4. the HLC wall time is exposed as `recorded_at` when it can be decoded;
5. a signed local `note_added` custody entry commits to the v3 semantic representation with
   `stage=migration`;
6. the packet carries a signed `migration` disclosure and the verifier requires the matching custody
   commitment.

Repeat exports are idempotent: an exact existing binding is reused rather than appended again.

## New event contract

Use `habitable timeline --type ... --occurred-at ... --source ...`; the hidden `--kind` option remains
only so older scripts do not stop working immediately. The local app exposes reviewed choices plus
Other, records `recorded_at` automatically, and can link captures plus notice/delivery/response events.

A recurrence reopens the same issue and appends an immutable `recurrence` event. It does not create an
orphan issue.

## Integrity boundary

For new events, the custody binding is created and Ed25519-signed in the vault at recording time. The
exported custody proof redacts actor identity and per-entry signatures; `bundle.sig.json` authenticates
the whole public bundle. The v3 verifier checks the semantic commitment and link types in addition to
the existing outer signature and hash-linked custody chain.

This establishes integrity of the recorded assertion. It does not prove that an event happened, that
the reported occurrence date is true, or that a source is accurate. A compromised local keyholder can
still rewrite a whole history before a peer or external anchor has seen the chain head.

## Integrator checklist

- Branch on `packet_version` before parsing timeline entries.
- Treat v1/v2 `hlc` and v3 `order_token` as opaque ordering data.
- Present `occurred_at`, `recorded_at`, and `source` as separate facts.
- Do not call a v3 event RFC 3161 timestamped; RFC 3161 tokens remain attached to media items.
- When reading a historical scoped packet, preserve links whose target capture was omitted by its
  old `since` scope; describe the target as not included rather than silently dropping the signed
  reference. New packet-v3 construction is whole-unit only.
- Reject unknown newer packet versions instead of guessing.

See [`../bundle-schema.md`](../bundle-schema.md) for the field table and
[`../evidence-method.md`](../evidence-method.md) for the proof boundary.
