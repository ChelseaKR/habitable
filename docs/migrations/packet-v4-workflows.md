<!-- SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0 -->
# Packet v4 and case-schema v3 migration

Packet v4 adds first-class corroborating artifacts, typed evidence relationships,
versioned use-case profiles, and presentation-only handoff manifests. Case schema
v3 adds append-only `artifacts` and `relationships` CRDT logs plus the selected
profile in ordinary signed metadata.

## Compatibility

- The verifier still accepts committed packet v1, v2, and v3 fixtures with their
  historical meanings. It rejects versions newer than v4.
- Opening a case-schema v1 or v2 state treats absent artifact and relationship
  logs as empty. Saving writes schema v3; old facts are not rewritten.
- A reader limited to case schema v2 fails closed on schema v3 instead of
  discarding new logs.
- Sync protocol v2 carries the additive case state and transfers artifact
  originals through the existing encrypted evidence collection. No relay can
  distinguish captures from artifacts outside the recipient-sealed message.

## Integrity changes

An artifact commits to its neutral metadata and original content hash. A
relationship commits to its type, endpoints, assertion, issue, and recorded time.
Packet v4 includes the commitments and requires matching `artifact_added` or
`relationship_added` custody entries. Imports that predate a local binding get an
honestly labelled `import_binding`; the exporter never claims original-time
protection it did not observe.

`items[].record_kind` distinguishes captures from artifacts. Artifact items retain
the historical `capture_id` field as their generic item identifier so the
standalone byte/timestamp verifier and old downstream item loops remain usable.
The nested `artifact` object carries the new semantics.

## Presentation and review gates

`use_case_profile` and `handoff_views` are signed bundle data, but they cannot
change verification verdicts. A handoff is explicitly `presentation_only` and
names `bundle.json` as its source of truth. Profiles whose legal, medical,
inspector, accessibility, or adopter review is unfinished travel with
`review_state=external_review_required`.

## Backout

The application can stop offering profile/artifact creation without rewriting
vaults. Existing case-schema v3 records remain readable and syncable. Packet v4
must not be relabelled as v3; a rollback release must retain the v4 verifier or
clearly refuse those packets. Artifact originals use the same encrypted storage
layout and can be exported for recovery by their recorded ids and hashes.

## Threat-model delta

- New document formats can contain active or identifying metadata. Habitable does
  not execute them; packet HTML links to non-image documents and warns that they
  are not sanitized. Original embedding remains deliberate.
- Relationship labels can overstate causation. They are rendered as assertions,
  never computed legal or medical conclusions.
- Profiles can become stale claim surfaces. They are built-in and versioned;
  review-dependent profiles remain externally gated.
- Building-pattern releases can be differenced. The implementation exposes one
  fixed question, coarse ISO weeks, household suppression, explicit per-export
  consent, no network transmission, and an unrecoverable-publication warning.
- Partner capsules prove producer-key integrity, not real-world identity or source
  truth. Import preserves the signed capsule as an artifact rather than silently
  adopting its embedded claims.
