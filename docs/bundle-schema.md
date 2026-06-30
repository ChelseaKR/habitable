<!-- SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0 -->
# The habitable packet & bundle format

> **Audience.** Integrators ingesting a packet downstream (persona P-23) and anyone auditing the
> wire format. This is the human companion to the machine-readable
> [`packet-bundle.schema.json`](packet-bundle.schema.json) (JSON Schema 2020-12). Realizes backlog
> **E-26 / R-51** (a documented, versioned bundle with a stability contract).

## A packet is a directory

`habitable export` (or `build_packet`) produces a self-contained directory:

```
4B-packet/
├── bundle.json            # the canonical, signed manifest (this document)
├── bundle.sig.json        # producer Ed25519 signature over bundle.json's bytes
├── media/                 # location-stripped shared copies (referenced by items[].shared_name)
├── originals/             # OPTIONAL sealed originals (present only with --include-originals)
├── packet.html            # accessible human-readable rendering (the conformant view)
└── packet.pdf             # paginated print rendering (optional)
```

`bundle.json` is the source of truth a verifier reads. The other rendered files (`packet.html`,
`packet.pdf`) are presentation; they are not what verification trusts. Those renderings present a
court-ready layout — a cover sheet, a single chronological timeline interleaving notes and photos,
the per-issue detail, and a chain-of-custody / integrity summary — all **derived from the fields
below** (no extra bundle fields, no `packet_version` change); see `src/habitable/bundleview.py`.

## Canonical bytes

`bundle.json` is serialized **canonically**: UTF-8, keys sorted, tight separators (`,` and `:`), no
insignificant whitespace, `NaN`/`Infinity` disallowed. This makes the bytes reproducible across
machines and Python versions — a prerequisite for the signature and for independent verification.
The signature in `bundle.sig.json` is over the SHA-256 of these exact bytes, so do **not**
re-serialize `bundle.json` before checking the signature.

## Top-level fields

| Field | Type | Notes |
| --- | --- | --- |
| `packet_version` | int | Format version. Verifier accepts `1..SUPPORTED_PACKET_VERSION`; newer is rejected, not mis-verified. |
| `case_id` | string | Case identifier. |
| `unit` | string | Unit label; may be empty. |
| `scope` | object | `{type: "issue"\|"unit", issue_id, since}` — what the packet covers. |
| `generated_at` | string | ISO 8601 UTC, e.g. `2026-01-02T00:00:00Z`. |
| `producer_fingerprint` | string | Producing device fingerprint (`xxxx-xxxx-xxxx-xxxx`). |
| `hash_algorithm` | string | Always `"sha256"`. |
| `language` | string | Language of the rendered packet (e.g. `en`, `es`). |
| `template` | object | `{header, footer}` — presentation only. |
| `issues` | array | Selected issues (see below). |
| `timeline` | array | Timeline entries for the selected issues. |
| `items` | array | The media items — the evidentiary core (see below). |
| `custody_proof` | object | Identity-stripped chain-of-custody proof (see below). |
| `disclosures` | array | Human-readable notes of what the packet reveals (location stripped, custody identities not exported, originals embedded). Also rendered, localized, in `packet.html`/`packet.pdf`. |
| `appendix` | object | `{item_count, timestamped_count, includes_originals}`. |

### `items[]` — the evidentiary core

| Field | Type | Notes |
| --- | --- | --- |
| `capture_id` | string | Stable id; also the filename under `originals/` when embedded. |
| `issue_id` | string | The issue this item documents. |
| `content_hash` | hex SHA-256 | Of the **sealed original**. The RFC 3161 token is taken over this. |
| `media_type` | string | MIME type, e.g. `image/jpeg`. |
| `captured_at` | string | Capture time. |
| `shared_name` | string | Filename under `media/` of the location-stripped copy; empty if none. |
| `shared_hash` | hex SHA-256 \| "" | Of the shared copy; empty when no shared media. |
| `stripped` | string | Which metadata was removed from the shared copy (`gps`, `none`, `skipped`, …). |
| `has_original` | bool | Whether the sealed original is embedded under `originals/`. |
| `timestamp` | object \| null | RFC 3161/dev token over `content_hash`; `null` while **awaiting timestamp**. |
| `archive_timestamps` | array | Archive (re-)timestamps chaining back to the primary token. |
| `additional_timestamps` | array | Independent redundant tokens from **other** authorities over the same `content_hash` (not a chain). The verifier counts the item as timestamped if ≥1 authority verifies — no proof rests on a single TSA. Absent in single-authority packets. |

A **timestamp token** is `{kind: "rfc3161"|"dev", tsa_name, token_b64}` where `token_b64` is base64
of the DER token (`rfc3161`) or a canonical-JSON token (`dev`, non-production/offline only).

### `custody_proof` — integrity without identities

The exported chain proves no insertion/deletion/reorder **without** disclosing who did what. It
contains `algorithm` (`sha256`), `length`, `head_hash`, a per-item `items` summary, and `entries[]`.
Each exported entry is:

```
{ seq, action, item_id, hlc, actor_commitment, details{…}, prev_hash, entry_hash }
```

with `entry_hash = SHA-256(canonical_json({seq, action, item_id, hlc, actor_commitment,
details(sorted), prev_hash}))` and `prev_hash` linking to the prior `entry_hash` (genesis = 64
zeros). `action` is one of `captured, imported, fixity_checked, timestamped, viewed,
copied_for_sharing, included_in_packet, note_added`. The clear actor, the per-entry salt, the
Ed25519 signature, and any identity/PII `private_details` are **vault-only** and never appear here —
so a recipient confirms the chain is intact but cannot learn the actors. See
[`crypto-spec.md`](crypto-spec.md) §6.2.

The verifiability bridge: because a shared copy is metadata-stripped, its bytes differ from the
original and cannot hash back to `content_hash`. A signed `copied_for_sharing` entry whose `details`
carry `content_hash` + `shared_hash` binds the two; the verifier requires that binding for any item
with shared media.

### `bundle.sig.json` (sibling file)

```
{ producer_fingerprint, sign_public(b64 Ed25519), bundle_sha256(hex), signature(b64) }
```

`signature` is an Ed25519 signature over the **ASCII hex** of `bundle_sha256`, which must equal the
SHA-256 of the `bundle.json` bytes.

## Stability & compatibility contract

- **SemVer on the format, independent of the package.** The packet format and the verification
  protocol are versioned by `packet_version`, separately from the `habitable` package version.
- **Old packets keep verifying.** A change that could break verification of an existing packet is a
  **major** `packet_version` bump with a migration note — never a silent change. A committed
  golden-packet corpus enforces this in CI.
- **Additive within a major.** New optional fields may appear within a `packet_version`. Consumers
  **must ignore unknown fields** (the JSON Schema sets `additionalProperties: true` at the document
  and object level for exactly this reason) and must not assume field order — the bytes are sorted,
  but treat the document as a mapping.
- **Forward rejection.** A verifier that meets a `packet_version` newer than it supports rejects the
  packet cleanly rather than guessing.

## See also

- Verify a packet (or cross-check it with general tools):
  [`verifier-decision-table.md`](verifier-decision-table.md).
- Embed verification in your own software: [`embedding-the-verifier.md`](embedding-the-verifier.md).
- How the evidence is produced and what it proves: [`evidence-method.md`](evidence-method.md).
