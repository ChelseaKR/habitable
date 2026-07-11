<!-- SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0 -->
# The habitable packet & bundle format

> **Audience.** Integrators ingesting a packet downstream (persona P-23) and anyone auditing the
> wire format. This is the human companion to the machine-readable
> [`packet-bundle.schema.json`](packet-bundle.schema.json) (JSON Schema 2020-12). Realizes backlog
> **E-26 / R-51** (a documented, versioned bundle with a stability contract).

## A packet is a directory

`habitable export` (or `build_packet`) produces a self-contained directory:

Packet construction happens in a fresh sibling staging directory. The completed
directory is renamed into place only after its bundle, signature, media, HTML, and
optional PDF have all rendered successfully. Re-exporting to an existing path
replaces the entire directory instead of writing into it, preventing stale media
or sealed originals from a broader prior export from leaking into a narrower one.
An ordinary publication failure restores the previous complete directory.

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
recipient-oriented layout — a cover sheet, a single chronological timeline interleaving events and photos,
the per-issue detail, and a chain-of-custody / integrity summary — all **derived from the fields
below**. Timeline 2.0 is an intentional `packet_version` 3 change; v1/v2 retain their historical
meanings. See `src/habitable/bundleview.py`.

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
| `scope` | object | `{type: "issue"\|"unit", issue_id, since, statement, exclusions}` — the versioned/historical shape describing what a packet covers. New packet-v3 construction currently permits only `type: "unit"` with no `since`; issue/date requests fail before output because the v3 custody proof is complete-case. The other field values remain in the schema so previously emitted packets keep verifying, not as a claim that new scoped exports are safe. See [`legal/minimal-disclosure.md`](./legal/minimal-disclosure.md). |
| `generated_at` | string | ISO 8601 UTC, e.g. `2026-01-02T00:00:00Z`. |
| `producer_fingerprint` | string | Producing device fingerprint (`xxxx-xxxx-xxxx-xxxx`). |
| `hash_algorithm` | string | Always `"sha256"`. |
| `language` | string | Language of the rendered packet (e.g. `en`, `es`). |
| `template` | object | `{header, footer}` — presentation only. |
| `issues` | array | Issues in the declared scope; currently all issues in the unit. |
| `timeline` | array | Versioned timeline events in the declared scope; currently the whole unit (see below). |
| `items` | array | The media items — the evidentiary core (see below). |
| `custody_proof` | object | Identity-stripped chain-of-custody proof (see below). |
| `disclosures` | array | Human-readable notes of what the packet reveals (location stripped, custody identities not exported, originals embedded). Also rendered, localized, in `packet.html`/`packet.pdf`. |
| `appendix` | object | `{item_count, timestamped_count, includes_originals, timeline_count, custody_bound_timeline_count}` in v3; the timeline counts are absent in older packets. `timestamped_count` means a token record is attached; it does not assert token validity or authority trust. |

### Opaque identifiers (packet_version ≥ 2)

Every exported id — `issues[].issue_id`, `items[].capture_id`, `timeline[].entry_id`, and the
`custody_proof` `item_id`s — is an **opaque, per-case-salted digest** (`prefix-<16 hex>`). It is
stable (the same event yields the same id on every device that shares the case) but encodes
**no device wall-clock time and no HLC node id**. In v2, `timeline[].hlc` and
`custody_proof.entries[].hlc` are pseudonymized. In v3, a timeline event instead calls that opaque
field `order_token`; this prevents a consumer from mistaking it for a date. Custody entries keep the
historical `hlc` field but it remains opaque. Internally the tool still keeps a full hybrid logical
clock for CRDT ordering and merge; that raw stamp never leaves the vault. In packet v1 only, the HLC
fields carried raw `wall_ms.counter.node_id`. A v3 consumer must not reinterpret v1/v2 fields as the
new occurrence/recording semantics.

### `timeline[]` — sourced case events (packet_version 3)

Packet v3 replaces the free-form v1/v2 `{kind, text, hlc}` presentation with explicit, separately
named facts. It does **not** redefine the old fields. Every v3 event carries:

| Field | Type | Meaning |
| --- | --- | --- |
| `timeline_schema` | int | Always `2`, the Timeline 2.0 event shape. |
| `entry_id`, `issue_id` | string | Opaque event and parent-issue ids. |
| `event_type` | enum | One of `condition_observed`, `notice_sent`, `delivery_confirmed`, `response_received`, `inspection`, `repair`, `recurrence`, `impact`, `other`. |
| `other_label` | string | Required only with `event_type: other`; preserves a neutral custom label. |
| `text` | string | Neutral factual note. |
| `occurred_at` | ISO date/time | What the recorder says was the date/time of the event. It is a claim, not a device timestamp or RFC 3161 attestation. A date without a known time is allowed. |
| `recorded_at` | ISO UTC timestamp | Device time when the append-only entry was created. It is separate from `occurred_at` and is not independently trusted time. |
| `source` | enum | `firsthand`, `message`, `document`, `official_record`, `other`; `unspecified` only on an explicit legacy migration. |
| `source_detail` | string | Required only with `source: other`. |
| `links` | object | `{capture_ids[], notice_entry_id, receipt_entry_id, response_entry_id}`. Event links point to the named reviewed event type. A capture deliberately omitted by export scope may remain referenced by opaque id. |
| `order_token` | string | Opaque CRDT ordering token. It is not a date. |
| `integrity` | object | `{algorithm: sha256, commitment, custody_action: note_added, binding_stage}`. The verifier recomputes the commitment over the semantic fields and requires a matching custody entry. |
| `migration` | object | Present only for an old case entry. Its free-form kind becomes an `other_label`; unknown occurrence/source remain empty/`unspecified`; `binding_stage` is `migration`. |

`binding_stage` is `recorded` for a Timeline 2.0 event protected when it was added, `backfill` for a
new-shape event that predates the custody hook, or `migration` for a legacy free-form entry. The stage
is signed data. A later binding is useful integrity protection but is never presented as if it existed
at the original occurrence or recording time.

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
| `additional_timestamps` | array | Optional redundant tokens naming other authorities over the same `content_hash` (not a chain). Token presence and authority names are untrusted metadata until the verifier validates each token against recipient-selected roots. Absent in single-authority packets. |
| `sensor` | object \| null | Present (non-null) only for **instrument data-file** captures (EXP-09, e.g. a temperature-logger or moisture-meter CSV): the readings interpreted from the sealed original for accessible chart + table rendering. `null`/absent for photos and video. The CSV bytes themselves stay the hash-anchored evidence under `content_hash`. |

A **timestamp token** is `{kind: "rfc3161"|"dev", tsa_name, token_b64}` where `token_b64` is base64
of the DER token (`rfc3161`) or a canonical-JSON token (`dev`, non-production/offline only).

A **sensor series** (`item.sensor`) is `{label_header, value_header, unit|null, readings: [{label, value}],
total_rows, truncated, minimum, maximum, mean, warnings[]}`. It is **corroboration, not proof of cause**:
an independent instrument's reading of a condition (a no-heat or mold case), rendered as a small line chart
over an accessible readings table (the table, never color, is the source of truth). Readings are capped at
500 rows; `total_rows`/`truncated` disclose any truncation, and the full data remains in the sealed original.
A data file is copied into `media/` **verbatim** (a CSV carries no embedded location metadata to strip), which
`stripped` records as *not applicable*.

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

For packet v3, `note_added` details include `timeline_schema=2`, `timeline_sha256=<commitment>`, and
`stage=<recorded|backfill|migration>`. The clear in-vault custody entry is Ed25519-signed. The exported
entry is identity-redacted, recomputed into the public hash chain, and authenticated with the rest of
`bundle.json` by `bundle.sig.json`. Verification requires both the exact semantic commitment and the
matching custody link; changing a date, source, note, or related-record link fails verification even
after an outer-only re-sign unless the custody proof is also rewritten. As with the rest of the
local custody model, a compromised keyholder can rewrite a still-local whole history before a peer
or external anchor has seen its head; the packet does not claim otherwise.

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

### Evidence receipt (downstream ingest record)

A downstream system does not have to re-run the verifier every time it references a packet. The
Apache-2.0 reference importer ([`../contrib/legal_aid_importer.py`](../contrib/legal_aid_importer.py))
distils a verification into a small, signed **evidence receipt**: a JSON object recording the verdict
and — crucially — `packet.bundle_sha256`, the same SHA-256 of the `bundle.json` bytes described above.
Because a receipt names the exact bundle bytes it is about, a relying party can re-hash a packet's
`bundle.json` and confirm a stored receipt refers to *this* packet. A signed receipt seals the receipt
with the ingesting organisation's Ed25519 key using the identical "sign the ASCII hex of the SHA-256"
convention, and pins itself to this document's `packet_version` contract via `receipt_version` and
`packet_schema`. See [`../contrib/README.md`](../contrib/README.md) for the receipt shape and
[`embedding-the-verifier.md`](embedding-the-verifier.md#reference-importer--signed-evidence-receipt-exp-10)
for usage.

## Stability & compatibility contract

- **SemVer on the format, independent of the package.** The packet format and the verification
  protocol are versioned by `packet_version`, separately from the `habitable` package version.
- **Old packets keep verifying.** A change that could break verification of an existing packet is a
  **major** `packet_version` bump with a migration note — never a silent change. A committed
  golden-packet corpus enforces this in CI.
- **The v3 migration is explicit.** V1/v2 `{kind, hlc}` retain exactly their old interpretation.
  V3 uses `{event_type, occurred_at, recorded_at, source, order_token}` and a custody commitment.
  Legacy case entries exported by new software carry a signed `migration` disclosure rather than
  invented occurrence/source facts.
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
