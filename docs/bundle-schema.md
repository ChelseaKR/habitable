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
├── bundle.json            # the canonical, signed evidentiary core (this document)
├── bundle.sig.json        # producer Ed25519 signature over bundle.json's bytes
├── manifest.json           # small, NON-signed export metadata (generated_at) — see below
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

## Canonical bytes, and determinism (EXP-02)

`bundle.json` is serialized **canonically**: UTF-8, keys sorted, tight separators (`,` and `:`), no
insignificant whitespace, `NaN`/`Infinity` disallowed. This makes the bytes reproducible across
machines and Python versions — a prerequisite for the signature and for independent verification.
The signature in `bundle.sig.json` is over the SHA-256 of these exact bytes, so do **not**
re-serialize `bundle.json` before checking the signature.

`bundle.json` also carries **no wall-clock export timestamp**, so it is fully deterministic:
exporting the same case state twice — same items, same issues, same custody chain, same packet
version — produces **byte-identical** `bundle.json` (and therefore an identical signature). The one
genuinely time-varying fact about an export, "when was this copy produced," is not evidentiary — it
says nothing about the underlying evidence — so it lives in the sibling `manifest.json` file
instead, which is deliberately **not signed**. This split means regenerating a packet from
unchanged case state never requires re-signing, and two recipients comparing bundles byte-for-byte
can trust that any difference reflects a real change to the evidence, not export jitter.

### `manifest.json` — non-evidentiary export metadata

```
{ "packet_version": 1, "generated_at": "2026-01-02T00:10:00Z" }
```

| Field | Type | Notes |
| --- | --- | --- |
| `packet_version` | int | Mirrors `bundle.json`'s `packet_version`, for convenience. |
| `generated_at` | string | ISO 8601 UTC. When this specific copy was produced. **Not signed** — do not treat it as evidence of anything; it is a courtesy timestamp for humans comparing exports, not a claim about the case. |

`manifest.json` is intentionally outside the signature: it is regenerated fresh on every export and
is not part of what `habitable verify` checks. A verifier that ignores or lacks this file still
verifies the packet completely. `habitable diff old/ new/` (see below) reads it only to report
*when* each export was produced, never as part of the comparison itself.

## Top-level fields

| Field | Type | Notes |
| --- | --- | --- |
| `packet_version` | int | Format version. Verifier accepts `1..SUPPORTED_PACKET_VERSION`; newer is rejected, not mis-verified. |
| `case_id` | string | Case identifier. |
| `unit` | string | Unit label; may be empty. |
| `scope` | object | `{type: "issue"\|"unit", issue_id, since, statement, exclusions}` — what the packet covers. `statement` is a human-readable minimal-disclosure summary; `exclusions` is an array of what is deliberately *not* included (vault contents outside the scope; pre-`since` items). Defensible against over-broad discovery (item R-35); see [`legal/minimal-disclosure.md`](./legal/minimal-disclosure.md). Also rendered, localized, in `packet.html`/`packet.pdf`. |
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

### Opaque identifiers (packet_version ≥ 2)

Every exported id — `issues[].issue_id`, `items[].capture_id`, `timeline[].entry_id`, and the
`custody_proof` `item_id`s — is an **opaque, per-case-salted digest** (`prefix-<16 hex>`). It is
stable (the same event yields the same id on every device that shares the case) but encodes
**no device wall-clock time and no HLC node id**. The `hlc` fields in `timeline[]` and
`custody_proof.entries[]` are likewise pseudonymized to opaque tokens in the export. Internally the
tool still keeps a full hybrid logical clock for CRDT ordering and merge; that raw stamp simply never
leaves the vault. (In `packet_version` 1 these fields carried the raw `wall_ms.counter.node_id` HLC;
treat all ids and `hlc` values as opaque strings regardless of version.)

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
- **Additive within a major.** New optional fields may appear within a `packet_version`. Consumers
  **must ignore unknown fields** (the JSON Schema sets `additionalProperties: true` at the document
  and object level for exactly this reason) and must not assume field order — the bytes are sorted,
  but treat the document as a mapping.
- **Forward rejection.** A verifier that meets a `packet_version` newer than it supports rejects the
  packet cleanly rather than guessing.
- **`generated_at` moved out of the signed core (EXP-02).** Packets exported before this change
  carried `generated_at` inside `bundle.json`; that field simply goes unread by current tooling
  (unknown/legacy fields are ignored per the rule above) and such packets still verify against the
  golden-packet corpus. New exports never write `generated_at` into `bundle.json` — it lives in
  `manifest.json` only. This is additive/non-breaking, not a `packet_version` bump: nothing a
  verifier checks depended on `generated_at`.

## Comparing two exports: `habitable diff`

`habitable diff old/ new/` compares two packet directories that claim to be exports of the **same**
`case_id` and reports, in the packet's language:

- **items** added, removed, or changed (by `capture_id`) — e.g. a new timestamp attached, a shared
  copy re-stripped, an item newly included;
- **issues** added, removed, or changed (by `issue_id`) — e.g. a severity or status edit;
- **disclosures** added or removed;
- whether the **chain of custody advanced honestly**: the tool checks that `old`'s custody entries
  are an unmodified, position-for-position **prefix** of `new`'s entries (same `entry_hash` at every
  shared index). Growth is expected and reported as e.g. "3 entries added, nothing removed or
  rewritten"; a mismatch in the shared prefix is flagged as a possible history rewrite rather than
  silently summarized as "changed."
- the two exports' `generated_at` (read from each `manifest.json`, purely informational).

It refuses (clean error, not a crash) to compare packets with different `case_id`s. Two exports of
literally unchanged state — identical `bundle.json` bytes — report no changes. See
`habitable diff --help` and :mod:`habitable.diff`.

## See also

- Verify a packet (or cross-check it with general tools):
  [`verifier-decision-table.md`](verifier-decision-table.md).
- Embed verification in your own software: [`embedding-the-verifier.md`](embedding-the-verifier.md).
- How the evidence is produced and what it proves: [`evidence-method.md`](evidence-method.md).
