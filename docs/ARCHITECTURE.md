<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright 2026 Chelsea Kelly-Reif -->

# habitable — Architecture

> **Status:** alpha / concept-stage reference implementation. The Python package
> described here exists and runs, but the project is early: APIs, formats, and the
> packet/verification protocol are not yet stable, and there is no app, no released
> distribution, and no production deployment. This document describes the code as it
> is, not a finished system.

## Overview

habitable is an offline-first, end-to-end-encrypted tool that lets tenants and their
unions document habitability problems as evidence a third party can independently
check. The whole system is built as a stack of small, single-purpose modules with a
strict dependency direction: cryptographic and serialization **foundations** carry no
domain knowledge; the **evidence** engine (content hashing, chain of custody) and the
CRDT **case model** build on them; the encrypted **vault** and the **capture** pipeline
assemble those into stored, sealed, timestamped records; **packet** assembly and the
standalone **verifier** turn a case into a shareable, checkable bundle; and **sync**
moves sealed state between peers. The ordering principle is one-way:
`foundation → evidence/model → vault/capture → packet/verify → sync`, and the verifier
(`habitable.verify`) depends only on the pure foundation and evidence/tsa modules — never
on the vault, capture, sync, packet assembly, or the CLI — so a skeptic can audit and
embed verification without pulling in the rest of the system.

## Layering principle

```
                       ┌──────────────────────────────────────────────┐
  foundation           │  canonical  ·  clock  ·  crypto  ·  errors    │
                       └──────────────────────────────────────────────┘
                                          ▲
                       ┌──────────────────┴───────────────────────────┐
  evidence / model     │  evidence (fixity + custody)  ·  exif         │
                       │  tsa (RFC 3161 + dev)         ·  model (CRDT)  │
                       └──────────────────┬───────────────────────────┘
                                          ▲
                       ┌──────────────────┴───────────────────────────┐
  vault / capture      │  vault (encrypted store)  ·  capture pipeline │
                       └──────────────────┬───────────────────────────┘
                                          ▲
                       ┌──────────────────┴───────────────────────────┐
  packet / verify      │  packet + pdf        ·  verify (standalone)   │
                       └──────────────────┬───────────────────────────┘
                                          ▲
                       ┌──────────────────┴───────────────────────────┐
  sync / transport     │  sync  ·  relay (client + server)            │
                       └──────────────────────────────────────────────┘
                                          ▲
                                    cli  ·  demo
```

Two properties matter most:

- **Nothing depends upward.** A lower layer never imports a higher one. Domain modules
  do not know about the CLI; the foundation knows about nothing.
- **`verify` is an island.** `habitable.verify` imports only `canonical`, `crypto`,
  `evidence`, `timeline`, `tsa`, and `errors` — the "verification subset" that is dual-licensed
  Apache-2.0 (see `NOTICE`). It never touches `vault`, `capture`, `sync`, `packet`, or
  `pdf`, so verification can be embedded and redistributed on its own.

## Module map

Foundation:

- **`canonical.py`** — deterministic JSON encoding (`canonical_json`: UTF-8, sorted keys,
  tight separators, no NaN) and SHA-256 helpers (`sha256_bytes`, streaming `sha256_file`).
  Every hash and signature in the system is taken over canonical bytes so the same logical
  content always yields the same bytes on any machine.
- **`clock.py`** — a Hybrid Logical Clock (HLC). Issues a monotonic total order over
  `(wall_ms, counter, node_id)` that tracks physical time but never goes backwards, so
  concurrent offline edits merge deterministically. Time source is injectable for tests.
- **`crypto.py`** — the single place secrets are handled. At rest: a random 32-byte data
  key (DEK) encrypts vault blobs with **ChaCha20-Poly1305 (AEAD)**, and the DEK is itself
  wrapped under a passphrase-derived KEK (**scrypt**), so passphrase rotation and recovery
  backups never re-encrypt bulk data. Identity: per-device **Ed25519** (signing) +
  **X25519** (key agreement) with a short out-of-band fingerprint. In transit: `seal_to`
  is an ECIES-style sealed box (ephemeral X25519 → HKDF → ChaCha20-Poly1305).
- **`errors.py`** — the exception hierarchy (`HabitableError` and friends: `CryptoError`,
  `FixityError`, `CustodyError`, `TimestampError`, `VaultError`, `CaptureError`,
  `PacketError`, `SyncError`, `VerificationError`) so failures surface as typed,
  intentional errors rather than bare library exceptions.

Evidence and case model:

- **`evidence.py`** — the evidence engine. `verify_fixity` recomputes a sealed file's
  SHA-256 and refuses mismatches; `CustodyLog` is an **append-only, hash-linked** chain
  of custody where each entry commits to the previous entry's hash, so insertion,
  deletion, or reordering breaks the chain detectably. Each entry's hash binds a *salted
  commitment* to the actor (not the actor in clear); the exported form drops actor, salt,
  and signature, and `integrity_proof()` emits an identity-free, standalone-verifiable
  proof. Entries may be Ed25519-signed by the device identity.
- **`exif.py`** — explicit, on-purpose EXIF handling. Reads embedded metadata without
  modifying the original; `make_shared_copy` writes a sanitized copy (default: strip all
  metadata; or strip GPS only) and returns a `StripReport` of exactly what was removed
  and retained. JPEG/TIFF via piexif; other raster via Pillow; it refuses files it cannot
  safely sanitize. (Video metadata stripping is intentionally out of scope.)
- **`tsa.py`** — trusted timestamping: proving content existed no later than a point in
  time. `Rfc3161HttpTSA` POSTs a hash to a real **RFC 3161** authority; `LocalRfc3161TSA`
  issues genuine RFC 3161 tokens from a self-signed authority (full offline code path for
  tests/demos); `DevTSA` is a tiny Ed25519 "authority" marked clearly non-production.
  `verify_token` checks the imprint, signature, and (for RFC 3161) the certificate chain,
  returning when the content provably existed.
- **`model.py`** — the case as one **state-based CRDT** document. Three shapes:
  `LWWRegister` (last-writer-wins fields, ordered by HLC), `ORSet` (add-wins set of issue
  ids), and `GrowLog` (append-only/grow-only logs for the timeline and captures, whose
  entries are immutable evidence). `merge` is commutative, associative, and idempotent.

Storage and capture:

- **`vault.py`** — the encrypted case vault: one directory per case. Sealed originals, the
  CRDT document, the custody log, the device identity, and the deferred-timestamp queue
  are all encrypted at rest under the DEK; the only plaintext is `config.toml` (policy, no
  secrets) and `keyfile.json` (the passphrase-wrapped DEK). Sealed originals are bound to
  their content hash via AEAD associated data, and every read re-checks fixity.
- **`capture.py`** — the capture pipeline. Hashes the media, seals the original, appends
  custody entries, and obtains a timestamp now-or-deferred (details below). Never blocks
  on the network.
- **`config.py`** — versioned, committed policy as plain files: configured timestamp
  authorities (`TSAConfig`), the node id, and the sharing policy (`SharingPolicy`:
  `strip_location`, `strip_all_metadata`, `export_custody_identities`). No secrets.

Export and verification:

- **`packet.py`** — assembles a court/inspector evidence packet: a deterministic, signed
  `bundle.json`, location-stripped shared copies of the media, an optional set of embedded
  sealed originals, and (via `pdf.py`) a paginated PDF. Records the privacy/verifiability
  binding described below.
- **`pdf.py`** — renders the human-readable, paginated `packet.pdf` from the bundle
  (selectable text, document language/title set for assistive tech, every visual status
  also stated in words). The machine-checkable truth stays in `bundle.json`; this is the
  presentation layer.
- **`verify.py`** — the standalone verifier a skeptic runs. Given only a packet directory
  (and optional trusted TSA roots), it re-derives every hash, validates each timestamp
  token, checks the producer's Ed25519 signature over the whole bundle, and walks the
  chain of custody — using nothing but the packet. Depends on no other domain module.

Sync and transport:

- **`sync.py`** — end-to-end-encrypted, peer-to-peer case sync. Builds a signed message
  (CRDT state + sealed originals + timestamp tokens) sealed to the recipient's X25519 key,
  and merges incoming messages idempotently (re-delivery changes nothing). Ships two
  transports: `LocalDirTransport` (a shared-directory mailbox, also good for USB/AirDrop)
  and `RelayClient` (ciphertext over HTTP).
- **`relay.py`** — the optional, zero-trust relay server: stores opaque blobs per room and
  hands them back, with a `/healthz` endpoint and passthrough-only metrics. It can read
  nothing (every message is sealed before it arrives) and keeps no per-message logs.
  Optional and replaceable; pure peer-to-peer needs no relay.

Entry points:

- **`cli.py`** — the `habitable` command line: `init`, `id`, `issue`, `capture`,
  `timeline`, `status`, `resolve`, `export`, `verify`, `sync`, `relay`, `demo`. No account,
  nothing to sign up for. `__main__.py` makes the package runnable; `demo.py` walks a
  synthetic case end to end with no network and no real data.

## Capture data flow

Capture is a fixed, offline-safe pipeline. None of the local steps require the network;
only the timestamp can wait.

```
media file
   │  sha256_file(src)                 → content_hash (SHA-256 of the original bytes)
   ▼
seal original                          → vault encrypts the bytes (ChaCha20-Poly1305),
   │                                      AEAD-bound to "original:<capture_id>:<hash>"
   ▼
custody: CAPTURED  (signed)            → append-only, hash-linked entry
   ▼
read back + re-check fixity            → defense in depth; raises on mismatch
custody: FIXITY_CHECKED (signed)
   ▼
trusted timestamp, now or deferred ───┬─ authority reachable: stamp(content_hash),
   │                                  │   verify_token, store token,
   │                                  │   custody: TIMESTAMPED (signed)
   │                                  └─ offline / unreachable: queue in the deferred
   │                                      queue; item is "awaiting timestamp"
   ▼
add Capture to the CRDT document  → save vault (all blobs encrypted)
```

Key points:

- The **content hash is taken over the original bytes** and is the anchor everything else
  binds to. The sealed original is never re-encoded.
- The timestamp authority only ever receives the **hash**, never the media.
- `resolve_deferred` later drains the queue once a device is online, stamping each queued
  item and appending its `TIMESTAMPED` custody entry.

## Export and verify flow

### The privacy / verifiability bridge

There is a real tension: the sealed original keeps its location metadata (it is part of
the evidentiary record), but a shared packet must never leak where a tenant lives.
habitable resolves it without weakening verifiability:

1. The packet exports a **location-stripped shared copy** of each image. Because metadata
   is removed, the shared copy's bytes differ from the original — so its hash (`shared_hash`)
   is *not* the recorded `content_hash`.
2. To keep the shared copy provably tied to the evidence, packet assembly appends a signed
   **`copied_for_sharing`** custody entry whose details bind the original `content_hash` to
   the shared copy's `shared_hash`.
3. The RFC 3161 token still covers the original `content_hash`, and the custody chain still
   threads through the timestamp.

So a recipient can confirm the image they hold is the one that was timestamped — via the
binding — **without** the packet ever disclosing the home's coordinates. (Passing
`include_originals=True` additionally embeds the sealed originals for end-to-end fixity, a
deliberate higher-disclosure choice.)

### Export (`packet.build_packet`)

```
require whole-unit scope (--issue / --since fail closed before staging)
   for each capture:
     read sealed original (re-checks fixity)
     write location-stripped shared copy → media/<id>.<ext>, hash it → shared_hash
     custody: COPIED_FOR_SHARING (signed)  {content_hash, shared_hash, stripped}
     [optional] embed sealed original → originals/<id>
     attach its timestamp token (if present)
   custody: INCLUDED_IN_PACKET (signed) per item
build bundle.json (deterministic canonical JSON):
   issues, timeline, items, custody integrity proof (identity-free), appendix
sign bundle  → bundle.sig.json (Ed25519 over the bundle hash + producer fingerprint)
render packet.pdf from the bundle
```

### Verify (`verify.verify_packet`)

The verifier reads only the packet directory and reports a structured verdict. For each
item it checks, independently:

- **Shared-media hash** — the file in `media/` hashes to its recorded `shared_hash`.
- **The binding** — a signed `copied_for_sharing` custody entry binds that `shared_hash`
  to the item's `content_hash`.
- **The RFC 3161 token** — `verify_token` validates the token over `content_hash`
  (imprint, signature, and certificate chain against any supplied trusted roots).
- **The producer signature** — `bundle.sig.json` is a valid Ed25519 signature over the
  canonical bundle hash.
- **The custody chain** — the integrity proof's entries walk cleanly (sequence, prev-hash
  links, recomputed entry hashes) and the declared head hash matches.
- **Embedded original fixity** — if originals were embedded, each re-derives to its
  `content_hash`.

The overall verdict is intact only if the signature verifies, the custody chain is whole,
there are no structural problems, and every item passes.

## Sync

Sync exchanges **state-based CRDT** messages between peers:

- **Build.** `export_message` packs the case state plus every sealed original and its
  timestamp token into an inner document, signs it (Ed25519), and **seals the whole
  envelope to the peer's X25519 public key** (`seal_to`). The sealed bytes are opaque to
  anyone but the recipient.
- **Import.** `import_messages` tries to open each blob (silently skipping any not
  addressed to this device), verifies the sender's signature, **merges the CRDT state**,
  and imports any new originals — re-checking fixity on receipt and rejecting a
  forged/mismatched timestamp token. Each import appends a signed `IMPORTED` custody entry.
- **Idempotent.** Because the model is a CRDT and originals are deduplicated by id with a
  fixity re-check, re-delivering a message changes nothing — merge is commutative,
  associative, and idempotent.
- **Transport-agnostic.** A shared directory (`LocalDirTransport`) or an HTTP relay
  (`RelayClient`) moves the bytes. The optional **relay sees ciphertext and room metadata
  only** — never contents — and keeps only aggregate passthrough counts. Pure peer-to-peer
  sync needs no relay at all.

## Determinism and reproducibility

Independent verification only works if the same logical content always produces the same
bytes everywhere. Two mechanisms guarantee it:

- **Canonical JSON.** Every hash and signature — custody entries, the packet bundle, sync
  envelopes, CRDT state — is taken over `canonical_json` (UTF-8, sorted keys, tight
  separators, `allow_nan=False`). The encoding is stable across Python versions and
  platforms, so a packet yields the same verdict on any machine.
- **Injected clocks.** The HLC (`clock.py`) and the timestamp authorities (`DevTSA`,
  `LocalRfc3161TSA`) accept an injectable time source, and `Vault` threads a `time_source`
  through to the document clock. Tests can drive time deterministically; CRDT ties break on
  the total `(wall_ms, counter, node_id)` order, so concurrent merges converge identically
  on every replica.
- **Stable ids and ordering.** Capture, issue, and timeline ids embed an HLC stamp, and
  read-model views sort by HLC, so the materialized order of a case is reproducible from
  its state.

## Directory tree

```
habitable/
├── README.md
├── docs/
│   └── ARCHITECTURE.md          # this document
└── src/
    └── habitable/
        ├── __init__.py          # package metadata; small, layered public API
        ├── __main__.py          # python -m habitable entry point
        ├── py.typed             # PEP 561 typing marker
        ├── canonical.py         # canonical JSON + SHA-256 primitives
        ├── clock.py             # hybrid logical clock (HLC)
        ├── crypto.py            # at-rest AEAD + scrypt-wrapped DEK; Ed25519/X25519; sealed box
        ├── errors.py            # typed exception hierarchy
        ├── evidence.py          # content fixity + append-only hash-linked custody log
        ├── exif.py              # explicit EXIF: seal original, strip shared copies
        ├── tsa.py               # RFC 3161 (HTTP + local) and dev TSA; token verification
        ├── model.py             # state-based CRDT case document (LWW + OR-Set + grow-logs)
        ├── config.py            # versioned policy: authorities, node id, sharing policy
        ├── vault.py             # encrypted per-case vault (sealed originals, state, tokens)
        ├── capture.py           # capture pipeline: hash → seal → custody → timestamp
        ├── packet.py            # signed, location-stripped packet bundle
        ├── pdf.py               # accessible paginated packet PDF
        ├── verify.py            # standalone packet verifier (Apache-2.0 subset)
        ├── sync.py              # E2E-encrypted peer-to-peer CRDT sync + transports
        ├── relay.py             # optional ciphertext-only relay server
        ├── cli.py               # the `habitable` command line
        └── demo.py              # synthetic end-to-end walkthrough (no real data)
```
