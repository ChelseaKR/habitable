<!-- SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0 -->
# habitable — verifier decision table and independent cross-check

> **Audience.** Security reviewers and verifier embedders. This enumerates exactly what
> `habitable.verify.verify_packet` decides for every malformed or hostile input — the truth table a
> reviewer fuzzes against (backlog **R-39**) — and how to confirm a packet **without** habitable at
> all, using general RFC 3161 and SHA-256 tooling (backlog **R-31**).
>
> **Contract.** The verifier **fails closed**: it never accepts altered or unverifiable evidence as
> intact, and never crashes on hostile input — malformed structure becomes a clean rejection, not an
> exception escaping `verify_packet`. (Two pre-structural conditions are raised as
> `VerificationError` by design; see [§1](#1-packet-level-outcomes).) This file is normative for
> `SUPPORTED_PACKET_VERSION = 1`.

## 0. What "intact" means

`VerificationReport.ok` is `True` **iff** *all* of:

- `signature_ok` — the bundle signature verifies over the bundle's own SHA-256, **and**
- `custody_ok` — the chain of custody walks cleanly **and** its computed head equals the declared
  `custody_proof.head_hash`, **and**
- `problems` is empty (no version/structural problem), **and**
- every item's `ItemVerdict.ok` is `True`.

`ItemVerdict.ok` is `True` **iff**: `timestamp_verified` **and** `shared_media_ok` **and**
`custody_binding_ok` **and** `original_fixity_ok is not False` (i.e. the embedded original either
matches or was not included).

> **Consequence worth noting:** an item that is still **awaiting timestamp** has
> `timestamp_verified = False`, so the item — and the whole packet — reports **NOT intact**. That is
> correct *degraded* behavior: an un-timestamped item lacks its timestamp proof, and the
> verifier says so rather than passing it as clean.

## 1. Packet-level outcomes

| Condition | Verifier behavior | `report.ok` |
| --- | --- | --- |
| `bundle.json` missing | raises `VerificationError` (cannot verify what isn't there) | — |
| `bundle.json` not valid JSON / not UTF-8 | raises `VerificationError` (clean message, no crash) | — |
| `bundle.json` is JSON but not an object | raises `VerificationError` | — |
| `packet_version` missing or not an integer | early return; `problems = ("bundle has no integer packet_version",)` | **False** |
| `packet_version` > `SUPPORTED_PACKET_VERSION` | early return; `problems = ("packet_version N is newer than supported 1; upgrade habitable…",)` | **False** |
| an entry in `items` is not an object | `problems` gains "malformed item in bundle"; that item is skipped | **False** |
| everything well-formed | full per-item + custody + signature evaluation below | depends |

> The two `VerificationError` cases are the only ones that do not return a `VerificationReport`.
> Embedders should treat a raised `VerificationError` as "NOT intact / could not verify" (see
> [`embedding-the-verifier.md`](embedding-the-verifier.md)). On the version-problem early return the
> signature is still evaluated and reported, but `custody_ok` is forced `False` and `items` is empty.

## 2. Signature (`bundle.sig.json` → `signature_ok`)

| Condition | `signature_ok` |
| --- | --- |
| `bundle.sig.json` missing | `False` |
| signature file not JSON / not an object | `False` |
| `doc.bundle_sha256` ≠ SHA-256 of the actual `bundle.json` bytes | `False` |
| `sign_public` or `signature` missing or not a string | `False` |
| Ed25519 verify of `signature` over ASCII(`bundle_sha256`) fails | `False` |
| all of the above pass | `True` |

Any malformed signature file is a *failed signature*, never a crash (`json`/`Unicode`/`Value`/`OS`
errors are caught). Note the signature binds the **producer's** key to the bundle bytes; it asserts
"this device produced exactly these bytes," not third-party identity (see
[`crypto-spec.md`](crypto-spec.md) §4).

## 3. Chain of custody (`custody_proof` → `custody_ok`)

The chain is parsed and walked; **any** of these makes `custody_ok = False`:

| Condition | Result |
| --- | --- |
| `custody_proof.entries` missing/empty or entries malformed | parse/verify raises internally → `(False, …)` |
| `seq` not strictly `1,2,3,…` | `CustodyError` → broken |
| an entry's `prev_hash` ≠ previous `entry_hash` | `CustodyError` → broken |
| an entry's recomputed hash ≠ its stored `entry_hash` (edited content) | `CustodyError` → broken |
| computed head ≠ declared `custody_proof.head_hash` | `head_ok = False` → broken |
| clean walk **and** declared head matches | `custody_ok = True` |

Walking never throws out of `_verify_custody`; a broken chain is a verdict, not an exception.

## 4. Per-item checks

For each item the verifier sets four booleans and a list of human-readable `notes`.

### 4.1 Timestamp (`timestamp_verified`, `gen_time`, `tsa_name`)

| Condition | `timestamp_verified` | note |
| --- | --- | --- |
| `item.timestamp` is not an object (null/absent) | `False` | `awaiting timestamp` |
| token present, `verify_token(token, content_hash, trusted_certs)` succeeds | `True` | (sets `gen_time`, `tsa_name`) |
| token valid but TSA does **not** chain to a supplied trusted root | `True` | `timestamp valid but authority not chained to a trusted root` |
| `archive_timestamps` present and chain back to the primary token | `True` | `archive-timestamped (N link(s))` |
| token, archive chain, digest, signature, or cert check fails | `False` | `timestamp check failed: <reason>` |

`verify_token` follows the **token's own** digest and signature algorithms (SHA-1…SHA-512, RSA or
ECDSA), so real public-TSA tokens verify, not just SHA-256/RSA ones. Pass `trusted_certs` to assert
the TSA chains to a root you trust; without it, a structurally valid token still verifies but is
flagged as not-chained (the item can still be `ok`, but a reviewer/court should supply roots).

**Multiple-authority redundancy.** An item may also carry `additional_timestamps`: independent
tokens from *other* authorities over the **same** `content_hash` (not a chain). The verifier checks
each, lists every authority that verified in `verified_authorities`, and treats the item as
timestamped if **at least one** authority (primary *or* additional) verifies — so the proof never
rests on a single TSA. With no `additional_timestamps`, behaviour is identical to a single-authority
packet: a failed/absent primary leaves the item not timestamp-verified. A token over a *different*
hash never satisfies the item.

### 4.2 Shared media (`shared_media_ok`)

| Condition | `shared_media_ok` | note |
| --- | --- | --- |
| no `shared_name` on the item | `True` | `no shared media included for this item` |
| `media/<shared_name>` missing | `False` | `shared media file missing` |
| `sha256(media/<shared_name>)` ≠ `shared_hash` | `False` | `shared media does not match its recorded hash` |
| file present and hash matches | `True` | — |

### 4.3 Custody binding (`custody_binding_ok`)

The privacy/verifiability bridge: a shared copy is metadata-stripped, so its bytes differ from the
sealed original and cannot hash back to `content_hash`. A signed `copied_for_sharing` custody entry
therefore binds `content_hash → shared_hash`.

| Condition | `custody_binding_ok` | note |
| --- | --- | --- |
| item has a `shared_name` but no custody entry binds `(content_hash, shared_hash)` | `False` | `no signed custody entry binds the shared copy to the original` |
| binding present (or no shared media) | `True` | — |

### 4.4 Original fixity (`original_fixity_ok`)

| Condition | `original_fixity_ok` |
| --- | --- |
| `originals/<capture_id>` not embedded | `None` (not penalized) |
| embedded and `sha256` matches `content_hash` | `True` |
| embedded and hash mismatch | `False` → item NOT ok; note `embedded original failed fixity` |

## 5. Independent cross-check without habitable (R-31)

A skeptic can confirm the core claims with off-the-shelf tools — the point of standards-based
evidence. Given a packet directory:

**a) Shared-media fixity** — recompute and compare to the item's `shared_hash`:

```console
$ sha256sum media/<shared_name>          # compare hex to items[].shared_hash in bundle.json
```

**b) Embedded-original fixity** (if `originals/` present) — compare to `content_hash`:

```console
$ sha256sum originals/<capture_id>       # compare to items[].content_hash
```

**c) Bundle signature** — the signature is Ed25519 over the **ASCII hex** of the bundle's SHA-256.
Recompute the digest and verify with any Ed25519 library:

```console
$ sha256sum bundle.json                  # must equal bundle.sig.json .bundle_sha256
```

```python
import base64, hashlib, json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
sig = json.load(open("bundle.sig.json"))
digest = hashlib.sha256(open("bundle.json","rb").read()).hexdigest()
assert digest == sig["bundle_sha256"]
Ed25519PublicKey.from_public_bytes(base64.b64decode(sig["sign_public"])) \
    .verify(base64.b64decode(sig["signature"]), digest.encode("ascii"))   # raises on failure
```

**d) RFC 3161 token** — `items[].timestamp.token_b64` is base64 of the DER timestamp token. Decode
and inspect/verify with OpenSSL against the content hash and the TSA's CA chain:

```console
$ python3 -c 'import base64,json,sys; \
  t=json.load(open("bundle.json"))["items"][0]["timestamp"]["token_b64"]; \
  open("token.tsr","wb").write(base64.b64decode(t))'
$ openssl ts -reply -in token.tsr -text                 # read genTime + the imprint (hash)
$ openssl ts -verify -digest <content_hash_hex> -in token.tsr -CAfile <tsa-ca-chain.pem>
```

The imprint in the token must equal the item's `content_hash`, and `genTime` is the upper bound on
when that content existed. If habitable's verdict and these tools ever disagree, that is a bug worth
a [security report](../SECURITY.md).

## 6. Cross-references

- Constructions and parameters: [`crypto-spec.md`](crypto-spec.md).
- Wire format and field meanings: [`bundle-schema.md`](bundle-schema.md),
  [`packet-bundle.schema.json`](packet-bundle.schema.json).
- Embedding the verifier in your own tool: [`embedding-the-verifier.md`](embedding-the-verifier.md).
