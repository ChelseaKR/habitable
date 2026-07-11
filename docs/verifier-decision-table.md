<!-- SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0 -->
# habitable — verifier decision table and independent cross-check

> **Audience.** Security reviewers and verifier embedders. This enumerates exactly what
> `habitable.verify.verify_packet` decides for every malformed or hostile input — the truth table a
> reviewer fuzzes against (backlog **R-39**) — and how to confirm a packet **without** habitable at
> all, using general RFC 3161 and SHA-256 tooling (backlog **R-31**).
>
> **Contract.** The verifier **fails closed**: it reports integrity, timestamp-authority trust, and
> evidence readiness as separate claims, and never crashes on hostile input. Malformed structure
> becomes a clean rejection, not an exception escaping `verify_packet`. (Pre-structural
> read/parse conditions are raised as
> `VerificationError` by design; see [§1](#1-packet-level-outcomes).) This file is normative for
> `SUPPORTED_PACKET_VERSION = 2`.

## 0. The three verdicts

`VerificationReport.structurally_intact` is `True` **iff** *all* of:

- `signature_ok` — the bundle signature verifies over the bundle's own SHA-256, **and**
- `custody_ok` — the chain of custody walks cleanly **and** its computed head equals the declared
  `custody_proof.head_hash`, **and**
- `problems` is empty (no version/structural problem), **and**
- every item's shared media, custody binding, and optional embedded-original fixity pass.

Timestamp presence and trust do **not** redefine structural integrity. A signed packet can therefore
be structurally intact while an item awaits a timestamp, contains an invalid token, or has a valid
token whose authority is untrusted.

`VerificationReport.timestamp_authority_trusted` is `True` **iff** the packet contains at least one
item and every item has at least one cryptographically valid timestamp whose signing certificate
chains to a caller-supplied trusted certificate. The certificate embedded in a token is evidence to
check, never an implicit trust anchor. `DevTSA` always reports `False`.

`VerificationReport.evidence_ready` is `True` **iff** the packet is structurally intact, contains at
least one item, and every item has a valid, authority-trusted timestamp. `VerificationReport.ok` is
retained as a fail-closed alias for `evidence_ready`; `ItemVerdict.ok` has the same tightened meaning.
This is technical readiness, **not** an admissibility or legal-outcome claim.

For migrations, `ItemVerdict.cryptographically_verified` and
`VerificationReport.cryptographically_verified_items` expose the historical mechanical check:
intact item bytes plus a valid timestamp token, regardless of root trust. They must never be
presented as evidence readiness.

## 1. Packet-level outcomes

| Condition | `structurally_intact` | `evidence_ready` / `ok` |
| --- | --- | --- |
| `bundle.json` missing | raises `VerificationError` (cannot verify what isn't there) | — |
| `bundle.json` not valid JSON / not UTF-8 | raises `VerificationError` (clean message, no crash) | — |
| `bundle.json` is JSON but not an object | raises `VerificationError` | — |
| `packet_version` missing or not an integer | **False** (`problems` set) | **False** |
| `packet_version` > supported | **False** (`problems` set) | **False** |
| an entry in `items` is not an object | **False** (`problems` set) | **False** |
| signed/custody-valid empty packet | **True** | **False** (`status = "no_items"`) |
| intact packet; item awaits timestamp | **True** | **False** (`status = "timestamp_missing"`) |
| intact packet; attached token invalid | **True** | **False** (`status = "timestamp_invalid"`) |
| intact packet; all tokens valid but any authority untrusted | **True** | **False** (`status = "timestamp_authority_untrusted"`) |
| intact packet; every item has a valid, trusted timestamp | **True** | **True** (`status = "evidence_ready"`) |

> The `VerificationError` cases are the only ones that do not return a `VerificationReport`.
> Embedders should treat a raised `VerificationError` as "could not assess integrity" (see
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

For each item the verifier exposes the structural checks below plus timestamp presence, mechanical
token verification, authority trust, and evidence readiness. `notes` remains diagnostic English
text for logs; localized CLI summaries are separate.

### 4.1 Timestamp (`timestamp_present`, `timestamp_verified`, authority trust)

| Condition | `timestamp_present` | `timestamp_verified` | `timestamp_authority_trusted` |
| --- | --- | --- | --- |
| no primary or additional token | `False` | `False` | `False` |
| token signature/imprint fails | `True` | `False` | `False` |
| valid token; no matching trusted certificate supplied | `True` | `True` | `False` |
| valid `DevTSA` token, with any certificate arguments | `True` | `True` | `False` |
| valid RFC 3161 token chaining to a supplied root | `True` | `True` | `True` |
| at least one valid/trusted redundant authority | `True` | `True` | `True` |

`verify_token` follows the **token's own** digest and signature algorithms (SHA-1…SHA-512, RSA or
ECDSA), so real public-TSA tokens verify, not just SHA-256/RSA ones. Pass `trusted_certs` to assert
the TSA chains to a root you trust. Without it, a mechanically valid token still has
`timestamp_verified = True`, but `timestamp_authority_trusted`, `evidence_ready`, and `ok` remain
`False`. `trusted_authorities` names only anchored authorities; `verified_authorities` names all
mechanically valid ones.

**Multiple-authority redundancy.** An item may also carry `additional_timestamps`: independent
tokens from *other* authorities over the **same** `content_hash` (not a chain). The verifier checks
each, lists every authority that verified in `verified_authorities`, and treats the item as
timestamped if **at least one** authority (primary *or* additional) verifies — so the proof never
rests on a single TSA. With no `additional_timestamps`, behaviour is identical to a single-authority
packet: a failed/absent primary leaves the item not timestamp-verified unless a redundant token
passes. A token over a *different* hash never satisfies the item. At least one valid token supplies
mechanical timestamp verification; at least one valid **and anchored** token supplies authority
trust.

### 4.2 Shared media (`shared_media_ok`)

| Condition | `shared_media_ok` | note |
| --- | --- | --- |
| no `shared_name` on the item | `True` | `no shared media included for this item` |
| `media/<shared_name>` missing | `False` | `shared media file missing` |
| `sha256(media/<shared_name>)` ≠ `shared_hash` | `False` | `shared media does not match its recorded hash` |
| file present and hash matches | `True` | — |

### 4.3 Custody binding (`custody_binding_ok`)

The privacy/verifiability bridge: a policy-processed packet copy has its own `shared_hash`; when
metadata is stripped, its bytes differ from the sealed original and cannot hash back to
`content_hash`. A signed `copied_for_sharing` custody entry binds the two hashes.

| Condition | `custody_binding_ok` | note |
| --- | --- | --- |
| item has a `shared_name` but no custody entry binds `(content_hash, shared_hash)` | `False` | `no signed custody entry binds the shared copy to the original` |
| binding present (or no shared media) | `True` | — |

### 4.4 Original fixity (`original_fixity_ok`)

| Condition | `original_fixity_ok` |
| --- | --- |
| `originals/<capture_id>` not embedded | `None` (not penalized) |
| embedded and `sha256` matches `content_hash` | `True` |
| embedded and hash mismatch | `False` → item not structurally intact; note `embedded original failed fixity` |

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
