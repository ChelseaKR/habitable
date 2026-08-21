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
> `VerificationError` by design; see [§1](#1-packet-level-outcomes).)
>
> **Coverage, stated rather than assumed.** The rows below are normative for the checks that apply
> to **every** packet version: structure, signature, custody, media/original fixity, evidence-bytes
> presence, and timestamp/authority outcomes. They are **not yet complete for the
> version-specific** checks — there is no row for a v3 timeline-commitment check, nor for a v4
> artifact-commitment, relationship-endpoint/cycle, profile/review-state, or handoff-suppression
> check, although the verifier implements all of them (`_verify_v3_timeline`,
> `_verify_v4_workflows`). Until those rows exist, derive an expected verdict for a v3/v4-specific
> case from the code and the committed golden corpus (`tests/golden/packet-v1`…`packet-v4`), not
> from this file, and treat a gap here as a gap in the document rather than a licence the verifier
> grants. This header previously read "normative for `SUPPORTED_PACKET_VERSION = 2`" while the
> verifier had moved to 4 — an auditor or an embedder working from it was working from a contract
> the verifier no longer implements (issue #160).

## 0. The three verdicts (and the fourth claim beside them)

`VerificationReport.structurally_intact` is `True` **iff** *all* of:

- `signature_ok` — the bundle signature verifies over the bundle's own SHA-256, **and**
- `custody_ok` — the chain of custody walks cleanly **and** its computed head equals the declared
  `custody_proof.head_hash`, **and**
- `problems` is empty (no version/structural problem), **and**
- every item's shared media, custody binding, and optional embedded-original fixity pass, **and**
- every item carries at least one real, checkable evidence artifact — a recorded shared copy or an
  embedded original (`evidence_present`, [§4.2b](#42b-evidence-bytes-present-evidence_present)). An
  item with only a content hash and a timestamp, and nothing a human can look at, is never
  structurally intact.

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

`VerificationReport.seal` is reported **alongside** those three, never folded into them: it says
whether a timestamp authority countersigned the whole bundle, which is the only thing in a packet
that binds it as a unit. It changes a verdict only through `problems` (§2.2) — an absent, unasserted
seal leaves every verdict above exactly as it was before this check existed.

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
| intact packet; all tokens valid, **no anchor supplied** | **True** | **False** (`status = "timestamp_authority_untrusted"`, `anchors_supplied = 0`; guidance says trust was *not assessed*) |
| intact packet; all tokens valid, **anchors supplied but none chained** | **True** | **False** (same `status`, `anchors_supplied > 0`; guidance says the anchors did not match or issue the signing certificate) |
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

**`sign_public` is taken from the signature file itself.** So `signature_ok = True` means the packet
is internally consistent with the key sitting next to it — *not* that the producer signed it. An
attacker who rewrites `bundle.json`, rebuilds the custody chain, and signs with a freshly generated
key satisfies every row above. This was **FIX-05**; the measured consequences, including which
tampering it lets through, are enumerated in [`tamper-challenge.md`](tamper-challenge.md) §4 and
executed by `tests/test_tamper_challenge.py`. Two mechanisms constrain it: the pin (§2.1) and the
packet seal (§2.2). Neither makes `signature_ok` mean more than it says.

### 2.1 Producer pin (`expected_producer_key` → `producer_key_pinned`)

Optional, recipient-supplied, and the answer to the paragraph above: the base64 Ed25519 key obtained
through a channel the packet's courier does not control.

| Condition | Result |
| --- | --- |
| not supplied | `producer_key_pinned = False`; no pin check runs |
| not valid base64 | `problems` gains "pinned producer key is not valid base64" |
| decodes to empty | `problems` gains "pinned producer key is empty" |
| supplied, but the packet has no readable `sign_public` | `problems` gains "producer key pinned, but this packet has no readable signing key" |
| supplied and ≠ the packet's `sign_public` | `problems` gains "packet signing key does not match the pinned producer key" |
| supplied and equal (constant-time) | no problem added |

Any of those problems makes `structurally_intact` — and therefore `evidence_ready` — **False**. The
pin fails closed: it is never silently skipped. `producer_fingerprint` is **not** a substitute; it is
derived from `sign_public ‖ box_public`, `box_public` is not in the packet, and the verifier never
reads it.

### 2.2 Packet seal (`packet_seal` → `report.seal`)

An optional RFC 3161 token in `bundle.sig.json` whose imprint is the SHA-256 of the whole
`bundle.json`. It therefore covers every field the signature covers — but with a signature the
producer's device cannot mint. See [`crypto-spec.md`](crypto-spec.md) §6.5 and
[ADR 0011](adr/0011-authority-seal-over-the-whole-packet.md).

| Condition | Result |
| --- | --- |
| no `packet_seal` (missing/unreadable signature file, or the key is absent) | `seal.present = False`; **no problem** unless asserted below |
| `packet_seal` present but not a token record, or its imprint ≠ the recomputed bundle digest, or its signature fails | `seal.present = True`, `seal.verified = False`; `problems` gains "packet seal does not cover this bundle: …" |
| present and valid, authority does **not** chain to a supplied certificate | `seal.trusted = False`; a note, and a problem **only** when `require_packet_seal` |
| present, valid, `kind = "dev"` | `seal.trusted` is always `False` (the DevTSA rule, ADR 0008) |
| present, valid, authority chains | `seal.ok = True` |
| `require_packet_seal` and no seal | `problems` gains "packet seal required, but this packet carries no authority seal over its contents" |
| `require_packet_seal` and an unanchored authority | `problems` gains "packet seal required, but its authority does not chain to a certificate you supplied" |
| `seal_not_after` is not a valid ISO 8601 instant | `problems` gains "seal date … is not a valid ISO 8601 UTC instant" |
| `seal_not_after` supplied and there is no seal | `problems` gains "seal date asserted, but this packet carries no authority seal to date" |
| `seal_not_after` supplied and the seal's `genTime` is later | `problems` gains "packet seal was minted at …, after the … you supplied" |

Any of those problems makes `structurally_intact` — and therefore `evidence_ready` — **False**. Two
asymmetries are deliberate:

- **A present seal is always checked**, asserted or not. A packet carrying a seal that does not
  cover it is making a false claim, and silence about that would be worse than no seal at all.
- **An absent seal is a state, not a failure.** A packet exported offline has none, and it verifies
  exactly as it did before this check existed. Requiring a seal by default would fail every such
  packet — and every packet in `tests/golden/` — in exchange for a guarantee an attacker sidesteps
  by deleting one JSON key. Recipient policy is the only thing that can close that, which is why
  `require_packet_seal` exists and why the CLI prints the seal's state on every run.

`report.seal_statement(language)` renders that state as one localized sentence (EN/ES), including
the "there is no seal" case.

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

`shared_media_ok = True` when `shared_name` is empty does **not**, by itself, mean the item is
fine — see [§4.2b](#42b-evidence-bytes-present-evidence_present), which independently requires
some real evidence artifact to exist at all.

### 4.2b Evidence bytes present (`evidence_present`)

Added for issue #158: a `.heic` capture (the iPhone default photo format) once had no packet
export mapping, so it shipped with `shared_name=""`, nothing in `media/`, and no embedded
original. Both `shared_media_ok` (§4.2, "no shared media" reads `True`) and `custody_binding_ok`
(§4.3, gated on `shared_name` being non-empty) read as "nothing to check, therefore fine" for that
item, so a packet holding zero photographs still verified `evidence_ready`. This check closes that
gap: an item must carry *some* real, checkable evidence artifact to ever be structurally intact — a
content hash and a timestamp with nothing behind them are not evidence a human can look at.

| Condition | `evidence_present` | note |
| --- | --- | --- |
| item has a non-empty `shared_name` | `True` | — |
| item has no `shared_name` but `has_original` is `true` (an embedded original was included) | `True` | — |
| item has neither a `shared_name` nor an embedded original | `False` | `no shared media and no embedded original: this item carries no checkable evidence bytes` |

`evidence_present` folds directly into `structurally_intact` ([§0](#0-the-three-verdicts)), so a
byteless item can never be `evidence_ready` regardless of an otherwise-valid, authority-trusted
timestamp. `packet.build_packet` independently refuses (rather than silently omitting) a
default-policy export of an item that would end up in this state, so it should not arise from a
packet this codebase produced; this check is defense-in-depth for a hand-crafted or otherwise
non-conformant bundle, a packet built by a future code path that bypasses `build_packet`, or a
packet produced by a different tool entirely. An item with an embedded original but no shared
preview copy (`--include-originals` on a media type with no default sanitizer, e.g. `.heic` today)
is a deliberate, disclosed, higher-disclosure choice, not a defect: it reads `evidence_present =
True` and can reach `evidence_ready`, and `packet.html` visibly renders it as an embedded original
with no shared preview, with a link to the original and a metadata-retention warning, rather than
silently rendering an empty figure (see README "Originals are sealed; sharing is a deliberate,
minimizing act").

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

**What the timestamp token does and does not reach.** The RFC 3161 token's imprint is
`content_hash` — the **original** bytes. When originals are not embedded (the default,
`has_original = false`), no file in the packet is bound by the token: the shared copy a reader
actually opens is bound only by `shared_hash`, which lives in the re-signable bundle. Embedding
originals makes the token checkable against real bytes, but still does not tie the shared copy to
the original — only a `copied_for_sharing` custody entry does, and that entry is rebuildable by
anyone who re-signs. A recipient who needs the *presented image* anchored must pin the producer key
(§2.1); the measurements are in [`tamper-challenge.md`](tamper-challenge.md) §4.

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
when that content existed.

**e) Packet seal** — `bundle.sig.json` `.packet_seal.token_b64` is the same DER token structure,
but its imprint is the SHA-256 of `bundle.json` itself. Same tools, one different digest:

```console
$ python3 -c 'import base64,json; \
  t=json.load(open("bundle.sig.json"))["packet_seal"]["token_b64"]; \
  open("seal.tsr","wb").write(base64.b64decode(t))'
$ openssl ts -reply -in seal.tsr -text                  # genTime = when this bundle existed
$ openssl ts -verify -digest $(sha256sum bundle.json | cut -d" " -f1) \
    -in seal.tsr -CAfile <tsa-ca-chain.pem>
```

If that verifies, every byte of `bundle.json` — every hash, date, name, and the custody head —
existed in exactly this form by `genTime`, attested by a party that is not the producer. A packet
with no `packet_seal` key simply has no such attestation; that is the pre-seal baseline, not a
failure.

**One documented, deliberate difference before you file a bug.** `openssl ts -verify -CAfile`
performs full X.509 **path validation**: it discovers intermediates, and checks validity periods,
basic constraints, key usage, and (where configured) revocation. habitable's `--trusted-cert` does
**not**. It is a *one-hop* check: an anchor is accepted when it **is** the token's signing
certificate (pinned by fingerprint) or **directly issued** it. The full statement is
`habitable.tsa.ANCHOR_RULE` in code, and it is repeated in
[`embedding-the-verifier.md`](embedding-the-verifier.md).

The practical consequence: for an authority that issues its responder through an intermediate
(DigiCert, for example), `openssl` succeeds with the published **root** while habitable reports
NOT TRUSTED with that same root, and needs the **issuing** certificate instead. That is not the two
tools disagreeing about the token — it is habitable checking less and saying so. It reports which
of the two untrusted cases occurred (`anchors_supplied`, `guidance()`, and each item's `notes`),
precisely so a reviewer can tell "my anchor did not chain" from "this packet's timestamps are not
from who it says". A disagreement about the **imprint, the signature, or `genTime`** is still a bug
worth a [security report](../SECURITY.md).

## 6. Cross-references

- Constructions and parameters: [`crypto-spec.md`](crypto-spec.md).
- Wire format and field meanings: [`bundle-schema.md`](bundle-schema.md),
  [`packet-bundle.schema.json`](packet-bundle.schema.json).
- Embedding the verifier in your own tool: [`embedding-the-verifier.md`](embedding-the-verifier.md).
