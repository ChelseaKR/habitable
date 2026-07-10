# Evidence method

> **Status:** concept stage — design documented, build not yet started. This describes a
> reference implementation and the procedure it is built to support. Treat every claim
> here as a spec to be checked against the code, not a finished, audited product.

This document is the precise, reproducible procedure that makes a habitable packet
*checkable* rather than merely asserted. It is written for a skeptic: an opposing
lawyer, a housing inspector, an auditor, or a future maintainer who wants to confirm —
without trusting this project — that a packet's media were not altered after capture,
that each item provably existed by a stated time, and that the custody record is intact.

Everything below maps to code in `src/habitable/`. The load-bearing modules are
[`canonical.py`](../src/habitable/canonical.py),
[`evidence.py`](../src/habitable/evidence.py),
[`tsa.py`](../src/habitable/tsa.py),
[`packet.py`](../src/habitable/packet.py), and
[`verify.py`](../src/habitable/verify.py). The verifier (`verify.py`) and the pure
modules it imports are offered under Apache-2.0 as an additional permission, so a court
or legal-aid group can embed verification without the AGPL reaching their code.

What this method does **not** establish is stated plainly in
[What this proves — and what it does not](#what-this-proves--and-what-it-does-not).

---

## Contents

- [Determinism: the foundation under every hash](#determinism-the-foundation-under-every-hash)
- [Fixity: pinning exact content](#fixity-pinning-exact-content)
- [Trusted timestamps: an upper bound on existence](#trusted-timestamps-an-upper-bound-on-existence)
- [Chain of custody: append-only and identity-free on export](#chain-of-custody-append-only-and-identity-free-on-export)
- [Packet binding: the privacy/verifiability bridge](#packet-binding-the-privacyverifiability-bridge)
- [Independent verification procedure](#independent-verification-procedure)
- [Versioning: old packets keep verifying](#versioning-old-packets-keep-verifying)
- [What this proves — and what it does not](#what-this-proves--and-what-it-does-not)

---

## Determinism: the foundation under every hash

Tamper-evidence and independent verification both require that the *same logical
content* always produces the *same bytes*, on any machine, forever. If serialization
were ambiguous, two honest parties could hash identical data and disagree, and the whole
scheme would collapse.

Every hash and every signature in habitable is taken over **canonical JSON**, produced
by `canonical_json` in [`canonical.py`](../src/habitable/canonical.py):

- **UTF-8** encoding, with `ensure_ascii=False` so characters are emitted directly.
- **Sorted keys** (`sort_keys=True`), so object key order never affects the bytes.
- **No insignificant whitespace** — separators are `(",", ":")`, the tightest legal form.
- **No NaN/Infinity** (`allow_nan=False`), which JSON cannot represent portably.

This encoding is stable across Python versions and platforms, which is the prerequisite
for reproducible verification. Anywhere this document says "the hash of X," it means the
SHA-256 of the canonical-JSON encoding of X, unless X is raw file bytes (see Fixity).

The hash algorithm is SHA-256 throughout (`HASH_ALGORITHM = "sha256"`), and it is named
explicitly in the custody integrity proof and the packet bundle so a verifier never has
to guess.

---

## Fixity: pinning exact content

**Goal.** Tie an exhibit to one exact sequence of bytes, so any later alteration —
malicious or accidental corruption — is detectable.

**At capture.** The original media's bytes are hashed with **streaming SHA-256** and the
result is recorded as the item's `content_hash`. Streaming matters in practice: media is
read in 1 MiB chunks (`sha256_file` in [`canonical.py`](../src/habitable/canonical.py))
rather than loaded whole into memory, so hashing a large video on a phone does not exhaust
RAM. The hash is over the **original bytes**, including the file's embedded EXIF capture
time and any GPS — that metadata is part of the evidentiary record and is preserved, not
stripped, in the sealed original.

**Sealed originals are immutable.** The original file is written to a case vault that the
app treats as read-only. Nothing in the normal flow rewrites or re-encodes a sealed
original; sharing produces a *separate* copy (see [Packet binding](#packet-binding-the-privacyverifiability-bridge))
and never touches the original.

**Fixity is re-checked on every read.** Reading a sealed original is not a bare file
read — it recomputes the SHA-256 and compares it to the recorded `content_hash`. The
primitives are in [`evidence.py`](../src/habitable/evidence.py):

- `content_hash(path)` — the SHA-256 recorded at capture.
- `fixity_ok(path, expected_hash)` — boolean re-check.
- `verify_fixity(path, expected_hash)` — raises `FixityError` on mismatch, refusing to
  proceed rather than silently serving altered bytes.

Because every read re-derives the hash, silent corruption or tampering surfaces as a
failed fixity check, never as a quietly altered exhibit.

---

## Trusted timestamps: an upper bound on existence

**Goal.** Turn "the tenant says this photo is from January" into "an independent
authority attests this exact content existed no later than 02 Jan."

**Mechanism: RFC 3161 over the content hash.** The `content_hash` — never the photo — is
submitted to an **RFC 3161** Time-Stamping Authority (TSA), which returns a signed token
binding that hash to the authority's `genTime`. The request carries the SHA-256
message-imprint and a random nonce (`_build_request` in
[`tsa.py`](../src/habitable/tsa.py)). **The TSA only ever sees the hash**, so it learns
nothing about the photo, the home, or the tenant.

### Semantics: what gen_time means

An RFC 3161 token proves an **upper bound** on existence/creation time: the content
existed *no later than* `genTime`. Equivalently, the file cannot have been fabricated or
edited after that moment without breaking the timestamp.

It does **not** prove a lower bound, authorship, or depiction:

- It does **not** prove *who* created the content.
- It does **not** prove *what* the content depicts or that a described condition is real.
- It does **not** prove the content did not exist *earlier* than `genTime`.

These limits are intrinsic to trusted timestamping and are restated in
[What this proves](#what-this-proves--and-what-it-does-not).

### Offline capture defers the token

Capture never blocks on the network. Offline, an item is hashed and sealed instantly and
the timestamp request is queued; the item carries an **awaiting-timestamp** status until
connectivity lets the token be fetched and attached. In a packet, an item with no token
serializes `"timestamp": null`, and the verifier records the note `awaiting timestamp`
for it (see `_verify_item` in [`verify.py`](../src/habitable/verify.py)) rather than
treating the absence as a pass.

### What a long awaiting-timestamp gap means for integrity

Fixity and the timestamp are **separate steps**, so a long delay before a token attaches
does not weaken the part that runs at capture. At capture — fully offline and instantly —
the original bytes are hashed (SHA-256) and sealed and a custody entry is appended, so the
exact content is **anchored the moment it is captured**, no matter when the device next
reaches a TSA. The hash pins those bytes; any later alteration still fails fixity, and the
re-check on every read does not depend on a token. What the gap defers is only the
**external time anchor** — the part the trusted timestamp, not the device, provides.

For a tenant on metered or intermittent data this is the point: documenting now is safe;
the timestamp catches up later. Read the gap honestly:

- **The hash anchors content, not time.** During the gap the content is fixed (tamper-
  evident against later alteration), but its *existence time* is not yet attested by an
  independent party.
- **A later token is an upper bound fixed when it attaches, not retroactively.** A token
  fetched after a gap proves the content existed no later than the token's `genTime` — the
  moment it was actually stamped — not the earlier capture time. A long gap therefore
  yields a *looser* upper bound, never a false one; the proof stays honest about when
  independent attestation began.
- **It never silently passes.** An item exported during the gap serializes
  `"timestamp": null` and the verifier reports `awaiting timestamp`, so a recipient is
  never misled into reading an un-anchored item as timestamped.
- **Honest limit (the keyholder window).** A gap with *no external anchor at all* is the
  window the [threat model](./threat-model.md) flags: the local custody chain is
  tamper-*evident* to anyone who later verifies it, but it cannot bind a hostile
  *keyholder* who rewrites the whole local record before any counterpart or timestamp has
  seen the chain head. An external anchor — a synced peer already holding the head, or the
  trusted timestamp itself — is what closes that window.
- **Close the gap to keep the bound tight.** Fetching the token as soon as the device is
  online — and stamping against several authorities (see
  [Multiple authorities](#multiple-authorities)) — keeps the upper bound close to capture
  and keeps the proof from resting on one party. The custody log's *order* is anchored
  locally throughout; only the external *time* anchor waits on connectivity.

### Multiple authorities

More than one TSA can be configured, so the proof does not rest on a single party.
`Rfc3161HttpTSA` (the production client) POSTs the request to a public authority's URL
and validates that the URL is HTTP(S) before sending; it parses the
`TimeStampResp`, accepts only `granted`/`grantedWithMods` status, and extracts the
signed token. Each token records the issuing authority's name, so a packet can carry
tokens from several authorities and each is verified on its own terms.

### Archive / re-timestamping (expiring TSA certificates)

A TSA's signing certificate eventually expires. A long-held packet can be
**re-timestamped** — an archive timestamp taken over the existing token — so that old
evidence keeps verifying after the original signing certificate is no longer current.
This is the standard RFC 3161 longevity pattern; the format and verifier are versioned
(see [Versioning](#versioning-old-packets-keep-verifying)) to preserve it.

### Token verification

`verify_token` in [`tsa.py`](../src/habitable/tsa.py) dispatches by token kind and, for
an RFC 3161 token (`_verify_rfc3161_token`), checks all of:

1. **CMS structure** — the token is CMS `SignedData` encapsulating `TSTInfo`.
2. **Message-imprint binding** — the token's imprint algorithm is SHA-256 and its
   `hashed_message` equals the `content_hash` being verified. A token for a different
   hash is rejected.
3. **CMS signature** — the signed attributes carry a `message_digest` matching the
   `TSTInfo`, and the signer's RSA signature over those attributes verifies against the
   signing certificate's public key.
4. **Certificate chain** — the signing certificate is checked against supplied trusted
   roots/pins (`_verify_cert_chain`): a fingerprint-pinned authority certificate is
   trusted directly, otherwise the signer must carry a valid signature from a trusted
   issuer. With no trusted certificates supplied, the chain is reported as **untrusted**
   (signature still validated) rather than failing outright.
5. **genTime** — the token's `genTime` is extracted and returned as the proven
   existence bound, normalized to ISO-8601 UTC.

The result is a `TimestampInfo` carrying `gen_time`, the digest, the authority name, and
a `trusted_chain` flag. When the chain is not trusted, the note is "signature valid;
signing certificate not chained to a trusted root."

### Non-production dev TSA

[`tsa.py`](../src/habitable/tsa.py) ships three authorities. Two issue **real RFC 3161
tokens** — `Rfc3161HttpTSA` (production, talks to a public authority) and
`LocalRfc3161TSA` (a self-signed X.509 authority that issues genuine RFC 3161 tokens so
the standard code path runs fully offline in tests and demos). The third, `DevTSA`, is a
minimal Ed25519 "authority" for offline use where even a local X.509 TSA is overkill.

`DevTSA` is **clearly non-production and the tokens say so**: a dev token is always
reported with `trusted_chain=False` and the note "non-production dev TSA (local key, no
trusted certificate chain)". Its verifier (`_verify_dev_token`) still checks the Ed25519
signature over the canonical-JSON payload and confirms the embedded digest matches the
content — so a dev token is internally sound, it simply has no trusted authority behind
it and must never stand in for real evidence.

---

## Chain of custody: append-only and identity-free on export

**Goal.** Record what happened to each item — captured, imported, viewed, copied for
sharing, included in a packet — in a log where insertion, deletion, or reordering is
detectable, *without* exporting who did those things.

**Append-only, hash-linked.** `CustodyLog` in
[`evidence.py`](../src/habitable/evidence.py) is a hash-linked chain. Each `CustodyEntry`
carries a `seq`, the action, the `item_id`, a hybrid-logical-clock stamp (`hlc`), a
details map, and `prev_hash` (the previous entry's hash; the first entry links to
`GENESIS_PREV_HASH`, 64 zeros). The `entry_hash` is the SHA-256 of the canonical JSON of
the entry's **public payload**, which includes `prev_hash`. Because each entry commits to
the previous entry's hash, the chain is tamper-evident end to end.

**Salted actor commitment, not the clear identity.** This is the privacy turn that lets a
chain be exported and still verify. The public payload — the thing the entry hash commits
to — contains an `actor_commitment`, which is `SHA-256("{salt}:{actor}")` with a random
16-byte per-entry salt (`_actor_commitment`, and `append` which draws fresh
`os.urandom(16)` per entry). The clear `actor`, the `actor_salt`, and any per-entry
signature are stored **only in the vault** and are blank in the exported form
(`redacted()` / `to_export_dict()` drop them). A recipient can therefore confirm the
chain is intact **without learning who viewed or copied an item**.

**Detection of alteration, deletion, reordering.** `CustodyLog.verify()` walks the chain
and raises `CustodyError` on any of:

- **Reordering / deletion** — `seq` is not the expected position, or `prev_hash` does not
  match the running previous hash.
- **Alteration** — an entry's recomputed hash does not equal its stored `entry_hash`.
- **Signature failure** — when vault-side signer keys are supplied, a signed entry whose
  Ed25519 signature does not verify.

`integrity_proof()` produces the compact, identity-free proof that ships in a packet: the
algorithm, the chain length, the head hash, a per-item summary, and the **redacted
entries** (which verify standalone). It calls `verify()` first, so a packet cannot embed
a proof for a chain that does not itself verify.

---

## Packet binding: the privacy/verifiability bridge

This is the crux that reconciles two goals that otherwise conflict: *do not leak where a
tenant lives*, and *let a stranger verify the evidence*.

**The tension.** Fixity pins the original bytes — which include EXIF location. But a
shared copy must have its location and metadata stripped, so producing a packet does not
publish a home's coordinates. Once stripped, the shared copy's bytes **differ** from the
original, so the shared copy **cannot** be hashed to `content_hash`. A naive scheme would
have to choose between privacy and verifiability.

**The bridge.** habitable records two hashes and a signed binding between them
(`_build_item` in [`packet.py`](../src/habitable/packet.py)):

- `content_hash` — SHA-256 of the sealed original (what the timestamp token is over).
- `shared_hash` — SHA-256 of the location/metadata-stripped shared copy that actually
  travels in the packet's `media/` directory.

When the shared copy is produced, the packet appends a signed `copied_for_sharing`
custody entry whose details bind the two: `content_hash`, `shared_hash`, and what was
`stripped`. A recipient can then verify, end to end and without ever seeing the
location:

1. the image they hold hashes to `shared_hash`;
2. a signed custody entry binds that `shared_hash` to `content_hash`;
3. the RFC 3161 token is valid over `content_hash`.

**Optional direct fixity.** Passing `include_originals=True` embeds the sealed originals
in the packet's `originals/` directory, enabling *direct* end-to-end fixity — the
verifier re-derives the content hash from the embedded original itself. This is a
deliberate, higher-disclosure choice: the disclosures list flags that sealed originals
(with full metadata, including any location) are embedded, and the user is shown what a
packet will reveal before it is produced.

**The signed bundle.** The packet's `bundle.json` is the canonical-JSON serialization of
the whole packet (version, case/unit, scope, items, timeline, the custody integrity
proof, and an appendix). Its SHA-256 is signed with the producer's Ed25519 key, and the
signature plus the producer's public key are written to `bundle.sig.json`
(`_write_signature`). This binds the producer to the exact bundle contents.

---

## Independent verification procedure

`verify_packet` in [`verify.py`](../src/habitable/verify.py) is the module a skeptic
runs. Given only a packet directory — and, optionally, trusted TSA root certificates — it
re-derives every hash and checks every claim, with no access to the union's other data.
The steps below match the code; run them, or read the code, to confirm.

For each media item (`_verify_item`):

1. **Recompute the shared-media hash.** Read the file in `media/<shared_name>` and
   confirm its SHA-256 equals the recorded `shared_hash`. A missing file or a mismatch
   fails `shared_media_ok`.
2. **Check the custody binding.** Confirm a `copied_for_sharing` custody entry exists for
   this item binding `(content_hash, shared_hash)` (collected by `_sharing_bindings`).
   Without it, the shared copy is not provably the stripped form of the timestamped
   original, and `custody_binding_ok` fails.
3. **Verify the RFC 3161 token over `content_hash`.** Run `verify_token` against the
   item's `content_hash` (CMS signature, certificate chain, SHA-256 message-imprint
   binding, and `genTime`, as detailed under [Trusted timestamps](#token-verification)).
   No token serializes as `null` and is reported as `awaiting timestamp`, not a pass.
4. **Re-derive the embedded original's content hash, if present.** If
   `originals/<capture_id>` exists, confirm its SHA-256 equals `content_hash`
   (`original_fixity_ok`). When no original is embedded, this is `None` (not applicable),
   and verification rests on steps 1–3.

For the packet as a whole (`verify_packet` / `_verify_signature` / `_verify_custody`):

5. **Verify the producer's signature over the canonical `bundle.json`.** Recompute the
   bundle's SHA-256, confirm `bundle.sig.json` records that same hash, and verify the
   Ed25519 signature against the embedded public key. Any tampering with `bundle.json`
   changes its hash and fails the signature.
6. **Walk the custody chain.** Rebuild the `CustodyLog` from the bundle's
   `custody_proof.entries`, run `CustodyLog.verify()` (sequence, `prev_hash` linkage, and
   per-entry hash recomputation), and confirm the proof's declared `head_hash` matches
   the walk's result.

An item's verdict (`ItemVerdict.ok`) requires the timestamp verified, the shared media
ok, the custody binding ok, and embedded-original fixity not false. The overall verdict
(`VerificationReport.ok`) requires the signature ok, custody ok, no structural problems,
and every item ok. The human-readable summary is, e.g., "27/27 items verify against their
sealed originals and timestamp tokens — packet intact."

Because verification depends only on the packet plus standard primitives (SHA-256,
RFC 3161, Ed25519), a packet can also be spot-checked with general-purpose tools rather
than this verifier.

---

## Versioning: old packets keep verifying

The packet format and the verification protocol are **versioned (semver)** so that
packets produced today keep verifying years later, after the code has moved on.

- The bundle carries an explicit `packet_version` (`PACKET_VERSION` in
  [`packet.py`](../src/habitable/packet.py)), and `hash_algorithm` is named in the
  bundle and in the custody proof, so a future verifier never has to infer the format or
  the algorithm.
- A new format version adds a code path rather than redefining the old one; verification
  is expected to be backward compatible across the supported range.
- This is what keeps the [archive / re-timestamping](#archive--re-timestamping-expiring-tsa-certificates)
  longevity path workable: a packet re-timestamped years later is still a known,
  versioned format the verifier can read.

---

## What this proves — and what it does not

Being precise about the boundaries is part of being credible; a tool that overpromises in
a courtroom fails the people relying on it.

**What the method establishes:**

- The media's bytes have not changed since capture (fixity).
- The exact content existed no later than the token's `genTime` (a trusted-timestamp
  upper bound).
- The custody record is internally intact — no insertion, deletion, reordering, or entry
  alteration — and was produced by the holder of the producer key (signature).
- A stripped shared copy is provably the sanitized form of the timestamped original
  (the custody binding), without disclosing the original's location.

**What it does not establish:**

- **Not authorship.** A timestamp bounds *when* content existed, not *who* made it.
- **Not depiction or truth of the underlying condition.** Tamper-evidence shows an item
  was not altered after capture; it does not prove a described condition was as a tenant
  states. The tool strengthens true records; it does not create them.
- **Not a lower time bound.** The token says "no later than"; it says nothing about how
  much earlier the content may have existed.
- **Not admissibility.** Whether a court or agency admits a packet, or what weight it
  carries, is a legal question this tool cannot answer. habitable produces
  well-documented evidence and is **not legal advice**.
- **Not a trusted dev TSA.** A `DevTSA` token is for tests and demos only; it carries no
  trusted certificate chain and must not stand in for real evidence.

The full threat model and the mitigation for each limit live in
[`threat-model.md`](./threat-model.md).
