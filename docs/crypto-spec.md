<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# habitable — cryptographic design specification

> **Audience.** Independent security and cryptographic reviewers (the audit is a
> [v1.0 gate item](../ROADMAP.md#the-v10-gate-when-alpha-comes-off)), and anyone embedding the
> Apache-2.0 verifier. This document specifies the cryptographic constructions *independently of
> the code* so they can be reviewed, argued about, and re-implemented — realizing backlog items
> **R-37** (crypto spec) and **R-38** (key-management security narrative) from
> [`research/synthetic-personas-feedback.md`](research/synthetic-personas-feedback.md).
>
> **Status: alpha, unaudited.** This is the *intended* design as implemented in
> `src/habitable/crypto.py`, `evidence.py`, `packet.py`, `verify.py`, and `tsa.py` at the time of
> writing. It has **not** had an independent cryptographic review. Where the spec and the code
> disagree, the code is the ground truth and the spec is the bug. Please report discrepancies via
> [`SECURITY.md`](../SECURITY.md).

## 1. Scope and security goals

habitable's promise: *no operator can read a union's data, and a packet's integrity is checkable
by anyone without trusting this project.* The cryptography serves four goals:

1. **Confidentiality at rest** — vault data is unreadable without the user's passphrase.
2. **Confidentiality in transit** — sync deltas are unreadable to a relay or network observer.
3. **Tamper-evidence** — any alteration of a captured item or a custody record is detectable.
4. **Independent verifiability** — a third party can confirm a packet was not altered after the
   fact, and bound *when* its contents existed, using only standard primitives.

Non-goals (stated so the threat model is honest): hiding sync **metadata** from a relay (see
[`relay-observability-matrix.md`](relay-observability-matrix.md)); resisting a **forensic or
coercing** adversary with the unlocked device (see the duress limits in
[`threat-model.md`](threat-model.md)); proving **authorship or depiction** of a photo (a timestamp
bounds *existence in time* only).

## 2. Primitives

All primitives come from [`cryptography`](https://cryptography.io) (and `asn1crypto` for RFC 3161
parsing). habitable implements no primitive itself.

| Purpose | Primitive | Parameters |
| --- | --- | --- |
| Authenticated encryption (AEAD) | **ChaCha20-Poly1305** | 256-bit key, 96-bit nonce |
| Password-based key derivation | **scrypt** | N=2¹⁵, r=8, p=1, 32-byte output |
| Key agreement (sync) | **X25519** | ephemeral–static ECDH |
| Key derivation (sync) | **HKDF-SHA256** | 32-byte output, context-bound `info` |
| Signatures | **Ed25519** | over a SHA-256 hex digest (ASCII) |
| Content hashing / fixity | **SHA-256** | streaming, 1 MiB chunks |
| Canonical bytes for hashing/signing | **canonical JSON** | sorted keys, `(",",":")`, UTF-8, no NaN |
| Trusted time | **RFC 3161** | TSA-chosen digest (SHA-1…SHA-512 accepted on verify) |

Nonces are 96-bit random (`os.urandom(12)`) and prepended to ciphertext as `nonce ‖ ciphertext`.
With random nonces under ChaCha20-Poly1305 the safe message bound per key is well below the ~2⁴⁸
birthday limit for the volumes habitable handles; see [§7](#7-review-focus--known-tradeoffs).

## 3. Encryption at rest (the vault)

A two-level key hierarchy keeps passphrase rotation and recovery cheap (no bulk re-encryption):

```
passphrase ──scrypt(salt,N,r,p)──▶ KEK ──AEAD-unwrap──▶ DEK ──AEAD──▶ vault blobs
```

- A random 256-bit **data encryption key (DEK)** encrypts every vault blob with ChaCha20-Poly1305.
- The DEK is wrapped under a **key-encryption key (KEK)** derived from the passphrase with scrypt
  over a random 128-bit salt.
- The DEK wrap is AEAD with associated data `b"habitable-dek-wrap-v1"` (domain separation /
  versioning of the wrap format).

**Keyfile format** (`habitable_keyfile_version = 1`), a JSON object:

```json
{
  "habitable_keyfile_version": 1,
  "aead": "chacha20poly1305",
  "kdf": { "name": "scrypt", "salt": "<b64>", "n": 32768, "r": 8, "p": 1, "length": 32 },
  "wrapped_dek": "<b64 of nonce‖ciphertext>"
}
```

Every authentication failure (wrong passphrase, tampered keyfile, malformed base64) surfaces as a
single `CryptoError` — "decryption failed (wrong key or tampered data)" — never a bare library
exception and never a distinguishable oracle beyond pass/fail.

### 3.1 Key lifecycle (R-38)

- **Rotation** (`habitable key rotate`): re-derive a KEK from the *new* passphrase over a *fresh*
  salt and re-wrap the **same** DEK. Bulk data is untouched. Old keyfiles for the old passphrase
  remain valid until discarded — rotation is not revocation of a leaked DEK (see tradeoffs).
- **Recovery blob** (`habitable key backup` / `restore`): the same DEK wrapped under an
  **independent** recovery passphrase, producing a standalone keyfile-format blob. Possession of
  the blob **and** the recovery passphrase reconstructs the DEK. This is the *only* way to recover
  a vault whose primary passphrase is lost.
- **Unrecoverability by design**: there is no escrow, no operator key, no backdoor. Lose every
  passphrase and every recovery blob and the data is cryptographically gone. This is a deliberate
  safety property, documented for organizers in [`key-management.md`](key-management.md) and
  operationalized (without recreating a honeypot) in
  [`key-custody-playbook.md`](key-custody-playbook.md).
- **Memory hygiene**: the DEK lives in a `SymmetricKey` whose raw bytes are never exposed outside
  the module (`_raw()` is private). Python offers no reliable zeroization of immutable `bytes`;
  this is called out as a [review focus](#7-review-focus--known-tradeoffs), not claimed as solved.

## 4. Device identity and signatures

Each device holds an **Identity**: an Ed25519 signing key (32-byte seed) and an X25519
key-agreement key (32-byte private), serialized as 64 raw bytes and stored **encrypted in the
vault**. The corresponding **PublicIdentity** is `sign_public ‖ box_public` (64 bytes).

- **Fingerprint** = the first 16 hex chars of `SHA-256(sign_public ‖ box_public)`, grouped as
  `xxxx-xxxx-xxxx-xxxx`. Peers compare fingerprints **out of band** to defeat key substitution; it
  is a short authenticator, not a collision-proof identifier (64-bit prefix — see tradeoffs).
- **`sign(message)`** → Ed25519 signature. **`verify(pub, message, sig)`** returns `False` on any
  failure (bad signature, malformed key) rather than raising — verification is total and
  side-effect-free.
- Signatures in habitable are taken over the **ASCII hex** of a SHA-256 digest (e.g. the custody
  `entry_hash`, the `bundle_sha256`), not over raw payloads — so signers commit to a hash, and the
  verifier independently recomputes that hash before checking the signature.

## 5. Sync confidentiality — the sealed box

`seal_to(recipient_pub, plaintext)` is an ECIES-style anonymous-sender sealed box:

```
eph        = X25519.generate()
shared     = ECDH(eph_priv, recipient_box_pub)
key        = HKDF-SHA256(shared, salt=None,
                         info = b"habitable-sealedbox-v1" ‖ eph_pub ‖ recipient_pub, len=32)
ciphertext = ChaCha20Poly1305(key).encrypt(nonce=os.urandom(12), plaintext, aad = eph_pub)
wire       = eph_pub(32) ‖ nonce(12) ‖ ciphertext
```

`open_sealed` reverses it with the recipient's static X25519 key. Properties:

- **Confidential to the recipient's key.** Only the holder of `box_private` can derive the shared
  secret and open the box.
- **Forward secrecy for the sender.** The sender's contribution is ephemeral and discarded;
  compromising the sender later does not decrypt past boxes.
- **Anonymous sender, by design.** The sealed box itself does **not** authenticate who sent it
  (there is no sender static key in the handshake). The HKDF `info` and the `aad` bind the
  ciphertext to *this* ephemeral and recipient public key, preventing key-reuse/cross-protocol
  confusion, but **sender authenticity is established at a higher layer** by the Ed25519 signatures
  on the custody entries and the packet bundle — not by the transport. Reviewers should confirm
  the sync layer (`sync.py`) enforces that expectation; see [§7](#7-review-focus--known-tradeoffs).

The guard tests in `tests/test_guards.py` assert that no plaintext (note text, image bytes, or a
sender identity) reaches a relay or an on-disk mailbox — only sealed boxes and metadata.

## 6. Tamper-evidence

### 6.1 Content fixity

At capture the original bytes are hashed with streaming SHA-256 and the sealed original is treated
as immutable. `verify_fixity` re-derives the hash on read and raises `FixityError` on mismatch, so
silent corruption or substitution becomes a failed check, never a quietly altered exhibit.

### 6.2 Chain of custody

`CustodyLog` is an append-only, hash-linked log. Each entry's **public payload** is:

```
{ seq, action, item_id, hlc, actor_commitment, details{sorted}, prev_hash }
```

and `entry_hash = SHA-256(canonical_json(public_payload))`, with `prev_hash` chaining to the
previous entry (`genesis = "0"*64`). Walking the chain checks, for every entry: strictly
increasing `seq`, `prev_hash` equals the prior `entry_hash`, and `recompute_hash() == entry_hash`.
Any insertion, deletion, reorder, or edit breaks the chain at a precise `seq`.

**Actor privacy.** The actor is committed, not exported in clear:
`actor_commitment = SHA-256("<salt_hex>:<actor>")` with a fresh 128-bit salt per entry. The clear
`actor`, the `actor_salt`, the Ed25519 `signature`, and any identity/PII `private_details` are
**vault-only** — they are *not* part of `public_payload` (so they are neither hashed nor
reconstructable from an export) and are dropped by `redacted()` before export. A recipient thus
verifies the chain is intact **without learning who did what**. The salt makes the commitment
preimage-resistant against guessing a small actor space; reviewers should weigh that the commitment
is unkeyed SHA-256 over a low-entropy actor string protected only by the per-entry salt.

**Optional per-entry signatures.** When an `Identity` is supplied, the entry is Ed25519-signed over
`entry_hash`. `verify(signer_keys=…)` checks signatures whose `actor_commitment` maps to a known
public key. The exported `integrity_proof()` includes redacted entries plus a per-item summary and
the chain `head_hash`.

### 6.3 Packet signature

`build_packet` serializes the bundle with `canonical_json`, writes `bundle.json`, and signs it: the
producer's device Ed25519 key signs `bundle_sha256` (hex, ASCII) into `bundle.sig.json`
(`{producer_fingerprint, sign_public(b64), bundle_sha256, signature(b64)}`). The verifier recomputes
`bundle_sha256`, checks it matches the claimed value, and verifies the signature over it.

### 6.4 Trusted time (RFC 3161)

The content **hash** — never the file — is sent to an RFC 3161 TSA, which returns a signed token
bounding when that content existed (*upper bound* on creation). Tokens are stored opaquely
(`{kind, tsa_name, token_b64}`; `kind ∈ {rfc3161, dev}`). `verify_token` follows the **token's own**
digest and signature algorithms (SHA-1…SHA-512, RSA-PKCS1v1.5 or ECDSA) rather than assuming
SHA-256, checks the signature and certificate, and reports `trusted_chain` if the TSA chains to a
supplied trusted root. **Archive (re-)timestamping** chains a new token over an existing one before a
TSA cert ages out; `verify_archive_chain` walks it and fails closed on any break. The `dev` token
kind is a non-production Ed25519 "authority" used only offline for tests/demos and labels itself as
such. **Multiple-authority redundancy:** a capture may be stamped by several authorities (the default
config ships more than one); the primary token is in `timestamp` and independent tokens over the same
hash are in `additional_timestamps`, so the existence proof does not rest on a single TSA. The
verifier accepts an item if at least one authority verifies and reports all that did.

## 7. Review focus / known tradeoffs

Stated plainly so a reviewer can target effort (and so the project isn't accused of hiding them):

- **scrypt cost.** N=2¹⁵ (≈32 MiB) targets an interactive unlock on a low-end phone. For a
  high-value at-rest secret this is on the lower side; evaluate raising it or offering a profile,
  against the reality that the tool runs on a tenant's only, possibly old, device.
- **Random 96-bit nonces.** Safe at habitable's message volumes; confirm no key is driven near the
  birthday bound, especially for the long-lived DEK.
- **Sender authentication of sync payloads** is *not* provided by the sealed box (anonymous sender
  by design). Confirm `sync.py` authenticates senders via the entry/bundle signatures and that an
  unauthenticated injected box cannot corrupt a peer's state (it should fail signature/custody
  checks downstream).
- **Actor commitment** is unkeyed SHA-256 over `salt:actor`; the salt is exported so the commitment
  is openable *with the actor*, not brute-force-resistant against a known small actor set absent the
  salt. By design the salt stays in the vault; confirm it never leaks into an export.
- **Fingerprint truncation.** 64-bit out-of-band authenticator — adequate against accidental
  collision and casual substitution; not a cryptographic commitment to the full key. Consider
  surfacing the full hash for high-assurance comparison.
- **Memory zeroization** of key bytes is not guaranteed under CPython.
- **DEK rotation ≠ DEK revocation.** Rotating the passphrase does not re-key bulk data; a leaked
  DEK stays valid for existing blobs. Document/΄design a re-key path if that is in scope.

## 8. Cross-references

- Independent verification semantics, failure-by-failure:
  [`verifier-decision-table.md`](verifier-decision-table.md).
- The on-the-wire packet/bundle contract: [`bundle-schema.md`](bundle-schema.md) +
  [`packet-bundle.schema.json`](packet-bundle.schema.json).
- Embedding the Apache-2.0 verifier: [`embedding-the-verifier.md`](embedding-the-verifier.md).
- Method, evidence theory, threat model: [`evidence-method.md`](evidence-method.md),
  [`threat-model.md`](threat-model.md).
