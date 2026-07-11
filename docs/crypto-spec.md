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
coercing** adversary with the unlocked device (see the planned duress mitigation and its limits in
[`threat-model.md`](threat-model.md)); proving **authorship or depiction** of a photo (a timestamp
bounds *existence in time* only).

## 2. Primitives

All primitives come from [`cryptography`](https://cryptography.io) (and `asn1crypto` for RFC 3161
parsing). habitable implements no primitive itself.

| Purpose | Primitive | Parameters |
| --- | --- | --- |
| Authenticated encryption (AEAD) | **ChaCha20-Poly1305** | 256-bit key, 96-bit nonce |
| Password-based key derivation | **scrypt** | N=2¹⁵–2²⁰ (profile-selected), r=8, p=1, 32-byte output |
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

`kdf.n` is the only field that varies between the named cost profiles below (`r`/`p` are fixed);
`open_keyfile` reads whatever `n` the keyfile carries, so different vaults — or the same vault
before and after hardening — can run at different costs with no format change.

Every authentication failure (wrong passphrase, tampered keyfile, malformed base64) surfaces as a
single `CryptoError` — "decryption failed (wrong key or tampered data)" — never a bare library
exception and never a distinguishable oracle beyond pass/fail.

### Normal save transaction and crash recovery

`Vault.save` preserves the existing encrypted filenames and AEAD associated data, but publishes its
five mutable state blobs (`case.enc`, `custody.enc`, `deferred.enc`, `peer_have.enc`, and
`sync_security.enc`) as one recoverable generation:

1. Encrypt every new blob in memory. Write each ciphertext and an exact encrypted backup of every
   existing live blob to uniquely named siblings in the vault directory; flush and `fsync` each
   staged file.
2. Atomically publish a small `.save-transaction.json` marker in the **prepared** phase. It contains
   only a random transaction id, the phase, and encrypted-state filenames—no case content, keys,
   identities, or record values.
3. Replace the five live blobs with same-directory renames, then sync the vault directory where the
   host/filesystem supports directory `fsync`.
4. Atomically change the marker to **committed**, then remove the encrypted backups, unused staged
   files, and marker (the marker is removed last).

`Vault.open` and the next `Vault.save` recover before reading or writing state. A prepared marker
restores every old ciphertext (or removes a newly created blob); a committed marker keeps the full
new generation and finishes cleanup. Recovery is repeatable if the recovery process itself is
interrupted: after restoring and syncing the old generation, prepared recovery removes and syncs
the journal **before** deleting backup copies, so a later open can safely discard any remaining
orphans. The journal is limited to 4 KiB and must be a regular file; recovery does not follow a
journal or encrypted-backup symlink, does not read from a FIFO, and streams backup restoration
instead of loading an unbounded artifact into memory. The vault format is unchanged, so vaults
created before this protocol still open and keep the same blob names.

This is a transaction for **normal mutable-state saves**, not a claim that every filesystem write in
the project is transactional. Keyfile changes, sealed-original creation, and DEK rotation retain
their separately documented write/recovery boundaries. Encrypted timestamp sidecars and their
legacy migration use the narrower protocol below; they do not join the five-blob transaction. The
strongest crash guarantee assumes a local filesystem that honors same-directory atomic replacement
and file/directory `fsync`. Directory syncing is best-effort on platforms that do not expose it;
network/exotic filesystems, lying storage hardware, media failure, and concurrent processes writing
the same vault can still violate durability or isolation.

### Encrypted timestamp-token sidecars and legacy migration

The public `TimestampToken` and packet formats do not change. Inside an unlocked vault, however,
the primary, additional-authority, and archive tokens for one capture are one canonical JSON value:

```json
{
  "version": 1,
  "capture_id": "<plaintext only inside the AEAD envelope>",
  "primary": { "kind": "rfc3161", "tsa_name": "…", "token_b64": "…" },
  "additional": [],
  "archive": []
}
```

That value is encrypted with the vault DEK and stored as
`tokens/<sha256(UTF-8 capture_id)>.tokens.enc`. Associated data is the domain-separated value
`b"habitable:timestamp-token-sidecar:v1:" || ASCII(filename digest)`. On read, the capture id
inside the authenticated plaintext must hash back to the filename. This prevents raw capture ids
(including separators and `..`) from becoming paths, binds ciphertext to its intended name, and
keeps token data, TSA name, and embedded `genTime` confidential while the vault is locked.

The hashed filename is deterministic. It therefore leaks equality/linkability for the same capture
id across observations or copied vault trees, and a party that can guess an id can test the guess.
Ciphertext length approximates per-capture token volume, while filesystem `mtime`/`ctime` expose
update timing to a storage observer; there is no padding or filesystem-metadata hiding. It is not
an anonymity mechanism. The encrypted sidecar supplies local confidentiality and
integrity only. It does **not** authenticate the timestamp authority, prove the token's imprint, or
make a token secret once exported: sync and packet formats intentionally carry the unchanged public
token structure, and recipients must still verify the token and its authority chain.

Writes use a flushed same-directory temporary ciphertext, owner-only `0600` mode on POSIX,
atomic replacement, and a directory `fsync` where supported. Reads require a regular file, use
no-follow/nonblocking opens, and reject tamper, symlinks, FIFOs, file replacement races, and
oversize records. Enumeration, read, temporary creation, rename, and unlink are all relative to one
no-follow directory descriptor whose device/inode is checked against the vault path on entry and
again before success. A concurrent directory swap therefore fails without following the replacement
symlink or reporting a detached write as successful. Platforms lacking descriptor-relative mkdir,
open, no-follow stat, scan, unlink, and rename support are unsupported for the **whole vault**:
creation preflights and refuses before making a vault, and open fails closed; there is no unsafe
path-based fallback. Creation accepts only an absent or real empty destination, creates
`originals/` and `tokens/` exclusively through a held no-follow root descriptor, and proves the new
token directory can be securely reopened before writing config, key, or case state.
Resource ceilings are 4,096 ordinary live/direct entries in `tokens/` (prospective creation of the
4,097th sidecar is rejected, while an existing sidecar may be updated), plus at most 64
strictly named `.token-atomic-<32 lowercase hex>.tmp` crash remnants so cleanup cannot itself be
stranded at the live-entry limit; 32 MiB ciphertext; 24 MiB decrypted sidecar JSON; 16 MiB per
legacy JSON file; 8 MiB per token; 4,096 valid-UTF-8 characters per capture id/name field; and 256
tokens in each additional/archive list. Both encrypted and legacy JSON must decode as strict UTF-8;
a string/escape-aware text preflight rejects nesting deeper than 64, more than 8,192 outside-string
structural punctuation tokens, and number tokens longer than 128 characters. Integer parsing uses
the same explicit 128-character ceiling rather than Python's mutable process-global digit limit.
Exceeding a ceiling fails closed rather than making unlock or packet assembly unbounded. DEK
rotation is the explicit
exception to the ordinary live-entry count: while staging it may add exactly one encrypted
`<sidecar>.new` per existing sidecar, so token
directory entries can transiently double but remain bounded. `SIGKILL` can leave those stages;
retry/open may then require manual recovery under the documented nontransactional rotation boundary.

After a successful unlock, pre-sidecar vaults migrate deterministically before the vault is
returned:

1. Enumerate direct legacy `*.json` entries under the real (not symlinked) `tokens/` directory;
   securely read and strictly validate every component and preserve list order. Top-level shape
   disambiguates suffix-bearing capture ids: an object in `tenant.additional.json` is the primary
   token for capture `tenant.additional`, while a list is the additional-token component for
   capture `tenant` (and likewise for `.archive.json`). Other ambiguous shapes fail closed. The old
   format reused that one filename for both logical records, so it could never retain both at once:
   migration preserves the surviving object or list but cannot reconstruct a record an earlier
   legacy write already overwrote. Orphan token capture ids remain supported, so case-document
   membership cannot safely override the surviving shape.
2. Atomically write, sync, reread, decrypt, and compare the consolidated encrypted sidecar.
3. Re-check that every remaining plaintext entry is the exact regular inode that was read, unlink
   it, then sync `tokens/`.

No legacy plaintext is deleted after a validation, encryption, publish, or durability failure. A
crash after encrypted publication can leave both generations; restart compares every legacy
component that still remains against the corresponding authenticated component and resumes
cleanup. Missing legacy components are treated as already removed, so interruption halfway through
the three-file cleanup is repeatable. Disagreement fails closed and preserves the plaintext for
manual recovery. At the 4,096-entry ceiling, migration alone may create one temporary 4,097th live
entry; restart accepts that overlap only when exactly one encrypted sidecar maps to a present legacy
group, both strictly decode, their remaining components match in order, and legacy cleanup returns
the directory to the ceiling. Any unrelated over-cap state fails closed. Orphan atomic-write
ciphertext temporaries are removed on the next migration.
Unlinking is cleanup, **not secure erasure**: old blocks, journaled filesystems, snapshots, backups,
swap, and storage forensics may retain pre-migration plaintext. The guarantees also assume no
concurrent writer and a local filesystem that truthfully implements regular-file checks, atomic
same-directory replacement, and flushes; directory `fsync` is unavailable on some platforms.

`config.toml` remains plaintext by design so policy is reviewable, including timestamp-authority
names/URLs and any user-edited peer, sharing, packet, or letter settings. The wrapped keyfile is
also visible. Do not put secrets in configuration. An unlocked process, malware, a compelled
passphrase, or memory inspection can read decrypted sidecars just as it can other vault contents.

### 3.1 Key lifecycle (R-38, FIX-08)

- **Rotation** (`habitable key rotate`): re-derive a KEK from the *new* passphrase over a *fresh*
  salt and re-wrap the **same** DEK. Bulk data is untouched. Old keyfiles for the old passphrase
  remain valid until discarded — passphrase rotation is not revocation of a leaked DEK (that's DEK
  rotation, below).
- **KDF hardening** (`habitable key harden`, `crypto.harden_keyfile` / `Vault.harden_key`):
  re-derive the KEK from the *same* passphrase at a **stronger named cost profile**, over a fresh
  salt, and re-wrap the **same** DEK. Cheap (only the keyfile changes) but every future unlock pays
  the new cost. Named profiles (`crypto.KDF_PROFILES`):

  | Profile | scrypt N | ~memory | Notes |
  | --- | --- | --- | --- |
  | `standard` | 2¹⁵ | ~32 MiB | default at vault creation; interactive unlock on a low-end phone |
  | `hardened` | 2¹⁷ | ~128 MiB | `key harden`'s default target; OWASP's current scrypt-minimum |
  | `paranoid` | 2²⁰ | ~1 GiB | for a device that can spare the time and memory |

  **Bump procedure**: raising the cost is *not* automatic (no vault silently gets slower); an
  organizer runs `key harden` explicitly, per device, when they judge their hardware can bear it —
  the interactive-unlock-on-old-hardware constraint (see [tradeoffs](#7-review-focus--known-tradeoffs))
  is a per-device judgment call, not a global one. Raising `KDF_PROFILES` values in a future release
  (or adding a profile) does not by itself change any existing keyfile; only re-running `key harden`
  does.
- **DEK rotation** (`habitable key rotate-dek`, `Vault.rotate_dek`): generates a **fresh** DEK and
  re-encrypts every vault blob, every encrypted timestamp-token sidecar, and every sealed original
  under it, then re-wraps the new DEK under the **same** passphrase. Sidecars are strictly decoded
  and re-encrypted with their filename-bound AAD; any legacy JSON migration finishes first. This is
  the actual remedy for a suspected DEK compromise that rotation alone cannot provide. Unlike
  rotation/hardening it is O(vault size), not O(1) — expensive but bounded, and meant to be rare.
  Each sealed original is decrypted and its fixity **re-checked** against the content hash already
  recorded in the case document before being re-sealed (a corrupt original is caught before, not
  after, it is carried into the new encryption). All re-encryption happens to staged `*.new`
  siblings before any file is modified in place. Each intended stage is registered before
  creation, then exclusively created no-follow with owner-only `0600` mode, fully written, and
  file-synced. Its device/inode/size/mtime/ctime generation is recorded; ordinary failures remove
  only that exact generation, and every stage is checked before publication and immediately before
  its rename. Before publication, every unique path-stage parent and `tokens/` is directory-synced.
  The wrapped-key stage's recorded generation is then re-verified and pinned through an open
  no-follow descriptor before the first publish rename. A final pass renames data, original, and
  token stages first and syncs their directories; the pinned wrapped keyfile is renamed last as the
  generation commit and followed by another vault-root sync. If post-commit exact-byte verification
  detects a keyfile race, rotation performs a
  controlled atomic forward repair from the already-fsynced expected bytes before reraising the
  triggering error. During partial publication, if the fixed keyfile stage was detached or replaced,
  Habitable preserves a random `keyfile.json.recovery-<32hex>.new` and adds its path to the exception
  for manual recovery without overwriting the alien entry. A retry fails closed while any known
  root/original/keyfile stage, token-sidecar stage, exact
  `.keyfile-forward-repair-<32hex>.tmp`, or exact `keyfile.json.recovery-<32hex>.new` remains. Known
  paths are checked directly, token enumeration is bounded, and the root recovery-artifact scan
  fails closed after 256 entries; exact-name symlinks and FIFOs block without being followed or
  removed. Directory sync remains best-effort where the host reports it unsupported. A process
  death can leave encrypted `*.new` debris. A crash during the (slow) staging phase leaves live
  files untouched; a crash during the (fast, metadata-only) swap phase could leave a partially
  migrated vault recoverable by hand from the leftover `*.new`/`*.enc` files — an accepted tradeoff
  at this effort tier, not a full transactional guarantee (see
  [tradeoffs](#7-review-focus--known-tradeoffs)).
- **Recovery blob** (`habitable key backup` / `restore`): the same DEK wrapped under an
  **independent** recovery passphrase, producing a standalone keyfile-format blob. Possession of
  the blob **and** the recovery passphrase reconstructs the DEK. This is the *only* way to recover
  a vault whose primary passphrase is lost. **After a DEK rotation, old recovery blobs wrap the old
  DEK and no longer open the vault** — take a fresh backup once rotation completes.
- **Unrecoverability by design**: there is no escrow, no operator key, no backdoor. Lose every
  passphrase and every recovery blob and the data is cryptographically gone. This is a deliberate
  safety property, documented for organizers in [`key-management.md`](key-management.md) and
  operationalized (without recreating a honeypot) in
  [`key-custody-playbook.md`](key-custody-playbook.md).
- **Memory hygiene**: the DEK lives in a `SymmetricKey` whose raw bytes are never exposed outside
  the module (`_raw()` is private). Python offers no reliable zeroization of immutable `bytes`;
  this is called out as a [review focus](#7-review-focus--known-tradeoffs), not claimed as solved.

### 3a. Threshold (M-of-N) social custody of recovery keys (EXP-11)

Implemented in `src/habitable/threshold.py`. This makes *distributed* custody cryptographic rather
than a matter of who-trusts-whom: recovery is split across `N` stewards so that any `M` of them —
but no fewer — can recover, and no single steward is a honeypot. The construction:

1. **Wrap.** Generate a fresh uniformly-random 256-bit **recovery secret** `S`. Because `S` is
   already full-entropy, it *is* the KEK: the DEK is wrapped directly with `ChaCha20-Poly1305`
   under `S` (no scrypt), with associated data `b"habitable-threshold-recovery-wrap-v1"` for domain
   separation. The result is a **recovery bundle** — a JSON blob that is **not secret** on its own
   (it is useless without `S`).
2. **Split.** `S` is shared with **Shamir's Secret Sharing over GF(2⁸)** (the AES field, reduction
   polynomial `0x11b`). Each of the 32 bytes of `S` is the constant term of an independent degree
   `M-1` polynomial with fixed random higher coefficients; share `i` is that set of polynomials
   evaluated at a distinct non-zero x-coordinate `x_i ∈ [1, 255]`. `M` shares reconstruct each byte
   by Lagrange interpolation at `x = 0`. Information-theoretically, any `M-1` shares reveal
   **nothing** about `S`.
3. **Bind.** Every share records the bundle's `bundle_id` (`sha256(wrapped_dek)[:16]`), so shares
   from different bundles cannot be silently combined and a mismatched set is rejected up front.
4. **Recover.** Collect ≥ `M` distinct shares (duplicates by x-coordinate are ignored, not
   double-counted), interpolate `S`, and AEAD-unwrap the DEK. A wrong, corrupt, or short share set
   fails the Poly1305 tag and surfaces as a single `CryptoError` — never a silently-wrong key.

**Bundle format** (`habitable_recovery_bundle_version = 1`):

```json
{
  "habitable_recovery_bundle_version": 1,
  "aead": "chacha20poly1305",
  "scheme": "shamir-gf256",
  "threshold": 2,
  "shares": 3,
  "bundle_id": "<hex16>",
  "wrapped_dek": "<b64 of nonce‖ciphertext>"
}
```

**Share format** (`habitable_share_version = 1`): `{ version, scheme, threshold, shares, index,
steward, bundle_id, y: "<b64 of per-byte evaluations>" }`.

Exposed as `habitable key share` (produce a bundle + one share per steward) and `habitable key
recover` (rebuild the keyfile from a bundle and a quorum). The Shamir primitive is implemented in
this project because `cryptography` ships no threshold scheme; it is a small, self-contained target
for the independent review and should be a focus of it. Operational guidance lives in
[`key-custody-playbook.md`](key-custody-playbook.md).

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
- Custody and packet signatures are taken over the **ASCII hex** of a SHA-256 digest. Sync-v2
  messages and pairing invitations instead sign their canonical JSON bytes directly; both sides
  deterministically reproduce those bytes with `canonical_json`.

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
- **Anonymous sender at this primitive, by design.** The sealed box itself does **not** authenticate who sent it
  (there is no sender static key in the handshake). The HKDF `info` and the `aad` bind the
  ciphertext to *this* ephemeral and recipient public key, preventing key-reuse/cross-protocol
  confusion. Protocol v2 establishes sender authenticity and authorization at the higher layer:
  signed, recipient-sealed, case-bound pairing pins an exact identity and random pairing key, then
  each canonical message is Ed25519-signed and HMAC-authenticated before sealing. See
  [`sync-protocol-v2.md`](sync-protocol-v2.md).

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

- **scrypt cost.** N=2¹⁵ (≈32 MiB), the `standard` profile, targets an interactive unlock on a
  low-end phone and is still what new vaults get by default — that reality (a tenant's only,
  possibly old, device) doesn't go away. FIX-08 addressed the "no path to raise it" half of the
  problem with per-device, opt-in `key harden` profiles (§3.1) rather than by silently raising the
  default; whether `standard` itself should move is a judgment call for the crypto audit, not
  resolved here.
- **Random 96-bit nonces.** Safe at habitable's message volumes; confirm no key is driven near the
  birthday bound, especially for the long-lived DEK.
- **Sender authentication of sync payloads** is not provided by the sealed-box primitive. Confirm
  protocol v2's exact encrypted allowlist, Ed25519 signature, pairing HMAC, case/recipient binding,
  and replay database all fail closed before merge.
- **Actor commitment** is unkeyed SHA-256 over `salt:actor`; the salt is exported so the commitment
  is openable *with the actor*, not brute-force-resistant against a known small actor set absent the
  salt. By design the salt stays in the vault; confirm it never leaks into an export.
- **Fingerprint truncation.** 64-bit out-of-band authenticator — adequate against accidental
  collision and casual substitution; not a cryptographic commitment to the full key. Consider
  surfacing the full hash for high-assurance comparison.
- **Memory zeroization** of key bytes is not guaranteed under CPython.
- **DEK rotation's multi-file swap is not fully transactional.** `Vault.rotate_dek` (§3.1) stages
  every re-encrypted file—including token sidecars—before touching anything in place, so the
  expensive, failure-prone work (decrypt, validate tokens, re-verify fixity, re-encrypt) can't
  corrupt the live vault. Stages use exclusive no-follow owner-only creation, full writes, file
  flushes, and recorded filesystem generations. Ordinary staging failures clean only the exact
  app-created generation and sync the affected directories; a raced-in or replaced entry fails
  closed and is preserved. All stage directories are synced and the wrapped-key stage is pinned
  after generation/ownership verification before publication. Data, original, and token stages are
  then renamed and their directories synced before the pinned wrapped keyfile is renamed last and
  the vault root is synced.
  Process death may leave encrypted `*.new` debris. Immediately before the first publish rename is
  attempted, cleanup becomes conservative: any exception may have arrived after the kernel committed
  a rename, so every remaining `*.new` stage and `keyfile.json.new` is preserved. Deleting the wrapped
  new key at that point could make already-published data unrecoverable. If the final keyfile commit
  was attempted, all data already uses the new DEK; the in-memory vault adopts it, verifies the
  still-open staged inode against the live keyfile, and, if that proof fails, attempts a controlled
  atomic forward repair before reraising the original error. If forward repair itself fails, its
  artifact is retained and reported, and a separately named recovery artifact is attempted too.
  During partial publication, a detached or replaced fixed keyfile stage is never overwritten or
  deleted: a random `keyfile.json.recovery-<32hex>.new` is durably written and its path is attached to
  the exception for manual recovery. Failures after creating either recovery artifact retain and
  report it only when its bytes are positively verified against the expected wrapped key; otherwise
  the error explicitly says that no verified artifact was retained. The final swap is a tight loop
  of same-filesystem renames (each individually atomic), but a crash *inside* that loop — not during
  staging — can still leave a vault whose keyfile and blobs disagree about which DEK is current,
  recoverable by hand from the `*.new`/`*.enc` files left behind. These recovery measures do not
  isolate concurrent writers; a reviewer should weigh whether that residual window is acceptable
  for the threat model or needs a real journal/commit marker. A retry treats known root/original/
  keyfile stages, token-sidecar `<name>.new`, exact `.keyfile-forward-repair-<32hex>.tmp`, and exact
  `keyfile.json.recovery-<32hex>.new` as ambiguous manual-recovery state. It fails closed without
  following, overwriting, or auto-deleting regular files, symlinks, or FIFOs at those names; the root
  scan is capped at 256 entries and near-miss names are not classified as recovery artifacts.

## 8. Cross-references

- Independent verification semantics, failure-by-failure:
  [`verifier-decision-table.md`](verifier-decision-table.md).
- The on-the-wire packet/bundle contract: [`bundle-schema.md`](bundle-schema.md) +
  [`packet-bundle.schema.json`](packet-bundle.schema.json).
- Embedding the Apache-2.0 verifier: [`embedding-the-verifier.md`](embedding-the-verifier.md).
- Method, evidence theory, threat model: [`evidence-method.md`](evidence-method.md),
  [`threat-model.md`](threat-model.md).
