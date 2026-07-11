<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Sharing a case with an organizer — trust & key-exchange model

> **Audience.** Tenants and organizers using `habitable share` / `habitable receive`, and
> reviewers auditing the end-to-end-encryption guarantee. Companion to
> [`crypto-spec.md`](crypto-spec.md) and [`threat-model.md`](threat-model.md).

## What sharing is

`habitable share` lets a tenant hand a **full case** to a
tenant-union organizer who was not previously on the case, without any server, relay, or
courier ever being able to read it. The `unit` metadata field may be omitted; that one-field
omission is not anonymization. It is the one-way cousin of peer-to-peer sync
(`docs` → `sync`): sync keeps two devices on the *same* case in step; sharing bootstraps a
*new* recipient.

It reuses the existing primitives unchanged:

- **Full-case CRDT state.** The tenant builds the whole case state, optionally dropping
  the unit-label metadata. Merging it on the organizer's device is still a valid,
  commutative, idempotent CRDT join — receiving the same share twice changes nothing.
- **Signed + sealed envelope.** The payload (the CRDT state, plus the sealed-original
  bytes and RFC 3161 tokens for the case's captures) is **signed** by the tenant's
  Ed25519 device key and **sealed** to the organizer's X25519 public key with
  `crypto.seal_to` — an ephemeral-key ECIES box (X25519 → HKDF-SHA256 →
  ChaCha20-Poly1305). Only the holder of the organizer's private key can open it.

The serialized `.share` file is therefore ciphertext. It can travel over anything — a
USB stick, AirDrop, email, or the optional habitable relay — and a passive or active
network attacker sees only an opaque blob.

## The trust model: direct, out-of-band, no directory

There is **no central key directory and no account system** — by design, so there is no
server to compromise or subpoena. Trust is established directly between two humans:

1. **The organizer publishes their identity.** They run `habitable id`, which prints a
   `public-id` (their Ed25519 + X25519 public keys) and a short **fingerprint**
   (`xxxx-xxxx-xxxx-xxxx`).
2. **The tenant verifies the fingerprint out of band.** Over a channel they already
   trust — in person, or a phone/video call where they recognize the organizer — the
   tenant confirms the short fingerprint. *This is the human step that defeats a
   man-in-the-middle.* A fingerprint is a hash over both public keys, short enough to read
   aloud but long enough (64 bits shown) to make collision forgery impractical for this
   threat model.
3. **The devices pair for this case.** The tenant creates signed,
   recipient-sealed `.hpair` material with `sync-pair-create`; the organizer
   accepts it with `sync-pair-accept`. This pins the complete expected identity,
   case, and pairing key in each encrypted vault. A public id alone is not
   authorization.
4. **The tenant shares to that key.** `habitable share --peer <public-id>` seals the
   full case (optionally without its `unit` metadata field) to exactly that key and prints back the fingerprint so the
   tenant can re-confirm before sending.
5. **The organizer receives.** `habitable receive` opens the box with their private key,
   verifies the tenant's signature, checks the share is for the case they opened, re-checks
   each original's fixity (SHA-256) and any RFC 3161 token, and merges the CRDT state.

### What each party — and a never-trusted server — can and cannot do

| Party | Can | Cannot |
| --- | --- | --- |
| Relay / courier / cloud drive | Move the sealed blob; see its size and timing | Read or forge the sealed payload; transport filenames and account metadata remain outside this protocol |
| A wrong recipient | — | Open a box not sealed to their key (`receive` opens nothing and errors) |
| Active network attacker | Drop or replay the blob (replay is detected and skipped) | Authenticate as an unpaired key; substitute the case/recipient; tamper undetected (AEAD + signature + pairing MAC) |
| The organizer (trusted recipient) | Read the full case, including sealed originals with their original metadata | Read an omitted `unit` field from the CRDT state; other case content can still reveal the same fact |

## Redaction levers (what a tenant can withhold)

Sharing is currently **full-case**:

- **Issue subsets are blocked** — passing `--issue` fails before a sync message id is minted,
  recorded, signed, sealed, or returned. Sync v2 carries the complete source-custody proof on an
  original-bearing transfer; that proof can identify excluded capture and timeline records even
  when the CRDT state and originals are filtered.
- **One metadata field can be omitted** — `--redact-unit` drops the `unit` field from the
  otherwise full-case CRDT state. Custody entries do not carry that field. This is not an
  anonymity guarantee: the case identifier, issue text, timeline, opaque custody identifiers,
  filenames outside the sealed protocol, and original EXIF/GPS can still identify a unit or
  household. Review the decrypted payload as a full-case disclosure.

The safe restoration path is a new, explicitly versioned scoped/rehashed custody-view contract.
It must label the view as derived, bind it to its declared scope, and must not delete arbitrary
entries from the existing chain or present a truncated chain as complete.

> **Deliberate limit.** Sharing the sealed *originals* gives the organizer end-to-end
> fixity, but those originals retain their full metadata (including any GPS). That is
> acceptable because the organizer is a recipient the tenant has chosen and verified — but
> it is a real disclosure to that person. A future enhancement could offer "shared copies
> only" (location-stripped, as in a court packet) for a lower-trust organizer relationship;
> see *For human review* below.

## Guarantees preserved

- **No plaintext leaves the device unencrypted.** The payload is sealed to the recipient
  before it is written to disk or a transport. (Verified by `test_share` asserting issue
  titles and the unit label do not appear in the sealed bytes.)
- **No new third-party egress.** `share`/`receive` are file-based; moving the blob is the
  user's choice of channel. The optional relay already only moves ciphertext.
- **Offline-first.** Producing and opening a share needs no network.

## For human review

- **Fingerprint-verification UX.** The cryptography is only as strong as the out-of-band
  fingerprint check. A field rollout should make that step hard to skip and easy to do
  (e.g. a QR exchange in the PWA). Today it is a CLI affordance plus this document.
- **Redaction depth.** Issue and intra-issue selection are unavailable until the versioned
  custody-view work lands. Separately decide whether to add a "shared copies only" mode that
  withholds original metadata from the organizer.
- **No revocation.** Like any disclosure, a share cannot be recalled once delivered. This
  matches sync's semantics but is worth stating to users.
