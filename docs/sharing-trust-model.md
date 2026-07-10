<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Sharing a case with an organizer — trust & key-exchange model

> **Audience.** Tenants and organizers using `habitable share` / `habitable receive`, and
> reviewers auditing the end-to-end-encryption guarantee. Companion to
> [`crypto-spec.md`](crypto-spec.md) and [`threat-model.md`](threat-model.md).

## What sharing is

`habitable share` lets a tenant hand a case — or a **redactable subset of it** — to a
tenant-union organizer who was not previously on the case, without any server, relay, or
courier ever being able to read it. It is the one-way cousin of peer-to-peer sync
(`docs` → `sync`): sync keeps two devices on the *same* case in step; sharing bootstraps a
*new* recipient.

It reuses the existing primitives unchanged:

- **CRDT subset.** The tenant builds a filtered case state with
  `CaseDocument.subset_state(issue_ids, redact_meta=…)`. Because the result is a *subset*
  of the same grow-only / observed-remove / last-writer-wins state, merging it on the
  organizer's device is still a valid, commutative, idempotent CRDT join — receiving the
  same share twice changes nothing.
- **Signed + sealed envelope.** The payload (the CRDT subset, plus the sealed-original
  bytes and RFC 3161 tokens for the selected captures) is **signed** by the tenant's
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
   (possibly redacted) subset to exactly that key and prints back the fingerprint so the
   tenant can re-confirm before sending.
5. **The organizer receives.** `habitable receive` opens the box with their private key,
   verifies the tenant's signature, checks the share is for the case they opened, re-checks
   each original's fixity (SHA-256) and any RFC 3161 token, and merges the CRDT subset.

### What each party — and a never-trusted server — can and cannot do

| Party | Can | Cannot |
| --- | --- | --- |
| Relay / courier / cloud drive | Move the sealed blob; see its size and timing | Read contents (sealed), forge it (signed), or learn the unit (redactable) |
| A wrong recipient | — | Open a box not sealed to their key (`receive` opens nothing and errors) |
| Active network attacker | Drop or replay the blob (replay is detected and skipped) | Authenticate as an unpaired key; substitute the case/recipient; tamper undetected (AEAD + signature + pairing MAC) |
| The organizer (trusted recipient) | Read everything the tenant chose to share, including sealed originals with their original metadata | Learn about issues the tenant did **not** include (they never leave the device) |

## Redaction levers (what a tenant can withhold)

Sharing is **scoped by the tenant**, not all-or-nothing:

- **Issue subset** — `--issue i1 --issue i3` shares only those issues, their timeline
  entries, and their captures. Evidence for excluded issues is never placed in the
  payload, so it cannot leak even to a trusted-but-curious organizer.
- **Unit redaction** — `--redact-unit` drops the case's unit label from the shared CRDT
  state, so a subset need not disclose which unit it concerns.

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
- **Redaction depth.** Subset selection is issue-level; intra-issue redaction (e.g.
  removing a sentence from a description) is out of scope. Confirm issue-level is the right
  granularity for organizer sharing, and decide whether to add a "shared copies only" mode
  that withholds original metadata from the organizer.
- **No revocation.** Like any disclosure, a share cannot be recalled once delivered. This
  matches sync's semantics but is worth stating to users.
