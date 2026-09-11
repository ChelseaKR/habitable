<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Sneakernet sync — exchange a case on a USB stick or SD card

Sometimes the right network is no network. A tenant on a metered plan, a
church-basement meeting with no usable Wi-Fi, an organizer who does not want a
relay to see even connection metadata — all of them can keep a case in step by
handing over a small encrypted file in person. No relay, no data plan, no
account.

This is the same end-to-end-encrypted CRDT delta habitable already syncs over a
folder or a relay, surfaced as a first-class file workflow: `sync-export` writes
it, `sync-import` merges it. A delta is **sealed to one recipient's key and
signed by the sender**, so a stick lost on the bus leaks nothing and a forged or
swapped file is rejected on import.

## Before you start: pair the exact devices and case

Each device prints its public identity once. Share the **public-id** with your
peer and confirm the short **fingerprint** out of band — read it aloud on a call
or in person — so you know you are sealing the delta to the right person.

```console
$ habitable id --vault ./case-4B
fingerprint: 1a2b-3c4d-5e6f-7a8b
public-id:   MC4w...          # the long string your peer needs
```

After confirming the fingerprint, one side creates authenticated pairing
material. It is signed, bound to this case, and sealed to the other device, so
the `.hpair` line can be handed over as a file or encoded as a QR payload.

```console
$ habitable sync-pair-create --vault ./case-4B \
    --peer <B-public-id> --out /Volumes/USB/B-case-4B.hpair
$ habitable sync-pair-accept --vault ./case-4B \
    --in /Volumes/USB/B-case-4B.hpair
```

You only need to do this once per peer. Merely knowing a public id is no longer
enough: the exact identity must be locally allowlisted by pairing.

## Export a delta to the stick

```console
# Tenant A seals a delta to organizer B and writes it onto the mounted stick:
$ habitable sync-export --vault ./case-4B \
    --peer <B-public-id> \
    --out /Volumes/USB/habitable-delta-1a2b3c4d.hsync
habitable: wrote sync delta to /Volumes/USB/habitable-delta-1a2b3c4d.hsync (10240 bytes)
           sealed to peer 1a2b-3c4d-5e6f-7a8b only — a lost stick leaks nothing.
           hand it over by USB/SD; no relay, no data plan needed.
```

Omit `--out` and habitable picks a stable, recognizable name for you —
`./habitable-delta-<peerfp8>.hsync`, where `<peerfp8>` is the first eight
characters of the peer's fingerprint. The name is only a convenience; the file
is encrypted regardless of what it is called.

Then eject the stick and hand it over.

## Import deltas from the stick

The recipient points `sync-import` at the file — or at a whole folder, since one
stick can carry deltas from several tenants:

```console
# Organizer B merges everything sealed to them on the stick:
$ habitable sync-import --vault ./case-4B /Volumes/USB/*.hsync
habitable: synced — merged 1 message, imported 1 capture
```

Import is **not silent**: it reports how many messages merged and how many
captures came in, so you can tell a real exchange from a fumbled one. Replay is
explicitly detected — re-importing the same file reports it as already accepted
and changes neither state nor custody. Because the case is a CRDT, both sides
converge with no lost edits no matter which order fresh deltas are exchanged.

To keep two people in step, the recipient exports a delta back the same way
(`sync-export --peer <A-public-id>`) and hands the stick back, or carries a fresh
one to the next meeting.

## Carrying a sealed original on the stick instead of a delta

The deltas above move the *case*. `habitable offload` moves one file's **bytes**, for
a different reason: a phone that is full (issue #296, RR-08). It writes the sealed
original into an encrypted container on the stick and leaves the custody-bound stub
in the vault — the content hash the timestamp token covers, every token, and the
whole chain of custody.

```sh
habitable offload cap-… --vault ~/case --to /Volumes/STICK/habitable --label "green stick"
habitable restore cap-… --vault ~/case --from /Volumes/STICK/habitable
```

The container is named `<item-id>.habitable-offload`, and it is not a delta: it is
not sealed to anybody, it carries no case state, and no other device can import it.

- **The key is not on the stick.** Each container has its own AEAD key, generated at
  offload time and stored inside the vault, so a found stick is ciphertext and a
  `key rotate-dek` — which cannot reach a drive — leaves it readable.
- **The stick holds the only copy.** Unlike a delta, which is a copy of something
  still on the device, an offload container *is* the file. Deleting it destroys the
  photograph and leaves the record of it with nothing behind.
- **Restoring re-hashes before it re-attaches.** The container's SHA-256 is compared
  with the one recorded when it was written, before anything is decrypted, and the
  plaintext is checked against the content hash after. Altered bytes are refused by
  name and nothing in the vault changes.
- **A drive that is not the right one is named, not guessed at.** A missing container
  is a refusal that says so.
- **Offloaded items do not travel.** `habitable sync` and `habitable sync-export`
  refuse while any original is offloaded, because this device cannot send bytes it
  does not hold, and a peer refuses a message whose originals neither side has.
  Restore first, then sync.
- **`habitable export` refuses too.** See [`mobile.md`](mobile.md#storage-footprint--what-a-case-costs-on-this-device-r-03)
  for the `--allow-offloaded` escape hatch and what a verifier says about the
  resulting packet.

## What a lost or tampered stick means

- **Lost stick → no leak.** Every delta is end-to-end encrypted and sealed to a
  single recipient. Someone who finds the stick sees ciphertext; they cannot read
  the note text, the photo, or even the sender's identity, and they are not the
  recipient the file is sealed to.
- **Wrong recipient → clean refusal.** Importing a delta sealed to someone else
  imports nothing and exits with a clear error rather than pretending to succeed.
- **Unknown or wrong-case sender → rejected.** A signature from an arbitrary key
  is not authorization. The sender must match the paired allowlist, prove the
  pairing key, and bind both the envelope and state to the open case.
- **Forged or swapped file → rejected.** The delta is signed and pairing-MACed;
  a tampered envelope, mismatched original, broken custody proof, or forged
  timestamp token is rejected before merge.

For the full guarantees and threat model, see
[`sync-protocol-v2.md`](sync-protocol-v2.md),
[`sync-threat-model.md`](sync-threat-model.md), and
[`crypto-spec.md`](crypto-spec.md).
