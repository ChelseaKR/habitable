<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Set up your union in an afternoon

A practical, no-jargon walkthrough for an organizer. By the end you'll have an
encrypted case on your own device, evidence captured with trusted timestamps, a
second organizer synced peer-to-peer, and a verified packet you can hand to a
court or inspector. **Nothing leaves your devices unencrypted, and there is no
account to create.**

> **Alpha software.** habitable works end to end, but it is not yet proven for
> real legal matters. Practice with the steps below before relying on it, and
> read [Honest limits](../README.md#honest-limits--what-habitable-does-not-do).

## 0. What you need (15 min)

- A laptop (or two) per organizer. Phones come later via the app.
- [uv](https://docs.astral.sh/uv/) installed. The right Python (3.14) is fetched
  for you.
- A strong **passphrase** per device, written down somewhere safe. **If you lose
  it with no backup, the data is gone — by design, no one can recover it for you.**

```console
$ git clone https://github.com/ChelseaKR/habitable && cd habitable
$ uv sync
$ uv run habitable --help
```

## 1. See it work first (5 min)

```console
$ uv run habitable demo
```

This fabricates a couple of photos, captures them as evidence, builds a packet
(with location stripped from the shared copies), and verifies it — all offline,
with no real data. When you see `packet intact`, the toolchain is healthy.

## 2. Create a case (10 min)

```console
$ export HABITABLE_PASSPHRASE='choose-a-strong-one'   # or you'll be prompted
$ uv run habitable init ./case-4B --case bldg-12 --unit 4B
$ uv run habitable id --vault ./case-4B               # note your fingerprint + public-id
```

Open `./case-4B/config.toml` to set your jurisdiction wording (`[packet_template]`)
and confirm sharing defaults (location is stripped from shared copies by default).

## 3. Document an issue (30 min)

```console
$ uv run habitable issue   --vault ./case-4B --category mold --room bathroom --title "Black mold"
$ uv run habitable capture ./photos/ceiling.jpg --vault ./case-4B --issue <issue-id>
$ uv run habitable timeline --vault ./case-4B --issue <issue-id> --kind sent_request --text "Emailed landlord"
$ uv run habitable status   --vault ./case-4B
```

Offline is fine: capture seals and hashes instantly and queues the trusted
timestamp. When you're back online, run `habitable resolve --vault ./case-4B`.

Prefer a screen? Run the local app (accessible, English/Español) and use a phone
or laptop browser on the same machine:

```console
$ uv run habitable app --vault ./case-4B
```

## 4. Sync with another organizer (20 min)

Each organizer runs `habitable id` and shares their **public-id** (and verifies
the **fingerprint** out loud — by phone, in person). Then either sync over a
shared folder (USB/cloud-drive) or via a relay.

```console
# Folder transport (no server):
$ uv run habitable sync --vault ./case-4B --peer <their-public-id> --channel 4B-room --dir /path/to/shared
# Or run your own ciphertext-only relay (sees nothing but ciphertext + metadata):
$ uv run habitable relay --host 0.0.0.0 --port 8787
$ uv run habitable sync --vault ./case-4B --peer <their-public-id> --channel 4B-room --relay http://<host>:8787
```

Both sides converge with no lost edits. The relay can read nothing.

## 5. Export and verify a packet (15 min)

```console
$ uv run habitable export --vault ./case-4B --out ./4B-packet
$ uv run habitable verify ./4B-packet
habitable: N/N items verify against their sealed originals and timestamp tokens — packet intact
```

Hand the recipient `./4B-packet` (the `bundle.json`, the `media/`, and
`packet.pdf`). Anyone — including the opposing side — can run `habitable verify`
to confirm nothing was altered. The shared copies carry **no location**; the
sealed originals stay encrypted in your vault.

## Good habits

- Keep an **encrypted backup** of each vault and a recorded recovery passphrase.
- Verify peer **fingerprints** out of band before syncing.
- Re-export and re-verify before any filing; the packet format and verification
  protocol are versioned so old packets keep verifying.
- This produces **documentation, not legal advice.** Work with your tenant
  attorney or legal-aid group on what to file and when.
