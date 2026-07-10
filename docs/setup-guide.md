<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Set up your union in an afternoon

A practical, no-jargon walkthrough for an organizer. By the end you'll have four
things: an encrypted case on your own device; photos captured with **trusted
timestamps** (independent proof of *when* each photo was taken); a second
organizer synced device to device; and a verified **packet** — the folder of
evidence you hand to a court or inspector. **Nothing leaves your devices
unencrypted, and there is no account to create.**

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

This makes up a couple of photos, captures them as evidence, builds a packet
(with location removed from the shared copies), and checks it — all offline, with
no real data. When you see `packet intact`, the tool is working.

## 2. Create a case (10 min)

```console
$ export HABITABLE_PASSPHRASE='choose-a-strong-one'   # or you'll be prompted
$ uv run habitable init ./case-4B --case bldg-12 --unit 4B
$ uv run habitable id --vault ./case-4B               # note your fingerprint + public-id
```

Two IDs print here. Your **fingerprint** is a short code for this device — the
same value the app shows under *Device ID*. Your **public-id** is the address
another organizer uses to sync with you. Write both down.

Open `./case-4B/config.toml` to set the wording for your area (`[packet_template]`)
and confirm the sharing defaults (location is removed from shared copies by
default).

## 3. Document an issue (30 min)

```console
$ uv run habitable issue   --vault ./case-4B --category mold --room bathroom --title "Black mold"
$ uv run habitable capture ./photos/ceiling.jpg --vault ./case-4B --issue <issue-id>
$ uv run habitable timeline --vault ./case-4B --issue <issue-id> --kind sent_request --text "Emailed landlord"
$ uv run habitable status   --vault ./case-4B
```

Offline is fine. Each capture is sealed and fingerprinted right away, and the
trusted timestamp is queued for when you have a connection. Once you're back
online, run `habitable resolve --vault ./case-4B` to add the waiting timestamps.

Prefer a screen? Run the local app (accessible, English/Español) and use a laptop
or desktop browser on the same machine. The alpha has no supported phone package;
do not expose this unlocked server over a LAN (see [`docs/mobile.md`](mobile.md)):

```console
$ uv run habitable app --vault ./case-4B
```

## 4. Sync with another organizer (20 min)

Each organizer runs `habitable id` and shares their **public-id**. First, read
your **fingerprints** to each other another way — by phone or in person — and
check that they match. Then sync one of two ways: over a shared folder (USB or a
cloud drive), or through a relay.

```console
# Folder transport (no server):
$ uv run habitable sync --vault ./case-4B --peer <their-public-id> --channel 4B-room --dir /path/to/shared
# Or run your own relay. It only ever sees scrambled data — never your photos or text:
$ uv run habitable relay --host 0.0.0.0 --port 8787
$ uv run habitable sync --vault ./case-4B --peer <their-public-id> --channel 4B-room --relay http://<host>:8787
```

Both sides end up with the same case, and no edits are lost. The relay can read
nothing.

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

- Keep an **encrypted backup** of each vault, and write down the recovery
  passphrase.
- Check each other's **fingerprint** another way — by phone or in person — before
  you sync.
- Re-export and re-verify before any court filing. The packet format and the way
  it is checked are versioned, so old packets keep verifying.
- This produces **documentation, not legal advice.** Work with your tenant
  attorney or legal-aid group on what to file and when.
