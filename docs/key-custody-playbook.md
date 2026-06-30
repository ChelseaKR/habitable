<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Key custody for unions — a playbook for the IT steward

This is for the person a union ends up calling "the computer one" — the de-facto
IT steward who runs the relay, helps people set up, and tends to end up holding
backups. It is opinionated on purpose. Key custody is the place where a tool
built to *avoid* a honeypot can accidentally *recreate* one, and you are the
person most likely to do it by accident, with the best intentions.

> **Read the basics first.** This playbook assumes you have read
> [`key-management.md`](key-management.md), which explains the `habitable key
> rotate | backup | restore` commands and the one hard truth: **if a passphrase
> is lost *and* there is no recovery backup *and* no synced peer who still has
> the case, the data is gone.** That is by design — it is the same property that
> stops a landlord, a breach, or a subpoena from getting it. This playbook is
> about living with that tradeoff safely.
>
> **Honesty note:** the commands below (`key rotate`, `key backup`, `key
> restore`) exist today. The *practices* in this playbook — splitting custody,
> drilling recovery, a who-can-recover-what map — are organizational practices
> you implement *around* those commands. Where a smoother built-in feature is
> only planned, this document says so rather than implying it exists.

## The core tension, stated plainly

Two true things pull in opposite directions:

1. **Recovery is impossible by design without a backup.** No operator, not even
   the project, can recover a lost passphrase. So a union that does not make
   recovery backups *will* eventually lose a family's whole case to a dropped
   phone or a forgotten passphrase.
2. **One person hoarding everyone's recovery blobs is the honeypot.** If all
   twelve families' recovery backups sit on your laptop, you have rebuilt exactly
   the single point of compromise the project exists to avoid — one device to
   steal, one person to coerce, one subpoena to serve, one disk failure to lose
   everything.

The whole job of key custody is to get the safety of (1) **without** becoming the
liability of (2). The answer is never "no backups" and never "all backups with
one person." It is **distributed custody**: backups exist, but no single person
holds enough to be worth attacking, and no single failure loses a case.

## What a recovery blob is

A vault is encrypted with a random **data key**; your everyday **passphrase**
wraps that key. A **recovery blob** is a second, independent wrapping of the same
data key under a *different* **recovery passphrase** — produced by:

```console
$ uv run habitable key backup --vault ./case-4B --out ./case-4B-recovery.txt
```

Two things follow from that, and both matter for custody:

- **The blob file alone is useless without its recovery passphrase.** They are
  two separate secrets. Keep them apart, held differently, by different logic —
  ideally by different people. A blob with its passphrase written on it is a
  plaintext key.
- **Restoring also needs the encrypted vault directory** (the case data) to still
  exist somewhere — the blob recovers *access*, not the *data*. A re-synced peer
  who still has the case is therefore itself a kind of backup.

```console
$ uv run habitable key restore ./case-4B --recovery-file ./case-4B-recovery.txt
# (enter the recovery passphrase, then choose a new vault passphrase)
```

## Good and bad places to keep a recovery blob

**Good:**

- An **offline** medium held by a *different* trusted person than the everyday
  keyholder — a USB stick or a printed copy in a safe place, with the recovery
  passphrase held by yet another person or memorized.
- **Distributed**, so any one location can be lost or seized without losing the
  case and without exposing it. (See *Splitting custody* below.)
- For a union, the pattern from [`key-management.md`](key-management.md): each
  case's recovery file held by a *second* trusted organizer, with a recovery
  passphrase only that person knows — so neither the everyday keyholder nor the
  steward alone can recover it, and neither alone is the single point of failure.

**Bad:**

- **All recovery blobs for the whole union on one device** — your laptop, your
  phone, one cloud account. That is the honeypot. Even encrypted, it concentrates
  every case into one thing to steal, coerce, or subpoena.
- **Blob and its passphrase stored together** — same file, same drive, same
  sticky note. Now it is one secret, not two.
- **A blob whose passphrase is the same as the everyday vault passphrase** — that
  defeats the point of an *independent* recovery passphrase; one leak loses both.
- **Anything that re-introduces a server the project controls.** "Let me just put
  them in a shared cloud folder so I don't lose them" rebuilds the central store
  the architecture forbids. If you must use remote storage, the *union* controls
  it and the blobs are useless without separately-held passphrases.

## Splitting and distributing custody

The goal: **no single person is a single point of compromise *or* a single point
of failure.** Some practical patterns, from simplest to strongest:

- **Two-person rule per case (baseline, recommended for every union).** The
  tenant (or everyday keyholder) holds the vault and its passphrase; a *second*
  organizer holds that case's recovery blob with a recovery passphrase only they
  know. Losing either person alone does not lose the case, and neither alone can
  open it without the other's secret. This is directly supported today by `key
  backup` / `key restore`.
- **Separate the blob from its passphrase across two people.** Person A holds the
  blob file; person B holds the recovery passphrase. Neither alone can recover;
  together they can. This raises the bar for an adversary from "compromise one
  person" to "compromise two specific people."
- **Spread custody across cases, not concentrate it.** Rather than you holding
  every case's blob, arrange that *different* second-organizers hold different
  cases' blobs. No one device, if lost or seized, exposes more than a few cases.
- **Peer-sync as living redundancy.** A second organizer's synced device already
  holds the case data; combined with that device's own passphrase and recovery
  blob, the case survives the loss of any one phone. Treat multi-device sync as
  part of the custody plan, not separate from it.

> **A note on "threshold / split-key" schemes.** A true cryptographic
> threshold-backup ("any 3 of 5 organizers can recover") is an attractive idea
> and a documented *future* direction, **not a built-in command today**. Do not
> tell a union it exists. The patterns above approximate its *intent* —
> distributing trust so no one is the honeypot — using the commands that do
> exist. If you want the real thing, say so in the backlog rather than improvising
> a homegrown crypto scheme.

## Per-member vs shared responsibilities

Be explicit about who owns what; ambiguity is how cases get lost.

**Each member / everyday keyholder owns:**

- Their own vault passphrase. (No one, including you, can recover it for them.)
- Knowing *that* a recovery backup exists and *who* holds it.
- Telling the steward promptly if they suspect their device or passphrase was
  compromised, so keys can be rotated.

**The steward (you) and the union together own:**

- Making sure a recovery backup exists for every active case *before* it is
  needed — guided at setup, not after a loss.
- The **who-can-recover-what map**: a simple, current record of which second
  organizer holds which case's blob and who holds which recovery passphrase.
  Keep it minimal and protect it; it is sensitive (it describes where the keys
  are), but it must not itself contain blobs or passphrases.
- Running the relay (if any) so it only ever sees ciphertext, and never becoming
  the place all secrets pile up.
- **Custody handoff when a member leaves** the union mid-case — who inherits the
  vault and the recovery responsibility. (A smoother built-in custody-transfer
  flow is on the backlog; today this is a manual, documented handoff: re-issue a
  recovery backup to the new custodian and update the map.)

## Rotating after a suspected compromise

If a device is lost or stolen, a passphrase may have leaked, or a member's
account/phone was accessed by someone who should not have it — **rotate.**

```console
$ uv run habitable key rotate --vault ./case-4B
# (enter the current passphrase, then choose a new one)
```

Rotation re-wraps the same data key under a new passphrase; the evidence is not
re-encrypted, so it is instant. After rotating:

- **Update the recovery backups.** An old recovery blob still opens with its own
  recovery passphrase — so a compromise of an old blob is still live until you
  refresh it. Re-issue the recovery backup with a fresh recovery passphrase and
  update the who-can-recover-what map.
- **Rotate on every affected device.** Each device has its own passphrase and its
  own recovery backup; rotating one does not rotate the others. Across multiple
  devices and partial connectivity this gets fiddly — multi-device key-lifecycle
  UX is a known rough edge and a roadmap item, so go device by device,
  deliberately, and write down what you have done.
- **Honest limit:** rotation changes the *secret*, not history. If an adversary
  already copied the plaintext off a device while it was unlocked, rotation does
  not un-disclose it. Rotation limits *future* access through the old secret; it
  is not a time machine. Say so plainly to the affected member.

## Rehearse recovery before you trust it

The most common way custody fails is that no one ever tested restore, and it
turns out the blob was incomplete, the passphrase was mis-recorded, or the vault
directory was missing — discovered at the worst possible moment, the night before
a hearing.

**Rehearse on a throwaway case, not on a real one:**

1. Spin up a synthetic vault you can afford to destroy — `uv run habitable demo`
   produces case data with no real tenant in it.
2. Make a recovery backup of it (`key backup`), store the blob and its passphrase
   the way your real custody plan says to.
3. Now *actually restore it* (`key restore`) from the blob and passphrase, on a
   different machine if you can, and confirm `uv run habitable status` opens it.
4. Repeat with each second-organizer who holds real blobs, so *they* have done it
   once before it counts.

A built-in, safer recovery-**drill** mode is on the backlog; until it lands, the
synthetic-data dry run above is the practice to adopt. **A recovery procedure you
have never run is not a backup — it is a hope.** Drill it until it is boring,
then trust it.

## The one-paragraph summary to hand a union

Make a recovery backup for every case (`key backup`), keep each blob and its
passphrase apart and held by *different* trusted people, never pile all the
union's blobs onto one device, rotate (`key rotate`) and re-issue backups after
any suspected compromise, keep a small current map of who-can-recover-what, and
rehearse a restore (`key restore`) on throwaway demo data before you ever need it
for real. Recovery is impossible by design without a backup — and one person
holding all the backups is the very honeypot this tool exists to avoid.
