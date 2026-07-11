<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Custody transfer & membership churn — handing off a case when a member leaves

People join and leave a union. Cases outlast the person who opened them. This
document is for the moment a member with an active case stops being the person who
holds it — they quit, go unreachable, are expelled, or die or are incapacitated —
and someone else has to inherit the vault and the recovery responsibility without
losing the case and without rebuilding a honeypot.

> **Read the custody basics first.** This assumes you have read the
> [key custody playbook](key-custody-playbook.md) and
> [`key-management.md`](key-management.md). It reuses their vocabulary — **vault**,
> **passphrase**, **recovery blob**, the **who-can-recover-what map**, and the
> **two-person rule per case** — and does not re-explain them.
>
> **Honesty note.** There is **no built-in "transfer custody" command**. Threshold
> recovery does exist: `habitable key share` can prepare an M-of-N split and
> `habitable key recover` can restore from a quorum. It only helps when the bundle,
> enough separate shares, and a surviving encrypted vault were arranged beforehand.
> What follows is a **manual, documented flow** built entirely on commands that exist
> today — `habitable sync`, `habitable key rotate`, `habitable key backup`,
> `habitable key restore`, `habitable key rotate-dek`, `habitable key share`,
> `habitable key recover`, `habitable status`, and `habitable export`. Every
> command cited below is real; nothing here invents a feature.

## Scope and principles

- **It is the member's data.** A custody transfer is not the union seizing a case;
  it is the union continuing to *hold* a case on the member's behalf, under whatever
  the member agreed to. Whose data is it? The member's — see
  [*Data ownership and consent*](#data-ownership-and-consent-devons-board-question)
  below and the [board risk briefing](adoption/board-risk-briefing.md).
- **Consent-first.** The clean path (Scenario A) happens *with* the departing
  member, on their say-so. The recovery path (Scenario B) exists precisely because
  consent is not always available — but it only works if the union *already*
  arranged a recovery backup **before** it was needed, with the member's knowledge.
  You cannot manufacture custody after the fact.
- **No honeypot.** A handoff must not become an excuse to pile a departing member's
  case (or everyone's) onto the steward's laptop. Custody moves to *a* new
  custodian and the who-can-recover-what map is updated; it does not collapse onto
  one person.
- **When this applies:** a member quits the union mid-case; a member goes silent and
  unreachable; a member is expelled; or a member dies or is incapacitated and the
  case must continue (a hearing is scheduled, a filing is pending).

## Scenario A — cooperative departure (the clean path)

The member is reachable and willing. This is the path to steer toward, and the one
to make easy at onboarding by keeping the recovery backup and the map current.

1. **Get the current case onto the incoming custodian's device.** The departing
   member syncs their final state to the new custodian, peer to peer:

   ```console
   $ uv run habitable sync --vault ./case-4B --peer <custodian-id> --channel case-4B
   # (the new custodian runs `uv run habitable id` to print the id to share;
   #  add --dir <shared-folder> or --relay <https://...> for the transport)
   ```

   Confirm both sides landed on the same state with `uv run habitable status` on
   each device before anyone deletes anything.

2. **Make the new custodian the keyholder.** Two supported ways — pick one:
   - **The new custodian rotates their own copy.** After sync, the incoming
     custodian holds a vault that still opens with the *member's* passphrase. They
     set a passphrase only they know:

     ```console
     $ uv run habitable key rotate --vault ./case-4B
     # (enter the current passphrase, then choose a new one)
     ```

   - **The member re-issues a recovery backup to the new custodian.** If the case is
     staying with the everyday keyholder but a *new second organizer* is taking over
     the recovery role, the member issues a fresh recovery blob under a new recovery
     passphrase and hands the two secrets to two different people:

     ```console
     $ uv run habitable key backup --vault ./case-4B --out ./case-4B-recovery.txt
     # (choose a fresh recovery passphrase; give the blob and the passphrase to
     #  *different* trusted people, never together)
     ```

3. **Update the who-can-recover-what map.** Record the new keyholder and/or the new
   second organizer, and retire the departing member's entry. Old recovery blobs or
   threshold shares do **not** expire after `key rotate`; that command changes the
   everyday passphrase wrapping only. If the departing person held recovery material,
   run `key rotate-dek`, then issue a new backup or threshold split and retire every
   old copy. Note the change on the map.

4. **The departing member's obligations — decide and record which:**
   - **Delete their copy.** Cleanest. Once the new custodian has synced state and
     re-keyed, the member removes the vault directory from their device. The case
     lives on with the union; the member is no longer a custody surface to lose or
     coerce.
   - **Keep their copy.** Legitimate — it is *their* data. But then it is a live
     second copy under *their* passphrase and recovery, outside the union's map. If
     it later matters (a subpoena to them, a lost phone), that risk is theirs to
     carry. Whichever they choose, write it on the map so the union knows whether a
     second live copy exists.

### Scenario A checklist

- [ ] New custodian shared their `habitable id`; member synced final state to them.
- [ ] `habitable status` matches on both devices.
- [ ] New custodian ran `key rotate` **or** member re-issued `key backup` to the new second organizer.
- [ ] Who-can-recover-what map updated; departing member's old entry retired; stale blobs re-issued if re-keyed.
- [ ] Recorded whether the departing member deleted or kept their copy.

## Scenario B — unreachable or uncooperative member

The member is gone, silent, or hostile, and the case must continue. There is no
consent to sync a fresh copy, so recovery depends **entirely** on a backup the union
arranged **earlier**. This is why the playbook insists on the two-person rule at
setup: Scenario B is only survivable if you prepared for it.

**If recovery material exists**, use the ceremony arranged at onboarding. The
single-custodian baseline is a recovery blob held by a *second* organizer, with its
recovery passphrase held apart:

1. **Restore access from the second organizer's blob.** The second organizer, using
   their recovery passphrase, rebuilds a usable keyfile on a device that holds the
   vault directory (their own synced copy, or a copy of the departed member's vault):

   ```console
   $ uv run habitable key restore ./case-4B --recovery-file ./case-4B-recovery.txt
   # (enter the recovery passphrase, then choose a new vault passphrase)
   ```

   Restore needs **both** the recovery blob *and* the encrypted vault directory to
   still exist somewhere — the blob recovers *access*, not the *data*. A synced peer
   who still holds the case is itself that vault directory.

2. **Replace the data key immediately.** The departed member may still know the old
   passphrase, and the recovery blob just used is now spent material. Replace the DEK
   so the old blob cannot recover the current vault, then issue a fresh backup under
   a fresh recovery passphrase:

   ```console
   $ uv run habitable key rotate-dek --vault ./case-4B
   $ uv run habitable key backup --vault ./case-4B --out ./case-4B-recovery.txt
   ```

3. **Update the map** with the new keyholder, the new second organizer, and the fact
   that the departed member's old secrets no longer open the current vault.

**If the case uses threshold custody instead**, assemble the non-secret bundle and
the configured quorum of separately held shares, then restore on a device that still
holds the encrypted vault directory:

```console
$ uv run habitable key recover ./case-4B \
    --bundle ./case-4B-custody/recovery-bundle.json \
    --share ./from-ana.json --share ./from-cy.json
```

No single share can recover the key. After recovery, run `key rotate-dek`, issue a
fresh split, distribute its shares separately, and retire the used bundle and shares.
See the current [key-management incident procedure](key-management.md).

**If no usable recovery material exists — be plain: the case is gone.** No operator,
not the project, not the steward, can recover a vault whose only passphrase left with
a member who will not return it, when neither a usable single backup nor a threshold
bundle and quorum nor a surviving synced peer exists. A threshold setup also fails
if its bundle or quorum of shares is unavailable.
This is the same by-design unrecoverability that stops a landlord, a breach, or a
subpoena — it does not make an exception for the union. There is no back door. The
only defense is to have set up and protected recovery material *before* this
scenario.

### Scenario B checklist

- [ ] Confirmed a single recovery blob **or** a threshold bundle plus quorum of shares, **and** a surviving vault directory, all exist. (If not, stop — the case is unrecoverable; record that honestly.)
- [ ] Custodian ran `key restore`, or the quorum ran `key recover`, using the prearranged material.
- [ ] `key rotate-dek` run immediately after restore; fresh backup or split issued; used material retired.
- [ ] Who-can-recover-what map updated; departed member's old secrets marked dead.

## Scenario C — case handoff without a departure (steward change)

Sometimes nobody leaves the union, but the *responsibility* moves: a new IT steward
takes over, or a different second organizer inherits a case's recovery role. No sync
of ownership is needed — the everyday keyholder keeps their vault and passphrase. You
only move the recovery custody:

1. The everyday keyholder re-issues a recovery backup for the incoming second
   organizer, under a fresh recovery passphrase held apart from the blob:

   ```console
   $ uv run habitable key backup --vault ./case-4B --out ./case-4B-recovery.txt
   ```

2. Update the who-can-recover-what map: new second organizer in, old one out.
3. If the outgoing organizer held a blob, treat it as retired — the re-issued backup
   under a new recovery passphrase is what is now live; the old blob should be
   destroyed and marked dead on the map.

### Scenario C checklist

- [ ] Everyday keyholder re-issued `key backup` to the incoming second organizer.
- [ ] Who-can-recover-what map updated (new organizer in, old out).
- [ ] Outgoing organizer's old blob destroyed and marked dead.

## Data ownership and consent (Devon's board question)

> *"What happens when a member quits the union mid-case? Whose data is it? How do we
> hand off custodianship?"*

- **Whose data is it? The member's.** The architecture makes this concrete rather
  than a promise: there is no central store, no operator copy, no account. The case
  lives encrypted on devices the union and its members hold. A custody transfer is
  the union continuing to hold the member's case on the member's terms — not a
  claim of ownership over it. See the
  [board risk briefing](adoption/board-risk-briefing.md) ("No central honeypot" and
  "Lost key = lost data") and the [key custody playbook](key-custody-playbook.md).
- **Consent is the dividing line between the scenarios.** Scenario A is done *with*
  the member. Scenario B is only available because the union arranged — with the
  member's knowledge, at onboarding — a recovery backup held by a second organizer.
  A union that never set up that backup has, correctly, no way to take a member's
  case without them; that is a feature, not a gap.
- **Agree the exit terms up front.** The board and the workshop should settle, at
  adoption time, what happens to a case when a member leaves: does the case stay
  with the union, and does the departing member delete or keep their copy? Record
  the union's default, and let each member choose otherwise for their own case.
- **This is documentation, not legal advice.** Whether a departing member can compel
  deletion, or whether the union may retain a case, can be a legal question for your
  tenant attorney or legal-aid group. The tool enforces the *technical* facts above;
  it does not adjudicate the human agreement.

## The one-paragraph summary

When a member leaves mid-case: if they cooperate, have them `sync` their final state
to the new custodian, then have the custodian `key rotate` (or re-issue `key backup`
to a new second organizer), update the who-can-recover-what map, and record whether
the member deleted or kept their copy. If they are unreachable, recover *only* if a
surviving encrypted vault exists together with either a usable single backup or a
prearranged threshold bundle and its quorum. Run `key restore` or `key recover`, then
`key rotate-dek` and issue fresh recovery material immediately. If neither recovery
path was arranged, be honest that the case is permanently gone by design.
For a steward change
with nobody leaving, just re-issue the recovery backup to the new organizer and
update the map. There is no transfer command; this is a manual flow on real commands,
and it only works if the chosen recovery material existed before you needed it.
