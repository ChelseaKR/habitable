<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Keys, backup, and recovery

A vault is encrypted with a random **data key**, and that key is wrapped by your
**passphrase**. This is the one thing you must not lose carelessly — and the one
thing no one (not even the project) can recover for you.

> **The hard truth, stated plainly:** if you lose your passphrase **and** have no
> recovery backup **and** no synced peer who still has the case, the data is
> **gone**. That is by design — it is the same property that means a landlord, a
> breach, or a subpoena can't get it either. So **make a recovery backup now.**

## Change your passphrase (rotation)

Re-wraps the same data key under a new passphrase; your evidence is not
re-encrypted, so it's instant.

```console
$ uv run habitable key rotate --vault ./case-4B
# (enter the current passphrase, then choose a new one)
```

After rotating, **update any recovery backups** — an old backup still opens with
its own recovery passphrase, which you may want to refresh too.

## Make a recovery backup

Exports the data key wrapped under an **independent recovery passphrase**. Keep
the file and its passphrase **safe and separate** (different place, different
passphrase from the everyday one).

```console
$ uv run habitable key backup --vault ./case-4B --out ./case-4B-recovery.txt
```

A good practice for a union: each case has a recovery file held by a second
trusted organizer, with a recovery passphrase only they know.

## Restore from a backup

If the keyfile is lost or the passphrase is forgotten, rebuild access from the
recovery backup under a new passphrase. (This needs the rest of the vault
directory — the encrypted case data — to still be present.)

```console
$ uv run habitable key restore ./case-4B \
    --recovery-file ./case-4B-recovery.txt
# (enter the recovery passphrase, then choose a new vault passphrase)
$ uv run habitable status --vault ./case-4B   # opens with the new passphrase
```

## Multiple devices

A second organizer's device is itself a kind of backup: sync the case
peer-to-peer (see [`setup-guide.md`](setup-guide.md)), and the evidence survives
the loss of any one device. Each device has its own passphrase and its own
recovery backup.

## Under the hood

- The data key is 256-bit; the passphrase wraps it via **scrypt** + ChaCha20-Poly1305.
- Rotation and backup operate on the small wrapped key, never the bulk data.
- The recovery backup is the same wrapped-key format as the keyfile, protected by
  a separate passphrase. Implementation: `crypto.export_recovery_blob` /
  `import_recovery_blob`, exercised by `tests/test_cli_key.py`.
