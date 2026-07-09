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

## Harden the KDF cost (FIX-08)

Every unlock re-derives a key-encryption key from your passphrase with **scrypt**,
at a cost (memory + time) that trades off unlock speed against resistance to
offline brute force if the keyfile is ever stolen. The default (`standard`)
targets an interactive unlock on a low-end phone. If your device can spare the
extra time and memory — or you simply want more headroom as hardware gets
faster — bump the cost with `key harden`:

```console
$ uv run habitable key harden --vault ./case-4B
# (enter the current passphrase; the keyfile is re-wrapped at the "hardened" profile)
```

Like rotation, this only rewrites the small keyfile — the bulk evidence is never
touched — but **every future unlock pays the new cost**, so expect `habitable
status`/`app`/etc. to take noticeably longer to open the vault afterward. Three
profiles are available (`--profile standard|hardened|paranoid`); see
[`crypto-spec.md`](crypto-spec.md#31-key-lifecycle-r-38-fix-08) for the concrete scrypt
parameters and a bump procedure. Hardening does **not** change the data key or the
passphrase — it is orthogonal to both rotation (above) and DEK rotation (below).

## Rotate the data key (FIX-08)

Passphrase rotation (above) re-wraps the *same* data key — it does nothing for a
suspected leak of the key itself (e.g. a device believed compromised, or a bug
that may have exposed decrypted blobs). For that, rotate the data key:

```console
$ uv run habitable key rotate-dek --vault ./case-4B
# (enter the current passphrase; a NEW data key replaces the old one)
```

This is the expensive operation the others deliberately avoid: every encrypted
vault blob and every sealed original is decrypted, its fixity re-verified, and
re-encrypted under the fresh key. It is bounded by the size of the case (not
instant like rotation/hardening) but is meant to be rare — a deliberate incident
response, not routine hygiene. The passphrase does not change; only the key it
wraps does. Update recovery backups afterward, same as after a passphrase
rotation — an old recovery blob still wraps the *old* data key.

## Threshold (M-of-N) social custody

A plain recovery backup is one blob held by one person. **Threshold custody**
splits recovery across several stewards so that *any* `M` of `N` can recover,
but no single steward can — so no single steward is the honeypot:

```console
$ uv run habitable key share --vault ./case-4B \
    --threshold 2 --steward Ana --steward Bo --steward Cy \
    --out-dir ./case-4B-custody
# writes recovery-bundle.json + one share file per steward (a 2-of-3 split)
```

Give each `share-*.json` to its named steward and keep them apart; the
`recovery-bundle.json` is not secret on its own but is useless without a quorum
of shares. When recovery is needed, bring any `M` shares together:

```console
$ uv run habitable key recover ./case-4B \
    --bundle ./case-4B-custody/recovery-bundle.json \
    --share ./from-ana.json --share ./from-cy.json
# (any 2 of the 3 shares, then choose a new vault passphrase)
```

See the [`key-custody-playbook.md`](key-custody-playbook.md) for when to use this
and [`crypto-spec.md`](crypto-spec.md) §3a for the construction.

## Multiple devices

A second organizer's device is itself a kind of backup: sync the case
peer-to-peer (see [`setup-guide.md`](setup-guide.md)), and the evidence survives
the loss of any one device. Each device has its own passphrase and its own
recovery backup.

## Under the hood

- The data key is 256-bit; the passphrase wraps it via **scrypt** + ChaCha20-Poly1305.
- Rotation, hardening, and backup all operate on the small wrapped key, never the
  bulk data; DEK rotation is the one operation that touches every encrypted file.
- The recovery backup is the same wrapped-key format as the keyfile, protected by
  a separate passphrase. Implementation: `crypto.export_recovery_blob` /
  `import_recovery_blob`, exercised by `tests/test_cli_key.py`.
- `key harden`: `crypto.harden_keyfile` / `Vault.harden_key`, `crypto.KDF_PROFILES`.
- `key rotate-dek`: `Vault.rotate_dek`, exercised by `tests/test_vault_capture.py`
  and `tests/test_cli_key.py`.
