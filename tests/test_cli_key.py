# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Vault key lifecycle: rotate the passphrase, back up, and restore."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from habitable.cli import main
from habitable.crypto import KDF_PROFILES


def test_rotate_backup_and_restore(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    vault = tmp_path / "vault"
    monkeypatch.setenv("HABITABLE_PASSPHRASE", "pw-old")
    assert main(["init", str(vault), "--case", "bldg-12", "--unit", "4B"]) == 0
    assert main(["issue", "--vault", str(vault), "--category", "mold", "--title", "M"]) == 0

    # Rotate: old passphrase stops working, new one opens the same data.
    assert main(["key", "rotate", "--vault", str(vault), "--new-passphrase", "pw-new"]) == 0
    monkeypatch.setenv("HABITABLE_PASSPHRASE", "pw-old")
    assert main(["status", "--vault", str(vault)]) == 1  # wrong passphrase → error exit
    monkeypatch.setenv("HABITABLE_PASSPHRASE", "pw-new")
    assert main(["status", "--vault", str(vault)]) == 0

    # Back up the key under an independent recovery passphrase.
    recovery = tmp_path / "recovery.txt"
    assert (
        main(
            [
                "key",
                "backup",
                "--vault",
                str(vault),
                "--out",
                str(recovery),
                "--recovery-passphrase",
                "rec-pass",
            ]
        )
        == 0
    )
    assert recovery.exists()

    # Simulate a lost keyfile; the vault no longer opens.
    (vault / "keyfile.json").unlink()
    assert main(["status", "--vault", str(vault)]) == 1

    # Restore from the backup under a new passphrase; the data is intact.
    assert (
        main(
            [
                "key",
                "restore",
                str(vault),
                "--recovery-file",
                str(recovery),
                "--recovery-passphrase",
                "rec-pass",
                "--new-passphrase",
                "pw-restored",
            ]
        )
        == 0
    )
    monkeypatch.setenv("HABITABLE_PASSPHRASE", "pw-restored")
    assert main(["status", "--vault", str(vault)]) == 0


def test_restore_with_wrong_recovery_passphrase_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = tmp_path / "vault"
    monkeypatch.setenv("HABITABLE_PASSPHRASE", "pw")
    assert main(["init", str(vault), "--case", "c"]) == 0
    recovery = tmp_path / "r.txt"
    assert (
        main(
            [
                "key",
                "backup",
                "--vault",
                str(vault),
                "--out",
                str(recovery),
                "--recovery-passphrase",
                "right",
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "key",
                "restore",
                str(vault),
                "--recovery-file",
                str(recovery),
                "--recovery-passphrase",
                "WRONG",
                "--new-passphrase",
                "n",
            ]
        )
        == 1
    )


def test_key_harden_raises_kdf_cost_same_passphrase(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """FIX-08: `key harden` bumps the KDF cost profile; the same passphrase still
    opens the vault, a wrong one still doesn't."""
    vault = tmp_path / "vault"
    monkeypatch.setenv("HABITABLE_PASSPHRASE", "pw")
    assert main(["init", str(vault), "--case", "bldg-12"]) == 0

    keyfile_before = json.loads((vault / "keyfile.json").read_text(encoding="utf-8"))
    assert keyfile_before["kdf"]["n"] == KDF_PROFILES["standard"]

    assert main(["key", "harden", "--vault", str(vault)]) == 0  # default profile: hardened
    keyfile_after = json.loads((vault / "keyfile.json").read_text(encoding="utf-8"))
    assert keyfile_after["kdf"]["n"] == KDF_PROFILES["hardened"]

    assert main(["status", "--vault", str(vault)]) == 0  # same passphrase still opens it
    monkeypatch.setenv("HABITABLE_PASSPHRASE", "WRONG")
    assert main(["status", "--vault", str(vault)]) == 1


def test_key_harden_paranoid_profile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    vault = tmp_path / "vault"
    monkeypatch.setenv("HABITABLE_PASSPHRASE", "pw")
    assert main(["init", str(vault), "--case", "c"]) == 0
    assert main(["key", "harden", "--vault", str(vault), "--profile", "paranoid"]) == 0
    keyfile = json.loads((vault / "keyfile.json").read_text(encoding="utf-8"))
    assert keyfile["kdf"]["n"] == KDF_PROFILES["paranoid"]


def test_key_rotate_dek_preserves_data_and_passphrase(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """FIX-08: `key rotate-dek` re-encrypts the whole vault under a fresh data key,
    but the passphrase and the data itself are unchanged."""
    vault = tmp_path / "vault"
    monkeypatch.setenv("HABITABLE_PASSPHRASE", "pw")
    assert main(["init", str(vault), "--case", "bldg-12", "--unit", "4B"]) == 0
    assert main(["issue", "--vault", str(vault), "--category", "mold", "--title", "M"]) == 0

    case_before = (vault / "case.enc").read_bytes()
    assert main(["key", "rotate-dek", "--vault", str(vault)]) == 0
    case_after = (vault / "case.enc").read_bytes()
    assert case_before != case_after  # re-encrypted under a new key

    assert main(["status", "--vault", str(vault)]) == 0  # same passphrase still works
    assert not list(vault.glob("*.new"))

    monkeypatch.setenv("HABITABLE_PASSPHRASE", "WRONG")
    assert main(["status", "--vault", str(vault)]) == 1
