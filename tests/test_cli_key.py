# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Vault key lifecycle: rotate the passphrase, back up, and restore."""

from __future__ import annotations

from pathlib import Path

import pytest

from habitable.cli import main


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
