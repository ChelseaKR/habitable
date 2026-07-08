# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""CLI: threshold (M-of-N) social custody of recovery keys (EXP-11)."""

from __future__ import annotations

from pathlib import Path

import pytest

from habitable.cli import main


def _init_case(vault: Path) -> None:
    assert main(["init", str(vault), "--case", "bldg-12", "--unit", "4B"]) == 0
    assert main(["issue", "--vault", str(vault), "--category", "mold", "--title", "M"]) == 0


def test_share_and_recover_2_of_3(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    vault = tmp_path / "vault"
    monkeypatch.setenv("HABITABLE_PASSPHRASE", "pw")
    _init_case(vault)

    out_dir = tmp_path / "custody"
    assert (
        main(
            [
                "key",
                "share",
                "--vault",
                str(vault),
                "--threshold",
                "2",
                "--steward",
                "Ana",
                "--steward",
                "Bo",
                "--steward",
                "Cy",
                "--out-dir",
                str(out_dir),
            ]
        )
        == 0
    )
    bundle = out_dir / "recovery-bundle.json"
    shares = sorted(out_dir.glob("share-*.json"))
    assert bundle.exists()
    assert len(shares) == 3

    # Lose the keyfile; the vault no longer opens.
    (vault / "keyfile.json").unlink()
    assert main(["status", "--vault", str(vault)]) == 1

    # Any two stewards' shares reconstruct the key under a new passphrase.
    assert (
        main(
            [
                "key",
                "recover",
                str(vault),
                "--bundle",
                str(bundle),
                "--share",
                str(shares[0]),
                "--share",
                str(shares[2]),
                "--new-passphrase",
                "pw-recovered",
            ]
        )
        == 0
    )
    monkeypatch.setenv("HABITABLE_PASSPHRASE", "pw-recovered")
    assert main(["status", "--vault", str(vault)]) == 0


def test_single_share_cannot_recover(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    vault = tmp_path / "vault"
    monkeypatch.setenv("HABITABLE_PASSPHRASE", "pw")
    _init_case(vault)
    out_dir = tmp_path / "custody"
    assert (
        main(
            [
                "key",
                "share",
                "--vault",
                str(vault),
                "--threshold",
                "2",
                "--steward",
                "Ana",
                "--steward",
                "Bo",
                "--steward",
                "Cy",
                "--out-dir",
                str(out_dir),
            ]
        )
        == 0
    )
    shares = sorted(out_dir.glob("share-*.json"))
    bundle = out_dir / "recovery-bundle.json"
    # One share is below quorum: the CLI refuses before touching crypto.
    assert (
        main(
            [
                "key",
                "recover",
                str(vault),
                "--bundle",
                str(bundle),
                "--share",
                str(shares[0]),
                "--new-passphrase",
                "x",
            ]
        )
        == 1
    )


def test_share_rejects_threshold_larger_than_stewards(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = tmp_path / "vault"
    monkeypatch.setenv("HABITABLE_PASSPHRASE", "pw")
    _init_case(vault)
    assert (
        main(
            [
                "key",
                "share",
                "--vault",
                str(vault),
                "--threshold",
                "3",
                "--steward",
                "Ana",
                "--steward",
                "Bo",
                "--out-dir",
                str(tmp_path / "c"),
            ]
        )
        == 1
    )


def test_recover_rejects_mismatched_shares(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    vault = tmp_path / "vault"
    monkeypatch.setenv("HABITABLE_PASSPHRASE", "pw")
    _init_case(vault)
    dir_a = tmp_path / "a"
    dir_b = tmp_path / "b"
    for d in (dir_a, dir_b):
        assert (
            main(
                [
                    "key",
                    "share",
                    "--vault",
                    str(vault),
                    "--threshold",
                    "2",
                    "--steward",
                    "Ana",
                    "--steward",
                    "Bo",
                    "--out-dir",
                    str(d),
                ]
            )
            == 0
        )
    shares_a = sorted(dir_a.glob("share-*.json"))
    shares_b = sorted(dir_b.glob("share-*.json"))
    # Mixing a share from bundle A with bundle B fails (bundle_id mismatch).
    assert (
        main(
            [
                "key",
                "recover",
                str(vault),
                "--bundle",
                str(dir_a / "recovery-bundle.json"),
                "--share",
                str(shares_a[0]),
                "--share",
                str(shares_b[1]),
                "--new-passphrase",
                "x",
            ]
        )
        == 1
    )
