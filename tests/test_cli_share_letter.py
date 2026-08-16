# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""CLI wiring for the letter generator and organizer sharing."""

from __future__ import annotations

from pathlib import Path

import pytest

from habitable.cli import main
from habitable.vault import Vault


def test_cli_letter_writes_accessible_letter(tmp_path: Path) -> None:
    vault = tmp_path / "vault"
    assert main(["init", str(vault), "--case", "c", "--unit", "4B", "--passphrase", "pw"]) == 0
    assert (
        main(
            [
                "issue",
                "--vault",
                str(vault),
                "--passphrase",
                "pw",
                "--category",
                "mold",
                "--title",
                "Mold",
            ]
        )
        == 0
    )
    out = tmp_path / "letter"
    assert (
        main(
            [
                "letter",
                "--vault",
                str(vault),
                "--passphrase",
                "pw",
                "--out",
                str(out),
                "--to",
                "Landlord",
                "--from-name",
                "Tenant",
                "--cure-days",
                "10",
                "--no-pdf",
            ]
        )
        == 0
    )
    html = (out / "letter.html").read_text(encoding="utf-8")
    assert "Repair request" in html
    assert "10 days" in html


def test_cli_letter_on_a_spanish_vault_says_the_letter_is_english(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Issue #161: a vault configured `--lang es` must not receive English prose
    labelled Spanish, and the person generating it must be told, in Spanish."""
    vault = tmp_path / "vault"
    assert (
        main(
            [
                "init",
                str(vault),
                "--case",
                "c",
                "--unit",
                "4B",
                "--passphrase",
                "pw",
                "--lang",
                "es",
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "issue",
                "--vault",
                str(vault),
                "--passphrase",
                "pw",
                "--category",
                "mold",
                "--title",
                "Moho",
            ]
        )
        == 0
    )
    out = tmp_path / "letter"
    capsys.readouterr()
    assert (
        main(
            [
                "letter",
                "--vault",
                str(vault),
                "--passphrase",
                "pw",
                "--out",
                str(out),
                "--no-pdf",
            ]
        )
        == 0
    )

    printed = capsys.readouterr().out
    assert "esta carta está escrita en inglés" in printed
    html = (out / "letter.html").read_text(encoding="utf-8")
    assert 'lang="en"' in html
    assert 'lang="es"' not in html


def test_cli_share_and_receive(tmp_path: Path) -> None:
    tenant = tmp_path / "tenant"
    organizer = tmp_path / "org"
    main(["init", str(tenant), "--case", "case-4B", "--unit", "4B", "--passphrase", "pw"])
    main(["init", str(organizer), "--case", "case-4B", "--passphrase", "pw"])
    main(
        [
            "issue",
            "--vault",
            str(tenant),
            "--passphrase",
            "pw",
            "--category",
            "mold",
            "--title",
            "Mold",
        ]
    )

    peer = Vault.open(organizer, "pw").identity.public().encode()
    pairing = tmp_path / "organizer.hpair"
    assert (
        main(
            [
                "sync-pair-create",
                "--vault",
                str(tenant),
                "--passphrase",
                "pw",
                "--peer",
                peer,
                "--out",
                str(pairing),
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "sync-pair-accept",
                "--vault",
                str(organizer),
                "--passphrase",
                "pw",
                "--in",
                str(pairing),
            ]
        )
        == 0
    )
    share_file = tmp_path / "case.share"
    assert (
        main(
            [
                "share",
                "--vault",
                str(tenant),
                "--passphrase",
                "pw",
                "--peer",
                peer,
                "--out",
                str(share_file),
            ]
        )
        == 0
    )
    assert share_file.exists()

    assert (
        main(["receive", "--vault", str(organizer), "--passphrase", "pw", "--in", str(share_file)])
        == 0
    )
    received = Vault.open(organizer, "pw")
    assert [i.title for i in received.document.issues()] == ["Mold"]
