# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""CLI wiring for the letter generator and organizer sharing."""

from __future__ import annotations

from pathlib import Path

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
