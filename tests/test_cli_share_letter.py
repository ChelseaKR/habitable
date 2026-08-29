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


def _vault_with_issue(tmp_path: Path, config_extra: str = "") -> Path:
    vault = tmp_path / "vault"
    assert main(["init", str(vault), "--case", "c", "--unit", "4B", "--passphrase", "pw"]) == 0
    if config_extra:
        config = vault / "config.toml"
        config.write_text(
            config.read_text(encoding="utf-8") + "\n" + config_extra + "\n", encoding="utf-8"
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
                "Mold",
            ]
        )
        == 0
    )
    return vault


def test_cli_letter_withholds_expired_local_law_wording_and_says_so(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """ADR 0013: a lapsed citation must not ride out on the tenant's letter."""
    citation = "Notice under the Example City housing code, section 12-34"
    vault = _vault_with_issue(
        tmp_path,
        "\n".join(
            [
                "[letter]",
                f'header = "{citation}"',
                'local_law_reviewer = "Example Legal Aid"',
                'local_law_reviewed_at = "2024-01-01"',
                'local_law_expires_at = "2025-01-01"',
            ]
        ),
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
                "--no-pdf",
            ]
        )
        == 0
    )
    html = (out / "letter.html").read_text(encoding="utf-8")
    assert citation not in html
    printed = capsys.readouterr().out
    assert "2025-01-01" in printed
    assert "left out of this letter" in printed


def test_cli_letter_keeps_current_local_law_wording_silently(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    citation = "Notice under the Example City housing code, section 12-34"
    vault = _vault_with_issue(
        tmp_path,
        "\n".join(
            [
                "[letter]",
                f'header = "{citation}"',
                'local_law_reviewed_at = "2026-01-01"',
                'local_law_expires_at = "2999-01-01"',
            ]
        ),
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
                "--no-pdf",
            ]
        )
        == 0
    )
    assert citation in (out / "letter.html").read_text(encoding="utf-8")
    printed = capsys.readouterr().out
    assert "left out of this letter" not in printed
    assert "no review date" not in printed
