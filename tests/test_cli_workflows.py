# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from habitable.cli import main
from habitable.vault import Vault


def test_cli_profile_artifact_relationship_and_handoff(
    make_vault: Callable[..., Vault], tmp_path: Path
) -> None:
    vault = make_vault()
    issue = vault.document.add_issue(category="mold", issue_id="i1")
    vault.save()
    document = tmp_path / "request.txt"
    document.write_text("Synthetic request.", encoding="utf-8")

    assert (
        main(
            [
                "profile",
                "set",
                "--vault",
                str(vault.path),
                "--passphrase",
                "test-passphrase",
                "repair_delivery",
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "artifact",
                "--vault",
                str(vault.path),
                "--passphrase",
                "test-passphrase",
                str(document),
                "--issue",
                issue,
                "--type",
                "repair_request",
                "--title",
                "Repair request",
                "--source",
                "tenant copy",
                "--occurred-at",
                "2026-01-03",
                "--no-timestamp",
            ]
        )
        == 0
    )
    reopened = Vault.open(vault.path, "test-passphrase")
    artifact_id = reopened.document.artifacts()[0].artifact_id
    assert (
        main(
            [
                "relate",
                "--vault",
                str(vault.path),
                "--passphrase",
                "test-passphrase",
                "--issue",
                issue,
                "--type",
                "documents_condition",
                "--source",
                artifact_id,
                "--target",
                issue,
            ]
        )
        == 0
    )
    packet = tmp_path / "packet"
    assert (
        main(
            [
                "export",
                "--vault",
                str(vault.path),
                "--passphrase",
                "test-passphrase",
                "--out",
                str(packet),
                "--no-pdf",
                "--handoff-profile",
                "repair_delivery",
            ]
        )
        == 0
    )
    assert (packet / "handoff-repair_delivery.html").exists()


def test_cli_lists_all_profiles(capsys: object) -> None:
    assert main(["profile", "list"]) == 0
    captured = capsys.readouterr()  # type: ignore[attr-defined]
    assert captured.out.count("\tv1\t") == 10
    assert "external review required" in captured.out
