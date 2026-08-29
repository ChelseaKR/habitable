# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

import pytest

from habitable.cli import main
from habitable.usecases import get_profile, list_profiles
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
                "--dev-tsa",  # seal offline: a unit test must never call a public TSA
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
    assert captured.out.count("\tv1\t") == 11
    assert "external review required" in captured.out
    assert "move_out_deposit\tv1\timplemented" in captured.out


def test_cli_profile_list_flags_an_expired_profile(
    capsys: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    expired = replace(get_profile("repair_delivery"), expires_at="2000-01-01")
    patched = tuple(
        expired if profile.profile_id == "repair_delivery" else profile
        for profile in list_profiles()
    )
    monkeypatch.setattr("habitable.cli.list_profiles", lambda: patched)

    assert main(["profile", "list"]) == 0
    captured = capsys.readouterr()  # type: ignore[attr-defined]
    assert "repair_delivery\tv1\treview expired 2000-01-01\t" in captured.out


def test_cli_status_notes_an_expired_selected_profile(
    make_vault: Callable[..., Vault], capsys: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = make_vault()
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
    expired = replace(get_profile("repair_delivery"), expires_at="2000-01-01")
    monkeypatch.setattr("habitable.cli.get_profile", lambda profile_id: expired)

    assert main(["status", "--vault", str(vault.path), "--passphrase", "test-passphrase"]) == 0
    captured = capsys.readouterr()  # type: ignore[attr-defined]
    assert "review expired 2000-01-01; export falls back to generic" in captured.out
