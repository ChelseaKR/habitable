# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""The `recur` command: reopen an issue and log the relapse on its own timeline."""

from __future__ import annotations

from pathlib import Path

import pytest

from habitable.cli import main


def test_recur_reopens_issue_without_creating_an_orphan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    vault = tmp_path / "vault"
    monkeypatch.setenv("HABITABLE_PASSPHRASE", "pw")
    assert main(["init", str(vault), "--case", "bldg-12", "--unit", "4B"]) == 0
    capsys.readouterr()  # drain init's output
    assert main(["issue", "--vault", str(vault), "--category", "mold", "--title", "M"]) == 0
    # "habitable: added issue <id> (mold)" — the id is the fourth whitespace token.
    issue_id = capsys.readouterr().out.split()[3]

    assert main(["recur", "--vault", str(vault), "--issue", issue_id, "--text", "back again"]) == 0
    assert "reopened" in capsys.readouterr().out

    # Still one issue: the relapse attached to the same issue, not a new orphan.
    assert main(["status", "--vault", str(vault)]) == 0
    status_out = capsys.readouterr().out
    assert status_out.count(f"· {issue_id}") == 1


def test_recur_unknown_issue_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    vault = tmp_path / "vault"
    monkeypatch.setenv("HABITABLE_PASSPHRASE", "pw")
    assert main(["init", str(vault), "--case", "c"]) == 0
    assert main(["recur", "--vault", str(vault), "--issue", "nope"]) == 1
