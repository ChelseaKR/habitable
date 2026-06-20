# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""End-to-end CLI flow and the offline demo."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from habitable.cli import main
from habitable.demo import run_demo


def test_demo_runs_offline() -> None:
    assert run_demo() == 0


def _init_capture_export(
    tmp_path: Path,
    make_jpeg: Callable[..., Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> Path:
    monkeypatch.setenv("HABITABLE_PASSPHRASE", "pw")
    vault = tmp_path / "vault"
    assert main(["init", str(vault), "--case", "bldg-12", "--unit", "4B"]) == 0

    assert main(["issue", "--vault", str(vault), "--category", "mold", "--title", "Mold"]) == 0
    out = capsys.readouterr().out
    issue_id = next(token for token in out.split() if token.startswith("issue-"))

    photo = make_jpeg(with_location=True)
    capture_args = ["capture", str(photo), "--vault", str(vault), "--issue", issue_id, "--dev-tsa"]
    assert main(capture_args) == 0
    assert (
        main(
            [
                "timeline",
                "--vault",
                str(vault),
                "--issue",
                issue_id,
                "--kind",
                "observed",
                "--text",
                "cold",
            ]
        )
        == 0
    )
    assert main(["status", "--vault", str(vault)]) == 0

    packet = tmp_path / "packet"
    assert main(["export", "--vault", str(vault), "--out", str(packet)]) == 0
    return packet


def test_cli_full_flow_verifies(
    tmp_path: Path,
    make_jpeg: Callable[..., Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    packet = _init_capture_export(tmp_path, make_jpeg, monkeypatch, capsys)
    assert main(["verify", str(packet)]) == 0
    assert "packet intact" in capsys.readouterr().out


def test_cli_verify_detects_tamper(
    tmp_path: Path,
    make_jpeg: Callable[..., Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    packet = _init_capture_export(tmp_path, make_jpeg, monkeypatch, capsys)
    bundle = json.loads((packet / "bundle.json").read_text())
    bundle["unit"] = "TAMPERED"
    (packet / "bundle.json").write_text(json.dumps(bundle))
    assert main(["verify", str(packet)]) == 1


def test_cli_verify_json_is_structured(
    tmp_path: Path,
    make_jpeg: Callable[..., Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    packet = _init_capture_export(tmp_path, make_jpeg, monkeypatch, capsys)
    capsys.readouterr()  # drop prior output
    assert main(["verify", str(packet), "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["ok"] is True
    assert report["signature_ok"] and report["custody_ok"]
    assert report["item_count"] >= 1 and report["verified_items"] == report["item_count"]
    item = report["items"][0]
    for key in ("capture_id", "content_hash", "ok", "timestamp_verified", "notes"):
        assert key in item


def test_cli_recur_records_recurrence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("HABITABLE_PASSPHRASE", "pw")
    vault = tmp_path / "vault"
    assert main(["init", str(vault), "--case", "c"]) == 0
    assert main(["issue", "--vault", str(vault), "--category", "mold", "--title", "Mold"]) == 0
    issue_id = next(t for t in capsys.readouterr().out.split() if t.startswith("issue-"))
    assert main(["recur", "--vault", str(vault), "--issue", issue_id, "--note", "came back"]) == 0
    assert "recorded recurrence" in capsys.readouterr().out

    from habitable.vault import Vault

    doc = Vault.open(vault, "pw").document
    assert [e for e in doc.timeline(issue_id) if e.kind == "recurrence"]
    assert next(i for i in doc.issues() if i.issue_id == issue_id).status == "recurring"


def test_no_command_prints_help() -> None:
    assert main([]) == 2


def test_cli_id_prints_fingerprint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("HABITABLE_PASSPHRASE", "pw")
    vault = tmp_path / "vault"
    assert main(["init", str(vault), "--case", "c"]) == 0
    capsys.readouterr()
    assert main(["id", "--vault", str(vault)]) == 0
    out = capsys.readouterr().out
    assert "fingerprint:" in out and "public-id:" in out


def test_cli_sync_requires_transport(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from habitable.vault import Vault

    monkeypatch.setenv("HABITABLE_PASSPHRASE", "pw")
    vault = tmp_path / "vault"
    assert main(["init", str(vault), "--case", "c"]) == 0
    peer = Vault.open(vault, "pw").identity.public().encode()
    capsys.readouterr()
    # No --relay or --dir: the command reports a clear error and exits non-zero.
    assert main(["sync", "--vault", str(vault), "--peer", peer, "--channel", "r"]) == 1
    assert "transport" in capsys.readouterr().err
