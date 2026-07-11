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
                "--type",
                "condition_observed",
                "--occurred-at",
                "2026-01-03",
                "--source",
                "firsthand",
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


def test_cli_dev_timestamp_is_intact_but_never_evidence_ready(
    tmp_path: Path,
    make_jpeg: Callable[..., Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    packet = _init_capture_export(tmp_path, make_jpeg, monkeypatch, capsys)
    assert main(["verify", str(packet)]) == 1
    captured = capsys.readouterr()
    assert "integrity: intact" in captured.out
    assert "timestamp authority: NOT TRUSTED" in captured.out
    assert "evidence readiness: NOT READY" in captured.out
    assert "Development timestamps can never become trusted" in captured.err


def test_cli_status_shows_record_strength(
    tmp_path: Path,
    make_jpeg: Callable[..., Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """EXP-03: ``habitable status`` surfaces a per-issue record-strength line
    with its honesty caveat — never a bare level with no framing."""
    monkeypatch.setenv("HABITABLE_PASSPHRASE", "pw")
    vault = tmp_path / "vault"
    assert main(["init", str(vault), "--case", "bldg-12", "--unit", "4B"]) == 0

    assert main(["issue", "--vault", str(vault), "--category", "mold", "--title", "Mold"]) == 0
    out = capsys.readouterr().out
    issue_id = next(token for token in out.split() if token.startswith("issue-"))

    photo = make_jpeg(with_location=True)
    assert (
        main(["capture", str(photo), "--vault", str(vault), "--issue", issue_id, "--dev-tsa"]) == 0
    )
    capsys.readouterr()

    assert main(["status", "--vault", str(vault)]) == 0
    status_out = capsys.readouterr().out
    assert "record strength: developing" in status_out
    assert "not token validity, authority trust" in status_out
    assert "or admissibility" in status_out


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
    capsys.readouterr()
    assert main(["verify", str(packet)]) == 1
    assert "integrity: NOT INTACT" in capsys.readouterr().out


def test_cli_verify_json_is_structured(
    tmp_path: Path,
    make_jpeg: Callable[..., Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    packet = _init_capture_export(tmp_path, make_jpeg, monkeypatch, capsys)
    capsys.readouterr()  # drop prior output
    assert main(["verify", str(packet), "--json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["ok"] is False
    assert report["structurally_intact"] is True
    assert report["timestamp_authority_trusted"] is False
    assert report["evidence_ready"] is False
    assert report["status"] == "timestamp_authority_untrusted"
    assert report["signature_ok"] and report["custody_ok"]
    assert report["item_count"] >= 1
    assert report["cryptographically_verified_items"] == report["item_count"]
    assert report["verified_items"] == 0
    item = report["items"][0]
    for key in (
        "capture_id",
        "content_hash",
        "ok",
        "structurally_intact",
        "timestamp_verified",
        "timestamp_authority_trusted",
        "evidence_ready",
        "notes",
    ):
        assert key in item


def test_cli_verify_spanish_trust_output(
    tmp_path: Path,
    make_jpeg: Callable[..., Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    packet = _init_capture_export(tmp_path, make_jpeg, monkeypatch, capsys)
    capsys.readouterr()
    assert main(["verify", str(packet), "--lang", "es"]) == 1
    captured = capsys.readouterr()
    assert "integridad: íntegra" in captured.out
    assert "autoridad del sello de tiempo: NO CONFIABLE" in captured.out
    assert "preparación probatoria: NO LISTA" in captured.out
    assert "Los sellos de desarrollo nunca pueden volverse confiables" in captured.err
    assert "el sello de desarrollo no es confiable" in captured.err


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


def test_cli_export_discloses_awaiting_state(
    tmp_path: Path,
    make_jpeg: Callable[..., Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Exporting with queued-offline items states the degraded state and next step.

    FIX-09: a packet with awaiting items can remain structurally intact but is not
    evidence-ready — the export must say so up front, with the
    `habitable resolve` next step, instead of the recipient discovering it.
    """
    monkeypatch.setenv("HABITABLE_PASSPHRASE", "pw")
    vault = tmp_path / "vault"
    assert main(["init", str(vault), "--case", "bldg-12", "--unit", "4B"]) == 0
    assert main(["issue", "--vault", str(vault), "--category", "mold", "--title", "Mold"]) == 0
    out = capsys.readouterr().out
    issue_id = next(token for token in out.split() if token.startswith("issue-"))

    photo = make_jpeg()
    capture_args = ["capture", str(photo), "--vault", str(vault), "--issue", issue_id]
    assert main([*capture_args, "--no-timestamp"]) == 0
    capsys.readouterr()

    assert main(["export", "--vault", str(vault), "--out", str(tmp_path / "p1")]) == 0
    out = capsys.readouterr().out
    assert "awaiting a timestamp token" in out
    assert "habitable resolve" in out

    # Once every item is timestamped, the hint disappears — nothing cries wolf.
    assert main(["resolve", "--vault", str(vault), "--dev-tsa"]) == 0
    capsys.readouterr()
    assert main(["export", "--vault", str(vault), "--out", str(tmp_path / "p2")]) == 0
    out = capsys.readouterr().out
    assert "awaiting a timestamp token" not in out
