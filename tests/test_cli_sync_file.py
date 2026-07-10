# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""File-based sneakernet sync via the CLI (`sync-export` / `sync-import`, E-09).

Two vaults are built with the `test_sync.py` fixture pattern, then the real CLI
`main()` is driven (as in `test_cli_demo.py`) to export A's encrypted delta to a
file, hand it over, and import it into B — with no relay and no network at all.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from habitable.capture import capture
from habitable.cli import main
from habitable.sync import suggested_delta_filename
from habitable.tsa import LocalRfc3161TSA
from habitable.vault import Vault

SENTINEL = "PLAINTEXT-SENTINEL-mold-on-bathroom-ceiling"


def _seed(vault: Vault, make_jpeg: Callable[..., Path], tsa: LocalRfc3161TSA) -> str:
    """Add one issue + one timestamped capture; capture() persists to disk."""
    issue = vault.document.add_issue(category="mold", room="bath", title=SENTINEL, issue_id="i1")
    capture(vault, make_jpeg(with_location=True), issue_id=issue, tsa=tsa)
    return issue


def test_sneakernet_roundtrip_and_idempotent_reimport(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    a = make_vault("A")
    b = make_vault("B", passphrase="pw-b")
    _seed(a, make_jpeg, local_tsa)

    usb = tmp_path / "usb"
    usb.mkdir()
    delta = usb / "delta.hsync"
    peer_b = b.identity.public().encode()

    # A exports a delta sealed to B onto the "stick".
    assert (
        main(
            [
                "sync-export",
                "--vault",
                str(a.path),
                "--passphrase",
                "test-passphrase",
                "--peer",
                peer_b,
                "--out",
                str(delta),
            ]
        )
        == 0
    )
    assert delta.exists() and delta.stat().st_size > 0
    out = capsys.readouterr().out
    assert "sealed to peer" in out
    assert b.identity.public().fingerprint in out
    assert "leaks nothing" in out

    # B imports it: the output is not silent — it names merges and captures.
    assert main(["sync-import", "--vault", str(b.path), "--passphrase", "pw-b", str(delta)]) == 0
    out = capsys.readouterr().out
    assert "merged 1 message" in out
    assert "imported 1 capture" in out

    # B now holds the issue, the sealed original, the token, and intact custody.
    b_reopened = Vault.open(b.path, "pw-b")
    assert [i.issue_id for i in b_reopened.document.issues()] == ["i1"]
    record = b_reopened.document.captures()[0]
    assert b_reopened.read_original(record.capture_id, record.content_hash)
    assert b_reopened.get_token(record.capture_id) is not None
    assert b_reopened.custody.verify().ok

    # Re-importing the same file is explicitly detected and skipped as a replay.
    assert main(["sync-import", "--vault", str(b.path), "--passphrase", "pw-b", str(delta)]) == 0
    assert "replay protection skipped 1" in capsys.readouterr().out


def test_sneakernet_import_wrong_recipient_errors_cleanly(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    a = make_vault("A")
    b = make_vault("B", passphrase="pw-b")
    c = make_vault("C", passphrase="pw-c")
    _seed(a, make_jpeg, local_tsa)

    delta = tmp_path / "delta.hsync"
    assert (
        main(
            [
                "sync-export",
                "--vault",
                str(a.path),
                "--passphrase",
                "test-passphrase",
                "--peer",
                b.identity.public().encode(),  # sealed to B, not C
                "--out",
                str(delta),
            ]
        )
        == 0
    )
    capsys.readouterr()

    # C is not the recipient: a clean, non-zero error, and nothing is imported.
    assert main(["sync-import", "--vault", str(c.path), "--passphrase", "pw-c", str(delta)]) == 1
    assert "sealed to this device" in capsys.readouterr().err
    assert Vault.open(c.path, "pw-c").document.issues() == []


def test_sneakernet_import_rejects_forged_blob(
    make_vault: Callable[..., Vault],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    b = make_vault("B", passphrase="pw-b")
    forged = tmp_path / "forged.hsync"
    forged.write_bytes(b"not a sealed habitable delta at all")

    assert main(["sync-import", "--vault", str(b.path), "--passphrase", "pw-b", str(forged)]) == 1
    assert "sealed to this device" in capsys.readouterr().err


def test_sneakernet_export_default_filename_uses_peer_fp8(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    a = make_vault("A")
    b = make_vault("B", passphrase="pw-b")
    _seed(a, make_jpeg, local_tsa)
    peer = b.identity.public()

    monkeypatch.chdir(tmp_path)
    assert (
        main(
            [
                "sync-export",
                "--vault",
                str(a.path),
                "--passphrase",
                "test-passphrase",
                "--peer",
                peer.encode(),
            ]
        )
        == 0
    )
    expected = tmp_path / suggested_delta_filename(peer)
    assert expected.exists() and expected.stat().st_size > 0


def test_suggested_delta_filename_is_stable_and_fp8(
    make_vault: Callable[..., Vault],
) -> None:
    peer = make_vault("B").identity.public()
    fp8 = peer.fingerprint.replace("-", "")[:8]
    assert len(fp8) == 8
    assert suggested_delta_filename(peer) == f"habitable-delta-{fp8}.hsync"
