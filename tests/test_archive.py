# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Archive / re-timestamping: proofs that survive an authority's cert aging out."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from habitable.capture import capture, retimestamp_all
from habitable.cli import main
from habitable.errors import TimestampError
from habitable.packet import build_packet
from habitable.tsa import LocalRfc3161TSA, TimestampToken, verify_archive_chain
from habitable.vault import Vault
from habitable.verify import verify_packet


def test_archive_chain_verifies_in_a_packet(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], tmp_path: Path
) -> None:
    vault = make_vault()
    primary_tsa = LocalRfc3161TSA("tsa-primary", time_source=lambda: 1_767_312_000)
    later_tsa = LocalRfc3161TSA("tsa-archive", time_source=lambda: 1_800_000_000)
    issue = vault.document.add_issue(category="mold", issue_id="i1")
    capture(vault, make_jpeg(), issue_id=issue, tsa=primary_tsa)

    assert retimestamp_all(vault, later_tsa) == 1
    assert retimestamp_all(vault, later_tsa) == 1  # a second archive link
    capture_record = vault.document.captures()[0]
    assert len(vault.get_archive_tokens(capture_record.capture_id)) == 2

    out = tmp_path / "packet"
    build_packet(vault, out, generated_at="2026-01-02T00:10:00Z")
    report = verify_packet(out)
    assert report.ok
    notes = [n for item in report.items for n in item.notes]
    assert any("archive-timestamped (2 link(s))" in n for n in notes)


def test_archive_chain_anchors_existence_and_detects_tamper(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path]
) -> None:
    vault = make_vault()
    primary_tsa = LocalRfc3161TSA("p", time_source=lambda: 1_767_312_000)  # 2026-01-02
    later_tsa = LocalRfc3161TSA("a", time_source=lambda: 1_800_000_000)
    issue = vault.document.add_issue(category="mold", issue_id="i1")
    capture(vault, make_jpeg(), issue_id=issue, tsa=primary_tsa)
    retimestamp_all(vault, later_tsa)

    cap = vault.document.captures()[0]
    primary = vault.get_token(cap.capture_id)
    assert primary is not None
    archives = vault.get_archive_tokens(cap.capture_id)

    infos = verify_archive_chain(cap.content_hash, primary, archives)
    assert len(infos) == 2
    assert infos[0].gen_time == "2026-01-02T00:00:00Z"  # existence anchored at the primary

    # A truncated archive link breaks the chain.
    broken = [TimestampToken("rfc3161", "x", archives[0].data[:-20])]
    with pytest.raises(TimestampError):
        verify_archive_chain(cap.content_hash, primary, broken)


def test_retimestamp_cli_flow(
    tmp_path: Path,
    make_jpeg: Callable[..., Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("HABITABLE_PASSPHRASE", "pw")
    vault = tmp_path / "vault"
    assert main(["init", str(vault), "--case", "c", "--unit", "4B"]) == 0
    assert main(["issue", "--vault", str(vault), "--category", "mold", "--title", "M"]) == 0
    issue_id = next(t for t in capsys.readouterr().out.split() if t.startswith("issue-"))
    photo = make_jpeg()
    assert (
        main(["capture", str(photo), "--vault", str(vault), "--issue", issue_id, "--dev-tsa"]) == 0
    )
    assert main(["retimestamp", "--vault", str(vault), "--dev-tsa"]) == 0
    packet = tmp_path / "packet"
    assert main(["export", "--vault", str(vault), "--out", str(packet)]) == 0
    assert main(["verify", str(packet)]) == 0
