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
    report = verify_packet(out, trusted_certs=[primary_tsa.certificate, later_tsa.certificate])
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


def test_retimestamp_threads_redundant_authorities(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], tmp_path: Path
) -> None:
    """retimestamp_all extends the archive chain with each redundant authority (FIX-06).

    The extra authorities thread into the (still strictly linear) archive chain so the
    re-timestamp proof does not rest on a single TSA, and the packet still verifies.
    """
    vault = make_vault()
    primary = LocalRfc3161TSA("p", time_source=lambda: 1_767_312_000)
    extra = LocalRfc3161TSA("second", time_source=lambda: 1_767_312_000)
    issue = vault.document.add_issue(category="mold", issue_id="i1")
    capture(vault, make_jpeg(), issue_id=issue, tsa=primary, extra_tsas=[extra])
    cap_id = vault.document.captures()[0].capture_id
    assert len(vault.get_additional_tokens(cap_id)) == 1  # a redundant primary token

    later = LocalRfc3161TSA("archive-primary", time_source=lambda: 1_800_000_000)
    later_extra = LocalRfc3161TSA("archive-second", time_source=lambda: 1_800_000_000)
    assert retimestamp_all(vault, later, extra_tsas=[later_extra]) == 1  # one capture archived

    # One link from the primary archive authority, one threaded from the redundant one.
    archives = vault.get_archive_tokens(cap_id)
    assert [t.tsa_name for t in archives] == ["archive-primary", "archive-second"]
    archive_entries = [
        e
        for e in vault.custody.entries
        if e.item_id == cap_id and e.details.get("kind") == "archive"
    ]
    assert len(archive_entries) == 2
    assert sum(1 for e in archive_entries if e.details.get("role") == "additional") == 1

    # The threaded chain still verifies cleanly in an exported packet.
    out = tmp_path / "packet"
    build_packet(vault, out, generated_at="2026-01-02T00:10:00Z")
    report = verify_packet(
        out,
        trusted_certs=[
            primary.certificate,
            extra.certificate,
            later.certificate,
            later_extra.certificate,
        ],
    )
    assert report.ok
    item = report.items[0]
    assert {"p", "second"} <= set(item.verified_authorities)
    assert any("archive-timestamped (2 link(s))" in n for n in item.notes)


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
    # Dev timestamps remain mechanically valid but never authority-trusted or ready.
    assert main(["verify", str(packet)]) == 1
    output = capsys.readouterr()
    assert "integrity: intact" in output.out
    assert "evidence readiness: NOT READY" in output.out
    assert "Development timestamps can never become trusted" in output.err
