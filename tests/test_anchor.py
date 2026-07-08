# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""External anchoring (EXP-01): closing the hostile-keyholder gap in threat-model.md §5."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import cast

import pytest

from habitable.anchor import AnchorRecord, create_anchor, verify_anchor_records
from habitable.canonical import JSONValue
from habitable.capture import capture
from habitable.cli import main
from habitable.errors import AnchorError
from habitable.evidence import CustodyLog
from habitable.packet import build_packet
from habitable.tsa import LocalRfc3161TSA
from habitable.vault import Vault
from habitable.verify import verify_packet


def _captured_vault(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], tsa: LocalRfc3161TSA
) -> Vault:
    vault = make_vault()
    issue = vault.document.add_issue(category="mold", room="bathroom", title="Mold", issue_id="i1")
    capture(vault, make_jpeg("a.jpg"), issue_id=issue, tsa=tsa)
    return vault


def _exported_custody(vault: Vault) -> CustodyLog:
    proof = vault.custody.integrity_proof(hlc_map=lambda raw: vault.document.opaque_id("hlc", raw))
    raw_entries = proof.get("entries")
    assert isinstance(raw_entries, list)
    records = [
        cast(Mapping[str, JSONValue], entry) for entry in raw_entries if isinstance(entry, dict)
    ]
    return CustodyLog.from_records(records)


def test_create_anchor_requires_a_nonempty_chain(
    make_vault: Callable[..., Vault], local_tsa: LocalRfc3161TSA
) -> None:
    vault = make_vault()
    with pytest.raises(AnchorError, match="nothing to anchor"):
        create_anchor(vault, [local_tsa])


def test_create_anchor_requires_an_authority(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], local_tsa: LocalRfc3161TSA
) -> None:
    vault = _captured_vault(make_vault, make_jpeg, local_tsa)
    with pytest.raises(AnchorError, match="no timestamp authority"):
        create_anchor(vault, [])


def test_create_anchor_stamps_the_current_head(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], local_tsa: LocalRfc3161TSA
) -> None:
    vault = _captured_vault(make_vault, make_jpeg, local_tsa)
    head_before = _exported_custody(vault).head_hash
    length_before = len(vault.custody)

    record = create_anchor(vault, [local_tsa])

    assert record.head_hash == head_before
    assert record.chain_length == length_before
    assert len(record.tokens) == 1
    assert vault.anchors() == (record,)


def test_anchors_persist_across_open(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], local_tsa: LocalRfc3161TSA
) -> None:
    vault = _captured_vault(make_vault, make_jpeg, local_tsa)
    record = create_anchor(vault, [local_tsa])

    reopened = Vault.open(vault.path, "test-passphrase")
    assert reopened.anchors() == (record,)


def test_anchor_of_pre_exp01_vault_defaults_to_empty(
    make_vault: Callable[..., Vault],
) -> None:
    """A vault with no anchors.json (created before EXP-01) opens fine with no anchors."""
    vault = make_vault()
    (vault.path / "anchors.json").unlink(missing_ok=True)
    reopened = Vault.open(vault.path, "test-passphrase")
    assert reopened.anchors() == ()


def test_verify_anchor_records_matches_chain_at_recorded_length(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], local_tsa: LocalRfc3161TSA
) -> None:
    vault = _captured_vault(make_vault, make_jpeg, local_tsa)
    record = create_anchor(vault, [local_tsa])
    # A second capture grows the chain past what the anchor covers.
    issue = next(i.issue_id for i in vault.document.issues())
    capture(vault, make_jpeg("b.jpg"), issue_id=issue, tsa=local_tsa)

    exported = _exported_custody(vault)
    verdicts = verify_anchor_records([record], exported)
    assert len(verdicts) == 1
    assert verdicts[0].ok
    assert verdicts[0].chain_matches
    assert verdicts[0].record.chain_length < len(exported)  # covers a prefix, not the whole


def test_verify_anchor_records_rejects_head_mismatch(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], local_tsa: LocalRfc3161TSA
) -> None:
    vault = _captured_vault(make_vault, make_jpeg, local_tsa)
    record = create_anchor(vault, [local_tsa])
    forged = AnchorRecord(
        head_hash="0" * 64,  # does not match the actual chain
        chain_length=record.chain_length,
        created_at=record.created_at,
        tokens=record.tokens,
    )
    verdicts = verify_anchor_records([forged], _exported_custody(vault))
    assert len(verdicts) == 1
    assert not verdicts[0].ok
    assert not verdicts[0].chain_matches
    assert verdicts[0].problems


def test_verify_anchor_records_rejects_out_of_range_chain_length(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], local_tsa: LocalRfc3161TSA
) -> None:
    vault = _captured_vault(make_vault, make_jpeg, local_tsa)
    record = create_anchor(vault, [local_tsa])
    too_far = AnchorRecord(
        head_hash=record.head_hash,
        chain_length=len(vault.custody) + 5,
        created_at=record.created_at,
        tokens=record.tokens,
    )
    verdicts = verify_anchor_records([too_far], _exported_custody(vault))
    assert not verdicts[0].ok
    assert any("only" in p for p in verdicts[0].problems)


def test_packet_ships_and_verifies_anchor(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    vault = _captured_vault(make_vault, make_jpeg, local_tsa)
    create_anchor(vault, [local_tsa])

    out = tmp_path / "packet"
    build_packet(vault, out, generated_at="2026-01-02T00:10:00Z")
    bundle = json.loads((out / "bundle.json").read_text(encoding="utf-8"))
    assert len(bundle["anchors"]) == 1

    report = verify_packet(out)
    assert report.ok
    assert report.anchor_count == 1
    assert report.anchors_verified == 1
    assert report.anchored_by  # a non-empty gen_time
    assert report.anchored_through == bundle["anchors"][0]["chain_length"]
    assert "provably existed by" in report.summary()


def test_packet_with_no_anchors_verifies_unaffected(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    vault = _captured_vault(make_vault, make_jpeg, local_tsa)
    out = tmp_path / "packet"
    build_packet(vault, out, generated_at="2026-01-02T00:10:00Z")

    report = verify_packet(out)
    assert report.ok
    assert report.anchor_count == 0
    assert report.anchors_verified == 0
    assert report.anchored_by == ""
    assert "provably existed by" not in report.summary()


def test_tampered_anchor_head_hash_fails_verification_closed(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    """A packet that ships an anchor whose head_hash doesn't match its own chain is
    NOT intact — the anchor is a claim about this exact chain, and a mismatch is
    exactly the kind of inconsistency a hostile keyholder rewrite would produce."""
    vault = _captured_vault(make_vault, make_jpeg, local_tsa)
    create_anchor(vault, [local_tsa])

    out = tmp_path / "packet"
    build_packet(vault, out, generated_at="2026-01-02T00:10:00Z")
    bundle_path = out / "bundle.json"
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    bundle["anchors"][0]["head_hash"] = "1" * 64
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

    report = verify_packet(out)
    assert not report.ok
    assert any("anchor" in p for p in report.problems)


def test_anchored_through_reflects_the_most_recent_anchor(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    """threat-model.md §6: the mitigation covers 'events before the LAST anchor' — so
    with two anchors, the reported bound must come from the one covering more entries,
    not simply the earliest anchor made."""
    vault = _captured_vault(make_vault, make_jpeg, local_tsa)
    create_anchor(vault, [local_tsa])  # anchor #1, covers the chain so far
    issue = next(i.issue_id for i in vault.document.issues())
    capture(vault, make_jpeg("b.jpg"), issue_id=issue, tsa=local_tsa)
    create_anchor(vault, [local_tsa])  # anchor #2, covers more entries

    out = tmp_path / "packet"
    build_packet(vault, out, generated_at="2026-01-02T00:10:00Z")
    report = verify_packet(out)
    assert report.ok
    assert report.anchor_count == 2
    assert report.anchors_verified == 2
    assert report.anchored_through == max(a.chain_length for a in vault.anchors())


def test_cli_anchor_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, make_jpeg: Callable[..., Path]
) -> None:
    vault_path = tmp_path / "vault"
    monkeypatch.setenv("HABITABLE_PASSPHRASE", "pw")
    assert main(["init", str(vault_path), "--case", "bldg-12", "--unit", "4B"]) == 0
    assert (
        main(
            [
                "issue",
                "--vault",
                str(vault_path),
                "--category",
                "mold",
                "--title",
                "M",
                "--severity",
                "high",
            ]
        )
        == 0
    )
    photo = make_jpeg("a.jpg")
    vault = Vault.open(vault_path, "pw")
    issue_id = next(i.issue_id for i in vault.document.issues())
    assert (
        main(
            [
                "capture",
                "--vault",
                str(vault_path),
                str(photo),
                "--issue",
                issue_id,
                "--dev-tsa",
            ]
        )
        == 0
    )

    assert main(["anchor", "--vault", str(vault_path), "--dev-tsa"]) == 0

    reopened = Vault.open(vault_path, "pw")
    anchors = reopened.anchors()
    assert len(anchors) == 1
    assert anchors[0].chain_length == len(reopened.custody)


def test_cli_anchor_fails_closed_on_empty_chain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault_path = tmp_path / "vault"
    monkeypatch.setenv("HABITABLE_PASSPHRASE", "pw")
    assert main(["init", str(vault_path), "--case", "bldg-12"]) == 0
    # No captures yet: create_anchor rejects an empty chain before any network call,
    # even though `init` configures real (unreachable-in-tests) default TSAs.
    assert main(["anchor", "--vault", str(vault_path)]) != 0
