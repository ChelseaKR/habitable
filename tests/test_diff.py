# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""EXP-02: `habitable diff` — comparing two packet exports of the same case."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from habitable.capture import capture
from habitable.cli import main
from habitable.diff import IssueChange, ItemChange, diff_packets, format_diff
from habitable.errors import DiffError
from habitable.packet import build_packet
from habitable.tsa import LocalRfc3161TSA
from habitable.vault import Vault


def _base_case(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    tsa: LocalRfc3161TSA,
) -> tuple[Vault, str]:
    vault = make_vault()
    issue = vault.document.add_issue(
        category="mold", room="bathroom", title="Mold", severity="moderate", issue_id="i1"
    )
    capture(vault, make_jpeg("a.jpg"), issue_id=issue, tsa=tsa)
    return vault, issue


def test_no_changes_between_identical_exports(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    vault, _ = _base_case(make_vault, make_jpeg, local_tsa)
    out_a = tmp_path / "a"
    out_b = tmp_path / "b"
    build_packet(vault, out_a, generated_at="2026-01-01T00:00:00Z")
    build_packet(vault, out_b, generated_at="2026-02-02T00:00:00Z")

    diff = diff_packets(out_a, out_b)
    assert not diff.has_changes
    assert diff.ok
    assert diff.old_generated_at == "2026-01-01T00:00:00Z"
    assert diff.new_generated_at == "2026-02-02T00:00:00Z"
    lines = format_diff(diff, "en")
    assert any("identical" in line for line in lines)


def test_added_capture_and_advancing_custody(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    vault, issue = _base_case(make_vault, make_jpeg, local_tsa)
    out_old = tmp_path / "old"
    build_packet(vault, out_old, generated_at="2026-01-01T00:00:00Z")

    capture(vault, make_jpeg("b.jpg"), issue_id=issue, tsa=local_tsa)
    out_new = tmp_path / "new"
    build_packet(vault, out_new, generated_at="2026-01-05T00:00:00Z")

    diff = diff_packets(out_old, out_new)
    assert diff.has_changes
    assert diff.ok  # custody grew honestly
    assert len(diff.items_added) == 1
    assert not diff.items_removed
    assert diff.custody_length_new > diff.custody_length_old

    lines = format_diff(diff, "en")
    assert any("1 capture added" in line for line in lines)
    assert any("entries" in line and "→" in line for line in lines)


def test_issue_severity_change_is_reported(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    vault, issue = _base_case(make_vault, make_jpeg, local_tsa)
    out_old = tmp_path / "old"
    build_packet(vault, out_old, generated_at="2026-01-01T00:00:00Z")

    vault.document.update_issue(issue, severity="severe")
    out_new = tmp_path / "new"
    build_packet(vault, out_new, generated_at="2026-01-05T00:00:00Z")

    diff = diff_packets(out_old, out_new)
    assert diff.issues_changed == (IssueChange(issue_id=issue, fields=("severity",)),)
    lines = format_diff(diff, "en")
    assert any(issue in line and "severity" in line for line in lines)


def test_removed_item_is_reported(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    vault = make_vault()
    issue = vault.document.add_issue(category="mold", room="bathroom", title="Mold", issue_id="i1")
    capture(
        vault,
        make_jpeg("a.jpg", capture_time="2026:01:01 00:00:00"),
        issue_id=issue,
        tsa=local_tsa,
    )
    capture(
        vault,
        make_jpeg("b.jpg", capture_time="2026:01:03 00:00:00"),
        issue_id=issue,
        tsa=local_tsa,
    )
    out_old = tmp_path / "old"
    build_packet(vault, out_old, generated_at="2026-01-01T00:00:00Z")

    # A packet re-exported with --since narrows the item set — "removed" from the
    # recipient's point of view, though nothing was deleted from the vault.
    out_new = tmp_path / "new"
    build_packet(vault, out_new, since="2026-01-03T00:00:00Z", generated_at="2026-01-05T00:00:00Z")

    diff = diff_packets(out_old, out_new)
    assert len(diff.items_removed) == 1
    assert not diff.items_added
    lines = format_diff(diff, "en")
    assert any("1 capture removed" in line for line in lines)


def test_different_case_ids_refuse_to_diff(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    vault_a = make_vault("a", case_id="case-A")
    vault_b = make_vault("b", case_id="case-B")
    issue_a = vault_a.document.add_issue(category="mold", issue_id="i1")
    issue_b = vault_b.document.add_issue(category="mold", issue_id="i1")
    capture(vault_a, make_jpeg("a.jpg"), issue_id=issue_a, tsa=local_tsa)
    capture(vault_b, make_jpeg("b.jpg"), issue_id=issue_b, tsa=local_tsa)

    out_a = tmp_path / "a-packet"
    out_b = tmp_path / "b-packet"
    build_packet(vault_a, out_a, generated_at="2026-01-01T00:00:00Z")
    build_packet(vault_b, out_b, generated_at="2026-01-01T00:00:00Z")

    with pytest.raises(DiffError, match="different cases"):
        diff_packets(out_a, out_b)


def test_rewritten_custody_history_is_flagged(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    vault, issue = _base_case(make_vault, make_jpeg, local_tsa)
    out_old = tmp_path / "old"
    build_packet(vault, out_old, generated_at="2026-01-01T00:00:00Z")

    capture(vault, make_jpeg("b.jpg"), issue_id=issue, tsa=local_tsa)
    out_new = tmp_path / "new"
    build_packet(vault, out_new, generated_at="2026-01-05T00:00:00Z")

    # Tamper with an early entry in the "new" packet's exported custody chain.
    bundle_path = out_new / "bundle.json"
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    bundle["custody_proof"]["entries"][0]["entry_hash"] = "0" * 64
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

    diff = diff_packets(out_old, out_new)
    assert not diff.custody_prefix_intact
    assert not diff.ok
    assert diff.custody_divergence_index == 0
    lines = format_diff(diff, "en")
    assert any("diverges" in line for line in lines)


def test_missing_bundle_raises_diff_error(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    other = tmp_path / "other"
    other.mkdir()
    (other / "bundle.json").write_text("{}", encoding="utf-8")
    with pytest.raises(DiffError):
        diff_packets(empty, other)


def test_format_diff_in_spanish(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    vault, issue = _base_case(make_vault, make_jpeg, local_tsa)
    out_old = tmp_path / "old"
    build_packet(vault, out_old, generated_at="2026-01-01T00:00:00Z")
    capture(vault, make_jpeg("b.jpg"), issue_id=issue, tsa=local_tsa)
    out_new = tmp_path / "new"
    build_packet(vault, out_new, generated_at="2026-01-05T00:00:00Z")

    diff = diff_packets(out_old, out_new)
    lines = format_diff(diff, "es")
    assert any("añadida" in line for line in lines)


def test_item_change_dataclass_repr() -> None:
    change = ItemChange(capture_id="cap-1", fields=("timestamp",))
    assert change.capture_id == "cap-1"
    assert change.fields == ("timestamp",)


def test_cli_diff_reports_added_capture(
    tmp_path: Path,
    make_jpeg: Callable[..., Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("HABITABLE_PASSPHRASE", "pw")
    vault_dir = tmp_path / "vault"
    assert main(["init", str(vault_dir), "--case", "bldg-12", "--unit", "4B"]) == 0
    assert main(["issue", "--vault", str(vault_dir), "--category", "mold", "--title", "Mold"]) == 0
    out = capsys.readouterr().out
    issue_id = next(token for token in out.split() if token.startswith("issue-"))

    photo = make_jpeg("a.jpg")
    assert (
        main(["capture", str(photo), "--vault", str(vault_dir), "--issue", issue_id, "--dev-tsa"])
        == 0
    )
    old_out = tmp_path / "old-packet"
    assert main(["export", "--vault", str(vault_dir), "--out", str(old_out), "--no-pdf"]) == 0
    capsys.readouterr()

    photo2 = make_jpeg("b.jpg")
    assert (
        main(["capture", str(photo2), "--vault", str(vault_dir), "--issue", issue_id, "--dev-tsa"])
        == 0
    )
    new_out = tmp_path / "new-packet"
    assert main(["export", "--vault", str(vault_dir), "--out", str(new_out), "--no-pdf"]) == 0
    capsys.readouterr()

    assert main(["diff", str(old_out), str(new_out)]) == 0
    printed = capsys.readouterr().out
    assert "1 capture added" in printed

    assert main(["diff", str(old_out), str(new_out), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["items_added"] and len(payload["items_added"]) == 1
    assert payload["ok"] is True
