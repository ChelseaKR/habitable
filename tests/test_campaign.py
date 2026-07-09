# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""EXP-08: the on-device campaign engine (multi-vault roll-up + combined packet)."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

import pytest

from habitable.campaign import (
    build_campaign_packet,
    build_campaign_report,
    health_for,
)
from habitable.capture import capture
from habitable.cli import main
from habitable.tsa import LocalRfc3161TSA
from habitable.vault import Vault
from habitable.verify import verify_packet


def _ready_vault(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    *,
    name: str,
    unit: str,
) -> Vault:
    """A vault with one issue and one fully-timestamped capture."""
    vault = make_vault(name, unit=unit)
    issue = vault.document.add_issue(category="mold", room="bath", title="Mold")
    capture(vault, make_jpeg(f"{name}.jpg"), issue_id=issue, tsa=local_tsa)
    return vault


class TestHealthFor:
    def test_empty_vault_is_not_export_ready(self, make_vault: Callable[..., Vault]) -> None:
        vault = make_vault(unit="1A")
        health = health_for(vault)
        assert health.capture_count == 0
        assert health.custody_intact
        assert not health.export_ready  # nothing captured yet

    def test_fully_timestamped_vault_is_export_ready(
        self,
        make_vault: Callable[..., Vault],
        make_jpeg: Callable[..., Path],
        local_tsa: LocalRfc3161TSA,
    ) -> None:
        vault = _ready_vault(make_vault, make_jpeg, local_tsa, name="v1", unit="4B")
        health = health_for(vault)
        assert health.issue_count == 1
        assert health.capture_count == 1
        assert health.timestamped_count == 1
        assert health.awaiting_count == 0
        assert health.custody_intact
        assert health.export_ready

    def test_deferred_capture_is_not_export_ready(
        self,
        make_vault: Callable[..., Vault],
        make_jpeg: Callable[..., Path],
        local_tsa: LocalRfc3161TSA,
    ) -> None:
        vault = make_vault(unit="2C")
        issue = vault.document.add_issue(category="no_heat", title="No heat")
        capture(vault, make_jpeg("a.jpg"), issue_id=issue, tsa=None)  # queued offline
        health = health_for(vault)
        assert health.awaiting_count == 1
        assert not health.export_ready

    def test_broken_custody_is_caught_not_raised(
        self,
        make_vault: Callable[..., Vault],
        make_jpeg: Callable[..., Path],
        local_tsa: LocalRfc3161TSA,
    ) -> None:
        vault = _ready_vault(make_vault, make_jpeg, local_tsa, name="v1", unit="3A")
        # Tamper with an in-memory custody entry the way test_evidence_exif does.
        vault.custody._entries[0] = replace(vault.custody._entries[0], action="tampered")
        health = health_for(vault)
        assert not health.custody_intact
        assert not health.export_ready
        assert health.custody_error  # a human-readable reason survives, not just False


class TestCampaignReport:
    def test_rolls_up_across_units(
        self,
        make_vault: Callable[..., Vault],
        make_jpeg: Callable[..., Path],
        local_tsa: LocalRfc3161TSA,
    ) -> None:
        ready = _ready_vault(make_vault, make_jpeg, local_tsa, name="ready", unit="1A")
        needs_stamp = make_vault("needs-stamp", unit="1B")
        issue = needs_stamp.document.add_issue(category="mold", title="Mold")
        capture(needs_stamp, make_jpeg("b.jpg"), issue_id=issue, tsa=None)

        report = build_campaign_report(
            [(Path("/vaults/1A"), ready), (Path("/vaults/1B"), needs_stamp)]
        )
        assert report.unit_count == 2
        assert report.export_ready_count == 1
        assert report.broken_custody_count == 0
        assert report.awaiting_timestamp_count == 1
        units_by_path = {u.vault_path: u for u in report.units}
        assert units_by_path[Path("/vaults/1A")].export_ready
        assert not units_by_path[Path("/vaults/1B")].export_ready

    def test_one_broken_vault_does_not_stop_the_roll_up(
        self,
        make_vault: Callable[..., Vault],
        make_jpeg: Callable[..., Path],
        local_tsa: LocalRfc3161TSA,
    ) -> None:
        ready = _ready_vault(make_vault, make_jpeg, local_tsa, name="ready", unit="1A")
        broken = _ready_vault(make_vault, make_jpeg, local_tsa, name="broken", unit="1B")
        broken.custody._entries[0] = replace(broken.custody._entries[0], action="tampered")

        report = build_campaign_report([(Path("/vaults/1A"), ready), (Path("/vaults/1B"), broken)])
        assert report.unit_count == 2
        assert report.broken_custody_count == 1
        assert report.export_ready_count == 1

    def test_read_only_does_not_touch_disk(
        self,
        make_vault: Callable[..., Vault],
        make_jpeg: Callable[..., Path],
        local_tsa: LocalRfc3161TSA,
        tmp_path: Path,
    ) -> None:
        vault = _ready_vault(make_vault, make_jpeg, local_tsa, name="v1", unit="4B")
        before = {p: p.read_bytes() for p in sorted(vault.path.rglob("*")) if p.is_file()}
        build_campaign_report([(vault.path, vault)])
        after = {p: p.read_bytes() for p in sorted(vault.path.rglob("*")) if p.is_file()}
        assert before == after


class TestCampaignPacket:
    def test_writes_one_packet_per_unit_plus_manifest_and_index(
        self,
        make_vault: Callable[..., Vault],
        make_jpeg: Callable[..., Path],
        local_tsa: LocalRfc3161TSA,
        tmp_path: Path,
    ) -> None:
        v1 = _ready_vault(make_vault, make_jpeg, local_tsa, name="v1", unit="4B")
        v2 = _ready_vault(make_vault, make_jpeg, local_tsa, name="v2", unit="4C")
        out = tmp_path / "building-packet"

        result = build_campaign_packet(
            [(v1.path, v1), (v2.path, v2)], out, generated_at="2026-01-02T00:10:00Z"
        )

        assert result.report.unit_count == 2
        assert len(result.units) == 2
        assert result.manifest_path.exists()
        assert result.index_path.exists()

        manifest = json.loads(result.manifest_path.read_bytes())
        assert manifest["unit_count"] == 2
        assert manifest["export_ready_count"] == 2
        assert {u["unit"] for u in manifest["units"]} == {"4B", "4C"}

        index_html = result.index_path.read_text(encoding="utf-8")
        assert "4B" in index_html and "4C" in index_html
        assert "export-ready" in index_html

        # Each unit's own packet independently verifies with the existing verifier.
        for unit_result in result.units:
            report = verify_packet(unit_result.out_dir)
            assert report.ok

    def test_duplicate_unit_labels_get_distinct_directories(
        self,
        make_vault: Callable[..., Vault],
        make_jpeg: Callable[..., Path],
        local_tsa: LocalRfc3161TSA,
        tmp_path: Path,
    ) -> None:
        v1 = _ready_vault(make_vault, make_jpeg, local_tsa, name="v1", unit="Unit A")
        v2 = _ready_vault(make_vault, make_jpeg, local_tsa, name="v2", unit="Unit A")
        out = tmp_path / "out"

        result = build_campaign_packet([(v1.path, v1), (v2.path, v2)], out)

        dirs = {u.out_dir for u in result.units}
        assert len(dirs) == 2  # never collide, even with identical unit labels


class TestCampaignCli:
    def test_status_and_export_across_two_vaults(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("HABITABLE_PASSPHRASE", "pw")
        v1 = tmp_path / "unit-4b"
        v2 = tmp_path / "unit-4c"
        assert main(["init", str(v1), "--case", "bldg-4B", "--unit", "4B"]) == 0
        assert main(["init", str(v2), "--case", "bldg-4C", "--unit", "4C"]) == 0
        assert main(["issue", "--vault", str(v1), "--category", "mold", "--title", "Mold"]) == 0

        assert main(["campaign", "status", "--vault", str(v1), "--vault", str(v2)]) == 0

        out = tmp_path / "combined"
        assert (
            main(
                [
                    "campaign",
                    "export",
                    "--vault",
                    str(v1),
                    "--vault",
                    str(v2),
                    "--out",
                    str(out),
                    "--no-pdf",
                ]
            )
            == 0
        )
        assert (out / "campaign_manifest.json").exists()
        assert (out / "index.html").exists()

    def test_wrong_passphrase_for_one_vault_errors(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("HABITABLE_PASSPHRASE", "pw-a")
        v1 = tmp_path / "unit-a"
        assert main(["init", str(v1), "--case", "c1"]) == 0

        monkeypatch.setenv("HABITABLE_PASSPHRASE", "pw-b")
        v2 = tmp_path / "unit-b"
        assert main(["init", str(v2), "--case", "c2"]) == 0

        # A shared passphrase that only matches one of the two vaults fails closed.
        monkeypatch.setenv("HABITABLE_PASSPHRASE", "pw-a")
        assert main(["campaign", "status", "--vault", str(v1), "--vault", str(v2)]) == 1
