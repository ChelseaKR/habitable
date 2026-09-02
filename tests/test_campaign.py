# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""EXP-08: the on-device campaign engine (multi-vault roll-up + combined packet)."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

import pytest

from habitable.artifact import capture_artifact
from habitable.campaign import (
    build_campaign_packet,
    build_campaign_report,
    health_for,
)
from habitable.capture import capture
from habitable.cli import main
from habitable.sync import LocalDirTransport, sync
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
            report = verify_packet(unit_result.out_dir, trusted_certs=[local_tsa.certificate])
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


class TestCampaignSeal:
    """ADR 0011 named `campaign export` as a surface it had left unsealed.

    `campaign.py`'s own docstring promises a unit's packet is exactly what
    `habitable export` produces from that vault. Since ADR 0011 that includes an
    authority seal over the whole bundle, so until now the promise was false in
    the one way that costs a recipient something.
    """

    def test_each_unit_packet_is_sealed_by_its_own_vaults_authority(
        self,
        make_vault: Callable[..., Vault],
        make_jpeg: Callable[..., Path],
        local_tsa: LocalRfc3161TSA,
        tmp_path: Path,
    ) -> None:
        v1 = _ready_vault(make_vault, make_jpeg, local_tsa, name="v1", unit="4B")
        v2 = _ready_vault(make_vault, make_jpeg, local_tsa, name="v2", unit="4C")
        second = LocalRfc3161TSA("other-authority")
        authorities: dict[str, LocalRfc3161TSA] = {"4B": local_tsa, "4C": second}

        result = build_campaign_packet(
            [(v1.path, v1), (v2.path, v2)],
            tmp_path / "out",
            seal_authority=lambda vault: authorities[vault.document.get_meta("unit")],
        )

        assert result.sealed_count == 2
        # Per vault, not per campaign: each unit carries the authority ITS vault
        # named, so an organizer's choice never overrides a tenant's.
        by_unit = {unit.health.unit: unit.packet.seal for unit in result.units}
        assert by_unit["4B"].authority == local_tsa.name
        assert by_unit["4C"].authority == second.name

        for unit_result in result.units:
            report = verify_packet(
                unit_result.out_dir,
                trusted_certs=[local_tsa.certificate, second.certificate],
                require_packet_seal=True,
            )
            assert report.ok
            assert report.seal.ok

    def test_without_an_authority_every_unit_packet_is_unsealed_and_says_so(
        self,
        make_vault: Callable[..., Vault],
        make_jpeg: Callable[..., Path],
        local_tsa: LocalRfc3161TSA,
        tmp_path: Path,
    ) -> None:
        """The behaviour before this change, kept as the honest default when no
        callback is supplied, and now visible rather than silent."""
        v1 = _ready_vault(make_vault, make_jpeg, local_tsa, name="v1", unit="4B")

        result = build_campaign_packet([(v1.path, v1)], tmp_path / "out")

        assert result.sealed_count == 0
        assert not result.units[0].packet.seal.sealed
        assert result.units[0].packet.seal.note

        report = verify_packet(
            result.units[0].out_dir,
            trusted_certs=[local_tsa.certificate],
            require_packet_seal=True,
        )
        assert not report.ok

    def test_one_unit_can_fail_to_seal_without_costing_the_others_theirs(
        self,
        make_vault: Callable[..., Vault],
        make_jpeg: Callable[..., Path],
        local_tsa: LocalRfc3161TSA,
        tmp_path: Path,
    ) -> None:
        """ADR 0011's degradation, per unit: an unreachable authority costs that
        packet its seal, not its existence, and not anybody else's seal."""
        v1 = _ready_vault(make_vault, make_jpeg, local_tsa, name="v1", unit="4B")
        v2 = _ready_vault(make_vault, make_jpeg, local_tsa, name="v2", unit="4C")

        def only_the_first(vault: Vault) -> LocalRfc3161TSA | None:
            return local_tsa if vault.document.get_meta("unit") == "4B" else None

        result = build_campaign_packet(
            [(v1.path, v1), (v2.path, v2)], tmp_path / "out", seal_authority=only_the_first
        )

        assert result.sealed_count == 1
        by_unit = {unit.health.unit: unit.packet.seal for unit in result.units}
        assert by_unit["4B"].sealed
        assert not by_unit["4C"].sealed
        # Both packets still exist and still verify on their own terms.
        for unit_result in result.units:
            assert verify_packet(unit_result.out_dir, trusted_certs=[local_tsa.certificate]).ok

    def test_the_seal_is_reported_to_the_operator_and_written_into_no_artifact(
        self,
        make_vault: Callable[..., Vault],
        make_jpeg: Callable[..., Path],
        local_tsa: LocalRfc3161TSA,
        tmp_path: Path,
    ) -> None:
        """A seal is a file an attacker can delete, so a manifest or index page
        that announced one would be confidently wrong the moment it was
        stripped. It belongs in the operator's terminal, and in `verify`."""
        v1 = _ready_vault(make_vault, make_jpeg, local_tsa, name="v1", unit="4B")

        result = build_campaign_packet(
            [(v1.path, v1)], tmp_path / "out", seal_authority=lambda _vault: local_tsa
        )

        assert result.sealed_count == 1
        manifest = json.loads(result.manifest_path.read_bytes())
        keys = set(manifest) | {key for unit in manifest["units"] for key in unit}
        assert not any("seal" in key for key in keys)
        assert "seal" not in result.index_path.read_text(encoding="utf-8").lower()

    def test_cli_seals_with_the_dev_authority_and_names_it(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("HABITABLE_PASSPHRASE", "pw")
        vault_dir = tmp_path / "unit-4b"
        assert main(["init", str(vault_dir), "--case", "bldg-4B", "--unit", "4B"]) == 0
        capsys.readouterr()

        assert (
            main(
                [
                    "campaign",
                    "export",
                    "--vault",
                    str(vault_dir),
                    "--out",
                    str(tmp_path / "combined"),
                    "--no-pdf",
                    "--dev-tsa",
                ]
            )
            == 0
        )
        assert "sealed by dev-tsa at " in capsys.readouterr().out

    def test_cli_no_seal_says_what_that_costs(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("HABITABLE_PASSPHRASE", "pw")
        vault_dir = tmp_path / "unit-4b"
        assert main(["init", str(vault_dir), "--case", "bldg-4B", "--unit", "4B"]) == 0
        capsys.readouterr()

        assert (
            main(
                [
                    "campaign",
                    "export",
                    "--vault",
                    str(vault_dir),
                    "--out",
                    str(tmp_path / "combined"),
                    "--no-pdf",
                    "--no-seal",
                ]
            )
            == 0
        )
        out = capsys.readouterr().out
        assert "seal declined (--no-seal)" in out
        assert "indistinguishable from this one" in out

    def test_cli_wifi_only_skips_the_seal_and_says_that_is_why(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The reason matters. `build_packet` only ever learns that no authority
        was supplied, so a message sourced from it would name the wrong cause,
        and the metered link is that tenant's, read from that tenant's vault."""
        monkeypatch.setenv("HABITABLE_PASSPHRASE", "pw")
        vault_dir = tmp_path / "unit-4b"
        assert main(["init", str(vault_dir), "--case", "bldg-4B", "--unit", "4B"]) == 0
        capsys.readouterr()

        assert (
            main(
                [
                    "campaign",
                    "export",
                    "--vault",
                    str(vault_dir),
                    "--out",
                    str(tmp_path / "combined"),
                    "--no-pdf",
                    "--wifi-only",
                ]
            )
            == 0
        )
        out = capsys.readouterr().out
        assert "wifi-only mode for this unit" in out
        assert "--allow-metered" in out


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
        # `--no-seal`, because since ADR 0011 a campaign export seals each unit
        # packet with that unit's own configured authority, and this vault's
        # default is a real public TSA. Leaving it out here would make the merge
        # gate depend on freetsa.org being up, which `conftest`'s outbound-network
        # guard exists to prevent -- and which is exactly what it caught when
        # sealing was first threaded through.
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
                    "--no-seal",
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


class TestAwaitingIsTokenPresenceNotTheLocalQueue:
    """Issue #180: `awaiting` read a local queue sync never writes to."""

    def test_a_synced_in_capture_with_no_token_is_awaiting_and_blocks_export_ready(
        self,
        make_vault: Callable[..., Vault],
        make_jpeg: Callable[..., Path],
        local_tsa: LocalRfc3161TSA,
        tmp_path: Path,
    ) -> None:
        sender = make_vault("sender", unit="4B")
        receiver = make_vault("receiver", unit="4B", passphrase="pw-b")
        issue = sender.document.add_issue(category="no_heat", title="No heat")
        capture(sender, make_jpeg("cold.jpg"), issue_id=issue, tsa=None)  # no token

        transport = LocalDirTransport(tmp_path / "mbox")
        sync(sender, receiver.identity.public(), transport, channel="room")
        assert sync(receiver, sender.identity.public(), transport, channel="room")

        # The receiver holds the capture and no token for it.
        assert len(receiver.document.captures()) == 1
        assert receiver.get_token(receiver.document.captures()[0].capture_id) is None

        health = health_for(receiver)
        assert health.capture_count == 1
        assert health.timestamped_count == 0
        assert health.awaiting_count == 1
        assert not health.export_ready

        report = build_campaign_report([(receiver.path, receiver)])
        assert report.export_ready_count == 0
        assert report.awaiting_timestamp_count == 1

    def test_untimestamped_artifacts_are_inside_the_denominator_not_only_the_count(
        self,
        make_vault: Callable[..., Vault],
        make_jpeg: Callable[..., Path],
        local_tsa: LocalRfc3161TSA,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """`timestamps: 1/1 present; 3 awaiting` counted two different populations."""
        vault = _ready_vault(make_vault, make_jpeg, local_tsa, name="mixed", unit="5C")
        issue_id = vault.document.issues()[0].issue_id
        for index in range(3):
            source = tmp_path / f"notice-{index}.txt"
            source.write_text(f"Synthetic notice {index}.", encoding="utf-8")
            capture_artifact(
                vault,
                source,
                issue_id=issue_id,
                artifact_type="utility_notice",
                title=f"Utility notice {index}",
                source_assertion="tenant-received copy",
                occurred_at="2026-01-03",
            )
        vault.save()

        health = health_for(vault)
        assert health.capture_count == 4  # one photo + three documents
        assert health.timestamped_count == 1
        assert health.awaiting_count == 3

        assert main(["status", "--vault", str(vault.path), "--passphrase", "test-passphrase"]) == 0
        out = capsys.readouterr().out
        assert "timestamps: 1/4 present; 3 awaiting" in out
        # Every awaiting item is named, not just counted.
        for artifact in vault.document.artifacts():
            assert artifact.artifact_id in out
