# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Data-cost and storage UX: footprint math, sync byte counters, and the
Wi-Fi-only / metered network gate (items R-03, R-18, R-19)."""

from __future__ import annotations

import threading
import tomllib
from collections.abc import Callable
from pathlib import Path

import pytest

from habitable.appserver import AppServer
from habitable.capture import capture
from habitable.cli import main
from habitable.config import Config, NetworkPolicy, default_config_toml
from habitable.errors import ConfigError
from habitable.sync import LocalDirTransport, sync
from habitable.tsa import DevTSA, LocalRfc3161TSA
from habitable.vault import Vault, human_bytes

# --- R-03: storage footprint ---------------------------------------------------


def test_human_bytes_units() -> None:
    assert human_bytes(0) == "0 bytes"
    assert human_bytes(512) == "512 bytes"
    assert human_bytes(1500) == "1.5 KB"
    assert human_bytes(6_100_000) == "6.1 MB"
    assert human_bytes(2_500_000_000) == "2.5 GB"


def test_footprint_empty_vault_is_metadata_only(make_vault: Callable[..., Vault]) -> None:
    vault = make_vault()
    fp = vault.storage_footprint()
    assert fp.sealed_originals_bytes == 0
    assert fp.shared_copies_bytes == 0
    assert fp.per_capture == ()
    assert fp.metadata_bytes > 0  # config, keyfile, encrypted state blobs
    assert fp.total_bytes == fp.metadata_bytes


def test_footprint_counts_sealed_and_doubling(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    dev_tsa: DevTSA,
) -> None:
    vault = make_vault()
    issue = vault.document.add_issue(category="mold", room="bath", issue_id="i1")
    capture(vault, make_jpeg("p.jpg"), issue_id=issue, tsa=dev_tsa)

    fp = vault.storage_footprint()

    sealed_files = list((vault.path / "originals").glob("*.enc"))
    assert len(sealed_files) == 1
    expected_sealed = sum(p.stat().st_size for p in sealed_files)

    assert fp.sealed_originals_bytes == expected_sealed
    # Sealed originals are kept twice by design (sealed + shared copy on export).
    assert fp.shared_copies_bytes == expected_sealed
    assert fp.metadata_bytes > 0
    assert fp.total_bytes == (
        fp.sealed_originals_bytes + fp.shared_copies_bytes + fp.metadata_bytes
    )
    assert len(fp.per_capture) == 1
    assert fp.per_capture[0].capture_id.startswith("cap-")
    assert fp.per_capture[0].sealed_bytes == expected_sealed


def test_status_cli_prints_storage_line(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    dev_tsa: DevTSA,
    capsys: pytest.CaptureFixture[str],
) -> None:
    vault = make_vault()
    issue = vault.document.add_issue(category="mold", room="bath", issue_id="i1")
    capture(vault, make_jpeg("p.jpg"), issue_id=issue, tsa=dev_tsa)

    code = main(["status", "--vault", str(vault.path), "--passphrase", "test-passphrase"])
    assert code == 0
    out = capsys.readouterr().out
    assert "storage:" in out
    assert "sealed originals" in out and "shared copies" in out


def test_appserver_status_exposes_storage_and_metered(
    make_vault: Callable[..., Vault],
) -> None:
    vault = make_vault()
    app = AppServer(vault=vault, tsa=None, static_root=vault.path, lock=threading.Lock())
    st = app.status()
    storage = st["storage"]
    assert isinstance(storage, dict)
    assert storage["total_bytes"] >= storage["sealed_originals_bytes"] >= 0
    assert st["allow_metered"] is True


# --- R-18: sync data-cost transparency -----------------------------------------


def test_sync_counts_bytes_over_localdir(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    a = make_vault("A")
    b = make_vault("B", passphrase="pw-b")
    issue = a.document.add_issue(category="mold", room="bath", issue_id="i1")
    capture(a, make_jpeg(), issue_id=issue, tsa=local_tsa)

    transport = LocalDirTransport(tmp_path / "mbox")
    res_a = sync(a, b.identity.public(), transport, channel="room")
    assert res_a.sent
    assert res_a.bytes_sent > 0  # posted a sealed message carrying the sealed original
    # A fetches the channel back (its own, unopenable message): received is counted.
    assert res_a.bytes_received >= res_a.bytes_sent

    res_b = sync(b, a.identity.public(), transport, channel="room")
    assert res_b.captures_imported == 1
    assert res_b.bytes_sent > 0
    assert res_b.bytes_received > 0


def test_sync_cli_reports_data_cost(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    a = make_vault("A")
    b = make_vault("B", passphrase="pw-b")
    issue = a.document.add_issue(category="mold", room="bath", issue_id="i1")
    capture(a, make_jpeg(), issue_id=issue, tsa=local_tsa)

    code = main(
        [
            "sync",
            "--vault",
            str(a.path),
            "--passphrase",
            "test-passphrase",
            "--peer",
            b.identity.public().encode(),
            "--channel",
            "room",
            "--dir",
            str(tmp_path / "mbox"),
        ]
    )
    assert code == 0
    out = capsys.readouterr().out
    assert "sent" in out and "received" in out


# --- R-19: config parsing and the Wi-Fi-only gate ------------------------------


def test_network_policy_default_allows_metered() -> None:
    cfg = Config.from_mapping({"node_id": "n"})
    assert cfg.network == NetworkPolicy()
    assert cfg.network.allow_metered is True


def test_network_section_parsed() -> None:
    cfg = Config.from_mapping({"node_id": "n", "network": {"allow_metered": False}})
    assert cfg.network.allow_metered is False


def test_network_section_must_be_a_table() -> None:
    with pytest.raises(ConfigError):
        Config.from_mapping({"node_id": "n", "network": "nope"})


def test_default_config_toml_round_trips_network() -> None:
    toml = default_config_toml()
    assert "[network]" in toml and "allow_metered = true" in toml
    cfg = Config.from_mapping(tomllib.loads(toml))
    assert cfg.network.allow_metered is True


def test_sync_wifi_only_refuses_relay(
    make_vault: Callable[..., Vault],
    capsys: pytest.CaptureFixture[str],
) -> None:
    vault = make_vault()
    peer = make_vault("peer", passphrase="pw-p")
    code = main(
        [
            "sync",
            "--vault",
            str(vault.path),
            "--passphrase",
            "test-passphrase",
            "--peer",
            peer.identity.public().encode(),
            "--channel",
            "room",
            "--relay",
            "https://relay.example.org",
            "--wifi-only",
        ]
    )
    assert code == 1
    assert "wifi-only" in capsys.readouterr().err


def test_resolve_wifi_only_refuses_network_tsa(
    make_vault: Callable[..., Vault],
    capsys: pytest.CaptureFixture[str],
) -> None:
    vault = make_vault()  # default config: real RFC 3161 authorities (network)
    code = main(
        ["resolve", "--vault", str(vault.path), "--passphrase", "test-passphrase", "--wifi-only"]
    )
    assert code == 1
    assert "wifi-only" in capsys.readouterr().err


def test_resolve_wifi_only_allows_offline_dev_tsa(
    make_vault: Callable[..., Vault],
    capsys: pytest.CaptureFixture[str],
) -> None:
    vault = make_vault()
    # The dev TSA never touches the network, so wifi-only does not gate it.
    code = main(
        [
            "resolve",
            "--vault",
            str(vault.path),
            "--passphrase",
            "test-passphrase",
            "--dev-tsa",
            "--wifi-only",
        ]
    )
    assert code == 0


def test_config_metered_false_is_the_standing_gate(
    make_vault: Callable[..., Vault],
    capsys: pytest.CaptureFixture[str],
) -> None:
    vault = make_vault()
    config_path = vault.path / "config.toml"
    config_path.write_text(
        config_path.read_text(encoding="utf-8").replace(
            "allow_metered = true", "allow_metered = false"
        ),
        encoding="utf-8",
    )
    code = main(["resolve", "--vault", str(vault.path), "--passphrase", "test-passphrase"])
    assert code == 1
    assert "wifi-only" in capsys.readouterr().err


def test_allow_metered_overrides_config_gate(make_vault: Callable[..., Vault]) -> None:
    vault = make_vault()
    config_path = vault.path / "config.toml"
    config_path.write_text(
        config_path.read_text(encoding="utf-8").replace(
            "allow_metered = true", "allow_metered = false"
        ),
        encoding="utf-8",
    )
    # No deferred items, so resolve does no network even with a real authority once
    # --allow-metered opens the gate: it must succeed rather than refuse.
    code = main(
        [
            "resolve",
            "--vault",
            str(vault.path),
            "--passphrase",
            "test-passphrase",
            "--allow-metered",
        ]
    )
    assert code == 0
