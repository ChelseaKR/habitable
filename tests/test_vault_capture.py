# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Encrypted vault lifecycle and the capture pipeline."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from habitable.capture import capture, resolve_deferred
from habitable.errors import HabitableError, VaultError
from habitable.tsa import DevTSA, LocalRfc3161TSA
from habitable.vault import Vault


def test_create_open_round_trip(make_vault: Callable[..., Vault], tmp_path: Path) -> None:
    vault = make_vault()
    issue = vault.document.add_issue(category="mold", issue_id="i1")
    vault.save()
    reopened = Vault.open(tmp_path / "vault", "test-passphrase")
    assert [i.issue_id for i in reopened.document.issues()] == [issue]
    assert reopened.document.get_meta("unit") == "4B"


def test_node_id_is_random_not_passphrase_derived(make_vault: Callable[..., Vault]) -> None:
    """FIX-01: two vaults with the SAME case_id and passphrase must not share a node_id
    (the old sha256(case_id+passphrase) derivation made them identical and guessable)."""
    from habitable.canonical import sha256_bytes

    a = make_vault("a", case_id="case-x", passphrase="pw")
    b = make_vault("b", case_id="case-x", passphrase="pw")
    assert a.document.clock.node_id != b.document.clock.node_id
    leaked = sha256_bytes(("case-x" + "pw").encode())[:16]
    assert a.document.clock.node_id != leaked
    assert "node_id" not in (a.path / "config.toml").read_text(encoding="utf-8")


def test_legacy_plaintext_node_id_migrates_on_open(
    make_vault: Callable[..., Vault], tmp_path: Path
) -> None:
    """A pre-FIX-01 vault kept node_id in plaintext config.toml. Opening it must migrate
    the value into the encrypted store (preserving it, so existing ids stay valid) and
    strip the plaintext line — without breaking the case."""
    vault = make_vault()
    vault.document.add_issue(category="mold", issue_id="i1")
    vault.save()
    node_id = vault.document.clock.node_id

    # Simulate a legacy on-disk layout: no encrypted node blob, node_id in plaintext.
    (tmp_path / "vault" / "node.enc").unlink()
    config = tmp_path / "vault" / "config.toml"
    config.write_text(
        f'node_id = "{node_id}"\n' + config.read_text(encoding="utf-8"), encoding="utf-8"
    )

    reopened = Vault.open(tmp_path / "vault", "test-passphrase")
    assert reopened.document.clock.node_id == node_id  # value preserved
    assert [i.issue_id for i in reopened.document.issues()] == ["i1"]
    assert (tmp_path / "vault" / "node.enc").exists()  # migrated into the encrypted store
    assert "node_id" not in config.read_text(encoding="utf-8")  # stripped from plaintext

    # A second open now uses the encrypted blob and still works.
    again = Vault.open(tmp_path / "vault", "test-passphrase")
    assert again.document.clock.node_id == node_id


def test_wrong_passphrase_rejected(make_vault: Callable[..., Vault], tmp_path: Path) -> None:
    make_vault()
    with pytest.raises(HabitableError):
        Vault.open(tmp_path / "vault", "wrong")


def test_double_create_rejected(make_vault: Callable[..., Vault], tmp_path: Path) -> None:
    make_vault()
    with pytest.raises(VaultError):
        Vault.create(tmp_path / "vault", "x", case_id="c")


def test_online_capture_is_timestamped(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
) -> None:
    vault = make_vault()
    issue = vault.document.add_issue(category="mold", issue_id="i1")
    result = capture(vault, make_jpeg(with_location=True), issue_id=issue, tsa=local_tsa)
    assert result.timestamped and result.had_location
    assert result.timestamp_info is not None
    assert vault.get_token(result.capture_id) is not None
    assert vault.custody.verify().ok


def test_offline_capture_defers_then_resolves(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    dev_tsa: DevTSA,
) -> None:
    vault = make_vault()
    issue = vault.document.add_issue(category="mold", issue_id="i1")
    result = capture(vault, make_jpeg(), issue_id=issue, tsa=None)
    assert not result.timestamped
    assert len(vault.deferred()) == 1
    resolved = resolve_deferred(vault, dev_tsa)
    assert len(resolved) == 1 and resolved[0].timestamped
    assert len(vault.deferred()) == 0
    assert vault.get_token(result.capture_id) is not None


def test_sealed_original_fixity_on_read(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
) -> None:
    vault = make_vault()
    issue = vault.document.add_issue(category="mold", issue_id="i1")
    result = capture(vault, make_jpeg(), issue_id=issue, tsa=local_tsa)
    capture_record = vault.document.captures()[0]
    raw = vault.read_original(result.capture_id, capture_record.content_hash)
    assert len(raw) > 0

    # Corrupt the encrypted sealed original on disk -> read must fail loudly.
    sealed = vault.path / "originals" / f"{result.capture_id}.enc"
    data = bytearray(sealed.read_bytes())
    data[-1] ^= 0xFF
    sealed.write_bytes(bytes(data))
    with pytest.raises(HabitableError):
        vault.read_original(result.capture_id, capture_record.content_hash)
