# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Encrypted vault lifecycle and the capture pipeline."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from habitable.capture import capture, resolve_deferred
from habitable.errors import HabitableError, TimestampError, VaultError
from habitable.tsa import DevTSA, LocalRfc3161TSA, TimestampToken
from habitable.vault import Vault


class _UnreachableTSA:
    """A redundant authority that is always offline (its ``stamp`` raises)."""

    name = "flaky-extra"
    kind = "dev"

    def stamp(self, digest_hex: str) -> TimestampToken:
        raise TimestampError("simulated: redundant authority unreachable")


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
    a = make_vault("a", case_id="case-x", passphrase="pw")
    b = make_vault("b", case_id="case-x", passphrase="pw")
    assert a.document.clock.node_id != b.document.clock.node_id
    leaked = "58b90713d0ca1ac3"  # pre-FIX-01 sha256("case-x" + "pw")[:16]
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


def test_interrupted_migration_still_strips_plaintext_node_id(
    make_vault: Callable[..., Vault], tmp_path: Path
) -> None:
    """FIX-01 crash window: the migration writes node.enc *then* strips the plaintext
    line. If it dies in between, node.enc exists, so every later open takes the fast
    path — it must still remove the leaked passphrase-derived value from config.toml
    rather than leave it in plaintext forever."""
    vault = make_vault()
    node_id = vault.document.clock.node_id

    # Simulate the interrupted state: node.enc present AND the plaintext line present.
    assert (tmp_path / "vault" / "node.enc").exists()
    config = tmp_path / "vault" / "config.toml"
    config.write_text(
        f'node_id = "{node_id}"\n' + config.read_text(encoding="utf-8"), encoding="utf-8"
    )

    reopened = Vault.open(tmp_path / "vault", "test-passphrase")
    assert reopened.document.clock.node_id == node_id  # value unchanged
    assert "node_id" not in config.read_text(encoding="utf-8")  # leak removed


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


def test_deferred_resolve_gets_redundant_authorities(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    dev_tsa: DevTSA,
) -> None:
    """An item captured offline and later resolved carries >=2 verified authorities.

    This mirrors online capture's multi-TSA redundancy (item R-16 / FIX-06): the most
    at-risk captures — taken with no signal — must not rest on a single TSA.
    """
    vault = make_vault()
    issue = vault.document.add_issue(category="mold", issue_id="i1")
    result = capture(vault, make_jpeg(), issue_id=issue, tsa=None)
    assert not result.timestamped and len(vault.deferred()) == 1

    resolved = resolve_deferred(vault, dev_tsa, extra_tsas=[DevTSA("extra-a"), DevTSA("extra-b")])
    assert len(resolved) == 1 and resolved[0].timestamped
    assert resolved[0].extra_authorities == ("extra-a", "extra-b")
    assert len(vault.deferred()) == 0

    # The primary token plus two independent additional tokens: redundancy achieved.
    assert vault.get_token(result.capture_id) is not None
    additional = vault.get_additional_tokens(result.capture_id)
    assert {t.tsa_name for t in additional} == {"extra-a", "extra-b"}
    # Each redundant stamp is recorded in the (still-intact) chain of custody.
    additional_roles = [
        e.details.get("role")
        for e in vault.custody.entries
        if e.item_id == result.capture_id and e.details.get("role") == "additional"
    ]
    assert len(additional_roles) == 2
    assert vault.custody.verify().ok


def test_deferred_resolve_skips_unreachable_extra_authority(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    dev_tsa: DevTSA,
) -> None:
    """A redundant authority that is offline is skipped; the item still resolves."""
    vault = make_vault()
    issue = vault.document.add_issue(category="mold", issue_id="i1")
    result = capture(vault, make_jpeg(), issue_id=issue, tsa=None)
    assert len(vault.deferred()) == 1

    resolved = resolve_deferred(
        vault, dev_tsa, extra_tsas=[_UnreachableTSA(), DevTSA("good-extra")]
    )
    assert len(resolved) == 1 and resolved[0].timestamped
    assert len(vault.deferred()) == 0
    # Only the reachable authority is recorded; the failing one is silently skipped.
    assert resolved[0].extra_authorities == ("good-extra",)
    assert {t.tsa_name for t in vault.get_additional_tokens(result.capture_id)} == {"good-extra"}
    assert vault.custody.verify().ok


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


def test_rotate_dek_reencrypts_blobs_and_originals(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    """FIX-08: `rotate_dek` replaces the data key and re-encrypts everything under it,
    without disturbing the data itself or its fixity."""
    vault = make_vault()
    issue = vault.document.add_issue(category="mold", issue_id="i1")
    result = capture(vault, make_jpeg(), issue_id=issue, tsa=local_tsa)
    vault.document.add_timeline_entry(issue, "observed", "wet ceiling")
    vault.save()
    original_bytes = vault.read_original(result.capture_id, result.content_hash)

    sealed_path = vault.path / "originals" / f"{result.capture_id}.enc"
    case_path = vault.path / "case.enc"
    before_sealed = sealed_path.read_bytes()
    before_case = case_path.read_bytes()

    vault.rotate_dek("test-passphrase")

    # The ciphertext on disk actually changed (new key, new nonce) ...
    assert sealed_path.read_bytes() != before_sealed
    assert case_path.read_bytes() != before_case
    # ... but every *.new staging file was cleaned up (swapped into place).
    assert not list(vault.path.glob("*.new"))
    assert not list((vault.path / "originals").glob("*.new"))

    # The in-memory vault keeps working immediately after rotation.
    assert vault.read_original(result.capture_id, result.content_hash) == original_bytes
    assert vault.custody.verify().ok

    # Reopening from disk with the *same* passphrase proves the keyfile was re-wrapped
    # around the *new* DEK (opening with the passphrase alone recovers everything).
    reopened = Vault.open(tmp_path / "vault", "test-passphrase")
    assert [i.issue_id for i in reopened.document.issues()] == ["i1"]
    assert len(reopened.document.timeline()) == 1
    assert reopened.read_original(result.capture_id, result.content_hash) == original_bytes

    # Fixity checking still guards the re-encrypted original.
    corrupted = bytearray(sealed_path.read_bytes())
    corrupted[-1] ^= 0xFF
    sealed_path.write_bytes(bytes(corrupted))
    with pytest.raises(HabitableError):
        reopened.read_original(result.capture_id, result.content_hash)


def test_harden_key_then_open_with_same_passphrase(
    make_vault: Callable[..., Vault], tmp_path: Path
) -> None:
    """FIX-08: `harden_key` changes the KDF cost but the same passphrase still opens
    the vault -- and the wrong one still doesn't."""
    vault = make_vault()
    vault.document.add_issue(category="mold", issue_id="i1")
    vault.save()

    vault.harden_key("test-passphrase", profile="hardened")
    keyfile = json.loads((tmp_path / "vault" / "keyfile.json").read_text(encoding="utf-8"))
    assert keyfile["kdf"]["n"] == 2**17

    reopened = Vault.open(tmp_path / "vault", "test-passphrase")
    assert [i.issue_id for i in reopened.document.issues()] == ["i1"]
    with pytest.raises(HabitableError):
        Vault.open(tmp_path / "vault", "WRONG")
