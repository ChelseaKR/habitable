# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Adversarial coverage for encrypted timestamp-token sidecars and migration."""

from __future__ import annotations

import hashlib
import json
import os
import signal
import stat
import subprocess
import sys
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import cast

import pytest

import habitable.vault as vault_module
from habitable.crypto import open_keyfile
from habitable.errors import HabitableError, VaultError
from habitable.tsa import TimestampToken
from habitable.vault import Vault


def _token(label: str) -> TimestampToken:
    marker = f"PRIVATE-GEN-TIME-{label}-2041-02-03T04:05:06Z"
    return TimestampToken(
        kind="dev",
        tsa_name=f"PRIVATE-TSA-{label}",
        data=json.dumps({"gen_time": marker, "label": label}).encode(),
    )


def _deep_json_with_escape_prefix() -> str:
    prefix = json.dumps({"x": '"'})[:-1] + ', "d": '
    return prefix + "[" * 256 + "null" + "]" * 256 + "}"


def _sidecar_path(vault: Vault, capture_id: str) -> Path:
    digest = hashlib.sha256(capture_id.encode()).hexdigest()
    return vault.path / "tokens" / f"{digest}.tokens.enc"


def _write_legacy_set(vault: Vault, capture_id: str) -> tuple[TimestampToken, ...]:
    primary = _token("primary")
    extra_one = _token("extra-one")
    extra_two = _token("extra-two")
    archive_one = _token("archive-one")
    archive_two = _token("archive-two")
    directory = vault.path / "tokens"
    (directory / f"{capture_id}.json").write_text(json.dumps(primary.to_dict()))
    (directory / f"{capture_id}.additional.json").write_text(
        json.dumps([extra_one.to_dict(), extra_two.to_dict()])
    )
    (directory / f"{capture_id}.archive.json").write_text(
        json.dumps([archive_one.to_dict(), archive_two.to_dict()])
    )
    return primary, extra_one, extra_two, archive_one, archive_two


def test_one_encrypted_sidecar_preserves_public_tokens_order_and_path_safety(
    make_vault: Callable[..., Vault],
) -> None:
    vault = make_vault("consolidated")
    capture_id = "../../escaped-sidecar"
    primary = _token("primary-distinctive")
    additional = [_token("additional-a"), _token("additional-b")]
    archives = [_token("archive-a"), _token("archive-b")]

    vault.store_token(capture_id, primary)
    for token in additional:
        vault.add_additional_token(capture_id, token)
    for token in archives:
        vault.add_archive_token(capture_id, token)

    sidecar = _sidecar_path(vault, capture_id)
    entries = list((vault.path / "tokens").iterdir())
    assert entries == [sidecar]
    assert sidecar.is_file()
    assert not (vault.path.parent / "escaped-sidecar.json").exists()
    assert vault.get_token(capture_id) == primary
    assert vault.get_additional_tokens(capture_id) == additional
    assert vault.get_archive_tokens(capture_id) == archives
    assert vault.latest_token(capture_id) == archives[-1]
    assert vault.get_token(capture_id).to_dict() == primary.to_dict()  # type: ignore[union-attr]

    ciphertext = sidecar.read_bytes()
    for private_text in (
        capture_id,
        primary.tsa_name,
        additional[0].tsa_name,
        "PRIVATE-GEN-TIME",
        "gen_time",
    ):
        assert private_text.encode() not in ciphertext
    if os.name == "posix":
        assert stat.S_IMODE(sidecar.stat().st_mode) == 0o600

    reopened = Vault.open(vault.path, "test-passphrase")
    assert reopened.get_token(capture_id) == primary
    assert reopened.get_additional_tokens(capture_id) == additional
    assert reopened.get_archive_tokens(capture_id) == archives

    with pytest.raises(VaultError, match="must not be empty"):
        vault.store_token("", primary)
    with pytest.raises(VaultError, match="valid UTF-8"):
        vault.store_token("\ud800", primary)


def test_legacy_migration_waits_for_unlock_then_removes_all_plaintext(
    make_vault: Callable[..., Vault],
) -> None:
    vault = make_vault("legacy")
    capture_id = "legacy-cap"
    primary, extra_one, extra_two, archive_one, archive_two = _write_legacy_set(vault, capture_id)
    legacy_paths = sorted((vault.path / "tokens").glob("*.json"))

    with pytest.raises(HabitableError):
        Vault.open(vault.path, "wrong-passphrase")
    assert all(path.exists() for path in legacy_paths)
    assert not _sidecar_path(vault, capture_id).exists()

    migrated = Vault.open(vault.path, "test-passphrase")
    assert not list((vault.path / "tokens").glob("*.json"))
    assert migrated.get_token(capture_id) == primary
    assert migrated.get_additional_tokens(capture_id) == [extra_one, extra_two]
    assert migrated.get_archive_tokens(capture_id) == [archive_one, archive_two]


@pytest.mark.parametrize(
    "capture_id",
    ["tenant.additional", "tenant.archive"],
    ids=["additional-suffix", "archive-suffix"],
)
def test_legacy_primary_capture_ids_ending_component_suffix_migrate(
    make_vault: Callable[..., Vault], capture_id: str
) -> None:
    vault = make_vault(f"legacy-{capture_id}")
    primary, extra_one, extra_two, archive_one, archive_two = _write_legacy_set(vault, capture_id)

    migrated = Vault.open(vault.path, "test-passphrase")

    assert migrated.get_token(capture_id) == primary
    assert migrated.get_additional_tokens(capture_id) == [extra_one, extra_two]
    assert migrated.get_archive_tokens(capture_id) == [archive_one, archive_two]
    assert _sidecar_path(vault, capture_id).is_file()
    assert not list((vault.path / "tokens").glob("*.json"))


@pytest.mark.parametrize(
    ("name", "payload", "message"),
    [
        ("tenant.json", [], "corrupt token record"),
        ("tenant.additional.json", "not-an-object-or-list", "invalid top-level shape"),
        ("tenant.archive.json", None, "invalid top-level shape"),
    ],
    ids=["plain-list", "additional-scalar", "archive-null"],
)
def test_legacy_filename_shape_ambiguity_fails_closed(
    make_vault: Callable[..., Vault], name: str, payload: object, message: str
) -> None:
    vault = make_vault(f"ambiguous-{name}")
    legacy = vault.path / "tokens" / name
    legacy.write_text(json.dumps(payload))

    with pytest.raises(VaultError, match=message):
        Vault.open(vault.path, "test-passphrase")

    assert legacy.exists()
    assert not list((vault.path / "tokens").glob("*.tokens.enc"))


@pytest.mark.parametrize("survivor", ["primary", "additional"])
def test_legacy_shared_suffix_filename_preserves_only_surviving_shape(
    make_vault: Callable[..., Vault], survivor: str
) -> None:
    vault = make_vault(f"legacy-shared-name-{survivor}")
    shared = vault.path / "tokens" / "tenant.additional.json"
    suffix_primary = _token("suffix-primary")
    shorter_additional = _token("shorter-additional")
    first, last = (
        (suffix_primary.to_dict(), [shorter_additional.to_dict()])
        if survivor == "additional"
        else ([shorter_additional.to_dict()], suffix_primary.to_dict())
    )
    shared.write_text(json.dumps(first))
    shared.write_text(json.dumps(last))  # the legacy format reused this exact path

    migrated = Vault.open(vault.path, "test-passphrase")

    if survivor == "additional":
        assert migrated.get_additional_tokens("tenant") == [shorter_additional]
        assert migrated.get_token("tenant.additional") is None
    else:
        assert migrated.get_token("tenant.additional") == suffix_primary
        assert migrated.get_additional_tokens("tenant") == []
    assert not shared.exists()


def test_legacy_shape_change_between_grouping_and_reread_fails_closed(
    make_vault: Callable[..., Vault], monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = make_vault("legacy-shape-race")
    capture_id = "tenant.additional"
    primary_path = vault.path / "tokens" / f"{capture_id}.json"
    primary_path.write_text(json.dumps(_token("shape-primary").to_dict()))
    real_read = vault_module._read_legacy_token_json_value
    classified = False

    def mutate_after_classification(
        directory: vault_module._TokenDirectory,
        name: str,
        *,
        parse_error: str | None = None,
    ) -> object:
        nonlocal classified
        raw = real_read(directory, name, parse_error=parse_error)
        if not classified and name == primary_path.name:
            classified = True
            primary_path.write_text(json.dumps([_token("shape-list").to_dict()]))
        return raw

    monkeypatch.setattr(vault_module, "_read_legacy_token_json_value", mutate_after_classification)
    with pytest.raises(VaultError, match="corrupt token record"):
        Vault.open(vault.path, "test-passphrase")

    assert primary_path.exists()
    assert not _sidecar_path(vault, capture_id).exists()


def test_live_limit_migration_classifies_legacy_directory_once(
    make_vault: Callable[..., Vault], monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = make_vault("legacy-linear-classification")
    expected: dict[str, TimestampToken] = {}
    for index in range(4):
        capture_id = f"cap-{index}"
        token = _token(f"linear-{index}")
        expected[capture_id] = token
        (vault.path / "tokens" / f"{capture_id}.json").write_text(json.dumps(token.to_dict()))

    monkeypatch.setattr(vault_module, "_MAX_TOKEN_DIRECTORY_ENTRIES", len(expected))
    real_groups = vault_module._legacy_token_groups
    group_calls = 0

    def count_groups(
        directory: vault_module._TokenDirectory, entries: Iterable[str]
    ) -> dict[str, dict[str, str]]:
        nonlocal group_calls
        group_calls += 1
        return real_groups(directory, entries)

    monkeypatch.setattr(vault_module, "_legacy_token_groups", count_groups)
    migrated = Vault.open(vault.path, "test-passphrase")

    assert group_calls == 1
    assert not list((vault.path / "tokens").glob("*.json"))
    assert all(migrated.get_token(capture_id) == token for capture_id, token in expected.items())


def test_migration_failure_before_publish_keeps_plaintext(
    make_vault: Callable[..., Vault], monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = make_vault("before-publish")
    capture_id = "cap-before"
    _write_legacy_set(vault, capture_id)
    legacy_paths = sorted((vault.path / "tokens").glob("*.json"))

    def fail_publish(_directory: vault_module._TokenDirectory, _name: str, _data: bytes) -> None:
        raise OSError("injected pre-publish failure")

    monkeypatch.setattr(vault_module, "_atomic_replace_private_entry", fail_publish)
    with pytest.raises(OSError, match="pre-publish"):
        Vault.open(vault.path, "test-passphrase")
    assert all(path.exists() for path in legacy_paths)
    assert not _sidecar_path(vault, capture_id).exists()


def test_partial_plaintext_cleanup_resumes_from_both_present_state(
    make_vault: Callable[..., Vault], monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = make_vault("partial-cleanup")
    capture_id = "cap-partial"
    expected = _write_legacy_set(vault, capture_id)

    def delete_one_then_fail(
        directory: vault_module._TokenDirectory,
        names: tuple[str, ...],
        _snapshots: object,
    ) -> None:
        directory.unlink(names[0])
        directory.fsync()
        raise OSError("injected crash after first plaintext unlink")

    monkeypatch.setattr(vault_module, "_remove_migrated_token_entries", delete_one_then_fail)
    with pytest.raises(OSError, match="after first plaintext unlink"):
        Vault.open(vault.path, "test-passphrase")

    sidecar = _sidecar_path(vault, capture_id)
    assert sidecar.exists()
    assert len(list((vault.path / "tokens").glob("*.json"))) == 2

    monkeypatch.undo()
    reopened = Vault.open(vault.path, "test-passphrase")
    assert reopened.get_token(capture_id) == expected[0]
    assert reopened.get_additional_tokens(capture_id) == list(expected[1:3])
    assert reopened.get_archive_tokens(capture_id) == list(expected[3:])
    assert not list((vault.path / "tokens").glob("*.json"))


def test_both_present_disagreement_fails_closed_without_deleting_plaintext(
    make_vault: Callable[..., Vault], monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = make_vault("disagree")
    capture_id = "cap-disagree"
    _write_legacy_set(vault, capture_id)

    def fail_cleanup(
        _directory: vault_module._TokenDirectory,
        _names: tuple[str, ...],
        _snapshots: object,
    ) -> None:
        raise OSError("leave both generations")

    monkeypatch.setattr(vault_module, "_remove_migrated_token_entries", fail_cleanup)
    with pytest.raises(OSError, match="both generations"):
        Vault.open(vault.path, "test-passphrase")
    monkeypatch.undo()

    primary_path = vault.path / "tokens" / f"{capture_id}.json"
    primary_path.write_text(json.dumps(_token("different").to_dict()))
    with pytest.raises(VaultError, match="disagree"):
        Vault.open(vault.path, "test-passphrase")
    assert primary_path.exists()
    assert _sidecar_path(vault, capture_id).exists()


def test_migration_reread_mismatch_keeps_legacy_plaintext(
    make_vault: Callable[..., Vault], monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = make_vault("migration-reread-mismatch")
    capture_id = "cap-migration-reread"
    _write_legacy_set(vault, capture_id)
    real_read = Vault._read_token_sidecar_entry

    def mismatching_read(
        self: Vault,
        directory: vault_module._TokenDirectory,
        name: str,
        *,
        expected_capture_id: str | None = None,
    ) -> vault_module._TokenSidecar:
        record = real_read(self, directory, name, expected_capture_id=expected_capture_id)
        return vault_module._TokenSidecar(
            record.capture_id,
            _token("injected-reread-mismatch"),
            record.additional,
            record.archive,
        )

    monkeypatch.setattr(Vault, "_read_token_sidecar_entry", mismatching_read)
    with pytest.raises(VaultError, match="migration verification"):
        Vault.open(vault.path, "test-passphrase")
    assert len(list((vault.path / "tokens").glob("*.json"))) == 3
    assert _sidecar_path(vault, capture_id).exists()


def test_atomic_sidecar_failure_preserves_previous_ciphertext(
    make_vault: Callable[..., Vault], monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = make_vault("atomic")
    capture_id = "cap-atomic"
    original_token = _token("old")
    vault.store_token(capture_id, original_token)
    sidecar = _sidecar_path(vault, capture_id)
    original_ciphertext = sidecar.read_bytes()
    real_write = vault_module._write_private_entry_and_fsync

    def fail_after_flush(directory: vault_module._TokenDirectory, name: str, data: bytes) -> None:
        real_write(directory, name, data)
        raise OSError("injected failure after ciphertext flush")

    monkeypatch.setattr(vault_module, "_write_private_entry_and_fsync", fail_after_flush)
    with pytest.raises(OSError, match="after ciphertext flush"):
        vault.store_token(capture_id, _token("new"))
    assert sidecar.read_bytes() == original_ciphertext
    assert vault.get_token(capture_id) == original_token
    assert not list((vault.path / "tokens").glob(".token-atomic-*.tmp"))


def test_private_writer_removes_partial_file_after_short_write(
    make_vault: Callable[..., Vault], monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = make_vault("short-write")
    capture_id = "cap-short-write"
    original = _token("old-short-write")
    vault.store_token(capture_id, original)
    sidecar = _sidecar_path(vault, capture_id)
    before = sidecar.read_bytes()
    real_write = os.write
    calls = 0

    def short_then_fail(descriptor: int, data: memoryview[bytes]) -> int:
        nonlocal calls
        calls += 1
        if calls == 1:
            partial = max(1, len(data) // 2)
            return int(real_write(descriptor, data[:partial]))
        raise OSError("injected short-write failure")

    monkeypatch.setattr(os, "write", short_then_fail)
    with pytest.raises(OSError, match="short-write"):
        vault.store_token(capture_id, _token("new-short-write"))
    assert sidecar.read_bytes() == before
    assert vault.get_token(capture_id) == original
    assert not list((vault.path / "tokens").glob(".token-atomic-*.tmp"))


def test_tamper_and_aad_filename_swap_are_rejected(
    make_vault: Callable[..., Vault],
) -> None:
    vault = make_vault("tamper")
    vault.store_token("cap-a", _token("a"))
    vault.store_token("cap-b", _token("b"))
    sidecar_a = _sidecar_path(vault, "cap-a")
    sidecar_b = _sidecar_path(vault, "cap-b")
    bytes_a = sidecar_a.read_bytes()
    bytes_b = sidecar_b.read_bytes()

    sidecar_a.write_bytes(bytes_b)
    sidecar_b.write_bytes(bytes_a)
    with pytest.raises(VaultError, match="corrupt encrypted"):
        vault.get_token("cap-a")
    with pytest.raises(VaultError, match="corrupt encrypted"):
        vault.get_token("cap-b")

    sidecar_a.write_bytes(bytes_a)
    damaged = bytearray(bytes_a)
    damaged[-1] ^= 0xFF
    sidecar_a.write_bytes(damaged)
    with pytest.raises(VaultError, match="corrupt encrypted"):
        vault.get_token("cap-a")


def test_sidecar_filename_and_expected_capture_bindings_fail_closed(
    make_vault: Callable[..., Vault],
) -> None:
    vault = make_vault("binding-errors")
    with pytest.raises(VaultError, match="invalid encrypted"):
        vault._read_token_sidecar_path(vault.path / "tokens" / "not-a-sidecar")
    with pytest.raises(VaultError, match="invalid encrypted"):
        vault_module._token_sidecar_aad("not-a-sidecar")

    token = _token("binding")
    path_a = _sidecar_path(vault, "cap-a")
    wrong_record = vault_module._TokenSidecar("cap-b", token)
    path_a.write_bytes(
        vault._dek.encrypt(
            vault_module._encode_token_sidecar(wrong_record),
            aad=vault_module._token_sidecar_aad(path_a.name),
        )
    )
    with pytest.raises(VaultError, match="does not match its name"):
        vault.get_token("cap-a")

    vault.store_token("cap-good", token)
    good_path = _sidecar_path(vault, "cap-good")
    with pytest.raises(VaultError, match="belongs to another"):
        vault._read_token_sidecar_path(good_path, expected_capture_id="cap-other")


def test_same_inode_same_size_change_between_stat_and_open_is_rejected(
    make_vault: Callable[..., Vault], monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = make_vault("ctime-open-race")
    capture_id = "cap-ctime-race"
    token = _token("ctime-race")
    vault.store_token(capture_id, token)
    sidecar = _sidecar_path(vault, capture_id)
    real_stat = vault_module._TokenDirectory.stat
    token_stat_calls = 0

    def mutate_after_snapshot(directory: vault_module._TokenDirectory, name: str) -> os.stat_result:
        nonlocal token_stat_calls
        before = real_stat(directory, name)
        if name == sidecar.name:
            token_stat_calls += 1
            if token_stat_calls == 2:
                ciphertext = sidecar.read_bytes()
                sidecar.write_bytes(ciphertext)
                os.utime(
                    sidecar,
                    ns=(before.st_atime_ns, before.st_mtime_ns),
                )
        return before

    monkeypatch.setattr(vault_module._TokenDirectory, "stat", mutate_after_snapshot)
    with pytest.raises(VaultError, match="changed while opening"):
        vault.get_token(capture_id)
    assert token_stat_calls == 2

    monkeypatch.undo()
    assert vault.get_token(capture_id) == token


def test_encrypted_sidecar_rejects_symlink_fifo_and_oversize(
    make_vault: Callable[..., Vault], tmp_path: Path
) -> None:
    vault = make_vault("hostile-sidecar")
    capture_id = "cap-hostile"
    vault.store_token(capture_id, _token("hostile"))
    sidecar = _sidecar_path(vault, capture_id)

    sidecar.unlink()
    target = tmp_path / "outside-ciphertext"
    target.write_bytes(b"outside")
    sidecar.symlink_to(target)
    with pytest.raises(VaultError, match="must be regular"):
        vault.get_token(capture_id)
    assert target.read_bytes() == b"outside"

    sidecar.unlink()
    if hasattr(os, "mkfifo"):
        os.mkfifo(sidecar)
        with pytest.raises(VaultError, match="must be regular"):
            vault.get_token(capture_id)
        sidecar.unlink()

    with sidecar.open("wb") as handle:
        handle.truncate(vault_module._MAX_TOKEN_SIDECAR_BYTES + 1)
    with pytest.raises(VaultError, match="too large"):
        vault.get_token(capture_id)


def test_legacy_inputs_reject_symlink_fifo_bad_base64_and_excess_count(
    make_vault: Callable[..., Vault], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = make_vault("hostile-legacy")
    directory = vault.path / "tokens"
    outside = tmp_path / "outside-legacy.json"
    outside.write_text(json.dumps(_token("outside").to_dict()))
    legacy = directory / "linked.json"
    legacy.symlink_to(outside)
    with pytest.raises(VaultError, match="must be regular"):
        Vault.open(vault.path, "test-passphrase")
    assert outside.exists()
    legacy.unlink()

    if hasattr(os, "mkfifo"):
        fifo = directory / "fifo.additional.json"
        os.mkfifo(fifo)
        with pytest.raises(VaultError, match="must be regular"):
            Vault.open(vault.path, "test-passphrase")
        fifo.unlink()

    (directory / "bad.json").write_text(
        json.dumps({"kind": "dev", "tsa_name": "bad", "token_b64": "%%%"})
    )
    with pytest.raises(VaultError, match="corrupt token record"):
        Vault.open(vault.path, "test-passphrase")
    (directory / "bad.json").unlink()

    monkeypatch.setattr(vault_module, "_MAX_TOKENS_PER_LIST", 1)
    (directory / "many.additional.json").write_text(
        json.dumps([_token("one").to_dict(), _token("two").to_dict()])
    )
    with pytest.raises(VaultError, match="too many"):
        Vault.open(vault.path, "test-passphrase")


def test_real_token_directory_required_and_entry_scan_is_bounded(
    make_vault: Callable[..., Vault], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = make_vault("directory")
    directory = vault.path / "tokens"
    directory.rmdir()
    outside = tmp_path / "outside-token-directory"
    outside.mkdir()
    directory.symlink_to(outside, target_is_directory=True)
    with pytest.raises(VaultError, match="real directory"):
        vault.get_token("cap")
    assert not list(outside.iterdir())

    directory.unlink()
    directory.mkdir()
    monkeypatch.setattr(vault_module, "_MAX_TOKEN_DIRECTORY_ENTRIES", 3)
    for index in range(4):
        (directory / f"unrelated-{index}").touch()
    with pytest.raises(VaultError, match="too many entries"):
        Vault.open(vault.path, "test-passphrase")


def test_missing_token_directory_is_a_controlled_error(
    make_vault: Callable[..., Vault],
) -> None:
    vault = make_vault("missing-token-directory")
    (vault.path / "tokens").rmdir()
    with pytest.raises(VaultError, match="unavailable"):
        vault.get_token("cap")


def test_directory_swap_race_fails_without_touching_symlink_target(
    make_vault: Callable[..., Vault], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = make_vault("directory-swap-race")
    token_directory = vault.path / "tokens"
    displaced = vault.path / "tokens-displaced"
    outside = tmp_path / "outside-swap-target"
    outside.mkdir()
    real_exists = vault_module._TokenDirectory.exists
    calls = 0

    def swap_before_write(directory: vault_module._TokenDirectory, name: str) -> bool:
        nonlocal calls
        calls += 1
        if calls == 2:
            token_directory.rename(displaced)
            token_directory.symlink_to(outside, target_is_directory=True)
        return real_exists(directory, name)

    monkeypatch.setattr(vault_module._TokenDirectory, "exists", swap_before_write)
    with pytest.raises(VaultError, match="changed during operation"):
        vault.store_token("cap-race", _token("race"))
    assert calls == 2
    assert not list(outside.iterdir())
    assert list(displaced.glob("*.tokens.enc"))


def test_unsupported_directory_fd_platform_fails_closed(
    make_vault: Callable[..., Vault], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = make_vault("unsupported-dirfd")
    monkeypatch.setattr(vault_module, "_secure_token_directory_operations_supported", lambda: False)
    with pytest.raises(VaultError, match="cannot securely anchor"):
        vault.get_token("cap")
    with pytest.raises(VaultError, match="vaults are unsupported"):
        Vault.open(vault.path, "test-passphrase")
    unsupported = tmp_path / "unsupported-new-vault"
    with pytest.raises(VaultError, match="vaults are unsupported"):
        Vault.create(unsupported, "passphrase", case_id="case")
    assert not unsupported.exists()


def test_missing_stat_nofollow_capability_rejects_create_and_open(
    make_vault: Callable[..., Vault], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = make_vault("missing-stat-nofollow")
    monkeypatch.setattr(
        os,
        "supports_follow_symlinks",
        os.supports_follow_symlinks - {os.stat},
    )
    assert not vault_module._secure_token_directory_operations_supported()

    with pytest.raises(VaultError, match="vaults are unsupported"):
        Vault.open(vault.path, "test-passphrase")
    destination = tmp_path / "unsupported-stat-nofollow"
    with pytest.raises(VaultError, match="vaults are unsupported"):
        Vault.create(destination, "passphrase", case_id="case")
    assert not destination.exists()


def test_create_rejects_destination_symlink_without_mutating_target(tmp_path: Path) -> None:
    outside = tmp_path / "outside-destination"
    outside.mkdir()
    sentinel = outside / "sentinel"
    sentinel.write_bytes(b"untouched")
    destination = tmp_path / "vault-link"
    destination.symlink_to(outside, target_is_directory=True)

    with pytest.raises(VaultError, match="real directory"):
        Vault.create(destination, "passphrase", case_id="case")

    assert destination.is_symlink()
    assert sentinel.read_bytes() == b"untouched"
    assert set(outside.iterdir()) == {sentinel}


@pytest.mark.parametrize("child", ["tokens", "originals"])
def test_create_rejects_preexisting_child_symlink_without_writing_state(
    tmp_path: Path, child: str
) -> None:
    outside = tmp_path / f"outside-{child}"
    outside.mkdir()
    sentinel = outside / "sentinel"
    sentinel.write_bytes(b"untouched")
    destination = tmp_path / f"vault-{child}-link"
    destination.mkdir()
    (destination / child).symlink_to(outside, target_is_directory=True)

    with pytest.raises(VaultError, match="must be empty"):
        Vault.create(destination, "passphrase", case_id="case")

    assert sentinel.read_bytes() == b"untouched"
    assert set(outside.iterdir()) == {sentinel}
    assert not (destination / "config.toml").exists()
    assert not (destination / "keyfile.json").exists()
    assert not list(destination.glob("*.enc"))


def test_create_rejects_nonempty_token_directory_before_state_writes(tmp_path: Path) -> None:
    destination = tmp_path / "vault-nonempty-tokens"
    tokens = destination / "tokens"
    tokens.mkdir(parents=True)
    sentinel = tokens / "legacy.json"
    sentinel.write_bytes(b"do not touch")

    with pytest.raises(VaultError, match="must be empty"):
        Vault.create(destination, "passphrase", case_id="case")

    assert sentinel.read_bytes() == b"do not touch"
    assert not (destination / "config.toml").exists()
    assert not (destination / "keyfile.json").exists()
    assert not list(destination.glob("*.enc"))


def test_create_accepts_precreated_empty_real_destination(tmp_path: Path) -> None:
    destination = tmp_path / "empty-vault-root"
    destination.mkdir()

    vault = Vault.create(destination, "passphrase", case_id="case")

    assert vault.path == destination
    assert Vault.open(destination, "passphrase").path == destination


def test_new_sidecar_capacity_is_enforced_but_existing_update_is_allowed(
    make_vault: Callable[..., Vault], monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = make_vault("sidecar-capacity")
    monkeypatch.setattr(vault_module, "_MAX_TOKEN_DIRECTORY_ENTRIES", 1)
    first = _token("first-at-cap")
    updated = _token("updated-at-cap")
    vault.store_token("cap-one", first)
    with pytest.raises(VaultError, match="live-entry limit"):
        vault.store_token("cap-two", _token("over-cap"))
    vault.store_token("cap-one", updated)
    assert vault.get_token("cap-one") == updated
    assert vault.get_token("cap-two") is None


def test_live_entry_limit_still_allows_strictly_bounded_orphan_cleanup(
    make_vault: Callable[..., Vault],
) -> None:
    vault = make_vault("full-token-directory")
    directory = vault.path / "tokens"
    token = _token("full-directory")
    for index in range(vault_module._MAX_TOKEN_DIRECTORY_ENTRIES):
        capture_id = f"cap-{index}"
        path = _sidecar_path(vault, capture_id)
        record = vault_module._TokenSidecar(capture_id, token)
        path.write_bytes(
            vault._dek.encrypt(
                vault_module._encode_token_sidecar(record),
                aad=vault_module._token_sidecar_aad(path.name),
            )
        )
    orphan = directory / f".token-atomic-{'a' * 32}.tmp"
    if not hasattr(signal, "SIGKILL"):
        pytest.skip("SIGKILL crash injection requires POSIX")
    script = (
        "import os, signal, sys; "
        "open(sys.argv[1], 'wb').write(b'partial ciphertext'); "
        "os.kill(os.getpid(), signal.SIGKILL)"
    )
    killed = subprocess.run([sys.executable, "-c", script, str(orphan)], check=False)
    assert killed.returncode == -signal.SIGKILL
    assert orphan.exists()

    reopened = Vault.open(vault.path, "test-passphrase")

    assert reopened.path == vault.path
    assert not orphan.exists()
    assert len(list(directory.iterdir())) == vault_module._MAX_TOKEN_DIRECTORY_ENTRIES
    assert reopened.get_token("cap-4095") == token


def test_full_legacy_directory_allows_one_verified_crash_overlap(
    make_vault: Callable[..., Vault], monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = make_vault("full-legacy-overlap")
    directory = vault.path / "tokens"
    capture_id = "cap-full-legacy"
    token = _token("full-legacy")
    (directory / f"{capture_id}.json").write_text(json.dumps(token.to_dict()))
    for index in range(vault_module._MAX_TOKEN_DIRECTORY_ENTRIES - 1):
        (directory / f"filler-{index}").touch()

    def crash_after_publish(
        _directory: vault_module._TokenDirectory,
        _names: tuple[str, ...],
        _snapshots: object,
    ) -> None:
        raise OSError("injected cap-overlap crash")

    monkeypatch.setattr(vault_module, "_remove_migrated_token_entries", crash_after_publish)
    with pytest.raises(OSError, match="cap-overlap crash"):
        Vault.open(vault.path, "test-passphrase")
    assert len(list(directory.iterdir())) == vault_module._MAX_TOKEN_DIRECTORY_ENTRIES + 1
    assert _sidecar_path(vault, capture_id).exists()

    monkeypatch.undo()
    reopened = Vault.open(vault.path, "test-passphrase")
    assert len(list(directory.iterdir())) == vault_module._MAX_TOKEN_DIRECTORY_ENTRIES
    assert not (directory / f"{capture_id}.json").exists()
    assert reopened.get_token(capture_id) == token


def test_temporary_entry_allowance_is_itself_bounded(
    make_vault: Callable[..., Vault], monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = make_vault("too-many-token-temps")
    directory = vault.path / "tokens"
    monkeypatch.setattr(vault_module, "_MAX_TOKEN_TEMP_ENTRIES", 1)
    for marker in ("a", "b"):
        (directory / f".token-atomic-{marker * 32}.tmp").touch()
    with pytest.raises(VaultError, match="too many temporary"):
        Vault.open(vault.path, "test-passphrase")


def test_directory_scan_stops_at_limit_without_materializing_the_rest(
    make_vault: Callable[..., Vault], monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = make_vault("streaming-directory-bound")
    directory_path = vault.path / "tokens"
    for index in range(3):
        (directory_path / f"entry-{index}").touch()
    consumed = 0

    with vault_module._open_token_directory(vault.path) as directory:
        real_scandir = os.scandir

        @contextmanager
        def limited_scandir(
            descriptor: int,
        ) -> Iterator[Iterator[os.DirEntry[str]]]:
            nonlocal consumed
            with real_scandir(descriptor) as scanned:

                def limited_entries() -> Iterator[os.DirEntry[str]]:
                    nonlocal consumed
                    for entry in scanned:
                        consumed += 1
                        if consumed > 2:
                            raise AssertionError("scanner consumed beyond fail-closed limit")
                        yield entry

                yield limited_entries()

        monkeypatch.setattr(os, "scandir", limited_scandir)
        monkeypatch.setattr(vault_module, "_MAX_TOKEN_DIRECTORY_ENTRIES", 1)
        with pytest.raises(VaultError, match="too many entries"):
            vault_module._bounded_token_directory_entries(directory)
    assert consumed == 2


def test_eager_migration_scan_happens_once_not_per_getter(
    make_vault: Callable[..., Vault], monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = make_vault("scan-once")
    for index in range(20):
        vault.store_token(f"cap-{index}", _token(f"token-{index}"))

    real_scan = vault_module._bounded_token_directory_entries
    scan_count = 0

    def counted_scan(
        directory: vault_module._TokenDirectory,
        *,
        allow_migration_overlap: bool = False,
    ) -> list[str]:
        nonlocal scan_count
        scan_count += 1
        return real_scan(directory, allow_migration_overlap=allow_migration_overlap)

    monkeypatch.setattr(vault_module, "_bounded_token_directory_entries", counted_scan)
    reopened = Vault.open(vault.path, "test-passphrase")
    assert scan_count == 1
    for _repeat in range(3):
        for index in range(20):
            assert reopened.get_token(f"cap-{index}") == _token(f"token-{index}")
            assert reopened.get_additional_tokens(f"cap-{index}") == []
            assert reopened.get_archive_tokens(f"cap-{index}") == []
    assert scan_count == 1


def test_dek_rotation_reencrypts_token_sidecars_and_preserves_all_tokens(
    make_vault: Callable[..., Vault],
) -> None:
    vault = make_vault("rotate")
    capture_id = "cap-rotate"
    primary = _token("primary")
    additional = [_token("extra-one"), _token("extra-two")]
    archive = [_token("archive-one"), _token("archive-two")]
    vault.store_token(capture_id, primary)
    for token in additional:
        vault.add_additional_token(capture_id, token)
    for token in archive:
        vault.add_archive_token(capture_id, token)
    sidecar = _sidecar_path(vault, capture_id)
    before = sidecar.read_bytes()

    vault.rotate_dek("test-passphrase")

    assert sidecar.read_bytes() != before
    assert not list((vault.path / "tokens").glob("*.new"))
    assert vault.get_token(capture_id) == primary
    assert vault.get_additional_tokens(capture_id) == additional
    assert vault.get_archive_tokens(capture_id) == archive
    reopened = Vault.open(vault.path, "test-passphrase")
    assert reopened.get_token(capture_id) == primary
    assert reopened.get_additional_tokens(capture_id) == additional
    assert reopened.get_archive_tokens(capture_id) == archive


def test_dek_rotation_fsync_failure_cleans_staging_and_is_retryable(
    make_vault: Callable[..., Vault], monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = make_vault("rotate-fsync")
    capture_id = "cap-rotate-fsync"
    token = _token("rotate-fsync")
    vault.store_token(capture_id, token)
    sidecar = _sidecar_path(vault, capture_id)
    before_sidecar = sidecar.read_bytes()
    before_keyfile = (vault.path / "keyfile.json").read_bytes()

    def fail_fsync(_descriptor: int) -> None:
        raise OSError("injected rotation fsync failure")

    monkeypatch.setattr(os, "fsync", fail_fsync)
    with pytest.raises(OSError, match="rotation fsync"):
        vault.rotate_dek("test-passphrase")
    assert sidecar.read_bytes() == before_sidecar
    assert (vault.path / "keyfile.json").read_bytes() == before_keyfile
    assert not list((vault.path / "tokens").glob("*.new"))
    assert vault.get_token(capture_id) == token

    monkeypatch.undo()
    vault.rotate_dek("test-passphrase")
    assert Vault.open(vault.path, "test-passphrase").get_token(capture_id) == token


def test_prepublication_directory_fsync_failure_prevents_all_renames(
    make_vault: Callable[..., Vault], monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = make_vault("rotate-prepublish-directory-fsync")
    capture_id = "cap-prepublish-directory-fsync"
    token = _token("prepublish-directory-fsync")
    vault.store_token(capture_id, token)
    before_case = (vault.path / "case.enc").read_bytes()
    real_path_replace = Path.replace
    real_token_replace = vault_module._TokenDirectory.replace
    path_replace_calls = 0
    token_replace_calls = 0

    def count_path_replace(source: Path, destination: Path) -> Path:
        nonlocal path_replace_calls
        path_replace_calls += 1
        return real_path_replace(source, destination)

    def count_token_replace(
        directory: vault_module._TokenDirectory, source: str, destination: str
    ) -> None:
        nonlocal token_replace_calls
        token_replace_calls += 1
        real_token_replace(directory, source, destination)

    def fail_prepublication_fsync(_path: Path) -> bool:
        raise OSError("injected prepublication directory fsync failure")

    monkeypatch.setattr(Path, "replace", count_path_replace)
    monkeypatch.setattr(vault_module._TokenDirectory, "replace", count_token_replace)
    monkeypatch.setattr(vault_module, "_fsync_directory", fail_prepublication_fsync)
    with pytest.raises(OSError, match="prepublication directory fsync"):
        vault.rotate_dek("test-passphrase")

    assert path_replace_calls == 0
    assert token_replace_calls == 0
    assert (vault.path / "case.enc").read_bytes() == before_case
    assert not list(vault.path.rglob("*.new"))
    assert vault.get_token(capture_id) == token
    monkeypatch.undo()
    vault.rotate_dek("test-passphrase")
    assert Vault.open(vault.path, "test-passphrase").get_token(capture_id) == token


def test_dek_rotation_commits_data_directories_before_keyfile(
    make_vault: Callable[..., Vault], monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = make_vault("rotate-durability-order")
    vault.store_token("cap-durability-order", _token("durability-order"))
    events: list[tuple[str, str]] = []
    real_path_fsync = vault_module._fsync_directory
    real_token_fsync = vault_module._TokenDirectory.fsync
    real_path_replace = Path.replace
    real_token_replace = vault_module._TokenDirectory.replace

    def log_path_fsync(path: Path) -> bool:
        events.append(("fsync-path", str(path)))
        return real_path_fsync(path)

    def log_token_fsync(directory: vault_module._TokenDirectory) -> bool:
        events.append(("fsync-token", "tokens"))
        return real_token_fsync(directory)

    def log_path_replace(source: Path, destination: Path) -> Path:
        events.append(("replace-path", source.name))
        return real_path_replace(source, destination)

    def log_token_replace(
        directory: vault_module._TokenDirectory, source: str, destination: str
    ) -> None:
        events.append(("replace-token", source))
        real_token_replace(directory, source, destination)

    monkeypatch.setattr(vault_module, "_fsync_directory", log_path_fsync)
    monkeypatch.setattr(vault_module._TokenDirectory, "fsync", log_token_fsync)
    monkeypatch.setattr(Path, "replace", log_path_replace)
    monkeypatch.setattr(vault_module._TokenDirectory, "replace", log_token_replace)

    vault.rotate_dek("test-passphrase")

    replace_indexes = [
        index for index, (operation, _name) in enumerate(events) if operation.startswith("replace")
    ]
    keyfile_index = events.index(("replace-path", "keyfile.json.new"))
    assert keyfile_index == max(replace_indexes)
    first_replace = min(replace_indexes)
    assert ("fsync-path", str(vault.path)) in events[:first_replace]
    assert ("fsync-token", "tokens") in events[:first_replace]
    last_data_replace = max(index for index in replace_indexes if index != keyfile_index)
    between_data_and_key = events[last_data_replace + 1 : keyfile_index]
    assert ("fsync-path", str(vault.path)) in between_data_and_key
    assert ("fsync-token", "tokens") in between_data_and_key
    assert ("fsync-path", str(vault.path)) in events[keyfile_index + 1 :]


def test_root_stage_post_return_failure_is_cleaned_and_retryable(
    make_vault: Callable[..., Vault], monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = make_vault("rotate-root-stage-return")
    before_case = (vault.path / "case.enc").read_bytes()
    real_write = vault_module._write_private_path_stage_and_fsync
    real_fsync_directory = vault_module._fsync_directory
    real_token_fsync = vault_module._TokenDirectory.fsync
    fsynced_paths: list[Path] = []
    token_fsyncs = 0
    injected = False

    def create_then_fail(stage: vault_module._PathRotationStage, data: bytes) -> None:
        nonlocal injected
        real_write(stage, data)
        if not injected and stage.destination.name == "case.enc.new":
            injected = True
            raise OSError("injected root post-return failure")

    def record_directory_fsync(path: Path) -> bool:
        fsynced_paths.append(path)
        return real_fsync_directory(path)

    def record_token_fsync(directory: vault_module._TokenDirectory) -> bool:
        nonlocal token_fsyncs
        token_fsyncs += 1
        return real_token_fsync(directory)

    monkeypatch.setattr(vault_module, "_write_private_path_stage_and_fsync", create_then_fail)
    monkeypatch.setattr(vault_module, "_fsync_directory", record_directory_fsync)
    monkeypatch.setattr(vault_module._TokenDirectory, "fsync", record_token_fsync)
    with pytest.raises(OSError, match="root post-return"):
        vault.rotate_dek("test-passphrase")

    assert injected
    assert (vault.path / "case.enc").read_bytes() == before_case
    assert not list(vault.path.rglob("*.new"))
    assert vault.path in fsynced_paths
    assert token_fsyncs == 1
    monkeypatch.undo()
    vault.rotate_dek("test-passphrase")
    assert Vault.open(vault.path, "test-passphrase").path == vault.path


def test_token_stage_post_return_failure_is_cleaned_and_retryable(
    make_vault: Callable[..., Vault], monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = make_vault("rotate-token-stage-return")
    capture_id = "cap-token-stage-return"
    token = _token("token-stage-return")
    vault.store_token(capture_id, token)
    real_write = vault_module._write_private_token_stage_and_fsync
    injected = False

    def create_then_fail(
        directory: vault_module._TokenDirectory,
        stage: vault_module._TokenRotationStage,
        data: bytes,
    ) -> None:
        nonlocal injected
        real_write(directory, stage, data)
        if not injected and stage.destination_name.endswith(".tokens.enc.new"):
            injected = True
            raise OSError("injected token post-return failure")

    monkeypatch.setattr(vault_module, "_write_private_token_stage_and_fsync", create_then_fail)
    with pytest.raises(OSError, match="token post-return"):
        vault.rotate_dek("test-passphrase")

    assert injected
    assert not list(vault.path.rglob("*.new"))
    assert vault.get_token(capture_id) == token
    monkeypatch.undo()
    vault.rotate_dek("test-passphrase")
    assert Vault.open(vault.path, "test-passphrase").get_token(capture_id) == token


def test_keyfile_stage_post_return_failure_is_cleaned_and_retryable(
    make_vault: Callable[..., Vault], monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = make_vault("rotate-keyfile-stage-return")
    vault.store_token("cap-keyfile-stage", _token("keyfile-stage"))
    before_keyfile = (vault.path / "keyfile.json").read_bytes()
    real_write = vault_module._write_private_path_stage_and_fsync
    injected = False

    def create_then_fail(stage: vault_module._PathRotationStage, data: bytes) -> None:
        nonlocal injected
        real_write(stage, data)
        if not injected and stage.destination.name == "keyfile.json.new":
            injected = True
            raise OSError("injected keyfile post-return failure")

    monkeypatch.setattr(vault_module, "_write_private_path_stage_and_fsync", create_then_fail)
    with pytest.raises(OSError, match="keyfile post-return"):
        vault.rotate_dek("test-passphrase")

    assert injected
    assert (vault.path / "keyfile.json").read_bytes() == before_keyfile
    assert not list(vault.path.rglob("*.new"))
    monkeypatch.undo()
    vault.rotate_dek("test-passphrase")
    assert Vault.open(vault.path, "test-passphrase").path == vault.path


@pytest.mark.parametrize("stage_name", ["case.enc.new", "keyfile.json.new"])
def test_path_stage_symlink_race_preserves_link_and_outside_target(
    make_vault: Callable[..., Vault],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stage_name: str,
) -> None:
    vault = make_vault(f"rotate-symlink-{stage_name}")
    outside = tmp_path / f"outside-{stage_name}"
    outside.write_bytes(b"outside-untouched")
    real_write = vault_module._write_private_path_stage_and_fsync
    raced: Path | None = None

    def insert_symlink(stage: vault_module._PathRotationStage, data: bytes) -> None:
        nonlocal raced
        if raced is None and stage.destination.name == stage_name:
            raced = stage.destination
            raced.symlink_to(outside)
        real_write(stage, data)

    monkeypatch.setattr(vault_module, "_write_private_path_stage_and_fsync", insert_symlink)
    with pytest.raises(OSError):
        vault.rotate_dek("test-passphrase")

    assert raced is not None and raced.is_symlink()
    assert outside.read_bytes() == b"outside-untouched"
    raced.unlink()
    monkeypatch.undo()
    vault.rotate_dek("test-passphrase")
    assert Vault.open(vault.path, "test-passphrase").path == vault.path


def test_token_stage_symlink_race_preserves_link_and_outside_target(
    make_vault: Callable[..., Vault], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = make_vault("rotate-token-symlink-race")
    capture_id = "cap-token-symlink-race"
    token = _token("token-symlink-race")
    vault.store_token(capture_id, token)
    outside = tmp_path / "outside-token-stage"
    outside.write_bytes(b"outside-untouched")
    real_write = vault_module._write_private_token_stage_and_fsync
    raced: Path | None = None

    def insert_symlink(
        directory: vault_module._TokenDirectory,
        stage: vault_module._TokenRotationStage,
        data: bytes,
    ) -> None:
        nonlocal raced
        if raced is None:
            raced = vault.path / "tokens" / stage.destination_name
            raced.symlink_to(outside)
        real_write(directory, stage, data)

    monkeypatch.setattr(vault_module, "_write_private_token_stage_and_fsync", insert_symlink)
    with pytest.raises(OSError):
        vault.rotate_dek("test-passphrase")

    assert raced is not None and raced.is_symlink()
    assert outside.read_bytes() == b"outside-untouched"
    assert vault.get_token(capture_id) == token
    raced.unlink()
    monkeypatch.undo()
    vault.rotate_dek("test-passphrase")
    assert Vault.open(vault.path, "test-passphrase").get_token(capture_id) == token


def test_raced_in_regular_path_stage_is_not_owned_or_removed(
    make_vault: Callable[..., Vault], monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = make_vault("rotate-root-regular-race")
    real_write = vault_module._write_private_path_stage_and_fsync
    raced: Path | None = None

    def insert_regular(stage: vault_module._PathRotationStage, data: bytes) -> None:
        nonlocal raced
        if raced is None and stage.destination.name == "case.enc.new":
            raced = stage.destination
            raced.write_bytes(b"raced-regular")
        real_write(stage, data)

    monkeypatch.setattr(vault_module, "_write_private_path_stage_and_fsync", insert_regular)
    with pytest.raises(OSError):
        vault.rotate_dek("test-passphrase")

    assert raced is not None and raced.read_bytes() == b"raced-regular"
    raced.unlink()
    monkeypatch.undo()
    vault.rotate_dek("test-passphrase")
    assert Vault.open(vault.path, "test-passphrase").path == vault.path


def test_raced_in_regular_token_stage_is_not_owned_or_removed(
    make_vault: Callable[..., Vault], monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = make_vault("rotate-token-regular-race")
    vault.store_token("cap-token-regular-race", _token("token-regular-race"))
    real_write = vault_module._write_private_token_stage_and_fsync
    raced: Path | None = None

    def insert_regular(
        directory: vault_module._TokenDirectory,
        stage: vault_module._TokenRotationStage,
        data: bytes,
    ) -> None:
        nonlocal raced
        if raced is None:
            raced = vault.path / "tokens" / stage.destination_name
            raced.write_bytes(b"raced-regular")
        real_write(directory, stage, data)

    monkeypatch.setattr(vault_module, "_write_private_token_stage_and_fsync", insert_regular)
    with pytest.raises(OSError):
        vault.rotate_dek("test-passphrase")

    assert raced is not None and raced.read_bytes() == b"raced-regular"
    raced.unlink()
    monkeypatch.undo()
    vault.rotate_dek("test-passphrase")
    assert Vault.open(vault.path, "test-passphrase").path == vault.path


def test_replaced_path_stage_is_not_published_or_removed(
    make_vault: Callable[..., Vault], monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = make_vault("rotate-root-replaced-stage")
    before_case = (vault.path / "case.enc").read_bytes()
    real_write = vault_module._write_private_path_stage_and_fsync
    replaced: Path | None = None

    def replace_after_write(stage: vault_module._PathRotationStage, data: bytes) -> None:
        nonlocal replaced
        real_write(stage, data)
        if replaced is None and stage.destination.name == "case.enc.new":
            replaced = stage.destination
            replaced.unlink()
            replaced.write_bytes(b"replacement-generation")

    monkeypatch.setattr(vault_module, "_write_private_path_stage_and_fsync", replace_after_write)
    with pytest.raises(VaultError, match="staging file changed"):
        vault.rotate_dek("test-passphrase")

    assert (vault.path / "case.enc").read_bytes() == before_case
    assert replaced is not None and replaced.read_bytes() == b"replacement-generation"
    replaced.unlink()
    monkeypatch.undo()
    vault.rotate_dek("test-passphrase")
    assert Vault.open(vault.path, "test-passphrase").path == vault.path


def test_replaced_token_stage_is_not_published_or_removed(
    make_vault: Callable[..., Vault], monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = make_vault("rotate-token-replaced-stage")
    capture_id = "cap-token-replaced-stage"
    token = _token("token-replaced-stage")
    vault.store_token(capture_id, token)
    sidecar = _sidecar_path(vault, capture_id)
    before = sidecar.read_bytes()
    real_write = vault_module._write_private_token_stage_and_fsync
    replaced: Path | None = None

    def replace_after_write(
        directory: vault_module._TokenDirectory,
        stage: vault_module._TokenRotationStage,
        data: bytes,
    ) -> None:
        nonlocal replaced
        real_write(directory, stage, data)
        if replaced is None:
            replaced = vault.path / "tokens" / stage.destination_name
            replaced.unlink()
            replaced.write_bytes(b"replacement-generation")

    monkeypatch.setattr(vault_module, "_write_private_token_stage_and_fsync", replace_after_write)
    with pytest.raises(VaultError, match="staging file changed"):
        vault.rotate_dek("test-passphrase")

    assert sidecar.read_bytes() == before
    assert replaced is not None and replaced.read_bytes() == b"replacement-generation"
    replaced.unlink()
    monkeypatch.undo()
    vault.rotate_dek("test-passphrase")
    assert Vault.open(vault.path, "test-passphrase").get_token(capture_id) == token


def test_path_stage_fstat_failure_closes_fd_and_cleans_exact_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "stage.new"
    stage = vault_module._PathRotationStage(tmp_path / "final", destination)
    real_open = os.open
    real_fstat = os.fstat
    opened_descriptor = -1
    failed = False

    def capture_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o600,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal opened_descriptor
        if dir_fd is None:
            opened_descriptor = real_open(path, flags, mode)
        else:
            opened_descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        return opened_descriptor

    def fail_first_fstat(descriptor: int) -> os.stat_result:
        nonlocal failed
        if descriptor == opened_descriptor and not failed:
            failed = True
            raise OSError("injected first fstat failure")
        return real_fstat(descriptor)

    monkeypatch.setattr(os, "open", capture_open)
    monkeypatch.setattr(os, "fstat", fail_first_fstat)
    with pytest.raises(OSError, match="first fstat"):
        vault_module._write_private_path_stage_and_fsync(stage, b"ciphertext")

    assert failed
    assert not destination.exists()
    with pytest.raises(OSError):
        real_fstat(opened_descriptor)


def test_uncreated_and_missing_rotation_stages_fail_closed(tmp_path: Path) -> None:
    missing_path = tmp_path / "missing-path.new"
    path_stage = vault_module._PathRotationStage(tmp_path / "path", missing_path)
    with pytest.raises(VaultError, match="not safely created"):
        vault_module._assert_path_rotation_stage_owned(path_stage)

    missing_path.write_bytes(b"staged")
    path_stage.generation = missing_path.lstat()
    missing_path.unlink()
    with pytest.raises(VaultError, match="staging file changed"):
        vault_module._assert_path_rotation_stage_owned(path_stage)

    root = tmp_path / "missing-token-stage"
    (root / "tokens").mkdir(parents=True)
    with vault_module._open_token_directory(root) as directory:
        token_stage = vault_module._TokenRotationStage("token.enc", "token.enc.new")
        with pytest.raises(VaultError, match="not safely created"):
            vault_module._assert_token_rotation_stage_owned(directory, token_stage)

        token_path = root / "tokens" / token_stage.destination_name
        token_path.write_bytes(b"staged")
        token_stage.generation = directory.stat(token_stage.destination_name)
        token_path.unlink()
        with pytest.raises(VaultError, match="staging file changed"):
            vault_module._assert_token_rotation_stage_owned(directory, token_stage)
        vault_module._unlink_token_rotation_stage(directory, token_stage)


def test_keyfile_recovery_proofs_handle_missing_and_live_paths(tmp_path: Path) -> None:
    expected = b"expected wrapped key"
    live = tmp_path / "keyfile.json"
    live.write_bytes(expected)
    generation = live.lstat()

    published_stage = vault_module._PathRotationStage(
        live, tmp_path / "missing-repair.tmp", generation
    )
    published_stage.publish_descriptor = os.open(live, os.O_RDONLY)
    published_descriptor = published_stage.publish_descriptor
    assert vault_module._verified_keyfile_recovery_path(published_stage, expected) == live
    vault_module._close_path_rotation_publish_descriptor(published_stage)
    assert published_stage.publish_descriptor == -1
    with pytest.raises(OSError):
        os.fstat(published_descriptor)

    missing_final_stage = vault_module._PathRotationStage(
        tmp_path / "missing-final", live, generation, os.open(live, os.O_RDONLY)
    )
    try:
        assert not vault_module._published_keyfile_matches_open_stage(missing_final_stage, expected)
    finally:
        vault_module._close_path_rotation_publish_descriptor(
            missing_final_stage, suppress_errors=True
        )

    size_mismatch_stage = vault_module._PathRotationStage(live, live, generation)
    assert not vault_module._path_rotation_stage_has_expected_bytes(
        size_mismatch_stage, expected + b"!"
    )


def test_keyfile_pin_mismatch_closes_fd_and_missing_repair_bytes_are_noted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "keyfile.json.new"
    destination.write_bytes(b"expected")
    decoy = tmp_path / "decoy"
    decoy.write_bytes(b"expected")
    stage = vault_module._PathRotationStage(
        tmp_path / "keyfile.json", destination, destination.lstat()
    )
    real_open = os.open
    real_fstat = os.fstat
    opened_descriptor = -1

    def capture_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o600,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal opened_descriptor
        if dir_fd is None:
            opened_descriptor = real_open(path, flags, mode)
        else:
            opened_descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        return opened_descriptor

    def return_mismatched_generation(descriptor: int) -> os.stat_result:
        if descriptor == opened_descriptor:
            return decoy.lstat()
        return real_fstat(descriptor)

    monkeypatch.setattr(os, "open", capture_open)
    monkeypatch.setattr(os, "fstat", return_mismatched_generation)
    with pytest.raises(VaultError, match="staging file changed"):
        vault_module._open_path_rotation_stage_readonly(stage)

    assert stage.publish_descriptor == -1
    with pytest.raises(OSError):
        real_fstat(opened_descriptor)

    primary_error = VaultError("primary rotation failure")
    vault_module._repair_committed_keyfile_if_needed(stage, None, primary_error)
    assert "DEK-rotation keyfile bytes were unavailable for repair" in primary_error.__notes__


def test_stale_rotation_sidecar_stage_fails_closed_until_manual_recovery(
    make_vault: Callable[..., Vault],
) -> None:
    vault = make_vault("rotate-stale-stage")
    capture_id = "cap-stale-stage"
    token = _token("stale-stage")
    vault.store_token(capture_id, token)
    stale = _sidecar_path(vault, capture_id).with_name(
        _sidecar_path(vault, capture_id).name + ".new"
    )
    stale.write_bytes(b"encrypted crash debris")
    before_keyfile = (vault.path / "keyfile.json").read_bytes()

    with pytest.raises(VaultError, match="manual recovery"):
        vault.rotate_dek("test-passphrase")
    assert stale.exists()
    assert (vault.path / "keyfile.json").read_bytes() == before_keyfile
    assert vault.get_token(capture_id) == token

    stale.unlink()
    vault.rotate_dek("test-passphrase")
    assert Vault.open(vault.path, "test-passphrase").get_token(capture_id) == token


@pytest.mark.parametrize(
    "artifact_name",
    [
        ".keyfile-forward-repair-" + "a" * 32 + ".tmp",
        "keyfile.json.recovery-" + "b" * 32 + ".new",
    ],
)
def test_retained_keyfile_recovery_artifact_blocks_rotation_retry(
    make_vault: Callable[..., Vault], artifact_name: str
) -> None:
    vault = make_vault("rotate-stale-keyfile-recovery")
    artifact = vault.path / artifact_name
    artifact.write_bytes(b"manual recovery state")

    with pytest.raises(VaultError, match="manual recovery") as raised:
        vault.rotate_dek("test-passphrase")

    assert artifact.name in str(raised.value)
    assert artifact.read_bytes() == b"manual recovery state"


@pytest.mark.parametrize(
    "artifact_name",
    [
        ".keyfile-forward-repair-" + "c" * 32 + ".tmp",
        "keyfile.json.recovery-" + "d" * 32 + ".new",
    ],
)
@pytest.mark.parametrize("entry_kind", ["symlink", "fifo"])
def test_nonregular_keyfile_recovery_artifact_blocks_without_following(
    make_vault: Callable[..., Vault],
    tmp_path: Path,
    artifact_name: str,
    entry_kind: str,
) -> None:
    if entry_kind == "fifo" and not hasattr(os, "mkfifo"):
        pytest.skip("FIFO coverage requires POSIX mkfifo")
    vault = make_vault(f"rotate-stale-keyfile-{entry_kind}")
    artifact = vault.path / artifact_name
    outside = tmp_path / f"outside-{entry_kind}"
    outside.write_bytes(b"outside untouched")
    if entry_kind == "symlink":
        artifact.symlink_to(outside)
    else:
        os.mkfifo(artifact, 0o600)

    with pytest.raises(VaultError, match="manual recovery"):
        vault.rotate_dek("test-passphrase")

    if entry_kind == "symlink":
        assert artifact.is_symlink()
    else:
        assert stat.S_ISFIFO(artifact.lstat().st_mode)
    assert outside.read_bytes() == b"outside untouched"


def test_keyfile_recovery_artifact_scan_is_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = tmp_path / "bounded-root-scan"
    directory.mkdir()
    for index in range(vault_module._MAX_ROOT_ROTATION_SCAN_ENTRIES + 1):
        (directory / f"unrelated-{index}").touch()
    artifact_name = ".keyfile-forward-repair-" + "e" * 32 + ".tmp"
    (directory / artifact_name).touch()
    real_scandir = os.scandir
    consumed = 0

    @contextmanager
    def artifact_last_scandir(path: Path) -> Iterator[Iterator[os.DirEntry[str]]]:
        with real_scandir(path) as scanned:
            entries = sorted(scanned, key=lambda entry: entry.name == artifact_name)

            def bounded_entries() -> Iterator[os.DirEntry[str]]:
                nonlocal consumed
                for entry in entries:
                    consumed += 1
                    if consumed > vault_module._MAX_ROOT_ROTATION_SCAN_ENTRIES + 1:
                        raise AssertionError("root scanner consumed beyond fail-closed limit")
                    yield entry

            yield bounded_entries()

    monkeypatch.setattr(os, "scandir", artifact_last_scandir)
    with pytest.raises(VaultError, match="too many entries"):
        vault_module._first_keyfile_rotation_recovery_artifact(directory)
    assert consumed == vault_module._MAX_ROOT_ROTATION_SCAN_ENTRIES + 1


def test_keyfile_recovery_artifact_near_misses_do_not_block_rotation(
    make_vault: Callable[..., Vault],
) -> None:
    vault = make_vault("rotate-keyfile-recovery-near-misses")
    near_misses = [
        ".keyfile-forward-repair-" + "a" * 31 + ".tmp",
        ".keyfile-forward-repair-" + "a" * 32 + ".tmp.extra",
        "keyfile.json.recovery-" + "B" * 32 + ".new",
        "xkeyfile.json.recovery-" + "b" * 32 + ".new",
    ]
    for name in near_misses:
        (vault.path / name).write_bytes(b"unrelated")

    vault.rotate_dek("test-passphrase")

    assert all((vault.path / name).read_bytes() == b"unrelated" for name in near_misses)


def test_async_exception_after_first_rename_preserves_new_key_generation(
    make_vault: Callable[..., Vault], monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = make_vault("rotate-root-publish-failure")
    vault.store_token("cap-root-failure", _token("root-failure"))
    real_replace = Path.replace
    replace_calls = 0

    def interrupt_after_first_root_replace(source: Path, destination: Path) -> Path:
        nonlocal replace_calls
        replace_calls += 1
        published = real_replace(source, destination)
        if replace_calls == 1:
            raise KeyboardInterrupt("injected post-rename asynchronous exception")
        return published

    monkeypatch.setattr(Path, "replace", interrupt_after_first_root_replace)
    with pytest.raises(KeyboardInterrupt, match="post-rename asynchronous"):
        vault.rotate_dek("test-passphrase")

    wrapped_new_key = vault.path / "keyfile.json.new"
    assert replace_calls == 1
    assert wrapped_new_key.exists()
    assert list(vault.path.glob("*.enc.new"))
    assert list((vault.path / "tokens").glob("*.new"))
    new_dek = open_keyfile(wrapped_new_key.read_text(), "test-passphrase")
    assert new_dek.decrypt((vault.path / "case.enc").read_bytes(), aad=b"case.enc")


def test_async_exception_after_keyfile_rename_updates_in_memory_dek(
    make_vault: Callable[..., Vault], monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = make_vault("rotate-keyfile-post-rename")
    capture_id = "cap-keyfile-post-rename"
    token = _token("keyfile-post-rename")
    vault.store_token(capture_id, token)
    before_keyfile = (vault.path / "keyfile.json").read_bytes()
    real_replace = Path.replace
    injected = False

    def interrupt_after_keyfile_replace(source: Path, destination: Path) -> Path:
        nonlocal injected
        published = real_replace(source, destination)
        if not injected and source.name == "keyfile.json.new":
            injected = True
            raise KeyboardInterrupt("injected keyfile post-rename exception")
        return published

    monkeypatch.setattr(Path, "replace", interrupt_after_keyfile_replace)
    with pytest.raises(KeyboardInterrupt, match="keyfile post-rename"):
        vault.rotate_dek("test-passphrase")

    assert injected
    assert (vault.path / "keyfile.json").read_bytes() != before_keyfile
    assert not list(vault.path.rglob("*.new"))
    assert vault.get_token(capture_id) == token
    assert Vault.open(vault.path, "test-passphrase").get_token(capture_id) == token


def test_async_exception_after_keyfile_pin_keeps_recovery_and_closes_fd(
    make_vault: Callable[..., Vault], monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = make_vault("rotate-keyfile-post-pin")
    capture_id = "cap-keyfile-post-pin"
    token = _token("keyfile-post-pin")
    vault.store_token(capture_id, token)
    old_dek = vault._dek
    real_pin = vault_module._open_path_rotation_stage_readonly
    pinned_descriptor = -1

    def pin_then_interrupt(stage: vault_module._PathRotationStage) -> None:
        nonlocal pinned_descriptor
        real_pin(stage)
        pinned_descriptor = stage.publish_descriptor
        raise KeyboardInterrupt("injected keyfile post-pin exception")

    monkeypatch.setattr(vault_module, "_open_path_rotation_stage_readonly", pin_then_interrupt)
    with pytest.raises(KeyboardInterrupt, match="keyfile post-pin"):
        vault.rotate_dek("test-passphrase")

    assert vault._dek is old_dek
    assert not list(vault.path.rglob("*.new"))
    assert vault.get_token(capture_id) == token
    assert Vault.open(vault.path, "test-passphrase").get_token(capture_id) == token
    with pytest.raises(OSError):
        os.fstat(pinned_descriptor)


@pytest.mark.parametrize("cleanup_failure", ["discard", "directory-fsync"])
def test_prepublication_cleanup_failure_preserves_primary_rotation_error(
    make_vault: Callable[..., Vault],
    monkeypatch: pytest.MonkeyPatch,
    cleanup_failure: str,
) -> None:
    vault = make_vault(f"rotate-prepublish-cleanup-{cleanup_failure}")
    old_dek = vault._dek
    real_unlink = vault_module._unlink_path_rotation_stage
    real_fsync_directory = vault_module._fsync_directory
    primary_failed = False

    def fail_keyfile_pin(_stage: vault_module._PathRotationStage) -> None:
        nonlocal primary_failed
        primary_failed = True
        raise KeyboardInterrupt("injected primary keyfile pin failure")

    def fail_cleanup_discard(stage: vault_module._PathRotationStage) -> None:
        if primary_failed and cleanup_failure == "discard":
            raise OSError("injected secondary stage cleanup failure")
        real_unlink(stage)

    def fail_cleanup_directory_fsync(path: Path) -> bool:
        if primary_failed and cleanup_failure == "directory-fsync":
            raise OSError("injected secondary cleanup directory fsync failure")
        return real_fsync_directory(path)

    monkeypatch.setattr(vault_module, "_open_path_rotation_stage_readonly", fail_keyfile_pin)
    monkeypatch.setattr(vault_module, "_unlink_path_rotation_stage", fail_cleanup_discard)
    monkeypatch.setattr(vault_module, "_fsync_directory", fail_cleanup_directory_fsync)
    with pytest.raises(KeyboardInterrupt, match="primary keyfile pin") as raised:
        vault.rotate_dek("test-passphrase")

    assert primary_failed
    assert any("cleanup" in note for note in raised.value.__notes__)
    assert vault._dek is old_dek


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO race requires POSIX mkfifo")
def test_keyfile_publish_fifo_race_is_nonblocking_and_preserved(
    make_vault: Callable[..., Vault], monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = make_vault("rotate-keyfile-fifo-race")
    capture_id = "cap-keyfile-fifo-race"
    token = _token("keyfile-fifo-race")
    vault.store_token(capture_id, token)
    before_keyfile = (vault.path / "keyfile.json").read_bytes()
    stage_path = vault.path / "keyfile.json.new"
    real_open = os.open
    raced = False

    def replace_with_fifo_before_read(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o600,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal raced
        if (
            not raced
            and isinstance(path, (str, os.PathLike))
            and os.fspath(path) == os.fspath(stage_path)
            and (flags & os.O_ACCMODE) == os.O_RDONLY
        ):
            stage_path.unlink()
            os.mkfifo(stage_path, 0o600)
            raced = True
        if dir_fd is None:
            return real_open(path, flags, mode)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", replace_with_fifo_before_read)
    monkeypatch.setattr(vault_module, "_secure_token_directory_operations_supported", lambda: True)
    with pytest.raises(VaultError, match="staging file changed"):
        vault.rotate_dek("test-passphrase")

    assert raced
    assert stat.S_ISFIFO(stage_path.lstat().st_mode)
    assert (vault.path / "keyfile.json").read_bytes() == before_keyfile
    assert vault.get_token(capture_id) == token
    assert Vault.open(vault.path, "test-passphrase").get_token(capture_id) == token


def test_keyfile_source_swap_preserves_valid_recovery_stage(
    make_vault: Callable[..., Vault], monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = make_vault("rotate-keyfile-source-swap")
    capture_id = "cap-keyfile-source-swap"
    token = _token("keyfile-source-swap")
    vault.store_token(capture_id, token)
    old_dek = vault._dek
    real_replace = Path.replace
    swapped = False

    def swap_source_before_replace(source: Path, destination: Path) -> Path:
        nonlocal swapped
        if not swapped and source.name == "keyfile.json.new":
            source.unlink()
            source.write_bytes(b"raced keyfile source")
            swapped = True
            published = real_replace(source, destination)
            source.write_bytes(b"alien fixed-name stage")
            return published
        return real_replace(source, destination)

    monkeypatch.setattr(Path, "replace", swap_source_before_replace)
    with pytest.raises(VaultError, match="published DEK-rotation keyfile changed"):
        vault.rotate_dek("test-passphrase")

    assert swapped
    assert (vault.path / "keyfile.json.new").read_bytes() == b"alien fixed-name stage"
    assert vault._dek is not old_dek
    assert vault.get_token(capture_id) == token
    assert Vault.open(vault.path, "test-passphrase").get_token(capture_id) == token


def test_same_inode_keyfile_corruption_preserves_valid_recovery_stage(
    make_vault: Callable[..., Vault], monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = make_vault("rotate-keyfile-same-inode-corruption")
    capture_id = "cap-keyfile-corrupt"
    token = _token("keyfile-corrupt")
    vault.store_token(capture_id, token)
    old_dek = vault._dek
    real_replace = Path.replace
    corrupted = False

    def corrupt_after_replace(source: Path, destination: Path) -> Path:
        nonlocal corrupted
        published = real_replace(source, destination)
        if not corrupted and source.name == "keyfile.json.new":
            before = destination.stat()
            payload = bytearray(destination.read_bytes())
            payload[len(payload) // 2] ^= 1
            destination.write_bytes(bytes(payload))
            os.utime(destination, ns=(before.st_atime_ns, before.st_mtime_ns))
            corrupted = True
        return published

    monkeypatch.setattr(Path, "replace", corrupt_after_replace)
    with pytest.raises(VaultError, match="published DEK-rotation keyfile changed"):
        vault.rotate_dek("test-passphrase")

    assert corrupted
    assert vault._dek is not old_dek
    assert vault.get_token(capture_id) == token
    assert Vault.open(vault.path, "test-passphrase").get_token(capture_id) == token


def test_keyfile_path_swap_during_proof_preserves_valid_recovery_stage(
    make_vault: Callable[..., Vault], monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = make_vault("rotate-keyfile-proof-path-swap")
    capture_id = "cap-keyfile-proof-swap"
    token = _token("keyfile-proof-swap")
    vault.store_token(capture_id, token)
    old_dek = vault._dek
    final = vault.path / "keyfile.json"
    displaced = vault.path / "keyfile.valid-but-displaced"
    real_replace = Path.replace
    real_read = os.read
    keyfile_published = False
    swapped = False

    def mark_keyfile_publish(source: Path, destination: Path) -> Path:
        nonlocal keyfile_published
        published = real_replace(source, destination)
        if source.name == "keyfile.json.new":
            keyfile_published = True
        return published

    def swap_final_after_descriptor_read(descriptor: int, count: int) -> bytes:
        nonlocal swapped
        data = real_read(descriptor, count)
        if keyfile_published and not swapped:
            final.rename(displaced)
            final.write_bytes(b"raced final keyfile")
            swapped = True
        return data

    monkeypatch.setattr(Path, "replace", mark_keyfile_publish)
    monkeypatch.setattr(os, "read", swap_final_after_descriptor_read)
    with pytest.raises(VaultError, match="published DEK-rotation keyfile changed"):
        vault.rotate_dek("test-passphrase")

    assert swapped
    assert vault._dek is not old_dek
    assert vault.get_token(capture_id) == token
    assert Vault.open(vault.path, "test-passphrase").get_token(capture_id) == token


@pytest.mark.parametrize("repair_failure", ["replace", "fsync"])
def test_forward_repair_failure_preserves_recovery_and_uses_new_dek(
    make_vault: Callable[..., Vault], monkeypatch: pytest.MonkeyPatch, repair_failure: str
) -> None:
    vault = make_vault(f"rotate-forward-repair-{repair_failure}")
    capture_id = f"cap-forward-repair-{repair_failure}"
    token = _token(f"forward-repair-{repair_failure}")
    vault.store_token(capture_id, token)
    old_dek = vault._dek
    real_replace = Path.replace
    real_fsync_directory = vault_module._fsync_directory
    mismatch_published = False
    repair_failed = False

    def force_mismatch_then_fail_repair(source: Path, destination: Path) -> Path:
        nonlocal mismatch_published, repair_failed
        if source.name == "keyfile.json.new":
            source.unlink()
            source.write_bytes(b"raced keyfile source")
            published = real_replace(source, destination)
            mismatch_published = True
            return published
        if source.name.startswith(".keyfile-forward-repair-") and repair_failure == "replace":
            repair_failed = True
            raise OSError("injected forward-repair replace failure")
        return real_replace(source, destination)

    def fail_forward_repair_fsync(path: Path) -> bool:
        nonlocal repair_failed
        if (
            repair_failure == "fsync"
            and mismatch_published
            and list(vault.path.glob(".keyfile-forward-repair-*.tmp"))
            and not repair_failed
        ):
            repair_failed = True
            raise OSError("injected forward-repair fsync failure")
        return real_fsync_directory(path)

    monkeypatch.setattr(Path, "replace", force_mismatch_then_fail_repair)
    monkeypatch.setattr(vault_module, "_fsync_directory", fail_forward_repair_fsync)
    with pytest.raises(VaultError, match="published DEK-rotation keyfile changed") as raised:
        vault.rotate_dek("test-passphrase")

    recovery_files = list(vault.path.glob(".keyfile-forward-repair-*.tmp"))
    assert mismatch_published and repair_failed
    assert any("forward keyfile repair also failed" in note for note in raised.value.__notes__)
    assert len(recovery_files) == 1
    recovered_dek = open_keyfile(recovery_files[0].read_text(), "test-passphrase")
    assert recovered_dek.decrypt((vault.path / "case.enc").read_bytes(), aad=b"case.enc")
    assert vault._dek is not old_dek
    assert vault.get_token(capture_id) == token


def test_forward_repair_post_return_failure_reports_retained_artifact(
    make_vault: Callable[..., Vault], monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = make_vault("rotate-forward-repair-post-return")
    capture_id = "cap-forward-repair-post-return"
    token = _token("forward-repair-post-return")
    vault.store_token(capture_id, token)
    old_dek = vault._dek
    real_replace = Path.replace
    real_write = vault_module._write_private_path_stage_and_fsync
    repair_path: Path | None = None

    def force_published_keyfile_mismatch(source: Path, destination: Path) -> Path:
        if source.name == "keyfile.json.new":
            source.unlink()
            source.write_bytes(b"raced keyfile source")
        return real_replace(source, destination)

    def write_repair_then_fail(stage: vault_module._PathRotationStage, data: bytes) -> None:
        nonlocal repair_path
        real_write(stage, data)
        if stage.destination.name.startswith(".keyfile-forward-repair-"):
            repair_path = stage.destination
            raise OSError("injected forward-repair post-return failure")

    monkeypatch.setattr(Path, "replace", force_published_keyfile_mismatch)
    monkeypatch.setattr(vault_module, "_write_private_path_stage_and_fsync", write_repair_then_fail)
    with pytest.raises(VaultError, match="published DEK-rotation keyfile changed") as raised:
        vault.rotate_dek("test-passphrase")

    assert repair_path is not None and repair_path.is_file()
    assert any(str(repair_path) in note for note in raised.value.__notes__)
    recovered_dek = open_keyfile(repair_path.read_text(), "test-passphrase")
    assert recovered_dek.decrypt((vault.path / "case.enc").read_bytes(), aad=b"case.enc")
    alternate = list(vault.path.glob("keyfile.json.recovery-*.new"))
    assert len(alternate) == 1
    assert vault._dek is not old_dek
    assert vault.get_token(capture_id) == token

    monkeypatch.undo()
    with pytest.raises(VaultError, match="manual recovery"):
        vault.rotate_dek("test-passphrase")
    assert repair_path.is_file() and alternate[0].is_file()


def test_forward_repair_before_create_failure_reports_no_false_artifact(
    make_vault: Callable[..., Vault], monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = make_vault("rotate-forward-repair-before-create")
    capture_id = "cap-forward-repair-before-create"
    token = _token("forward-repair-before-create")
    vault.store_token(capture_id, token)
    old_dek = vault._dek
    real_replace = Path.replace
    real_write = vault_module._write_private_path_stage_and_fsync
    repair_create_failed = False

    def force_published_keyfile_mismatch(source: Path, destination: Path) -> Path:
        if source.name == "keyfile.json.new":
            source.unlink()
            source.write_bytes(b"raced keyfile source")
        return real_replace(source, destination)

    def fail_before_repair_create(stage: vault_module._PathRotationStage, data: bytes) -> None:
        nonlocal repair_create_failed
        if stage.destination.name.startswith(".keyfile-forward-repair-"):
            repair_create_failed = True
            raise OSError("injected forward-repair before-create failure")
        real_write(stage, data)

    monkeypatch.setattr(Path, "replace", force_published_keyfile_mismatch)
    monkeypatch.setattr(
        vault_module, "_write_private_path_stage_and_fsync", fail_before_repair_create
    )
    with pytest.raises(VaultError, match="published DEK-rotation keyfile changed") as raised:
        vault.rotate_dek("test-passphrase")

    assert repair_create_failed
    assert "no verified forward-repair artifact retained" in raised.value.__notes__
    assert not list(vault.path.glob(".keyfile-forward-repair-*.tmp"))
    alternate = list(vault.path.glob("keyfile.json.recovery-*.new"))
    assert len(alternate) == 1
    assert all("forward-repair artifact retained at" not in note for note in raised.value.__notes__)
    recovered_dek = open_keyfile(alternate[0].read_text(), "test-passphrase")
    assert recovered_dek.decrypt((vault.path / "case.enc").read_bytes(), aad=b"case.enc")
    assert vault._dek is not old_dek
    assert vault.get_token(capture_id) == token


def test_partial_publication_with_detached_keyfile_stage_writes_alternate_recovery(
    make_vault: Callable[..., Vault], monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = make_vault("rotate-partial-detached-keyfile")
    old_dek = vault._dek
    fixed_stage = vault.path / "keyfile.json.new"
    real_replace = Path.replace
    injected = False

    def publish_one_then_detach_keyfile(source: Path, destination: Path) -> Path:
        nonlocal injected
        published = real_replace(source, destination)
        if not injected and source.name == "case.enc.new":
            fixed_stage.unlink()
            fixed_stage.write_bytes(b"alien fixed-name stage")
            injected = True
            raise OSError("injected partial publication")
        return published

    monkeypatch.setattr(Path, "replace", publish_one_then_detach_keyfile)
    with pytest.raises(OSError, match="partial publication") as raised:
        vault.rotate_dek("test-passphrase")

    recovery_files = list(vault.path.glob("keyfile.json.recovery-*.new"))
    assert injected
    assert fixed_stage.read_bytes() == b"alien fixed-name stage"
    assert len(recovery_files) == 1
    assert any(str(recovery_files[0]) in note for note in raised.value.__notes__)
    recovered_dek = open_keyfile(recovery_files[0].read_text(), "test-passphrase")
    assert recovered_dek.decrypt((vault.path / "case.enc").read_bytes(), aad=b"case.enc")
    assert vault._dek is old_dek


def test_alternate_recovery_fsync_failure_preserves_artifact(
    make_vault: Callable[..., Vault], monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = make_vault("rotate-alternate-recovery-fsync")
    old_dek = vault._dek
    fixed_stage = vault.path / "keyfile.json.new"
    real_replace = Path.replace
    real_fsync_directory = vault_module._fsync_directory
    partial = False
    recovery_fsync_failed = False

    def publish_one_then_detach_keyfile(source: Path, destination: Path) -> Path:
        nonlocal partial
        published = real_replace(source, destination)
        if not partial and source.name == "case.enc.new":
            fixed_stage.unlink()
            fixed_stage.write_bytes(b"alien fixed-name stage")
            partial = True
            raise OSError("injected partial publication before alternate fsync")
        return published

    def fail_alternate_fsync(path: Path) -> bool:
        nonlocal recovery_fsync_failed
        if (
            partial
            and list(vault.path.glob("keyfile.json.recovery-*.new"))
            and not recovery_fsync_failed
        ):
            recovery_fsync_failed = True
            raise OSError("injected alternate recovery fsync failure")
        return real_fsync_directory(path)

    monkeypatch.setattr(Path, "replace", publish_one_then_detach_keyfile)
    monkeypatch.setattr(vault_module, "_fsync_directory", fail_alternate_fsync)
    with pytest.raises(OSError, match="partial publication") as raised:
        vault.rotate_dek("test-passphrase")

    recovery_files = list(vault.path.glob("keyfile.json.recovery-*.new"))
    assert partial and recovery_fsync_failed
    assert len(recovery_files) == 1
    assert any("alternate keyfile recovery also failed" in note for note in raised.value.__notes__)
    recovered_dek = open_keyfile(recovery_files[0].read_text(), "test-passphrase")
    assert recovered_dek.decrypt((vault.path / "case.enc").read_bytes(), aad=b"case.enc")
    assert vault._dek is old_dek


def test_alternate_recovery_before_create_failure_reports_no_false_artifact(
    make_vault: Callable[..., Vault], monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = make_vault("rotate-alternate-recovery-before-create")
    old_dek = vault._dek
    fixed_stage = vault.path / "keyfile.json.new"
    real_replace = Path.replace
    real_write = vault_module._write_private_path_stage_and_fsync
    partial = False
    recovery_create_failed = False

    def publish_one_then_detach_keyfile(source: Path, destination: Path) -> Path:
        nonlocal partial
        published = real_replace(source, destination)
        if not partial and source.name == "case.enc.new":
            fixed_stage.unlink()
            fixed_stage.write_bytes(b"alien fixed-name stage")
            partial = True
            raise OSError("injected partial publication before alternate create")
        return published

    def fail_before_alternate_create(stage: vault_module._PathRotationStage, data: bytes) -> None:
        nonlocal recovery_create_failed
        if stage.destination.name.startswith("keyfile.json.recovery-"):
            recovery_create_failed = True
            raise OSError("injected alternate recovery before-create failure")
        real_write(stage, data)

    monkeypatch.setattr(Path, "replace", publish_one_then_detach_keyfile)
    monkeypatch.setattr(
        vault_module, "_write_private_path_stage_and_fsync", fail_before_alternate_create
    )
    with pytest.raises(OSError, match="partial publication") as raised:
        vault.rotate_dek("test-passphrase")

    assert partial and recovery_create_failed
    assert "no verified alternate recovery artifact retained" in raised.value.__notes__
    assert not list(vault.path.glob("keyfile.json.recovery-*.new"))
    assert all(
        "alternate recovery artifact retained at" not in note for note in raised.value.__notes__
    )
    assert fixed_stage.read_bytes() == b"alien fixed-name stage"
    assert vault._dek is old_dek


def test_token_rename_failure_preserves_stages_and_wrapped_new_key(
    make_vault: Callable[..., Vault], monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = make_vault("rotate-token-publish-failure")
    capture_id = "cap-token-failure"
    token = _token("token-failure")
    vault.store_token(capture_id, token)
    real_replace = vault_module._TokenDirectory.replace

    def fail_token_replace(
        directory: vault_module._TokenDirectory, source: str, destination: str
    ) -> None:
        if destination.endswith(".tokens.enc"):
            raise OSError("injected token publication failure")
        real_replace(directory, source, destination)

    monkeypatch.setattr(vault_module._TokenDirectory, "replace", fail_token_replace)
    with pytest.raises(OSError, match="token publication"):
        vault.rotate_dek("test-passphrase")

    wrapped_new_key = vault.path / "keyfile.json.new"
    staged_token = _sidecar_path(vault, capture_id).with_name(
        _sidecar_path(vault, capture_id).name + ".new"
    )
    assert wrapped_new_key.exists()
    assert staged_token.exists()
    new_dek = open_keyfile(wrapped_new_key.read_text(), "test-passphrase")
    assert new_dek.decrypt((vault.path / "case.enc").read_bytes(), aad=b"case.enc")
    staged_plaintext = new_dek.decrypt(
        staged_token.read_bytes(),
        aad=vault_module._token_sidecar_aad(_sidecar_path(vault, capture_id).name),
    )
    assert vault_module._decode_token_sidecar(staged_plaintext).primary == token


def test_late_rotation_directory_fsync_failure_keeps_new_dek_live(
    make_vault: Callable[..., Vault], monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = make_vault("rotate-late-fsync")
    capture_id = "cap-rotate-late-fsync"
    token = _token("rotate-late-fsync")
    vault.store_token(capture_id, token)
    sidecar = _sidecar_path(vault, capture_id)
    before = sidecar.read_bytes()
    before_keyfile = (vault.path / "keyfile.json").read_bytes()
    real_fsync_directory = vault_module._fsync_directory
    calls = 0

    def fail_after_all_renames(path: Path) -> bool:
        nonlocal calls
        calls += 1
        if calls == 3:
            raise OSError("injected late directory fsync failure")
        return real_fsync_directory(path)

    monkeypatch.setattr(vault_module, "_fsync_directory", fail_after_all_renames)
    with pytest.raises(OSError, match="late directory fsync"):
        vault.rotate_dek("test-passphrase")

    assert calls == 3
    assert sidecar.read_bytes() != before
    assert (vault.path / "keyfile.json").read_bytes() != before_keyfile
    assert vault.get_token(capture_id) == token
    assert Vault.open(vault.path, "test-passphrase").get_token(capture_id) == token
    assert not list(vault.path.rglob("*.new"))


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ([], "structure"),
        (
            {
                "version": 2,
                "capture_id": "cap",
                "primary": None,
                "additional": [],
                "archive": [],
            },
            "version",
        ),
        (
            {
                "version": 1,
                "capture_id": 7,
                "primary": None,
                "additional": [],
                "archive": [],
            },
            "capture id",
        ),
        (
            {
                "version": 1,
                "capture_id": "cap",
                "primary": "bad",
                "additional": [],
                "archive": [],
            },
            "corrupt token",
        ),
        (
            {
                "version": 1,
                "capture_id": "cap",
                "primary": None,
                "additional": {},
                "archive": [],
            },
            "additional-token",
        ),
        (
            {
                "version": 1,
                "capture_id": "cap",
                "primary": None,
                "additional": [1],
                "archive": [],
            },
            "additional-token",
        ),
        (
            {
                "version": 1,
                "capture_id": "cap",
                "primary": {"kind": "dev"},
                "additional": [],
                "archive": [],
            },
            "corrupt token",
        ),
        (
            {
                "version": 1,
                "capture_id": "cap",
                "primary": {"kind": 7, "tsa_name": "tsa", "token_b64": "eA=="},
                "additional": [],
                "archive": [],
            },
            "corrupt token",
        ),
    ],
)
def test_encrypted_sidecar_structure_is_strict(payload: object, message: str) -> None:
    with pytest.raises(VaultError, match=message):
        vault_module._decode_token_sidecar(json.dumps(payload).encode())


@pytest.mark.parametrize(
    "hostile_json",
    [
        b"[" * 256 + b"null" + b"]" * 256,
        b'{"nested":' * 256 + b"null" + b"}" * 256,
    ],
    ids=["excessive-array-depth", "excessive-object-depth"],
)
def test_hostile_json_depth_is_explicitly_bounded(hostile_json: bytes) -> None:
    original_limit = sys.getrecursionlimit()
    try:
        sys.setrecursionlimit(max(original_limit, 10_000))
        with pytest.raises(VaultError, match=r"corrupt encrypted.*JSON"):
            vault_module._decode_token_sidecar(hostile_json)
    finally:
        sys.setrecursionlimit(original_limit)


def test_json_structure_characters_and_escapes_inside_strings_do_not_count() -> None:
    noisy_text = '[{ "quoted" \\ path }] ' * 100
    token = TimestampToken(noisy_text, noisy_text, b"token")
    record = vault_module._TokenSidecar(noisy_text, token)

    vault_module._check_token_json_nesting(json.dumps('[{]},: "quoted" \\ path' * 2_000))
    assert vault_module._decode_token_sidecar(vault_module._encode_token_sidecar(record)) == record


@pytest.mark.parametrize("shape", ["array", "object"])
def test_hostile_json_width_is_explicitly_bounded(shape: str) -> None:
    if shape == "array":
        hostile_json = b"[" + b",".join([b"[]"] * 5_000) + b"]"
    else:
        hostile_json = (
            "{" + ",".join(f'"key-{index}":null' for index in range(5_000)) + "}"
        ).encode()

    with pytest.raises(VaultError, match=r"corrupt encrypted.*JSON"):
        vault_module._decode_token_sidecar(hostile_json)


def test_hostile_json_integer_is_controlled() -> None:
    hostile_json = b'{"integer":' + b"9" * 10_000 + b"}"
    original_limit = sys.get_int_max_str_digits()
    try:
        sys.set_int_max_str_digits(0)
        with pytest.raises(VaultError, match=r"corrupt encrypted.*JSON"):
            vault_module._decode_token_sidecar(hostile_json)
    finally:
        sys.set_int_max_str_digits(original_limit)


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be"])
def test_escape_prefix_deep_json_cannot_bypass_preflight(encoding: str) -> None:
    text = _deep_json_with_escape_prefix()
    original_limit = sys.getrecursionlimit()
    try:
        sys.setrecursionlimit(max(original_limit, 10_000))
        parsed = json.loads(text)
        assert isinstance(parsed, dict) and parsed["x"] == '"'
        with pytest.raises(VaultError, match=r"corrupt encrypted.*JSON"):
            vault_module._decode_token_sidecar(text.encode(encoding))
    finally:
        sys.setrecursionlimit(original_limit)


@pytest.mark.parametrize(
    "payload",
    [b"\xef\xbb\xbf{}", b"{\x00}"],
    ids=["utf8-bom", "embedded-nul"],
)
def test_bom_and_nul_json_fail_controlled(payload: bytes) -> None:
    with pytest.raises(VaultError, match=r"corrupt encrypted.*JSON"):
        vault_module._decode_token_sidecar(payload)


@pytest.mark.parametrize("encoding", ["utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be"])
def test_non_utf8_legacy_json_cannot_bypass_preflight(
    make_vault: Callable[..., Vault], encoding: str
) -> None:
    vault = make_vault(f"legacy-{encoding}")
    legacy = vault.path / "tokens" / "cap.json"
    legacy.write_bytes(_deep_json_with_escape_prefix().encode(encoding))

    with pytest.raises(VaultError, match="corrupt token record"):
        Vault.open(vault.path, "test-passphrase")
    assert legacy.exists()


def test_sidecar_size_and_runtime_type_limits_fail_closed(
    make_vault: Callable[..., Vault], monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = make_vault("token-limits")
    token = _token("limits")
    with pytest.raises(VaultError, match="capture id must be text"):
        vault.store_token(cast(str, 7), token)
    with pytest.raises(VaultError, match="capture id is too large"):
        vault.store_token("x" * (vault_module._MAX_TOKEN_TEXT_CHARS + 1), token)
    with pytest.raises(VaultError, match="invalid type"):
        vault.store_token("cap", cast(TimestampToken, object()))
    with pytest.raises(VaultError, match="metadata is too large"):
        vault.store_token("cap", TimestampToken("x" * 4097, "tsa", b"data"))
    with pytest.raises(VaultError, match="metadata must be text"):
        vault.store_token("cap", TimestampToken(cast(str, 7), "tsa", b"data"))
    with pytest.raises(VaultError, match="metadata must be valid UTF-8"):
        vault.store_token("cap", TimestampToken("dev", "\ud800", b"data"))
    with pytest.raises(VaultError, match="data must be bytes"):
        vault.store_token("cap", TimestampToken("dev", "tsa", cast(bytes, "data")))

    monkeypatch.setattr(vault_module, "_MAX_TOKEN_DATA_BYTES", 1)
    with pytest.raises(VaultError, match="token is too large"):
        vault.store_token("cap", TimestampToken("dev", "tsa", b"large"))


def test_encoded_and_encrypted_sidecar_limits_are_enforced(
    make_vault: Callable[..., Vault], monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = make_vault("encoded-token-limits")
    monkeypatch.setattr(vault_module, "_MAX_TOKEN_PLAINTEXT_BYTES", 1)
    with pytest.raises(VaultError, match="plaintext is too large"):
        vault.store_token("cap", _token("plaintext-limit"))
    with pytest.raises(VaultError, match="plaintext is too large"):
        vault_module._decode_token_sidecar(b"{}")

    monkeypatch.setattr(vault_module, "_MAX_TOKEN_PLAINTEXT_BYTES", 1024 * 1024)
    monkeypatch.setattr(vault_module, "_MAX_TOKEN_SIDECAR_BYTES", 1)
    with pytest.raises(VaultError, match=r"encrypted.*too large"):
        vault.store_token("cap", _token("ciphertext-limit"))


def test_invalid_legacy_json_and_changed_cleanup_inputs_are_preserved(
    make_vault: Callable[..., Vault], tmp_path: Path
) -> None:
    vault = make_vault("invalid-legacy-json")
    invalid = vault.path / "tokens" / "invalid.json"
    invalid.write_bytes(b"\xffnot-json")
    with pytest.raises(VaultError, match="corrupt token record"):
        Vault.open(vault.path, "test-passphrase")
    assert invalid.exists()

    invalid.unlink()
    giant_integer = vault.path / "tokens" / "giant.json"
    giant_integer.write_bytes(b'{"integer":' + b"9" * 10_000 + b"}")
    with pytest.raises(VaultError, match="corrupt token record"):
        Vault.open(vault.path, "test-passphrase")
    assert giant_integer.exists()

    helper_root = tmp_path / "cleanup-helper"
    (helper_root / "tokens").mkdir(parents=True)
    with vault_module._open_token_directory(helper_root) as directory:
        with pytest.raises(VaultError, match="unavailable"):
            vault_module._snapshot_legacy_token_entries(directory, ["missing.json"])

        changed = helper_root / "tokens" / "changed.json"
        changed.write_bytes(b"old")
        original_stat = changed.stat()
        snapshots = vault_module._snapshot_legacy_token_entries(directory, [changed.name])
        changed.write_bytes(b"new")
        os.utime(
            changed,
            ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns),
        )
        with pytest.raises(VaultError, match="changed before cleanup"):
            vault_module._remove_migrated_token_entries(directory, (changed.name,), snapshots)
        assert changed.exists()

        missing_after_read = helper_root / "tokens" / "missing-after-read.json"
        missing_after_read.write_bytes(b"old")
        missing_snapshots = vault_module._snapshot_legacy_token_entries(
            directory, [missing_after_read.name]
        )
        missing_after_read.unlink()
        with pytest.raises(VaultError, match="changed before cleanup"):
            vault_module._remove_migrated_token_entries(
                directory, (missing_after_read.name,), missing_snapshots
            )
        vault_module._remove_migrated_token_entries(directory, (), {})


def test_private_writer_zero_write_and_close_failure_remove_created_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "private-writer"
    (root / "tokens").mkdir(parents=True)
    zero_path = root / "tokens" / "zero-write.new"
    with vault_module._open_token_directory(root) as directory:
        monkeypatch.setattr(os, "write", lambda _descriptor, _data: 0)
        with pytest.raises(OSError, match="short write"):
            vault_module._write_private_entry_and_fsync(directory, zero_path.name, b"ciphertext")
        assert not zero_path.exists()

        monkeypatch.undo()
        close_path = root / "tokens" / "close-failure.new"
        real_close = os.close

        def close_then_fail(descriptor: int) -> None:
            real_close(descriptor)
            raise OSError("injected close failure")

        with monkeypatch.context() as close_patch:
            close_patch.setattr(os, "close", close_then_fail)
            with pytest.raises(OSError, match="close failure"):
                vault_module._write_private_entry_and_fsync(
                    directory, close_path.name, b"ciphertext"
                )
        assert not close_path.exists()
