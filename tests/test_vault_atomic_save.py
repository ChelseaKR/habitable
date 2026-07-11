# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Crash and fault-injection coverage for normal multi-blob vault saves."""

from __future__ import annotations

import errno
import json
import os
import subprocess
import sys
import textwrap
from collections.abc import Callable
from pathlib import Path

import pytest

import habitable.vault as vault_module
from habitable.errors import VaultError
from habitable.vault import Vault

_STATE_FILES = ("case.enc", "custody.enc", "deferred.enc", "peer_have.enc", "sync_security.enc")
_JOURNAL = ".save-transaction.json"


def _snapshot(path: Path) -> dict[str, bytes]:
    return {name: (path / name).read_bytes() for name in _STATE_FILES}


def _save_artifacts(path: Path) -> list[str]:
    return sorted(entry.name for entry in path.iterdir() if entry.name.startswith(".save-"))


def _issue_ids(vault: Vault) -> set[str]:
    return {issue.issue_id for issue in vault.document.issues()}


def _run_child(path: Path, source: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", textwrap.dedent(source), str(path)],
        check=False,
        capture_output=True,
        text=True,
    )


def _crash_mid_publish(path: Path) -> subprocess.CompletedProcess[str]:
    return _run_child(
        path,
        """
        import os
        import sys
        from pathlib import Path
        import habitable.vault as module
        from habitable.vault import Vault

        vault = Vault.open(Path(sys.argv[1]), "test-passphrase")
        vault.document.add_issue(category="mold", title="private crash marker", issue_id="crashed")
        real_replace = module._replace_path
        published = 0

        def crash_after_second_publish(source, destination):
            global published
            real_replace(source, destination)
            if source.name.endswith(".new") and destination.name in module._SAVE_BLOBS:
                published += 1
                if published == 2:
                    os._exit(86)

        module._replace_path = crash_after_second_publish
        vault.save()
        """,
    )


def test_normal_save_keeps_legacy_layout_and_leaves_no_transaction_files(
    make_vault: Callable[..., Vault], tmp_path: Path
) -> None:
    vault = make_vault()
    vault.document.add_issue(category="mold", issue_id="saved")
    vault.queue_deferred("capture-1", "a" * 64)

    vault.save()

    assert all((vault.path / name).is_file() for name in _STATE_FILES)
    assert _save_artifacts(vault.path) == []
    reopened = Vault.open(tmp_path / "vault", "test-passphrase")
    assert _issue_ids(reopened) == {"saved"}
    assert reopened.deferred()[0].capture_id == "capture-1"


def test_partial_staging_write_cannot_damage_live_vault(
    make_vault: Callable[..., Vault],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    vault = make_vault()
    before = _snapshot(vault.path)
    vault.document.add_issue(category="mold", issue_id="not-committed")
    real_write = vault_module._write_new_file_and_fsync
    injected = False

    def partial_then_fail(path: Path, data: bytes) -> None:
        nonlocal injected
        if not injected and path.name.endswith("case.enc.new"):
            injected = True
            with path.open("xb") as handle:
                handle.write(data[: max(1, len(data) // 2)])
                handle.flush()
            raise OSError("simulated interruption during staged write")
        real_write(path, data)

    monkeypatch.setattr(vault_module, "_write_new_file_and_fsync", partial_then_fail)
    with pytest.raises(OSError, match="staged write"):
        vault.save()

    assert _snapshot(vault.path) == before
    assert _save_artifacts(vault.path) == []
    assert "not-committed" not in _issue_ids(Vault.open(tmp_path / "vault", "test-passphrase"))


def test_replace_failure_rolls_back_every_blob_in_process(
    make_vault: Callable[..., Vault],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    vault = make_vault()
    before = _snapshot(vault.path)
    vault.document.add_issue(category="mold", issue_id="not-committed")
    real_replace = vault_module._replace_path
    published = 0

    def fail_second_publish(source: Path, destination: Path) -> None:
        nonlocal published
        if source.name.endswith(".new") and destination.name in _STATE_FILES:
            published += 1
            if published == 2:
                raise OSError("simulated replace failure")
        real_replace(source, destination)

    monkeypatch.setattr(vault_module, "_replace_path", fail_second_publish)
    with pytest.raises(OSError, match="replace failure"):
        vault.save()

    assert published == 2
    assert _snapshot(vault.path) == before
    assert _save_artifacts(vault.path) == []
    assert "not-committed" not in _issue_ids(Vault.open(tmp_path / "vault", "test-passphrase"))


def test_failure_after_prepared_journal_publication_still_rolls_back(
    make_vault: Callable[..., Vault],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    vault = make_vault()
    before = _snapshot(vault.path)
    vault.document.add_issue(category="mold", issue_id="not-committed")
    real_write_journal = vault_module._write_save_journal

    def publish_prepared_then_fail(path: Path, transaction: vault_module._SaveTransaction) -> None:
        real_write_journal(path, transaction)
        if transaction.phase == "prepared":
            raise OSError("simulated failure after prepared journal")

    monkeypatch.setattr(vault_module, "_write_save_journal", publish_prepared_then_fail)
    with pytest.raises(OSError, match="after prepared journal"):
        vault.save()

    assert _snapshot(vault.path) == before
    assert _save_artifacts(vault.path) == []
    assert "not-committed" not in _issue_ids(Vault.open(tmp_path / "vault", "test-passphrase"))


def test_process_death_mid_publish_is_rolled_back_on_open(
    make_vault: Callable[..., Vault], tmp_path: Path
) -> None:
    vault = make_vault()
    before = _snapshot(vault.path)
    result = _crash_mid_publish(vault.path)

    assert result.returncode == 86, result.stderr
    assert (vault.path / _JOURNAL).is_file()
    journal_text = (vault.path / _JOURNAL).read_text(encoding="utf-8")
    assert json.loads(journal_text)["phase"] == "prepared"
    assert "private crash marker" not in journal_text
    assert _snapshot(vault.path) != before

    reopened = Vault.open(tmp_path / "vault", "test-passphrase")
    assert "crashed" not in _issue_ids(reopened)
    assert _snapshot(vault.path) == before
    assert _save_artifacts(vault.path) == []


def test_process_death_during_prepared_rollback_cleanup_is_repeatable(
    make_vault: Callable[..., Vault], tmp_path: Path
) -> None:
    vault = make_vault()
    before = _snapshot(vault.path)
    assert _crash_mid_publish(vault.path).returncode == 86

    interrupted_recovery = _run_child(
        vault.path,
        """
        import os
        import sys
        from pathlib import Path
        import habitable.vault as module
        from habitable.vault import Vault

        def crash_during_artifact_cleanup(path, transaction):
            if (path / module._SAVE_JOURNAL).exists():
                os._exit(89)
            first_backup = module._save_artifact(
                path, transaction.transaction_id, module._SAVE_BLOBS[0], "old"
            )
            first_backup.unlink(missing_ok=True)
            os._exit(88)

        module._discard_save_artifacts = crash_during_artifact_cleanup
        Vault.open(Path(sys.argv[1]), "test-passphrase")
        """,
    )

    assert interrupted_recovery.returncode == 88, interrupted_recovery.stderr
    assert not (vault.path / _JOURNAL).exists()
    assert _snapshot(vault.path) == before
    assert _save_artifacts(vault.path)

    reopened = Vault.open(tmp_path / "vault", "test-passphrase")
    assert "crashed" not in _issue_ids(reopened)
    assert _snapshot(vault.path) == before
    assert _save_artifacts(vault.path) == []


def test_process_death_after_commit_keeps_new_generation_and_finishes_cleanup(
    make_vault: Callable[..., Vault], tmp_path: Path
) -> None:
    vault = make_vault()
    before = _snapshot(vault.path)
    result = _run_child(
        vault.path,
        """
        import os
        import sys
        from pathlib import Path
        import habitable.vault as module
        from habitable.vault import Vault

        vault = Vault.open(Path(sys.argv[1]), "test-passphrase")
        vault.document.add_issue(category="mold", issue_id="committed")

        def crash_before_cleanup(_path, _transaction):
            os._exit(87)

        module._cleanup_save_transaction = crash_before_cleanup
        vault.save()
        """,
    )

    assert result.returncode == 87, result.stderr
    assert json.loads((vault.path / _JOURNAL).read_text(encoding="utf-8"))["phase"] == "committed"
    assert _snapshot(vault.path) != before

    reopened = Vault.open(tmp_path / "vault", "test-passphrase")
    assert "committed" in _issue_ids(reopened)
    assert _save_artifacts(vault.path) == []


def test_orphaned_prejournal_copies_are_safe_to_remove(
    make_vault: Callable[..., Vault], tmp_path: Path
) -> None:
    vault = make_vault()
    before = _snapshot(vault.path)
    transaction_id = "a" * 32
    (vault.path / f".save-{transaction_id}-case.enc.new").write_bytes(b"partial new")
    (vault.path / f".save-{transaction_id}-case.enc.old").write_bytes(b"copied old")
    (vault.path / f".save-atomic-{'b' * 32}.tmp").write_bytes(b"partial temporary")

    Vault.open(tmp_path / "vault", "test-passphrase")

    assert _snapshot(vault.path) == before
    assert _save_artifacts(vault.path) == []


@pytest.mark.parametrize(
    ("record", "message"),
    [
        ({"version": 2}, "unsupported format"),
        (
            {"version": 1, "transaction_id": "bad", "phase": "prepared", "existing": []},
            "invalid transaction id",
        ),
        (
            {"version": 1, "transaction_id": "a" * 32, "phase": "unknown", "existing": []},
            "invalid phase",
        ),
        (
            {"version": 1, "transaction_id": "a" * 32, "phase": "prepared", "existing": "case.enc"},
            "invalid file inventory",
        ),
        (
            {
                "version": 1,
                "transaction_id": "a" * 32,
                "phase": "prepared",
                "existing": ["case.enc", "case.enc"],
            },
            "invalid file inventory",
        ),
        (
            {
                "version": 1,
                "transaction_id": "a" * 32,
                "phase": "prepared",
                "existing": ["identity.enc"],
            },
            "invalid file inventory",
        ),
    ],
)
def test_malformed_save_journal_fails_closed(
    make_vault: Callable[..., Vault],
    record: dict[str, object],
    message: str,
) -> None:
    vault = make_vault()
    (vault.path / _JOURNAL).write_text(json.dumps(record), encoding="utf-8")

    with pytest.raises(VaultError, match=message):
        Vault.open(vault.path, "test-passphrase")

    assert (vault.path / _JOURNAL).is_file()


def test_unreadable_save_journal_fails_closed(make_vault: Callable[..., Vault]) -> None:
    vault = make_vault()
    (vault.path / _JOURNAL).write_text("{", encoding="utf-8")

    with pytest.raises(VaultError, match="journal is unreadable"):
        Vault.open(vault.path, "test-passphrase")


def test_save_journal_symlink_is_not_followed(
    make_vault: Callable[..., Vault], tmp_path: Path
) -> None:
    vault = make_vault()
    outside = tmp_path / "outside-journal.json"
    outside.write_text("{}", encoding="utf-8")
    (vault.path / _JOURNAL).symlink_to(outside)

    with pytest.raises(VaultError, match="recovery file must be regular"):
        Vault.open(vault.path, "test-passphrase")


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO creation unavailable")
def test_save_journal_fifo_is_rejected_without_blocking(make_vault: Callable[..., Vault]) -> None:
    vault = make_vault()
    os.mkfifo(vault.path / _JOURNAL)

    with pytest.raises(VaultError, match="recovery file must be regular"):
        Vault.open(vault.path, "test-passphrase")


def test_oversized_save_journal_is_rejected_before_parsing(
    make_vault: Callable[..., Vault],
) -> None:
    vault = make_vault()
    (vault.path / _JOURNAL).write_bytes(b" " * 4097)

    with pytest.raises(VaultError, match="recovery file is too large"):
        Vault.open(vault.path, "test-passphrase")


def test_prepared_journal_without_backup_fails_closed(make_vault: Callable[..., Vault]) -> None:
    vault = make_vault()
    record = {
        "version": 1,
        "transaction_id": "a" * 32,
        "phase": "prepared",
        "existing": list(_STATE_FILES),
    }
    (vault.path / _JOURNAL).write_text(json.dumps(record), encoding="utf-8")

    with pytest.raises(VaultError, match=r"backup missing: case\.enc"):
        Vault.open(vault.path, "test-passphrase")


def test_prepared_backup_symlink_is_not_followed(
    make_vault: Callable[..., Vault], tmp_path: Path
) -> None:
    vault = make_vault()
    transaction_id = "a" * 32
    record = {
        "version": 1,
        "transaction_id": transaction_id,
        "phase": "prepared",
        "existing": list(_STATE_FILES),
    }
    (vault.path / _JOURNAL).write_text(json.dumps(record), encoding="utf-8")
    outside = tmp_path / "outside-backup.enc"
    outside.write_bytes((vault.path / "case.enc").read_bytes())
    (vault.path / f".save-{transaction_id}-case.enc.old").symlink_to(outside)

    with pytest.raises(VaultError, match="recovery file must be regular"):
        Vault.open(vault.path, "test-passphrase")


def test_committed_journal_without_live_file_fails_closed(make_vault: Callable[..., Vault]) -> None:
    vault = make_vault()
    record = {
        "version": 1,
        "transaction_id": "a" * 32,
        "phase": "committed",
        "existing": list(_STATE_FILES),
    }
    (vault.path / _JOURNAL).write_text(json.dumps(record), encoding="utf-8")
    (vault.path / "case.enc").unlink()

    with pytest.raises(VaultError, match=r"committed vault save is missing state file.*case\.enc"):
        Vault.open(vault.path, "test-passphrase")


def test_prepared_recovery_removes_blob_that_did_not_exist_before_save(
    make_vault: Callable[..., Vault], tmp_path: Path
) -> None:
    vault = make_vault()
    transaction_id = "a" * 32
    existing = set(_STATE_FILES) - {"sync_security.enc"}
    for name in existing:
        backup = vault.path / f".save-{transaction_id}-{name}.old"
        backup.write_bytes((vault.path / name).read_bytes())
    record = {
        "version": 1,
        "transaction_id": transaction_id,
        "phase": "prepared",
        "existing": sorted(existing),
    }
    (vault.path / _JOURNAL).write_text(json.dumps(record), encoding="utf-8")

    reopened = Vault.open(tmp_path / "vault", "test-passphrase")

    assert reopened.sync_peer_by_fingerprint("nobody") is None
    assert not (vault.path / "sync_security.enc").exists()
    assert _save_artifacts(vault.path) == []


def test_internal_incomplete_transaction_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(VaultError, match="incomplete vault save transaction"):
        vault_module._transactionally_replace_save_blobs(tmp_path, ())


def test_missing_staged_blob_and_failed_recovery_are_reported(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    transaction = vault_module._SaveTransaction("a" * 32, "prepared", frozenset())
    recovery_calls = 0

    def fail_second_recovery(_path: Path) -> None:
        nonlocal recovery_calls
        recovery_calls += 1
        if recovery_calls == 2:
            raise OSError("simulated recovery failure")

    monkeypatch.setattr(vault_module, "_recover_interrupted_save", fail_second_recovery)
    monkeypatch.setattr(
        vault_module,
        "_stage_save_transaction",
        lambda _path, _encrypted: transaction,
    )
    encrypted = tuple((name, b"ciphertext") for name in _STATE_FILES)

    with pytest.raises(VaultError, match="automatic recovery could not complete"):
        vault_module._transactionally_replace_save_blobs(tmp_path, encrypted)

    assert recovery_calls == 2


def test_directory_fsync_degrades_only_for_unsupported_operation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def unsupported(_path: Path, _flags: int) -> int:
        raise OSError(errno.EINVAL, "directory fsync unsupported")

    monkeypatch.setattr(os, "open", unsupported)
    assert vault_module._fsync_directory(tmp_path) is False


def test_directory_fsync_degrades_when_fsync_itself_is_unsupported(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    descriptor = 123
    monkeypatch.setattr(os, "open", lambda _path, _flags: descriptor)
    monkeypatch.setattr(
        os,
        "fsync",
        lambda _descriptor: (_ for _ in ()).throw(OSError(errno.EINVAL, "unsupported")),
    )
    monkeypatch.setattr(os, "close", lambda _descriptor: None)

    assert vault_module._fsync_directory(tmp_path) is False


def test_directory_open_propagates_io_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def failed_open(_path: Path, _flags: int) -> int:
        raise OSError(errno.EIO, "simulated directory I/O failure")

    monkeypatch.setattr(os, "open", failed_open)
    with pytest.raises(OSError, match="simulated directory I/O failure"):
        vault_module._fsync_directory(tmp_path)


def test_recovery_ignores_path_that_does_not_exist(tmp_path: Path) -> None:
    vault_module._recover_interrupted_save(tmp_path / "missing")


def test_directory_fsync_propagates_io_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    descriptor = 123
    monkeypatch.setattr(os, "open", lambda _path, _flags: descriptor)
    monkeypatch.setattr(
        os,
        "fsync",
        lambda _descriptor: (_ for _ in ()).throw(OSError(errno.EIO, "simulated I/O failure")),
    )
    monkeypatch.setattr(os, "close", lambda _descriptor: None)

    with pytest.raises(OSError, match="simulated I/O failure"):
        vault_module._fsync_directory(tmp_path)
