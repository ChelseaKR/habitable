# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Adversarial checks for restrictive, fail-closed plaintext workspaces."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from habitable.private_temp import private_temp_workspace


def test_private_workspace_is_restrictive_random_and_ephemeral(tmp_path: Path) -> None:
    vault = tmp_path / "vault"
    system_temp = tmp_path / "system-temp"
    vault.mkdir()
    system_temp.mkdir()
    payload = b"synthetic-private-media"
    root: Path | None = None
    staged: Path | None = None

    with private_temp_workspace(forbidden_root=vault, base_dir=system_temp) as workspace:
        root = workspace.root
        staged = workspace.write_bytes(payload, suffix=".JPG")
        assert staged.read_bytes() == payload
        assert staged.parent == root
        assert staged.name.startswith("item-") and staged.suffix == ".jpg"
        assert not staged.resolve().is_relative_to(vault.resolve())
        if os.name == "posix":
            assert stat.S_IMODE(root.stat().st_mode) == 0o700
            assert stat.S_IMODE(staged.stat().st_mode) == 0o600

    assert root is not None and not root.exists()
    assert staged is not None and not staged.exists()
    assert list(system_temp.iterdir()) == []


def test_partial_write_failure_removes_plaintext_and_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = tmp_path / "vault"
    system_temp = tmp_path / "system-temp"
    vault.mkdir()
    system_temp.mkdir()
    real_write = os.write
    calls = 0

    def fail_after_partial_write(descriptor: int, payload: bytes | memoryview) -> int:
        nonlocal calls
        calls += 1
        if calls == 1:
            return int(real_write(descriptor, payload[:1]))
        raise OSError("synthetic disk failure")

    monkeypatch.setattr(os, "write", fail_after_partial_write)
    with private_temp_workspace(forbidden_root=vault, base_dir=system_temp) as workspace:
        with pytest.raises(OSError, match="synthetic disk failure"):
            workspace.write_bytes(b"secret that must be cleaned", suffix=".jpg")
        assert list(workspace.root.iterdir()) == []
    assert list(system_temp.iterdir()) == []


def test_workspace_configuration_inside_vault_fails_before_plaintext_write(
    tmp_path: Path,
) -> None:
    vault = tmp_path / "vault"
    unsafe_temp = vault / "configured-temp"
    unsafe_temp.mkdir(parents=True)

    with (
        pytest.raises(OSError, match="must be outside the vault"),
        private_temp_workspace(forbidden_root=vault, base_dir=unsafe_temp) as workspace,
    ):
        workspace.write_bytes(b"must never be written")

    assert list(unsafe_temp.iterdir()) == []
