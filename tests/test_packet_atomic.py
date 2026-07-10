# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Transactional publication and re-export privacy for packet directories."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from habitable.capture import capture
from habitable.errors import PacketError
from habitable.packet import build_packet
from habitable.tsa import LocalRfc3161TSA
from habitable.vault import Vault
from habitable.verify import verify_packet


def _vault_with_capture(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    tsa: LocalRfc3161TSA,
) -> Vault:
    vault = make_vault()
    issue = vault.document.add_issue(category="mold", title="Mold", issue_id="i1")
    capture(vault, make_jpeg("condition.jpg", with_location=True), issue_id=issue, tsa=tsa)
    return vault


def _snapshot(directory: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(directory)): path.read_bytes()
        for path in sorted(directory.rglob("*"))
        if path.is_file()
    }


def _transaction_debris(parent: Path, packet_name: str) -> list[Path]:
    return [
        *parent.glob(f".{packet_name}.stage-*"),
        *parent.glob(f".{packet_name}.backup-*"),
    ]


def test_narrower_reexport_replaces_entire_directory(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    vault = _vault_with_capture(make_vault, make_jpeg, local_tsa)
    out = tmp_path / "packet"
    first = build_packet(
        vault,
        out,
        include_originals=True,
        generated_at="2026-01-02T00:10:00Z",
    )
    assert first.includes_originals and (out / "originals").is_dir()
    (out / "stale-private-file.txt").write_text("must not survive", encoding="utf-8")

    second = build_packet(
        vault,
        out,
        include_originals=False,
        generated_at="2026-01-02T00:20:00Z",
    )

    assert second.out_dir == out
    assert second.bundle_path == out / "bundle.json"
    assert second.pdf_path == out / "packet.pdf"
    assert second.html_path == out / "packet.html"
    assert not (out / "originals").exists()
    assert not (out / "stale-private-file.txt").exists()
    assert verify_packet(out).ok
    assert _transaction_debris(tmp_path, out.name) == []


def test_render_failure_preserves_previous_packet_and_custody(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from habitable import htmlpacket

    vault = _vault_with_capture(make_vault, make_jpeg, local_tsa)
    out = tmp_path / "packet"
    build_packet(vault, out, generated_at="2026-01-02T00:10:00Z")
    before_files = _snapshot(out)
    before_custody = vault.custody.to_vault_records()

    def fail_render(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("synthetic renderer failure")

    monkeypatch.setattr(htmlpacket, "render_packet_html", fail_render)
    with pytest.raises(RuntimeError, match="synthetic renderer failure"):
        build_packet(vault, out, generated_at="2026-01-02T00:20:00Z")

    assert _snapshot(out) == before_files
    assert vault.custody.to_vault_records() == before_custody
    reopened = Vault.open(vault.path, "test-passphrase")
    assert reopened.custody.to_vault_records() == before_custody
    assert verify_packet(out).ok
    assert _transaction_debris(tmp_path, out.name) == []


def test_failed_first_export_publishes_nothing(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from habitable import htmlpacket

    vault = _vault_with_capture(make_vault, make_jpeg, local_tsa)
    out = tmp_path / "packet"
    before_custody = vault.custody.to_vault_records()
    monkeypatch.setattr(
        htmlpacket,
        "render_packet_html",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("boom")),
    )

    with pytest.raises(RuntimeError, match="boom"):
        build_packet(vault, out, generated_at="2026-01-02T00:10:00Z")

    assert not out.exists()
    assert vault.custody.to_vault_records() == before_custody
    assert _transaction_debris(tmp_path, out.name) == []


def test_export_rejects_file_or_symlink_target(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    vault = _vault_with_capture(make_vault, make_jpeg, local_tsa)
    target_file = tmp_path / "not-a-directory"
    target_file.write_text("keep me", encoding="utf-8")
    with pytest.raises(PacketError, match="directory path"):
        build_packet(vault, target_file)
    assert target_file.read_text(encoding="utf-8") == "keep me"

    target_dir = tmp_path / "real-dir"
    target_dir.mkdir()
    target_link = tmp_path / "packet-link"
    target_link.symlink_to(target_dir, target_is_directory=True)
    with pytest.raises(PacketError, match="directory path"):
        build_packet(vault, target_link)
