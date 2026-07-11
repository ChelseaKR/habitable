# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Hostile packet file references stay inside regular packet files."""

from __future__ import annotations

import json
import os
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest

import habitable.verify as verifier
from habitable.canonical import JSONValue, canonical_json
from habitable.capture import capture
from habitable.packet import _write_signature, build_packet
from habitable.tsa import LocalRfc3161TSA
from habitable.vault import Vault


def _make_packet(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
    *,
    include_originals: bool = False,
) -> tuple[Vault, Path]:
    vault = make_vault()
    issue_id = vault.document.add_issue(category="mold", title="Mold", issue_id="i1")
    capture(vault, make_jpeg("reference.jpg"), issue_id=issue_id, tsa=local_tsa)
    packet = tmp_path / "packet"
    build_packet(
        vault,
        packet,
        include_originals=include_originals,
        generated_at="2026-01-02T00:10:00Z",
        make_pdf=False,
    )
    return vault, packet


def _rewrite_item(
    vault: Vault,
    packet: Path,
    fields: dict[str, JSONValue],
    *,
    resign: bool,
) -> None:
    bundle = cast("dict[str, JSONValue]", json.loads((packet / "bundle.json").read_text()))
    items = cast("list[JSONValue]", bundle["items"])
    item = cast("dict[str, JSONValue]", items[0])
    item.update(fields)
    bundle_bytes = canonical_json(bundle)
    (packet / "bundle.json").write_bytes(bundle_bytes)
    if resign:
        _write_signature(vault, packet, bundle_bytes)


def _only_item(packet: Path, local_tsa: LocalRfc3161TSA) -> verifier.ItemVerdict:
    report = verifier.verify_packet(packet, trusted_certs=[local_tsa.certificate])
    assert len(report.items) == 1
    return report.items[0]


@pytest.mark.parametrize(
    "reference",
    [
        "/etc/hosts",
        "../outside.jpg",
        "nested/outside.jpg",
        r"nested\outside.jpg",
        "..",
        r"C:\Windows\system.ini",
    ],
)
def test_signed_packet_rejects_non_basename_shared_references(
    reference: str,
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    vault, packet = _make_packet(make_vault, make_jpeg, local_tsa, tmp_path)
    _rewrite_item(vault, packet, {"shared_name": reference}, resign=True)

    report = verifier.verify_packet(packet, trusted_certs=[local_tsa.certificate])
    assert report.signature_ok
    assert not report.items[0].shared_media_ok
    assert any("reference must be one basename" in note for note in report.items[0].notes)


def test_signed_packet_rejects_absolute_poster_reference(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    vault, packet = _make_packet(make_vault, make_jpeg, local_tsa, tmp_path)
    _rewrite_item(
        vault,
        packet,
        {"poster_name": "/etc/hosts", "poster_hash": "0" * 64},
        resign=True,
    )

    item = _only_item(packet, local_tsa)
    assert not item.shared_media_ok
    assert any("poster frame reference must be one basename" in note for note in item.notes)


@pytest.mark.parametrize("capture_id", ["/etc/hosts", "../outside", r"nested\outside"])
def test_signed_packet_rejects_unsafe_original_reference(
    capture_id: str,
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    vault, packet = _make_packet(make_vault, make_jpeg, local_tsa, tmp_path, include_originals=True)
    _rewrite_item(vault, packet, {"capture_id": capture_id}, resign=True)

    item = _only_item(packet, local_tsa)
    assert item.original_fixity_ok is False
    assert any("embedded original reference must be one basename" in note for note in item.notes)


def test_rejects_symlinked_media_file_without_following_it(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    _, packet = _make_packet(make_vault, make_jpeg, local_tsa, tmp_path)
    media = next((packet / "media").iterdir())
    outside = tmp_path / "outside.jpg"
    shutil.copyfile(media, outside)
    media.unlink()
    media.symlink_to(outside)

    item = _only_item(packet, local_tsa)
    assert not item.shared_media_ok
    assert any("must not be a symlink" in note for note in item.notes)


def test_rejects_symlinked_designated_directory(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    _, packet = _make_packet(make_vault, make_jpeg, local_tsa, tmp_path)
    outside = tmp_path / "outside-media"
    (packet / "media").rename(outside)
    (packet / "media").symlink_to(outside, target_is_directory=True)

    item = _only_item(packet, local_tsa)
    assert not item.shared_media_ok
    assert any("directory must not be a symlink" in note for note in item.notes)


def test_rejects_packet_directory_symlink(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    _, packet = _make_packet(make_vault, make_jpeg, local_tsa, tmp_path)
    alias = tmp_path / "packet-alias"
    alias.symlink_to(packet, target_is_directory=True)

    item = _only_item(alias, local_tsa)
    assert not item.shared_media_ok
    assert any("packet directory must not be a symlink" in note for note in item.notes)


def test_rejects_directory_in_place_of_media_file(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    _, packet = _make_packet(make_vault, make_jpeg, local_tsa, tmp_path)
    media = next((packet / "media").iterdir())
    media.unlink()
    media.mkdir()

    item = _only_item(packet, local_tsa)
    assert not item.shared_media_ok
    assert any("not a regular file" in note for note in item.notes)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO creation is not portable")
def test_rejects_fifo_before_reading(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    _, packet = _make_packet(make_vault, make_jpeg, local_tsa, tmp_path)
    media = next((packet / "media").iterdir())
    media.unlink()
    os.mkfifo(media)

    item = _only_item(packet, local_tsa)
    assert not item.shared_media_ok
    assert any("not a regular file" in note for note in item.notes)


def test_rejects_file_over_verification_ceiling_before_hashing(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, packet = _make_packet(make_vault, make_jpeg, local_tsa, tmp_path)
    media = next((packet / "media").iterdir())
    monkeypatch.setattr(verifier, "_MAX_REFERENCED_FILE_BYTES", media.stat().st_size - 1)

    item = _only_item(packet, local_tsa)
    assert not item.shared_media_ok
    assert any("verification limit" in note for note in item.notes)


def test_invalid_signature_never_inspects_bundle_file_references(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vault, packet = _make_packet(make_vault, make_jpeg, local_tsa, tmp_path, include_originals=True)
    _rewrite_item(
        vault,
        packet,
        {
            "capture_id": "/etc/hosts",
            "shared_name": "/etc/hosts",
            "poster_name": "/dev/null",
            "poster_hash": "0" * 64,
            "has_original": True,
        },
        resign=False,
    )

    def forbidden_read(*args: object, **kwargs: object) -> tuple[str | None, str | None]:
        raise AssertionError(f"referenced-file inspection was called: {args!r} {kwargs!r}")

    monkeypatch.setattr(verifier, "_hash_packet_reference", forbidden_read)
    report = verifier.verify_packet(packet, trusted_certs=[local_tsa.certificate])

    assert not report.signature_ok
    [item] = report.items
    assert not item.shared_media_ok
    assert item.original_fixity_ok is False
    assert "bundle signature invalid; referenced packet files were not read" in item.notes


def test_declared_original_must_exist_as_regular_file(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    _, packet = _make_packet(make_vault, make_jpeg, local_tsa, tmp_path, include_originals=True)
    next((packet / "originals").iterdir()).unlink()

    item = _only_item(packet, local_tsa)
    assert item.original_fixity_ok is False
    assert "embedded original file missing" in item.notes


def test_ordinary_packet_filenames_still_verify(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    _, packet = _make_packet(make_vault, make_jpeg, local_tsa, tmp_path, include_originals=True)
    report = verifier.verify_packet(packet, trusted_certs=[local_tsa.certificate])

    assert report.evidence_ready
    assert report.items[0].shared_media_ok
    assert report.items[0].original_fixity_ok is True
