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
from habitable.canonical import JSONValue, canonical_json, sha256_bytes
from habitable.capture import capture
from habitable.errors import VerificationError
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


@pytest.mark.parametrize(
    ("poster_hash_from_media", "expected_note"),
    [
        (False, "poster frame does not match its recorded hash"),
        (True, "no signed custody entry binds the poster frame to the original"),
    ],
)
def test_signed_packet_checks_poster_hash_and_custody_binding(
    poster_hash_from_media: bool,
    expected_note: str,
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    vault, packet = _make_packet(make_vault, make_jpeg, local_tsa, tmp_path)
    media = next((packet / "media").iterdir())
    media_hash = sha256_bytes(media.read_bytes())
    _rewrite_item(
        vault,
        packet,
        {
            "poster_name": media.name,
            "poster_hash": media_hash if poster_hash_from_media else "0" * 64,
        },
        resign=True,
    )

    item = _only_item(packet, local_tsa)
    assert not item.structurally_intact
    assert expected_note in item.notes


def test_signed_audio_without_transcript_or_poster_reports_accessibility_gap(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    vault, packet = _make_packet(make_vault, make_jpeg, local_tsa, tmp_path)
    _rewrite_item(vault, packet, {"media_type": "audio/mpeg"}, resign=True)

    item = _only_item(packet, local_tsa)
    assert "no transcript or poster frame recorded for this item (accessibility gap)" in item.notes


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


@pytest.mark.parametrize("replacement", ["missing", "regular-file"])
def test_rejects_missing_or_non_directory_media_directory(
    replacement: str,
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    _, packet = _make_packet(make_vault, make_jpeg, local_tsa, tmp_path)
    media_dir = packet / "media"
    shutil.rmtree(media_dir)
    if replacement == "regular-file":
        media_dir.write_bytes(b"not a directory")

    item = _only_item(packet, local_tsa)
    assert not item.shared_media_ok
    expected = "shared media directory missing"
    if replacement == "regular-file":
        expected = "shared media directory is not a regular directory"
    assert expected in item.notes


def test_rejects_packet_directory_symlink(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    _, packet = _make_packet(make_vault, make_jpeg, local_tsa, tmp_path)
    alias = tmp_path / "packet-alias"
    alias.symlink_to(packet, target_is_directory=True)

    with pytest.raises(VerificationError, match="packet directory must not be a symlink"):
        verifier.verify_packet(alias, trusted_certs=[local_tsa.certificate])


def test_control_file_reader_rejects_missing_and_non_directory_packet_roots(
    tmp_path: Path,
) -> None:
    missing = tmp_path / "missing-packet"
    with pytest.raises(VerificationError, match="packet directory could not be safely inspected"):
        verifier.verify_packet(missing)

    regular_file = tmp_path / "not-a-packet"
    regular_file.write_bytes(b"not a directory")
    with pytest.raises(VerificationError, match="packet path is not a directory"):
        verifier.verify_packet(regular_file)


def test_reference_hasher_rejects_unsafe_packet_roots(tmp_path: Path) -> None:
    missing = tmp_path / "missing"
    assert verifier._hash_packet_reference(missing, "media", "item.jpg", label="shared media") == (
        None,
        "packet directory could not be safely inspected",
    )

    regular_file = tmp_path / "regular-file"
    regular_file.write_bytes(b"not a packet")
    assert verifier._hash_packet_reference(
        regular_file, "media", "item.jpg", label="shared media"
    ) == (None, "packet path is not a directory")

    packet = tmp_path / "packet"
    packet.mkdir()
    alias = tmp_path / "packet-alias"
    alias.symlink_to(packet, target_is_directory=True)
    assert verifier._hash_packet_reference(alias, "media", "item.jpg", label="shared media") == (
        None,
        "packet directory must not be a symlink",
    )


def test_rejects_symlinked_bundle_before_parsing(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    _, packet = _make_packet(make_vault, make_jpeg, local_tsa, tmp_path)
    bundle = packet / "bundle.json"
    outside = tmp_path / "outside-bundle.json"
    bundle.replace(outside)
    bundle.symlink_to(outside)

    with pytest.raises(VerificationError, match=r"bundle\.json must not be a symlink"):
        verifier.verify_packet(packet, trusted_certs=[local_tsa.certificate])


def test_symlinked_signature_fails_without_following_it(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    _, packet = _make_packet(make_vault, make_jpeg, local_tsa, tmp_path)
    signature = packet / "bundle.sig.json"
    outside = tmp_path / "outside-signature.json"
    signature.replace(outside)
    signature.symlink_to(outside)

    report = verifier.verify_packet(packet, trusted_certs=[local_tsa.certificate])
    assert not report.signature_ok
    assert not report.items[0].shared_media_ok


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO creation is not portable")
def test_rejects_fifo_bundle_before_reading(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    _, packet = _make_packet(make_vault, make_jpeg, local_tsa, tmp_path)
    bundle = packet / "bundle.json"
    bundle.unlink()
    os.mkfifo(bundle)

    with pytest.raises(VerificationError, match=r"bundle\.json is not a regular file"):
        verifier.verify_packet(packet, trusted_certs=[local_tsa.certificate])


def test_rejects_oversized_bundle_before_parsing(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, packet = _make_packet(make_vault, make_jpeg, local_tsa, tmp_path)
    bundle = packet / "bundle.json"
    monkeypatch.setattr(verifier, "_MAX_BUNDLE_BYTES", bundle.stat().st_size - 1)

    with pytest.raises(VerificationError, match=r"bundle\.json exceeds"):
        verifier.verify_packet(packet, trusted_certs=[local_tsa.certificate])


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
