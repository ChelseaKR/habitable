# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Chelsea Kelly-Reif
"""Cross-tests for the strict RFC 8493 Habitable packet transfer adapter."""

from __future__ import annotations

import hashlib
import os
import shutil
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

_CONTRIB = Path(__file__).resolve().parent.parent / "contrib"
sys.path.insert(0, str(_CONTRIB))

import bagit_packet_adapter as bagit  # noqa: E402

_GOLDEN = Path(__file__).resolve().parent / "golden" / "packet-v3"


def _packet(tmp_path: Path, *, unicode_note: bool = False) -> Path:
    packet = tmp_path / "packet"
    shutil.copytree(_GOLDEN, packet)
    if unicode_note:
        notes = packet / "notes"
        notes.mkdir()
        (notes / "café%.txt").write_text("preserved exactly\n", encoding="utf-8")
    return packet


def _snapshot(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file() and not path.is_symlink()
    }


def _manifest_paths(path: Path) -> list[str]:
    return [line.split(maxsplit=1)[1] for line in path.read_text(encoding="utf-8").splitlines()]


def _refresh_tag_manifest(bag: Path) -> None:
    lines = []
    for name in ("bagit.txt", "manifest-sha256.txt"):
        digest = hashlib.sha256((bag / name).read_bytes()).hexdigest()
        lines.append(f"{digest}  {name}\n")
    (bag / "tagmanifest-sha256.txt").write_text("".join(lines), encoding="utf-8")


def test_create_preserves_exact_packet_and_emits_complete_bag(tmp_path: Path) -> None:
    packet = _packet(tmp_path, unicode_note=True)
    before = _snapshot(packet)
    result = bagit.create_bag(packet, tmp_path / "transfer")

    assert result.packet_report.structurally_intact
    # The synthetic golden authority is not independently trusted. Packaging
    # preserves that truth instead of promoting transfer fixity to evidence readiness.
    assert not result.packet_report.evidence_ready
    assert result.validation.ok
    assert _snapshot(result.packet_dir) == before
    assert _snapshot(packet) == before
    assert {path.name for path in result.bag_dir.iterdir()} == {
        "bagit.txt",
        "data",
        "manifest-sha256.txt",
        "tagmanifest-sha256.txt",
    }
    assert (result.bag_dir / "bagit.txt").read_bytes() == (
        b"BagIt-Version: 1.0\nTag-File-Character-Encoding: UTF-8\n"
    )
    assert "data/packet/notes/café%25.txt" in _manifest_paths(
        result.bag_dir / "manifest-sha256.txt"
    )
    assert _manifest_paths(result.bag_dir / "tagmanifest-sha256.txt") == [
        "bagit.txt",
        "manifest-sha256.txt",
    ]


def test_output_is_deterministic_and_manifest_is_utf8_sorted(tmp_path: Path) -> None:
    packet = _packet(tmp_path, unicode_note=True)
    first = bagit.create_bag(packet, tmp_path / "first").bag_dir
    second = bagit.create_bag(packet, tmp_path / "second").bag_dir

    assert _snapshot(first) == _snapshot(second)
    paths = _manifest_paths(first / "manifest-sha256.txt")
    assert paths == sorted(paths, key=lambda value: value.encode("utf-8"))


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda path: path.write_bytes(b"tampered"), "SHA-256 mismatch"),
        (lambda path: path.unlink(), "payload manifest and data/packet differ"),
    ],
)
def test_validate_detects_tampered_or_missing_payload(
    tmp_path: Path, mutation: Callable[[Path], object], message: str
) -> None:
    bag = bagit.create_bag(_packet(tmp_path), tmp_path / "bag").bag_dir
    payload_file = next(path for path in (bag / "data" / "packet").rglob("*") if path.is_file())
    mutation(payload_file)

    result = bagit.validate_bag(bag)
    assert not result.ok
    assert message in result.problems[0]


def test_validate_detects_extra_payload(tmp_path: Path) -> None:
    bag = bagit.create_bag(_packet(tmp_path), tmp_path / "bag").bag_dir
    (bag / "data" / "packet" / "unlisted.txt").write_text("extra", encoding="utf-8")

    result = bagit.validate_bag(bag)
    assert not result.ok
    assert "payload manifest and data/packet differ" in result.problems[0]
    assert "extra data/packet/unlisted.txt" in result.problems[0]


def test_validate_checks_tag_manifest_digests(tmp_path: Path) -> None:
    bag = bagit.create_bag(_packet(tmp_path), tmp_path / "bag").bag_dir
    manifest = bag / "manifest-sha256.txt"
    # Digest hex is case-insensitive under RFC 8493, so payload validation still
    # passes. The tag manifest must nevertheless detect the changed tag bytes.
    first, *rest = manifest.read_text(encoding="utf-8").splitlines(keepends=True)
    digest, manifest_path = first.rstrip("\n").split(maxsplit=1)
    manifest.write_text(f"{digest.upper()}  {manifest_path}\n" + "".join(rest), encoding="utf-8")

    result = bagit.validate_bag(bag)
    assert not result.ok
    assert "SHA-256 mismatch for manifest-sha256.txt" in result.problems[0]


def test_validate_rejects_missing_or_extra_tags(tmp_path: Path) -> None:
    missing_bag = bagit.create_bag(_packet(tmp_path / "one"), tmp_path / "missing").bag_dir
    (missing_bag / "tagmanifest-sha256.txt").unlink()
    assert "missing required tag" in bagit.validate_bag(missing_bag).problems[0]

    extra_bag = bagit.create_bag(_packet(tmp_path / "two"), tmp_path / "extra").bag_dir
    (extra_bag / "bag-info.txt").write_text("External-Description: surprise\n", encoding="utf-8")
    result = bagit.validate_bag(extra_bag)
    assert not result.ok
    assert "untracked tag file" in result.problems[0]


def test_invalid_source_packet_is_never_published(tmp_path: Path) -> None:
    packet = _packet(tmp_path)
    media = next((packet / "media").iterdir())
    media.write_bytes(b"not the signed media")
    output = tmp_path / "bag"

    with pytest.raises(bagit.BagItAdapterError, match="not structurally intact"):
        bagit.create_bag(packet, output)
    assert not output.exists()
    assert list(tmp_path.glob(".bag.stage-*")) == []


def test_source_root_and_nested_symlinks_are_rejected(tmp_path: Path) -> None:
    packet = _packet(tmp_path)
    root_link = tmp_path / "packet-link"
    root_link.symlink_to(packet, target_is_directory=True)
    with pytest.raises(bagit.BagItAdapterError, match="root must not be a symlink"):
        bagit.create_bag(root_link, tmp_path / "root-link-bag")

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret").write_text("must never be copied", encoding="utf-8")
    (packet / "nested-link").symlink_to(outside, target_is_directory=True)
    with pytest.raises(bagit.BagItAdapterError, match="contains a symlink"):
        bagit.create_bag(packet, tmp_path / "nested-link-bag")


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO creation is unavailable")
def test_source_fifo_is_rejected_without_reading_it(tmp_path: Path) -> None:
    packet = _packet(tmp_path)
    os.mkfifo(packet / "blocking-pipe")

    with pytest.raises(bagit.BagItAdapterError, match="non-regular file"):
        bagit.create_bag(packet, tmp_path / "bag")


def test_validator_rejects_payload_symlink(tmp_path: Path) -> None:
    bag = bagit.create_bag(_packet(tmp_path), tmp_path / "bag").bag_dir
    payload = next(path for path in (bag / "data" / "packet").rglob("*") if path.is_file())
    outside = tmp_path / "outside"
    outside.write_text("outside", encoding="utf-8")
    payload.unlink()
    payload.symlink_to(outside)

    result = bagit.validate_bag(bag)
    assert not result.ok
    assert "contains a symlink" in result.problems[0]


@pytest.mark.parametrize(
    "unsafe",
    [
        "/absolute",
        "../escape",
        "nested/../escape",
        "nested//empty",
        r"C:\escape",
        r"nested\separator",
        "notes/line\nbreak",
        "data/CON.txt",
        "notes/\udcff.txt",
    ],
)
def test_path_profile_rejects_absolute_traversal_and_separator_ambiguity(unsafe: str) -> None:
    with pytest.raises(bagit.BagItAdapterError):
        bagit._validate_relative_paths([unsafe], context="test")


def test_path_profile_rejects_case_and_unicode_collisions() -> None:
    with pytest.raises(bagit.BagItAdapterError, match="collide by case"):
        bagit._validate_relative_paths(["media/Photo.jpg", "media/photo.jpg"], context="test")
    with pytest.raises(bagit.BagItAdapterError, match="Unicode normalization"):
        bagit._validate_relative_paths(
            ["notes/café.txt", "notes/cafe\N{COMBINING ACUTE ACCENT}.txt"], context="test"
        )


@pytest.mark.parametrize(
    "unsafe_manifest_path",
    [
        "data/packet/../escape",
        "/absolute/escape",
        r"data\packet\escape",
    ],
)
def test_validator_rejects_manifest_escape_before_access(
    tmp_path: Path, unsafe_manifest_path: str
) -> None:
    bag = bagit.create_bag(_packet(tmp_path), tmp_path / "bag").bag_dir
    manifest = bag / "manifest-sha256.txt"
    digest = manifest.read_text(encoding="utf-8").split(maxsplit=1)[0]
    manifest.write_text(f"{digest}  {unsafe_manifest_path}\n", encoding="utf-8")
    _refresh_tag_manifest(bag)

    result = bagit.validate_bag(bag)
    assert not result.ok
    assert any(
        phrase in result.problems[0]
        for phrase in ("traversal", "relative", "backslash", "outside data/packet")
    )


def test_validator_rejects_duplicate_and_case_colliding_manifest_paths(tmp_path: Path) -> None:
    first_bag = bagit.create_bag(_packet(tmp_path / "one"), tmp_path / "duplicate").bag_dir
    manifest = first_bag / "manifest-sha256.txt"
    first_line = manifest.read_text(encoding="utf-8").splitlines()[0]
    manifest.write_text(first_line + "\n" + first_line + "\n", encoding="utf-8")
    _refresh_tag_manifest(first_bag)
    assert "duplicate path" in bagit.validate_bag(first_bag).problems[0]

    second_bag = bagit.create_bag(_packet(tmp_path / "two"), tmp_path / "collision").bag_dir
    manifest = second_bag / "manifest-sha256.txt"
    first_line = manifest.read_text(encoding="utf-8").splitlines()[0]
    digest, original = first_line.split(maxsplit=1)
    parent, filename = original.rsplit("/", 1)
    collision = parent + "/" + filename.swapcase()
    manifest.write_text(first_line + "\n" + f"{digest}  {collision}\n", encoding="utf-8")
    _refresh_tag_manifest(second_bag)
    assert "collide by case" in bagit.validate_bag(second_bag).problems[0]


def test_existing_outputs_and_overlapping_paths_are_rejected_unchanged(tmp_path: Path) -> None:
    packet = _packet(tmp_path)
    output = tmp_path / "existing"
    output.mkdir()
    sentinel = output / "keep.txt"
    sentinel.write_text("keep", encoding="utf-8")

    with pytest.raises(bagit.BagItAdapterError, match="refusing to replace"):
        bagit.create_bag(packet, output)
    assert sentinel.read_text(encoding="utf-8") == "keep"

    with pytest.raises(bagit.BagItAdapterError, match="must not contain one another"):
        bagit.create_bag(packet, packet / "nested-output")


def test_file_and_symlink_outputs_are_rejected(tmp_path: Path) -> None:
    packet = _packet(tmp_path)
    output_file = tmp_path / "output-file"
    output_file.write_text("keep", encoding="utf-8")
    with pytest.raises(bagit.BagItAdapterError, match="refusing to replace"):
        bagit.create_bag(packet, output_file)
    assert output_file.read_text(encoding="utf-8") == "keep"

    real = tmp_path / "real"
    real.mkdir()
    output_link = tmp_path / "output-link"
    output_link.symlink_to(real, target_is_directory=True)
    with pytest.raises(bagit.BagItAdapterError, match="refusing to replace"):
        bagit.create_bag(packet, output_link)


def test_build_failure_leaves_no_partial_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    packet = _packet(tmp_path)
    output = tmp_path / "bag"

    def fail_manifest(_digests: dict[str, str]) -> bytes:
        raise RuntimeError("synthetic render failure")

    monkeypatch.setattr(bagit, "_render_manifest", fail_manifest)
    with pytest.raises(RuntimeError, match="synthetic render failure"):
        bagit.create_bag(packet, output)
    assert not output.exists()
    assert list(tmp_path.glob(".bag.stage-*")) == []


def test_cli_create_validate_and_report_failure(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    packet = _packet(tmp_path)
    bag = tmp_path / "bag"
    assert bagit._main(["create", str(packet), str(bag)]) == 0
    assert "created" in capsys.readouterr().out
    assert bagit._main(["validate", str(bag)]) == 0
    assert "valid Habitable transfer bag" in capsys.readouterr().out

    (bag / "bagit.txt").write_text("tampered", encoding="utf-8")
    assert bagit._main(["validate", str(bag)]) == 1
    assert "invalid Habitable transfer bag" in capsys.readouterr().err


def test_cli_rejects_invalid_source(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    packet = _packet(tmp_path)
    (packet / "bundle.sig.json").write_text("{}", encoding="utf-8")

    assert bagit._main(["create", str(packet), str(tmp_path / "bag")]) == 1
    assert "could not create Habitable transfer bag" in capsys.readouterr().err
