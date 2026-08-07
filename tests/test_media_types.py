# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Regression coverage for issue #158.

A capture whose media type had no packet export mapping (``.heic``, the
iPhone default photo format) used to ship with no bytes, no custody binding,
and a ``habitable verify`` verdict of READY. This module pins the fix's three
separable decisions:

1. ``build_packet`` fails closed -- it refuses to publish an item that would
   carry neither a shared copy nor an embedded original, for *any* media
   type, known or not (:func:`test_a_genuinely_unmapped_media_type_is_refused_at_export`).
2. The exporter and the capture classifier now read one canonical registry
   (:mod:`habitable.media_types`), and every entry in it -- including
   ``.heic``, which has no default sanitizer -- has a working export path,
   proven end to end: capture, export, and independent verification
   (:func:`test_every_registered_media_type_has_a_working_export_path`).
3. Decision 3 (an item with no evidence bytes can never be
   ``evidence_ready``) is pinned directly against ``verify.py`` in
   ``tests/test_packet_verify.py``.
"""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from PIL import Image

from habitable.capture import capture
from habitable.errors import PacketError
from habitable.media import ffmpeg_available
from habitable.media_types import REGISTRY, MediaTypeSpec
from habitable.packet import _DATA_EXT_BY_TYPE, _EXT_BY_TYPE, build_packet
from habitable.tsa import LocalRfc3161TSA
from habitable.vault import Vault
from habitable.verify import verify_packet

_PILLOW_FORMAT_BY_TYPE = {
    "image/jpeg": "JPEG",
    "image/png": "PNG",
    "image/webp": "WEBP",
    "image/tiff": "TIFF",
}

# ffmpeg lavfi source args per export kind; the fixture is muxed into whatever
# container/codec its extension implies (explicit -c:v/-c:a so the choice
# never silently depends on ffmpeg's per-container default).
_FFMPEG_ARGS_BY_EXT = {
    ".mp4": ["color=c=blue:s=32x32:d=0.3", "-c:v", "libx264", "-pix_fmt", "yuv420p"],
    ".mov": ["color=c=blue:s=32x32:d=0.3", "-c:v", "libx264", "-pix_fmt", "yuv420p"],
    ".wav": ["sine=frequency=440:duration=0.3"],
    ".m4a": ["sine=frequency=440:duration=0.3", "-c:a", "aac"],
    ".mp3": ["sine=frequency=440:duration=0.3", "-c:a", "libmp3lame"],
}


def _pillow_fixture(tmp_path: Path, spec: MediaTypeSpec) -> Path:
    path = tmp_path / f"sample{spec.extensions[0]}"
    Image.new("RGB", (8, 8), (120, 30, 30)).save(path, _PILLOW_FORMAT_BY_TYPE[spec.media_type])
    return path


def _ffmpeg_fixture(tmp_path: Path, spec: MediaTypeSpec) -> Path | None:
    ext = spec.extensions[0]
    path = tmp_path / f"sample{ext}"
    lavfi_source, *codec_args = _FFMPEG_ARGS_BY_EXT[ext]
    cmd = ["ffmpeg", "-y", "-f", "lavfi", "-i", lavfi_source, *codec_args, str(path)]
    try:
        subprocess.run(cmd, capture_output=True, check=True, timeout=30)
    except subprocess.CalledProcessError, OSError:
        return None
    return path


def _fixture_for(spec: MediaTypeSpec, tmp_path: Path) -> Path | None:
    """Fabricate a minimal, synthetic capture source for ``spec`` -- never real
    media (matching this project's fixture ethos, see tests/conftest.py)."""
    if spec.media_type == "image/heic":
        # No HEIC decoder is available to this project (see media_types.py's
        # module docstring); capture-time classification is by *extension*
        # only (habitable.capture._read_media_metadata degrades to a fallback
        # on unreadable bytes rather than raising), so placeholder bytes
        # exercise exactly the same code path a real iPhone .heic would.
        path = tmp_path / f"sample{spec.extensions[0]}"
        path.write_bytes(b"SYNTHETIC-PLACEHOLDER-NOT-A-REAL-HEIC-FILE")
        return path
    if spec.media_type in _PILLOW_FORMAT_BY_TYPE:
        return _pillow_fixture(tmp_path, spec)
    if spec.export_kind in {"video", "audio"}:
        return _ffmpeg_fixture(tmp_path, spec)
    if spec.media_type == "text/csv":
        path = tmp_path / f"sample{spec.extensions[0]}"
        path.write_text(
            "timestamp,value\n2026-01-01T00:00:00Z,72.5\n2026-01-01T01:00:00Z,73.0\n",
            encoding="utf-8",
        )
        return path
    raise AssertionError(f"test_media_types.py has no fixture strategy for {spec.media_type!r}")


def _cases() -> list[Any]:
    cases = []
    for spec in REGISTRY:
        marks = [pytest.mark.skipif(not ffmpeg_available(), reason="ffmpeg not installed")]
        if spec.export_kind not in {"video", "audio"}:
            marks = []
        cases.append(pytest.param(spec, id=spec.media_type, marks=marks))
    return cases


class TestRegistryIsPacketExporterSingleSourceOfTruth:
    """Fast, environment-independent consistency checks between the registry
    and the maps packet.py derives from it -- catches a hand-edit that lets
    the two drift again without needing ffmpeg/Pillow or a full export."""

    def test_supported_kinds_appear_in_exactly_one_derived_map(self) -> None:
        for spec in REGISTRY:
            if spec.export_kind in {"image", "video", "audio"}:
                assert _EXT_BY_TYPE.get(spec.media_type) == spec.export_ext
                assert spec.media_type not in _DATA_EXT_BY_TYPE
            elif spec.export_kind == "data":
                assert _DATA_EXT_BY_TYPE.get(spec.media_type) == spec.export_ext
                assert spec.media_type not in _EXT_BY_TYPE
            else:
                assert spec.export_kind == "unsupported"
                assert spec.export_ext == ""

    def test_unsupported_kinds_are_absent_from_both_export_maps(self) -> None:
        """The exact shape of issue #158's original gap: a registered-but-
        unsupported type (e.g. image/heic) must never silently reappear in an
        export map without its `export_kind` being updated to match."""
        unsupported = {spec.media_type for spec in REGISTRY if spec.export_kind == "unsupported"}
        assert "image/heic" in unsupported  # the fix stays honest about today's real gap
        for media_type in unsupported:
            assert media_type not in _EXT_BY_TYPE
            assert media_type not in _DATA_EXT_BY_TYPE


def test_a_genuinely_unmapped_media_type_is_refused_at_export(
    make_vault: Callable[..., Vault],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    """Decision 1's backstop for a media type that is not even in the
    registry -- e.g. a future capture type nobody has classified yet. This is
    independent of decision 2's registry: the guard in ``packet.py`` must
    catch *any* item that would ship with no bytes, not just the ones the
    registry already knows to mark unsupported.
    """
    vault = make_vault()
    issue = vault.document.add_issue(category="mold", title="Mold", issue_id="i1")
    source = tmp_path / "sample.bin"
    source.write_bytes(b"some hypothetical future media type's bytes")
    result = capture(
        vault,
        source,
        issue_id=issue,
        tsa=local_tsa,
        media_type="application/x-hypothetical-unmapped",
    )

    out = tmp_path / "packet"
    with pytest.raises(PacketError, match=re.escape("application/x-hypothetical-unmapped")):
        build_packet(vault, out, generated_at="2026-01-02T00:10:00Z")
    assert not out.exists()

    # The refusal names the capture too, not just the media type.
    with pytest.raises(PacketError, match=re.escape(result.capture_id)):
        build_packet(vault, out, generated_at="2026-01-02T00:10:00Z")

    # --include-originals still rescues it -- decision 1 does not strand a
    # capture whose bytes are otherwise perfectly good evidence.
    rescued = build_packet(vault, out, include_originals=True, generated_at="2026-01-02T00:10:00Z")
    assert rescued.item_count == 1
    report = verify_packet(out, trusted_certs=[local_tsa.certificate])
    assert report.evidence_ready


@pytest.mark.parametrize("spec", _cases())
def test_every_registered_media_type_has_a_working_export_path(
    spec: MediaTypeSpec,
    make_vault: Callable[..., Vault],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    """issue #158's core regression guard: no entry in the canonical media-type
    registry is ever a dead end. A supported type exports real, hash-verified
    shared media by default; an unsupported type (today: only image/heic)
    refuses a default-policy export and exports real, hash-verified bytes via
    --include-originals instead -- proven with a real capture -> export ->
    independent-verify round trip, not just data-shape assertions.
    """
    source = _fixture_for(spec, tmp_path)
    if source is None:
        pytest.skip(f"could not fabricate a {spec.media_type} fixture in this environment")

    vault = make_vault()
    issue = vault.document.add_issue(category="mold", title="Mold", issue_id="i1")
    capture(vault, source, issue_id=issue, tsa=local_tsa)

    out = tmp_path / "packet"
    if spec.export_kind == "unsupported":
        with pytest.raises(PacketError, match=re.escape(spec.media_type)):
            build_packet(vault, out, generated_at="2026-01-02T00:10:00Z")
        assert not out.exists()

        build_packet(vault, out, include_originals=True, generated_at="2026-01-02T00:10:00Z")
        bundle = json.loads((out / "bundle.json").read_text())
        item = bundle["items"][0]
        assert item["shared_name"] == ""
        assert item["has_original"] is True
        assert (out / "originals" / item["capture_id"]).is_file()
        html = (out / "packet.html").read_text(encoding="utf-8")
        assert "sealed original file is embedded and hash-verified" in html
        assert f"originals/{item['capture_id']}" in html
    else:
        build_packet(vault, out, generated_at="2026-01-02T00:10:00Z")
        bundle = json.loads((out / "bundle.json").read_text())
        item = bundle["items"][0]
        assert item["shared_name"]
        assert (out / "media" / item["shared_name"]).is_file()

    report = verify_packet(out, trusted_certs=[local_tsa.certificate])
    assert report.structurally_intact, report.items[0].notes
    assert report.evidence_ready
    assert all(v.evidence_present for v in report.items)
