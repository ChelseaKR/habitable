# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Explicit, on-purpose EXIF handling.

Two facts are in tension. The original photo's embedded capture time and GPS are
part of the evidentiary record, so the *sealed original* keeps them untouched.
The default shared-copy policy removes all embedded metadata. A nondefault policy
can retain non-GPS metadata or all metadata, including location. This module makes
the selected behavior explicit and reports what each output retains or removes.

Scope: still images. Full JPEG sanitization rebuilds decoded, correctly oriented
pixels through Pillow and removes every APP/COM segment; location-only JPEG and
TIFF EXIF editing uses piexif; other raster formats use Pillow. Video/audio
metadata stripping lives in :mod:`habitable.media` instead (a different
toolchain -- ffmpeg -- and a different optional-dependency story, see EXP-07);
:func:`make_shared_copy` refuses files it cannot safely sanitize.
"""

from __future__ import annotations

import io
import os
import shutil
import tempfile
import warnings
from dataclasses import dataclass, field
from pathlib import Path

import piexif
from PIL import Image, ImageOps, UnidentifiedImageError

from .config import SharingPolicy
from .errors import CaptureError

__all__ = [
    "MediaMetadata",
    "StripReport",
    "make_shared_copy",
    "read_metadata",
]

_JPEG_SUFFIXES = {".jpg", ".jpeg"}
_JPEG_METADATA_MARKERS = frozenset({*range(0xE0, 0xF0), 0xFE})
_JPEG_STANDALONE_MARKERS = frozenset({0x01, *range(0xD0, 0xD8)})

# A named tuple of the errors a corrupt/unreadable image raises. Referenced by name
# (not an inline `except (...)`) so the formatter cannot rewrite it to the
# parenthesis-free PEP 758 form, which is a SyntaxError on Python < 3.14 — this file
# is part of the Apache-2.0 verifier subset, kept portable for embedders. See
# docs/embedding-the-verifier.md.
_IMAGE_READ_ERRORS = (
    UnidentifiedImageError,
    OSError,
    ValueError,
    TypeError,
    EOFError,
    SyntaxError,
    Image.DecompressionBombError,
    Image.DecompressionBombWarning,
)
_TIFF_SUFFIXES = {".tif", ".tiff"}


@dataclass(frozen=True, slots=True)
class MediaMetadata:
    """What we could read from a file's embedded metadata."""

    media_format: str
    has_location: bool
    capture_time: str | None
    fields_present: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class StripReport:
    """What a shared copy retained and removed, for honest disclosure to the user."""

    source: str
    destination: str
    media_format: str
    source_had_location: bool
    removed: tuple[str, ...] = field(default_factory=tuple)
    retained: tuple[str, ...] = field(default_factory=tuple)

    def summary(self) -> str:
        removed = ", ".join(self.removed) or "nothing"
        retained = ", ".join(self.retained) or "nothing"
        return f"removed: {removed}; retained: {retained}"


def read_metadata(path: Path) -> MediaMetadata:
    """Read embedded metadata from a sealed original without modifying it."""
    suffix = path.suffix.lower()
    if suffix in _JPEG_SUFFIXES or suffix in _TIFF_SUFFIXES:
        return _read_metadata_piexif(path)
    return _read_metadata_pillow(path)


def make_shared_copy(source: Path, destination: Path, policy: SharingPolicy) -> StripReport:
    """Write a sanitized copy of ``source`` to ``destination`` per ``policy``.

    The original is never touched. By default all metadata is removed; if only
    ``strip_location`` is set, capture time and other tags are kept but GPS is
    dropped.
    """
    meta = read_metadata(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    suffix = source.suffix.lower()

    if suffix in _JPEG_SUFFIXES:
        return _strip_jpeg(source, destination, policy, meta)
    return _strip_with_pillow(source, destination, policy, meta)


# --- JPEG ---------------------------------------------------------------------


def _strip_jpeg(
    source: Path, destination: Path, policy: SharingPolicy, meta: MediaMetadata
) -> StripReport:
    removed: list[str] = []
    retained: list[str] = []
    if policy.strip_all_metadata:
        _strip_all_jpeg_metadata(source, destination)
        removed.append("all-embedded-metadata")
        retained.append("pixels-only")
    else:
        shutil.copy2(source, destination)
        try:
            exif_dict = piexif.load(str(destination))
        except Exception as exc:  # piexif raises bare exceptions on odd inputs
            raise CaptureError(f"could not parse EXIF of {source.name}: {exc}") from exc
        if policy.strip_location and exif_dict.get("GPS"):
            exif_dict["GPS"] = {}
            removed.append("gps")
        retained.append("capture-time" if meta.capture_time else "other-exif")
        piexif.insert(piexif.dump(exif_dict), str(destination))
    return StripReport(
        source=str(source),
        destination=str(destination),
        media_format=meta.media_format,
        source_had_location=meta.has_location,
        removed=tuple(removed),
        retained=tuple(retained),
    )


def _strip_all_jpeg_metadata(source: Path, destination: Path) -> None:
    """Decode, orient, and re-encode a JPEG without carrying source metadata.

    Removing only the EXIF APP1 segment is not sufficient: JPEGs can also carry
    XMP, IPTC/Photoshop, ICC, comments, thumbnails, and vendor-specific payloads
    in other APP/COM segments.  Rebuilding an image from decoded pixels prevents
    Pillow from copying any of those source fields.  The second pass removes the
    encoder's own application segments too, so the postcondition is a JPEG made
    only of image-coding segments and scan data.

    EXIF orientation is applied to the pixels before it is discarded.  The write
    is staged and atomically published only after the sanitized bytes decode, so
    malformed inputs cannot leave an unsanitized or partial new destination.
    """
    if source.resolve() == destination.resolve() or (
        destination.exists() and source.samefile(destination)
    ):
        raise CaptureError("source and shared-copy destination must be different files")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(source) as image:
                if image.format != "JPEG":
                    raise ValueError("file extension says JPEG but decoded format is not JPEG")
                image.load()
                ImageOps.exif_transpose(image, in_place=True)
                oriented: Image.Image = image
                if oriented.mode not in {"L", "RGB"}:
                    oriented = oriented.convert("RGB")
                clean = Image.new(oriented.mode, oriented.size)
                clean.paste(oriented)
                expected_size = clean.size
                encoded = io.BytesIO()
                clean.save(encoded, format="JPEG", quality=95, subsampling=0)

        sanitized = _remove_jpeg_application_segments(encoded.getvalue())
        with Image.open(io.BytesIO(sanitized)) as check:
            if check.format != "JPEG" or check.size != expected_size or check.info:
                raise ValueError("sanitized JPEG failed its metadata-free postcondition")
            check.load()
    except _IMAGE_READ_ERRORS as exc:
        raise CaptureError(
            f"refusing to share {source.name}: cannot safely strip metadata from JPEG ({exc})"
        ) from exc

    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(sanitized)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(destination)
        temporary = None
    except OSError as exc:
        raise CaptureError(f"could not write sanitized copy of {source.name}: {exc}") from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _remove_jpeg_application_segments(encoded: bytes) -> bytes:
    """Return a JPEG without APP0..APP15 or COM segments, or reject it.

    The parser understands multiple scans, byte-stuffed entropy data, restart
    markers, and metadata between progressive scans.  It is intentionally strict:
    malformed lengths, missing EOI, or trailing bytes fail instead of producing a
    file whose privacy properties are uncertain.
    """
    if not encoded.startswith(b"\xff\xd8"):
        raise ValueError("missing JPEG start-of-image marker")

    output = bytearray(encoded[:2])
    position = 2
    in_scan = False
    while position < len(encoded):
        if in_scan:
            position = _copy_jpeg_scan_data(encoded, position, output)
            in_scan = False

        marker, marker_bytes, position = _read_jpeg_marker(encoded, position)

        if marker == 0xD9:  # EOI
            output.extend(marker_bytes)
            if position != len(encoded):
                raise ValueError("JPEG has trailing data after end-of-image")
            return bytes(output)
        if marker in _JPEG_STANDALONE_MARKERS:
            output.extend(marker_bytes)
            continue
        if marker in {0x00, 0xD8}:
            raise ValueError("invalid standalone JPEG marker")
        segment_end = _jpeg_segment_end(encoded, position)

        if marker not in _JPEG_METADATA_MARKERS:
            output.extend(marker_bytes)
            output.extend(encoded[position:segment_end])
        position = segment_end
        if marker == 0xDA:  # SOS
            in_scan = True

    raise ValueError("JPEG has no end-of-image marker")


def _copy_jpeg_scan_data(encoded: bytes, position: int, output: bytearray) -> int:
    """Copy entropy bytes through stuffing/restarts; return at the next real marker."""
    while True:
        marker_start = encoded.find(b"\xff", position)
        if marker_start < 0:
            raise ValueError("JPEG scan has no end marker")
        output.extend(encoded[position:marker_start])
        marker_code_at = marker_start + 1
        while marker_code_at < len(encoded) and encoded[marker_code_at] == 0xFF:
            marker_code_at += 1
        if marker_code_at >= len(encoded):
            raise ValueError("truncated JPEG marker in scan data")
        marker = encoded[marker_code_at]
        if marker != 0x00 and not 0xD0 <= marker <= 0xD7:
            return marker_start
        output.extend(encoded[marker_start : marker_code_at + 1])
        position = marker_code_at + 1


def _read_jpeg_marker(encoded: bytes, position: int) -> tuple[int, bytes, int]:
    """Read one marker and return its code, original marker bytes, and next offset."""
    if encoded[position] != 0xFF:
        raise ValueError("expected JPEG marker")
    marker_start = position
    marker_code_at = marker_start + 1
    while marker_code_at < len(encoded) and encoded[marker_code_at] == 0xFF:
        marker_code_at += 1
    if marker_code_at >= len(encoded):
        raise ValueError("truncated JPEG marker")
    marker = encoded[marker_code_at]
    return marker, encoded[marker_start : marker_code_at + 1], marker_code_at + 1


def _jpeg_segment_end(encoded: bytes, position: int) -> int:
    """Validate one length-prefixed JPEG segment and return its exclusive end."""
    if position + 2 > len(encoded):
        raise ValueError("truncated JPEG segment length")
    segment_length = int.from_bytes(encoded[position : position + 2], "big")
    if segment_length < 2:
        raise ValueError("invalid JPEG segment length")
    segment_end = position + segment_length
    if segment_end > len(encoded):
        raise ValueError("truncated JPEG segment")
    return segment_end


# --- other raster formats (re-encode through Pillow drops embedded metadata) ---


def _strip_with_pillow(
    source: Path, destination: Path, policy: SharingPolicy, meta: MediaMetadata
) -> StripReport:
    try:
        with Image.open(source) as image:
            clean = Image.new(image.mode, image.size)
            clean.putdata(list(image.getdata()))
            clean.save(destination, format=image.format)
            media_format = image.format or meta.media_format
    except (UnidentifiedImageError, OSError, ValueError) as exc:
        raise CaptureError(
            f"refusing to share {source.name}: cannot safely strip metadata from "
            f"this file type ({exc})"
        ) from exc
    return StripReport(
        source=str(source),
        destination=str(destination),
        media_format=media_format,
        source_had_location=meta.has_location,
        removed=("all-embedded-metadata",),
        retained=("pixels-only",),
    )


# --- metadata reading ---------------------------------------------------------


def _read_metadata_piexif(path: Path) -> MediaMetadata:
    try:
        exif_dict = piexif.load(str(path))
    except Exception:  # no/!invalid EXIF is normal for many files
        return MediaMetadata(
            media_format=path.suffix.lstrip(".").upper() or "JPEG",
            has_location=False,
            capture_time=None,
            fields_present=(),
        )
    has_location = bool(exif_dict.get("GPS"))
    capture_time = _decode_capture_time(exif_dict)
    present: list[str] = []
    for ifd in ("0th", "Exif", "GPS", "1st"):
        if exif_dict.get(ifd):
            present.append(ifd)
    return MediaMetadata(
        media_format=path.suffix.lstrip(".").upper() or "JPEG",
        has_location=has_location,
        capture_time=capture_time,
        fields_present=tuple(present),
    )


def _decode_capture_time(exif_dict: dict[str, dict[int, object]]) -> str | None:
    exif_ifd = exif_dict.get("Exif") or {}
    raw = exif_ifd.get(piexif.ExifIFD.DateTimeOriginal)
    if isinstance(raw, bytes):
        return raw.decode("ascii", "replace")
    if isinstance(raw, str):
        return raw
    return None


def _read_metadata_pillow(path: Path) -> MediaMetadata:
    try:
        with Image.open(path) as image:
            media_format = image.format or path.suffix.lstrip(".").upper()
            exif = image.getexif()
            has_location = _GPS_IFD_TAG in exif
            present = ["exif"] if len(exif) else []
            if getattr(image, "info", None):
                present.append("info")
            return MediaMetadata(
                media_format=media_format,
                has_location=has_location,
                capture_time=None,
                fields_present=tuple(present),
            )
    except _IMAGE_READ_ERRORS:
        return MediaMetadata(
            media_format=path.suffix.lstrip(".").upper() or "UNKNOWN",
            has_location=False,
            capture_time=None,
            fields_present=(),
        )


# EXIF tag id for the GPS IFD pointer (0x8825).
_GPS_IFD_TAG = 0x8825
