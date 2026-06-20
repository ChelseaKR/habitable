# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Explicit, on-purpose EXIF handling.

Two facts are in tension. The original photo's embedded capture time and GPS are
part of the evidentiary record, so the *sealed original* keeps them untouched.
But producing a packet must never leak where a tenant lives, so any *shared or
exported copy* strips location (and, by default, all metadata). This module makes
both behaviours explicit and reports exactly what each output retains or removes —
no silent disclosure, no silent loss.

Scope: still images (JPEG/TIFF via piexif; other raster formats via Pillow).
Video metadata stripping is a separate concern and is intentionally not claimed
here; :func:`make_shared_copy` refuses files it cannot safely sanitize.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path

import piexif
from PIL import Image, UnidentifiedImageError

from .config import SharingPolicy
from .errors import CaptureError

__all__ = [
    "MediaMetadata",
    "StripReport",
    "make_shared_copy",
    "read_metadata",
]

_JPEG_SUFFIXES = {".jpg", ".jpeg"}

# A named tuple of the errors a corrupt/unreadable image raises. Referenced by name
# (not an inline `except (...)`) so the formatter cannot rewrite it to the
# parenthesis-free PEP 758 form, which is a SyntaxError on Python < 3.14 — this file
# is part of the Apache-2.0 verifier subset, kept portable for embedders. See
# docs/embedding-the-verifier.md.
_IMAGE_READ_ERRORS = (UnidentifiedImageError, OSError, ValueError)
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


# --- JPEG (piexif keeps the image bytes intact, only edits the metadata) -------


def _strip_jpeg(
    source: Path, destination: Path, policy: SharingPolicy, meta: MediaMetadata
) -> StripReport:
    shutil.copy2(source, destination)
    removed: list[str] = []
    retained: list[str] = []
    if policy.strip_all_metadata:
        piexif.remove(str(destination))
        removed.append("all-exif")
    else:
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
