# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Video/audio metadata stripping and poster-frame extraction (EXP-07).

``exif.py`` covers still images; this module covers the temporal media FIX-11
found half-built: video could be captured and sealed but never packetized,
because nothing could strip its metadata or produce an accessible rendering.
This closes that gap for real.

The one real dependency is an external ``ffmpeg`` binary -- never bundled, never
pip-installed. That is deliberate: a hard dependency on a multi-hundred-megabyte
media toolchain would work against the low-end-device/small-footprint value
(R-03), so video/audio evidence stays fully optional. A sealed video/audio
original is always captured, hashed, and timestamped regardless of whether
ffmpeg is present -- only *sharing/packetizing* it needs ffmpeg, and refuses
cleanly (never silently) when it is missing, the same honest-refusal posture
FIX-11 used for capture.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from .config import SharingPolicy
from .errors import CaptureError
from .exif import MediaMetadata, StripReport

__all__ = [
    "AUDIO_EXTENSIONS",
    "VIDEO_EXTENSIONS",
    "extract_poster_frame",
    "ffmpeg_available",
    "make_shared_media_copy",
    "probe_metadata",
]

VIDEO_EXTENSIONS = {".mp4", ".mov"}
AUDIO_EXTENSIONS = {".m4a", ".mp3", ".wav"}

_FFMPEG = "ffmpeg"
_FFPROBE = "ffprobe"
_SUBPROCESS_TIMEOUT = 120
_LOCATION_TAG_HINTS = ("location", "gps", "iso6709")


def ffmpeg_available() -> bool:
    """Whether both ``ffmpeg`` and ``ffprobe`` are on PATH."""
    return shutil.which(_FFMPEG) is not None and shutil.which(_FFPROBE) is not None


def probe_metadata(path: Path) -> MediaMetadata:
    """Read what a video/audio file's container metadata discloses, without editing it.

    Uses ``ffprobe`` (read-only) so this never touches the sealed original. If
    ffprobe is unavailable or the file cannot be probed, this degrades to an
    honest "nothing known" result rather than crashing capture -- the sealed
    original is still captured either way; only informational fields are lost.
    """
    media_format = path.suffix.lstrip(".").upper() or "UNKNOWN"
    if not ffmpeg_available():
        return MediaMetadata(
            media_format=media_format, has_location=False, capture_time=None, fields_present=()
        )
    try:
        result = subprocess.run(
            [
                _FFPROBE,
                "-v",
                "quiet",
                "-print_format",
                "json",
                "-show_format",
                "-show_streams",
                str(path),
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        payload = json.loads(result.stdout) if result.stdout else {}
    except subprocess.SubprocessError, json.JSONDecodeError, OSError:
        return MediaMetadata(
            media_format=media_format, has_location=False, capture_time=None, fields_present=()
        )

    tags: dict[str, str] = {}
    fmt = payload.get("format") if isinstance(payload, dict) else None
    if isinstance(fmt, dict) and isinstance(fmt.get("tags"), dict):
        tags.update({str(k): str(v) for k, v in fmt["tags"].items()})
    for stream in payload.get("streams", []) if isinstance(payload, dict) else []:
        if isinstance(stream, dict) and isinstance(stream.get("tags"), dict):
            tags.update({str(k): str(v) for k, v in stream["tags"].items()})

    has_location = any(hint in key.lower() for key in tags for hint in _LOCATION_TAG_HINTS)
    capture_time = tags.get("creation_time")
    detected_format = ""
    if isinstance(fmt, dict) and isinstance(fmt.get("format_name"), str):
        detected_format = fmt["format_name"]
    return MediaMetadata(
        media_format=detected_format.upper() or media_format,
        has_location=has_location,
        capture_time=capture_time,
        fields_present=tuple(sorted(tags)),
    )


def make_shared_media_copy(source: Path, destination: Path, policy: SharingPolicy) -> StripReport:
    """Write a metadata-stripped shared copy of a video/audio file.

    Remuxes with ``-map_metadata -1`` (drops all container/stream metadata --
    title, device make/model, embedded GPS, timestamps) using stream-copy, so
    the audio/video bytes themselves are untouched -- only the metadata atoms
    are dropped, exactly the same "sealed original keeps everything, shared
    copy discloses only what policy allows" contract ``exif.make_shared_copy``
    makes for photos.

    Raises :class:`CaptureError` -- never silently produces an unstripped or
    partial file -- if ffmpeg is unavailable or the remux fails.
    """
    if not ffmpeg_available():
        raise CaptureError(
            f"cannot share {source.name}: ffmpeg is not installed. Video/audio "
            "metadata stripping needs ffmpeg (an optional dependency, never "
            "bundled) -- install it to share or packetize this recording. The "
            "sealed original remains safely captured either way."
        )
    meta = probe_metadata(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [
            _FFMPEG,
            "-y",
            "-i",
            str(source),
            "-map_metadata",
            "-1",
            "-map_chapters",
            "-1",
            "-codec",
            "copy",
            str(destination),
        ],
        capture_output=True,
        text=True,
        timeout=_SUBPROCESS_TIMEOUT,
        check=False,
    )
    if result.returncode != 0 or not destination.exists():
        raise CaptureError(
            f"ffmpeg could not strip metadata from {source.name}: "
            f"{result.stderr.strip()[-500:] or 'unknown ffmpeg failure'}"
        )
    removed = ["all-container-metadata"]
    if meta.has_location and policy.strip_location:
        removed.append("gps")
    return StripReport(
        source=str(source),
        destination=str(destination),
        media_format=meta.media_format,
        source_had_location=meta.has_location,
        removed=tuple(removed),
        retained=("audio/video-stream-bytes",),
    )


def extract_poster_frame(source: Path, destination: Path, *, at_seconds: float = 0.5) -> bool:
    """Best-effort: write a metadata-free JPEG poster frame from a video.

    Returns ``False`` (leaving no file behind) if ffmpeg is unavailable or
    extraction fails for any reason -- a missing poster frame degrades the
    packet to transcript-only accessibility, it never crashes packet assembly.
    Audio has no poster frame; callers should not call this for audio media.
    """
    if not ffmpeg_available():
        return False
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        result = subprocess.run(
            [
                _FFMPEG,
                "-y",
                "-ss",
                str(at_seconds),
                "-i",
                str(source),
                "-frames:v",
                "1",
                "-map_metadata",
                "-1",
                str(destination),
            ],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except subprocess.SubprocessError:
        return False
    return result.returncode == 0 and destination.exists()
