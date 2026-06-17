# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Shared pytest fixtures: deterministic clocks and synthetic (never-real) media."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import piexif
import pytest
from PIL import Image

# A fixed instant (2026-01-02T00:00:00Z) so timestamped output is reproducible.
FIXED_EPOCH_SECONDS = 1_767_312_000


@pytest.fixture
def fixed_epoch() -> int:
    return FIXED_EPOCH_SECONDS


@pytest.fixture
def monotonic_ms() -> Callable[[], int]:
    """A deterministic millisecond clock that advances 1ms per call."""
    state = {"t": FIXED_EPOCH_SECONDS * 1000}

    def tick() -> int:
        state["t"] += 1
        return state["t"]

    return tick


@pytest.fixture
def make_jpeg(tmp_path: Path) -> Callable[..., Path]:
    """Factory for synthetic JPEGs, optionally carrying GPS + capture time."""

    def _make(
        name: str = "photo.jpg",
        *,
        color: tuple[int, int, int] = (120, 30, 30),
        with_location: bool = False,
        capture_time: str | None = "2026:01:02 03:04:05",
    ) -> Path:
        path = tmp_path / name
        image = Image.new("RGB", (16, 16), color)
        exif: dict[int, object] = {}
        if capture_time is not None:
            exif[piexif.ExifIFD.DateTimeOriginal] = capture_time.encode("ascii")
        gps: dict[int, object] = {}
        if with_location:
            gps = {
                piexif.GPSIFD.GPSLatitudeRef: b"N",
                piexif.GPSIFD.GPSLatitude: ((38, 1), (33, 1), (0, 1)),
                piexif.GPSIFD.GPSLongitudeRef: b"W",
                piexif.GPSIFD.GPSLongitude: ((121, 1), (44, 1), (0, 1)),
            }
        payload = {"0th": {}, "Exif": exif, "GPS": gps, "1st": {}, "thumbnail": None}
        image.save(path, "jpeg", exif=piexif.dump(payload))
        return path

    return _make
