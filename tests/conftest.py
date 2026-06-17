# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Shared pytest fixtures: deterministic clocks and synthetic (never-real) media."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import piexif
import pytest
from PIL import Image

from habitable.tsa import DevTSA, LocalRfc3161TSA
from habitable.vault import Vault

# A fixed instant (2026-01-02T00:00:00Z) so timestamped output is reproducible.
FIXED_EPOCH_SECONDS = 1_767_312_000


def counter_clock(start_ms: int) -> Callable[[], int]:
    """A deterministic millisecond clock advancing 1ms per call."""
    state = {"t": start_ms}

    def tick() -> int:
        state["t"] += 1
        return state["t"]

    return tick


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


@pytest.fixture
def local_tsa() -> LocalRfc3161TSA:
    """A real RFC 3161 issuer with a fixed gen-time (offline, deterministic)."""
    return LocalRfc3161TSA("test-rfc3161", time_source=lambda: FIXED_EPOCH_SECONDS)


@pytest.fixture
def dev_tsa() -> DevTSA:
    return DevTSA("test-dev-tsa", time_source=lambda: FIXED_EPOCH_SECONDS)


@pytest.fixture
def make_vault(tmp_path: Path) -> Callable[..., Vault]:
    """Factory for vaults with deterministic clocks under the test's tmp_path."""
    seq = {"n": 0}

    def _make(
        name: str = "vault",
        *,
        case_id: str = "case-4B",
        unit: str = "4B",
        passphrase: str = "test-passphrase",
    ) -> Vault:
        seq["n"] += 1
        clock = counter_clock(FIXED_EPOCH_SECONDS * 1000 + seq["n"] * 1_000_000)
        return Vault.create(
            tmp_path / name, passphrase, case_id=case_id, unit=unit, time_source=clock
        )

    return _make
