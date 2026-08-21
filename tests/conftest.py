# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Shared pytest fixtures: deterministic clocks and synthetic (never-real) media."""

from __future__ import annotations

import subprocess
import urllib.parse
import urllib.request
from collections.abc import Callable
from pathlib import Path

import piexif
import pytest
from PIL import Image

from habitable.pairing import accept_pairing_material, create_pairing_material
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
def make_mp4(tmp_path: Path) -> Callable[..., Path]:
    """Factory for tiny synthetic MP4s (a solid color, no real footage), built
    entirely by ffmpeg's ``lavfi`` test source, optionally tagged with a fake
    location so metadata-stripping can be exercised honestly."""

    def _make(
        name: str = "clip.mp4", *, with_location: bool = False, duration: float = 0.5
    ) -> Path:
        path = tmp_path / name
        cmd = ["ffmpeg", "-y", "-f", "lavfi", "-i", f"color=c=blue:s=32x32:d={duration}"]
        if with_location:
            cmd += ["-metadata", "location=+38.5816-121.4944/"]
        cmd += ["-metadata", "comment=synthetic-test-clip", "-pix_fmt", "yuv420p", str(path)]
        subprocess.run(cmd, capture_output=True, check=True, timeout=30)
        return path

    return _make


@pytest.fixture
def make_wav(tmp_path: Path) -> Callable[..., Path]:
    """Factory for tiny synthetic WAV files (a sine tone), built by ffmpeg."""

    def _make(name: str = "clip.wav", *, duration: float = 0.5) -> Path:
        path = tmp_path / name
        cmd = [
            "ffmpeg",
            "-y",
            "-f",
            "lavfi",
            "-i",
            f"sine=frequency=440:duration={duration}",
            "-metadata",
            "comment=synthetic-test-tone",
            str(path),
        ]
        subprocess.run(cmd, capture_output=True, check=True, timeout=30)
        return path

    return _make


@pytest.fixture
def make_vault(tmp_path: Path) -> Callable[..., Vault]:
    """Factory for deterministic vaults, pairing same-case peers as test setup.

    Production sync never auto-pairs. The fixture performs the explicit signed,
    sealed invitation exchange so legacy sync-focused tests exercise protocol v2
    without repeating ceremony in every case.
    """
    seq = {"n": 0}
    peers: list[Vault] = []

    def _make(
        name: str = "vault",
        *,
        case_id: str = "case-4B",
        unit: str = "4B",
        passphrase: str = "test-passphrase",
    ) -> Vault:
        seq["n"] += 1
        clock = counter_clock(FIXED_EPOCH_SECONDS * 1000 + seq["n"] * 1_000_000)
        vault = Vault.create(
            tmp_path / name, passphrase, case_id=case_id, unit=unit, time_source=clock
        )
        for existing in peers:
            if existing.document.case_id != case_id:
                continue
            material = create_pairing_material(existing, vault.identity.public())
            accept_pairing_material(vault, material)
        peers.append(vault)
        return vault

    return _make


@pytest.fixture(autouse=True)
def _no_outbound_network(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail any non-``integration`` test that opens a connection off this machine.

    A vault's default config names public authorities (freetsa, digicert), so any
    code path that resolves "the configured TSA" and stamps calls out over the
    network for real. That happened silently when packet sealing (ADR 0011) was
    added to `habitable export`: the merge gate quietly acquired a dependency on a
    third party being reachable, and on somebody else's rate limit, with nothing
    red to show for it.

    Loopback stays open, because the relay and app-server tests legitimately speak
    HTTP to a local port. Tests that fake `urllib.request.urlopen` themselves are
    unaffected: their `monkeypatch.setattr` runs after this one and wins. The
    `integration` marker is the sanctioned way to reach a real service
    (`make integration`), so it is exempt.
    """
    if "integration" in request.keywords:
        return

    real_urlopen = urllib.request.urlopen

    def guarded(url: object, *args: object, **kwargs: object) -> object:
        target = url.full_url if isinstance(url, urllib.request.Request) else str(url)
        host = (urllib.parse.urlsplit(target).hostname or "").lower()
        if host not in {"localhost", "127.0.0.1", "::1", ""}:
            raise AssertionError(
                f"test opened an outbound connection to {target!r}. Unit tests must stay "
                "offline: use the local_tsa/dev_tsa fixtures, or pass --dev-tsa / "
                "--no-seal to the command under test. Mark the test `integration` only "
                "if reaching a real service is the point."
            )
        return real_urlopen(url, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(urllib.request, "urlopen", guarded)
