# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Regenerate the current-version golden packet fixture.

The golden corpus (``tests/golden/packet-vN/``) pins backward compatibility: every
packet version habitable has ever emitted must keep verifying forever
(``tests/test_golden.py``). Run this after an intentional, reviewed change to the
export format to (re)build the *current* version's fixture:

    uv run python scripts/make_golden_packet.py

It builds a fresh, self-contained packet with the real pipeline (a deterministic
clock and a fixed-time local RFC 3161 issuer) and copies the verifiable subset —
``bundle.json``, its signature, and the shared media — into
``tests/golden/packet-v<PACKET_VERSION>/``. Older fixtures (e.g. ``packet-v1``) are
the back-compat contract and are never touched by this script.
"""

from __future__ import annotations

import shutil
import tempfile
from collections.abc import Callable
from pathlib import Path

import piexif
from PIL import Image

from habitable.capture import capture
from habitable.packet import PACKET_VERSION, build_packet
from habitable.tsa import LocalRfc3161TSA
from habitable.vault import Vault

_FIXED_EPOCH = 1_767_312_000  # 2026-01-02T00:00:00Z — reproducible timestamps
_GENERATED_AT = "2026-01-02T00:10:00Z"
_ROOT = Path(__file__).resolve().parent.parent
_GOLDEN = _ROOT / "tests" / "golden" / f"packet-v{PACKET_VERSION}"


def _counter_ms(start_ms: int) -> Callable[[], int]:
    state = {"t": start_ms}

    def tick() -> int:
        state["t"] += 1
        return state["t"]

    return tick


def _synthetic_photo(path: Path) -> None:
    """A never-real JPEG carrying an EXIF capture time and GPS (stripped on export)."""
    exif = {
        "0th": {},
        "Exif": {piexif.ExifIFD.DateTimeOriginal: b"2026:01:02 09:15:00"},
        "GPS": {
            piexif.GPSIFD.GPSLatitudeRef: b"N",
            piexif.GPSIFD.GPSLatitude: ((38, 1), (33, 1), (0, 1)),
            piexif.GPSIFD.GPSLongitudeRef: b"W",
            piexif.GPSIFD.GPSLongitude: ((121, 1), (44, 1), (0, 1)),
        },
        "1st": {},
        "thumbnail": None,
    }
    Image.new("RGB", (48, 48), (70, 70, 60)).save(path, "jpeg", exif=piexif.dump(exif))


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="golden-packet-"))
    vault = Vault.create(
        work / "vault",
        "golden-passphrase",
        case_id="golden-4B",
        unit="4B",
        time_source=_counter_ms(_FIXED_EPOCH * 1000),
    )
    issue = vault.document.add_issue(
        category="mold", room="bathroom", title="Black mold", severity="high"
    )
    vault.document.add_timeline_entry(issue, "observed", "mold on ceiling")
    vault.save()

    photo = work / "p.jpg"
    _synthetic_photo(photo)
    tsa = LocalRfc3161TSA("golden-tsa", time_source=lambda: _FIXED_EPOCH)
    capture(vault, photo, issue_id=issue, tsa=tsa)

    out = work / "packet"
    build_packet(vault, out, generated_at=_GENERATED_AT, make_pdf=False)

    # Commit only the verifiable, self-contained subset (mirrors packet-v1's shape).
    if _GOLDEN.exists():
        shutil.rmtree(_GOLDEN)
    (_GOLDEN / "media").mkdir(parents=True)
    shutil.copy(out / "bundle.json", _GOLDEN / "bundle.json")
    shutil.copy(out / "bundle.sig.json", _GOLDEN / "bundle.sig.json")
    for media_file in sorted((out / "media").iterdir()):
        shutil.copy(media_file, _GOLDEN / "media" / media_file.name)

    print(f"wrote {_GOLDEN.relative_to(_ROOT)} (packet_version={PACKET_VERSION})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
