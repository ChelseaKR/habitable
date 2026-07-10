# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""A self-contained, offline walkthrough on synthetic data.

``habitable demo`` (and ``make demo``) runs this: it fabricates a couple of photos
with embedded location, captures them as evidence, builds a packet, and verifies
it — proving the whole pipeline works with no network, no real tenant data, and a
real (locally-issued) RFC 3161 timestamp on every item.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import piexif
from PIL import Image

from .capture import capture
from .packet import build_packet
from .tsa import LocalRfc3161TSA
from .vault import Vault
from .verify import verify_packet

__all__ = ["run_demo"]

_PASSPHRASE = "demo-passphrase-not-secret"  # noqa: S105 - synthetic demo only


def run_demo() -> int:
    work = Path(tempfile.mkdtemp(prefix="habitable-demo-"))
    print("habitable demo — synthetic data, no network, no real tenant information\n")
    print(f"working directory: {work}\n")

    photos = _make_photos(work / "phone")
    tsa = LocalRfc3161TSA("demo-rfc3161-tsa")

    vault = Vault.create(work / "vault", _PASSPHRASE, case_id="demo-4B", unit="4B")
    print("1. created an encrypted vault for unit 4B")

    issue = vault.document.add_issue(
        category="mold", room="bathroom", title="Black mold on bathroom ceiling", severity="high"
    )
    vault.add_timeline_event(
        issue,
        event_type="condition_observed",
        text="mold spreading after roof leak",
        occurred_at="2026-01-02",
        source="firsthand",
    )
    vault.add_timeline_event(
        issue,
        event_type="notice_sent",
        text="emailed landlord requesting repair",
        occurred_at="2026-01-02",
        source="message",
    )
    print(f"2. opened issue {issue} and logged a 2-entry timeline")

    for photo in photos:
        result = capture(vault, photo, issue_id=issue, tsa=tsa)
        when = result.timestamp_info.gen_time if result.timestamp_info else "queued"
        print(f"3. captured {photo.name}: hash {result.content_hash[:12]}… · RFC 3161 @ {when}")

    out = work / "4B-packet"
    packet = build_packet(vault, out)
    print(
        f"4. exported packet to {out.name}/  ({packet.item_count} items, "
        f"{packet.timestamped_count} timestamped)"
    )
    for note in packet.disclosures:
        print(f"     · {note}")

    report = verify_packet(out)
    print(f"\n5. independent verification: {report.summary()}")
    print(f"\nInspect the packet at: {out}")
    return 0 if report.ok else 1


def _make_photos(folder: Path) -> list[Path]:
    folder.mkdir(parents=True, exist_ok=True)
    specs = [("ceiling.jpg", (70, 70, 60)), ("wall.jpg", (40, 50, 70))]
    paths: list[Path] = []
    for name, color in specs:
        path = folder / name
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
        Image.new("RGB", (48, 48), color).save(path, "jpeg", exif=piexif.dump(exif))
        paths.append(path)
    return paths
