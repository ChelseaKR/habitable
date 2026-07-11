# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Regenerate the synthetic packet published on the project site.

The Pages sample is a literal committed artifact, separate from the golden packet
fixtures.  Keep it on the current packet version and run the real capture, export,
signature, rendering, and verification pipeline:

    uv run python scripts/make_site_sample.py

Every person, event, image, and identifier in this scenario is generated.  The
source images deliberately contain synthetic EXIF time and Null Island GPS data so
the export exercises (and the regression test checks) metadata stripping.
"""

from __future__ import annotations

import shutil
import tempfile
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

import piexif
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from PIL import Image, ImageDraw

from habitable.capture import capture
from habitable.config import PacketTemplate
from habitable.packet import PACKET_VERSION, build_packet
from habitable.tsa import LocalRfc3161TSA
from habitable.vault import Vault
from habitable.verify import verify_packet

_FIXED_EPOCH = 1_767_312_000  # 2026-01-02T00:00:00Z
_GENERATED_AT = "2026-01-02T09:30:00Z"
_ROOT = Path(__file__).resolve().parent.parent
_SAMPLE = _ROOT / "site" / "sample-packet"
_PASSPHRASE = "public-synthetic-sample-not-secret"  # noqa: S105 - generated demo only
_SYNTHETIC_CERT = "synthetic-timestamp-authority.pem"
_SYNTHETIC_NOTICE = "SYNTHETIC-AUTHORITY.txt"


def _counter_ms(start_ms: int) -> Callable[[], int]:
    state = {"t": start_ms}

    def tick() -> int:
        state["t"] += 1
        return state["t"]

    return tick


def _save_synthetic_photo(path: Path, scene: str, capture_time: str) -> None:
    """Draw a clearly labelled, never-real condition photo with removable EXIF."""
    image = Image.new("RGB", (640, 420), (226, 220, 205))
    draw = ImageDraw.Draw(image)

    if scene == "ceiling":
        draw.rectangle((0, 0, 640, 330), fill=(219, 215, 199))
        draw.ellipse((155, 70, 505, 285), fill=(173, 151, 112))
        draw.ellipse((210, 95, 455, 260), fill=(131, 119, 91))
        for x, y, radius in (
            (240, 150, 10),
            (280, 125, 7),
            (315, 185, 12),
            (355, 145, 9),
            (390, 205, 8),
            (430, 170, 11),
        ):
            draw.ellipse((x - radius, y - radius, x + radius, y + radius), fill=(48, 55, 46))
    elif scene == "wall":
        draw.rectangle((0, 0, 640, 330), fill=(190, 198, 201))
        draw.polygon([(85, 330), (205, 80), (315, 330)], fill=(117, 135, 138))
        draw.line(
            [(330, 30), (318, 95), (350, 155), (326, 230), (365, 330)], fill=(75, 76, 72), width=6
        )
        draw.rectangle((0, 315, 640, 330), fill=(118, 105, 88))
    elif scene == "thermostat":
        draw.rectangle((0, 0, 640, 330), fill=(203, 197, 184))
        draw.rounded_rectangle(
            (190, 65, 450, 280), radius=18, fill=(235, 235, 226), outline=(72, 74, 72), width=5
        )
        draw.rectangle((230, 110, 410, 220), fill=(121, 142, 134), outline=(55, 61, 57), width=3)
        draw.text((278, 142), "49 F", fill=(18, 28, 23), stroke_width=1)
        draw.ellipse((305, 242, 335, 272), fill=(155, 156, 148), outline=(70, 70, 66))
    else:
        raise ValueError(f"unknown synthetic scene: {scene}")

    draw.rectangle((0, 330, 640, 420), fill=(27, 54, 48))
    draw.text((22, 350), "SYNTHETIC DEMONSTRATION IMAGE", fill=(255, 249, 225), stroke_width=1)
    draw.text((22, 382), "No real home, tenant, or address", fill=(255, 249, 225))

    # Null Island is intentional fake input. The packet must strip it, together
    # with capture time, from every published shared copy.
    exif = {
        "0th": {},
        "Exif": {piexif.ExifIFD.DateTimeOriginal: capture_time.encode("ascii")},
        "GPS": {
            piexif.GPSIFD.GPSLatitudeRef: b"N",
            piexif.GPSIFD.GPSLatitude: ((0, 1), (0, 1), (0, 1)),
            piexif.GPSIFD.GPSLongitudeRef: b"E",
            piexif.GPSIFD.GPSLongitude: ((0, 1), (0, 1), (0, 1)),
        },
        "1st": {},
        "thumbnail": None,
    }
    image.save(path, "jpeg", quality=90, exif=piexif.dump(exif))


def _build_sample(work: Path) -> Path:
    photos = work / "synthetic-source-media"
    photos.mkdir()
    ceiling = photos / "synthetic-ceiling.jpg"
    wall = photos / "synthetic-wall.jpg"
    thermostat = photos / "synthetic-thermostat.jpg"
    _save_synthetic_photo(ceiling, "ceiling", "2026:01:02 09:05:00")
    _save_synthetic_photo(wall, "wall", "2026:01:02 09:10:00")
    _save_synthetic_photo(thermostat, "thermostat", "2026:01:02 09:15:00")

    vault = Vault.create(
        work / "vault",
        _PASSPHRASE,
        case_id="synthetic-demo-case",
        unit="4B (synthetic)",
        time_source=_counter_ms(_FIXED_EPOCH * 1000),
    )
    vault.config = replace(
        vault.config,
        packet_template=PacketTemplate(
            header="SYNTHETIC DEMONSTRATION — NOT A REAL TENANT CASE",
            footer=(
                "Generated sample data only. Not legal advice and not evidence from a real home."
            ),
        ),
    )

    moisture = vault.document.add_issue(
        category="moisture",
        room="bathroom",
        title="Recurring ceiling leak and mold-like spotting",
        severity="high",
        description=(
            "Synthetic scenario: staining returned after rain and spread across the ceiling."
        ),
    )
    heat = vault.document.add_issue(
        category="heat",
        room="bedroom",
        title="No heat overnight",
        severity="urgent",
        description="Synthetic scenario: the room remained cold while the heater was set to warm.",
    )
    vault.save()

    tsa = LocalRfc3161TSA("sample-offline-rfc3161", time_source=lambda: _FIXED_EPOCH)
    ceiling_capture = capture(vault, ceiling, issue_id=moisture, tsa=tsa)
    wall_capture = capture(vault, wall, issue_id=moisture, tsa=tsa)
    thermostat_capture = capture(vault, thermostat, issue_id=heat, tsa=tsa)

    vault.add_timeline_event(
        moisture,
        event_type="condition_observed",
        text="Synthetic tenant observed new staining after rainfall.",
        occurred_at="2026-01-02",
        source="firsthand",
        capture_ids=(ceiling_capture.capture_id, wall_capture.capture_id),
    )
    notice_id = vault.add_timeline_event(
        moisture,
        event_type="notice_sent",
        text="Synthetic repair request sent to the property manager.",
        occurred_at="2026-01-02",
        source="message",
    )
    vault.add_timeline_event(
        moisture,
        event_type="delivery_confirmed",
        text="Synthetic portal displayed a delivery confirmation.",
        occurred_at="2026-01-02",
        source="document",
        notice_entry_id=notice_id,
    )
    vault.add_timeline_event(
        heat,
        event_type="condition_observed",
        text="Synthetic thermostat display read 49 F during the night.",
        occurred_at="2026-01-02",
        source="firsthand",
        capture_ids=(thermostat_capture.capture_id,),
    )

    out = work / "sample-packet"
    build_packet(vault, out, generated_at=_GENERATED_AT)
    (out / _SYNTHETIC_CERT).write_bytes(tsa.certificate.public_bytes(serialization.Encoding.PEM))
    (out / _SYNTHETIC_NOTICE).write_text(
        "SYNTHETIC DEMONSTRATION AUTHORITY ONLY\n\n"
        "This self-signed certificate was generated with this sample. Its presence "
        "does not make the timestamp authority independently trusted. Use it only to "
        "exercise Habitable's explicit --trusted-cert verification path against "
        "synthetic data; do not use it to assess real evidence.\n",
        encoding="utf-8",
    )

    unpinned = verify_packet(out)
    if (
        not unpinned.structurally_intact
        or unpinned.status != "timestamp_authority_untrusted"
        or unpinned.cryptographically_verified_items != 3
    ):
        raise RuntimeError(f"refusing to publish broken sample: {unpinned.summary()}")
    pinned = verify_packet(out, trusted_certs=[tsa.certificate])
    if not pinned.evidence_ready:
        raise RuntimeError(f"refusing to publish invalid pinned sample: {pinned.summary()}")
    return out


def _load_synthetic_cert(packet_dir: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate((packet_dir / _SYNTHETIC_CERT).read_bytes())


def main() -> int:
    site_dir = _SAMPLE.parent
    with tempfile.TemporaryDirectory(prefix=".sample-packet-", dir=site_dir) as raw_work:
        work = Path(raw_work)
        generated = _build_sample(work)
        previous = work / "previous-sample-packet"
        if _SAMPLE.exists():
            _SAMPLE.rename(previous)
        try:
            generated.rename(_SAMPLE)
        except BaseException:
            if previous.exists():
                previous.rename(_SAMPLE)
            raise
        shutil.rmtree(previous, ignore_errors=True)

    report = verify_packet(_SAMPLE)
    pinned = verify_packet(_SAMPLE, trusted_certs=[_load_synthetic_cert(_SAMPLE)])
    if not report.structurally_intact or report.status != "timestamp_authority_untrusted":
        raise RuntimeError("published sample failed its default trust-boundary check")
    if not pinned.evidence_ready:
        raise RuntimeError("published sample failed its explicitly pinned synthetic check")
    print(
        f"wrote {_SAMPLE.relative_to(_ROOT)} (packet_version={PACKET_VERSION}); "
        "default and explicitly pinned synthetic trust checks passed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
