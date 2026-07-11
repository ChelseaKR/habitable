# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Evidence engine (fixity + chain of custody) and EXIF handling."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import piexif
import pytest
from PIL import Image, ImageOps

from habitable.config import SharingPolicy
from habitable.crypto import Identity
from habitable.errors import CaptureError, CustodyError, FixityError
from habitable.evidence import CustodyAction, CustodyLog, content_hash, fixity_ok, verify_fixity
from habitable.exif import make_shared_copy, read_metadata


def _jpeg_segment(marker: int, payload: bytes) -> bytes:
    """Build one length-prefixed JPEG metadata segment for adversarial fixtures."""
    length = len(payload) + 2
    return b"\xff" + bytes((marker,)) + length.to_bytes(2, "big") + payload


def _inject_after_soi(path: Path, *segments: bytes) -> None:
    encoded = path.read_bytes()
    assert encoded.startswith(b"\xff\xd8")
    path.write_bytes(encoded[:2] + b"".join(segments) + encoded[2:])


class TestFixity:
    def test_verify_fixity_passes_and_fails(self, tmp_path: Path) -> None:
        f = tmp_path / "p.bin"
        f.write_bytes(b"original")
        digest = content_hash(f)
        verify_fixity(f, digest)  # no raise
        f.write_bytes(b"tampered")
        assert not fixity_ok(f, digest)
        with pytest.raises(FixityError):
            verify_fixity(f, digest)


class TestCustody:
    def _log(self) -> tuple[CustodyLog, Identity]:
        identity = Identity.generate()
        log = CustodyLog()
        fp = identity.public().fingerprint
        log.append(CustodyAction.CAPTURED, "item-1", actor=fp, hlc="t1", identity=identity)
        log.append(CustodyAction.TIMESTAMPED, "item-1", actor=fp, hlc="t2", identity=identity)
        log.append(CustodyAction.VIEWED, "item-1", actor=fp, hlc="t3", identity=identity)
        return log, identity

    def test_chain_links_and_verifies(self) -> None:
        log, identity = self._log()
        result = log.verify(
            signer_keys={e.actor_commitment: identity.public().sign_public for e in log.entries}
        )
        assert result.ok and result.length == 3 and result.signatures_checked == 3
        entries = log.entries
        assert entries[1].prev_hash == entries[0].entry_hash
        assert entries[2].prev_hash == entries[1].entry_hash

    def test_export_hides_identity(self) -> None:
        log, identity = self._log()
        fingerprint = identity.public().fingerprint
        export = log.to_export_records()
        assert all("actor" not in r and r.get("actor_salt", "") == "" for r in export)
        assert fingerprint not in json.dumps(log.integrity_proof())

    def test_redacted_export_still_verifies(self) -> None:
        log, _ = self._log()
        reloaded = CustodyLog.from_records(log.to_export_records())
        assert reloaded.verify().head_hash == log.head_hash

    def test_tamper_detected(self) -> None:
        log, _ = self._log()
        records = log.to_export_records()
        records[1]["action"] = "viewed"  # alter an entry
        with pytest.raises(CustodyError, match="altered"):
            CustodyLog.from_records(records).verify()

    def test_deletion_detected(self) -> None:
        log, _ = self._log()
        records = log.to_export_records()
        del records[1]  # drop the middle link
        with pytest.raises(CustodyError):
            CustodyLog.from_records(records).verify()

    def test_reorder_detected(self) -> None:
        log, _ = self._log()
        records = log.to_export_records()
        records[0], records[1] = records[1], records[0]
        with pytest.raises(CustodyError):
            CustodyLog.from_records(records).verify()


class TestExif:
    def test_reads_location_and_time(self, make_jpeg: Callable[..., Path]) -> None:
        photo = make_jpeg(with_location=True)
        meta = read_metadata(photo)
        assert meta.has_location and meta.capture_time == "2026:01:02 03:04:05"

    def test_strip_all_metadata(self, make_jpeg: Callable[..., Path], tmp_path: Path) -> None:
        photo = make_jpeg(with_location=True)
        out = tmp_path / "shared.jpg"
        report = make_shared_copy(photo, out, SharingPolicy())
        shared = read_metadata(out)
        assert not shared.has_location and shared.capture_time is None
        assert report.removed == ("all-embedded-metadata",)
        assert report.retained == ("pixels-only",)
        # original untouched
        assert read_metadata(photo).has_location

    def test_strip_all_removes_xmp_iptc_comments_and_contact_strings(
        self, make_jpeg: Callable[..., Path], tmp_path: Path
    ) -> None:
        photo = make_jpeg(with_location=True)
        xmp_secret = b"GPSLatitude=38.5816 contact=tenant@example.test"
        icc_secret = b"ICC_PROFILE\x00tenant-name=Synthetic Tenant"
        iptc_secret = b"Photoshop 3.0\x00IPTC phone=+1-555-0100"
        comment_secret = b"home-address=123-Synthetic-Street"
        trailing_secret = b"trailing-contact=tenant@example.test"
        _inject_after_soi(
            photo,
            _jpeg_segment(0xE1, b"http://ns.adobe.com/xap/1.0/\x00" + xmp_secret),
            _jpeg_segment(0xE2, icc_secret),
            _jpeg_segment(0xED, iptc_secret),
            _jpeg_segment(0xFE, comment_secret),
        )
        photo.write_bytes(photo.read_bytes() + trailing_secret)

        out = tmp_path / "shared.jpg"
        report = make_shared_copy(photo, out, SharingPolicy())

        exported = out.read_bytes()
        assert xmp_secret not in exported
        assert icc_secret not in exported
        assert iptc_secret not in exported
        assert comment_secret not in exported
        assert trailing_secret not in exported
        assert b"Exif\x00\x00" not in exported
        assert "all-embedded-metadata" in report.removed
        assert report.retained == ("pixels-only",)
        with Image.open(out) as clean:
            assert clean.info == {}

    def test_strip_all_applies_exif_orientation_before_removing_it(self, tmp_path: Path) -> None:
        photo = tmp_path / "rotated.jpg"
        image = Image.new("RGB", (8, 4))
        image.paste((240, 20, 20), (0, 0, 4, 4))
        image.paste((20, 20, 240), (4, 0, 8, 4))
        exif = {piexif.ImageIFD.Orientation: 6}
        image.save(photo, "JPEG", quality=95, exif=piexif.dump({"0th": exif}))
        with Image.open(photo) as source:
            expected_size = ImageOps.exif_transpose(source).size

        out = tmp_path / "shared.jpg"
        make_shared_copy(photo, out, SharingPolicy())

        with Image.open(out) as exported:
            assert exported.size == expected_size == (4, 8)
            assert exported.getexif().get(piexif.ImageIFD.Orientation) is None
            top = exported.getpixel((2, 1))
            bottom = exported.getpixel((2, 6))
            assert isinstance(top, tuple)
            assert isinstance(bottom, tuple)
            assert top[0] > top[2]
            assert bottom[2] > bottom[0]

    @pytest.mark.parametrize(
        "payload",
        [
            b"not-a-jpeg",
            b"\xff\xd8\xff\xe1",
            b"\xff\xd8\xff\xe1\x00\x10truncated-private-data",
            b"\xff\xd8\xff\xd9",
        ],
        ids=["wrong-header", "truncated-length", "truncated-segment", "no-image-data"],
    )
    def test_strip_all_rejects_malformed_jpeg_without_leaving_output(
        self, tmp_path: Path, payload: bytes
    ) -> None:
        photo = tmp_path / "malformed.jpg"
        photo.write_bytes(payload)
        out = tmp_path / "shared.jpg"

        with pytest.raises(CaptureError, match="cannot safely strip metadata"):
            make_shared_copy(photo, out, SharingPolicy())

        assert not out.exists()

    def test_strip_all_never_replaces_the_sealed_original(
        self, make_jpeg: Callable[..., Path]
    ) -> None:
        photo = make_jpeg(with_location=True)
        original = photo.read_bytes()

        with pytest.raises(CaptureError, match="must be different files"):
            make_shared_copy(photo, photo, SharingPolicy())

        assert photo.read_bytes() == original
        assert read_metadata(photo).has_location

    def test_strip_location_only(self, make_jpeg: Callable[..., Path], tmp_path: Path) -> None:
        photo = make_jpeg(with_location=True)
        out = tmp_path / "shared.jpg"
        policy = SharingPolicy(strip_location=True, strip_all_metadata=False)
        make_shared_copy(photo, out, policy)
        shared = read_metadata(out)
        assert not shared.has_location
        assert shared.capture_time == "2026:01:02 03:04:05"
