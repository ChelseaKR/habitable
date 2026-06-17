# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Evidence engine (fixity + chain of custody) and EXIF handling."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from habitable.config import SharingPolicy
from habitable.crypto import Identity
from habitable.errors import CustodyError, FixityError
from habitable.evidence import CustodyAction, CustodyLog, content_hash, fixity_ok, verify_fixity
from habitable.exif import make_shared_copy, read_metadata


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
        assert "all-exif" in report.removed
        # original untouched
        assert read_metadata(photo).has_location

    def test_strip_location_only(self, make_jpeg: Callable[..., Path], tmp_path: Path) -> None:
        photo = make_jpeg(with_location=True)
        out = tmp_path / "shared.jpg"
        policy = SharingPolicy(strip_location=True, strip_all_metadata=False)
        make_shared_copy(photo, out, policy)
        shared = read_metadata(out)
        assert not shared.has_location
        assert shared.capture_time == "2026:01:02 03:04:05"
