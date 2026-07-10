# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Recipient-facing bundle views: cover sheet, chronology, integrity summary."""

from __future__ import annotations

from habitable.bundleview import chronology, cover_sheet, integrity_summary
from habitable.canonical import JSONValue

# An hlc whose wall-clock part is 2026-01-02T00:00:00Z (1_767_312_000_000 ms).
_NOTE_HLC = "1767312000000.000001.nodeabc"


def _bundle() -> dict[str, JSONValue]:
    return {
        "case_id": "case-4B",
        "unit": "4B",
        "generated_at": "2026-01-02T00:10:00Z",
        "producer_fingerprint": "aaaa-bbbb-cccc-dddd",
        "hash_algorithm": "sha256",
        "scope": {"type": "unit", "issue_id": "", "since": ""},
        "issues": [{"issue_id": "i1", "title": "Mold", "category": "mold"}],
        "timeline": [{"issue_id": "i1", "kind": "observed", "text": "spreading", "hlc": _NOTE_HLC}],
        "items": [
            {
                "capture_id": "cap-x",
                "issue_id": "i1",
                "content_hash": "a" * 64,
                "captured_at": "2026-01-02T03:04:05Z",
                "shared_hash": "b" * 64,
                "timestamp": {"kind": "rfc3161", "tsa_name": "test-tsa"},
                "additional_timestamps": [{"kind": "rfc3161", "tsa_name": "second-tsa"}],
                "archive_timestamps": [{"kind": "rfc3161", "tsa_name": "test-tsa"}],
            }
        ],
        "custody_proof": {
            "algorithm": "sha256",
            "length": 6,
            "head_hash": "deadbeef",
            "items": {"cap-x": {"entries": 3, "head_hash": "cafef00d"}},
        },
        "appendix": {"item_count": 1, "timestamped_count": 1, "includes_originals": False},
    }


def test_cover_sheet_summarizes_the_bundle() -> None:
    cover = cover_sheet(_bundle())
    assert cover.case_id == "case-4B"
    assert cover.unit == "4B"
    assert cover.issue_count == 1
    assert cover.item_count == 1
    assert cover.timestamped_count == 1
    assert cover.custody_length == 6
    assert cover.includes_originals is False
    # The date range spans the earliest note and the latest photo.
    assert cover.earliest == "2026-01-02T00:00:00Z"
    assert cover.latest == "2026-01-02T03:04:05Z"
    assert "whole unit" in cover.scope


def test_chronology_interleaves_notes_and_photos_in_time_order() -> None:
    entries = chronology(_bundle())
    assert [e.kind for e in entries] == ["note", "photo"]
    note, photo = entries
    assert note.when == "2026-01-02T00:00:00Z"
    assert note.label == "observed"
    assert note.text == "spreading"
    assert photo.when == "2026-01-02T03:04:05Z"
    assert "timestamp token attached; authority trust not assessed" in photo.detail


def test_chronology_scope_subset_for_issue() -> None:
    bundle = _bundle()
    bundle["scope"] = {"type": "issue", "issue_id": "i1", "since": "2026-01-01"}
    cover = cover_sheet(bundle)
    assert "single issue (i1)" in cover.scope
    assert "2026-01-01" in cover.scope


def test_integrity_summary_collects_attestations_and_custody() -> None:
    summary = integrity_summary(_bundle())
    assert summary.algorithm == "sha256"
    assert summary.custody_length == 6
    assert summary.custody_head == "deadbeef"
    assert summary.timestamped_count == 1
    assert len(summary.rows) == 1
    row = summary.rows[0]
    assert row.capture_id == "cap-x"
    assert row.timestamp_status == "attached-unassessed"
    assert row.authorities == ("test-tsa", "second-tsa")
    assert row.archive_count == 1
    assert row.custody_entries == 3
    assert row.custody_head == "cafef00d"


def test_views_tolerate_an_empty_or_awaiting_bundle() -> None:
    bundle: dict[str, JSONValue] = {
        "items": [{"capture_id": "c1", "issue_id": "i1", "content_hash": "x", "captured_at": ""}],
        "appendix": {"item_count": 1, "timestamped_count": 0},
    }
    cover = cover_sheet(bundle)
    assert cover.earliest == "" and cover.latest == ""
    summary = integrity_summary(bundle)
    assert summary.rows[0].timestamp_status == "awaiting"
    assert summary.rows[0].authorities == ()
    # An undated photo still appears, sorted last.
    assert len(chronology(bundle)) == 1
