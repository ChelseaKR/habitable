# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Recipient-facing bundle views: cover sheet, chronology, integrity summary."""

from __future__ import annotations

from habitable.bundleview import chronology, cover_sheet, integrity_summary, item_extent
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


def test_cover_sheet_preserves_historical_issue_scope() -> None:
    """Old packets still render their signed scope; new issue-scoped export is blocked."""
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


def test_custody_length_is_counted_from_the_entries_not_taken_on_trust() -> None:
    """The rendered figure has to be one the verifier also checks (issue #278).

    ``custody_proof.length`` used to be read straight out of the proof and shown
    to a reader while `habitable.verify` ignored it entirely. It is checked there
    now, and counted here: a proof that carries its entries is rendered from them,
    so the number on a cover sheet cannot disagree with the number a verifier
    walked. A summary-only proof still falls back to the declared value -- there
    is nothing else to count -- which is the shape `_bundle` above exercises.
    """
    bundle = _bundle()
    proof = bundle["custody_proof"]
    assert isinstance(proof, dict)
    proof["entries"] = [{"seq": 1}, {"seq": 2}]  # two entries beside a declared six
    assert cover_sheet(bundle).custody_length == 2
    assert integrity_summary(bundle).custody_length == 2


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


# --------------------------------------------------------------------------- #
# The three figures the cover sheet leads with are counted, not taken on trust. #
# --------------------------------------------------------------------------- #
def test_the_media_figures_are_counted_from_the_items_not_the_appendix() -> None:
    """The same argument as ``custody_proof.length``, applied to three more fields.

    ``item_count``, ``timestamped_count`` and ``includes_originals`` were read
    straight out of ``appendix`` and printed as the packet's headline
    completeness figures. ``habitable.verify`` now re-derives them, so a
    mismatch is a verification failure -- but a renderer must not depend on
    having been handed a *verified* bundle, because these views also run over a
    bundle a recipient opened.
    """
    bundle = _bundle()
    appendix = bundle["appendix"]
    assert isinstance(appendix, dict)
    appendix["item_count"] = 9
    appendix["timestamped_count"] = 9
    appendix["includes_originals"] = True
    cover = cover_sheet(bundle)
    assert cover.item_count == 1
    assert cover.timestamped_count == 1
    assert cover.includes_originals is False
    summary = integrity_summary(bundle)
    assert summary.item_count == 1
    assert summary.timestamped_count == 1


def test_a_missing_appendix_does_not_render_as_zero_media_items() -> None:
    # A missing integer field arrives as 0 and a missing boolean as False, so an
    # absent appendix used to print "Media items: 0" above a table listing one.
    bundle = _bundle()
    del bundle["appendix"]
    cover = cover_sheet(bundle)
    assert cover.item_count == 1
    assert cover.timestamped_count == 1


def test_an_integrity_summary_total_cannot_disagree_with_its_own_rows() -> None:
    # The rows were already derived from `items`; the totals beside them were
    # not, so one function could print a row marked awaiting under a heading
    # saying every item is stamped.
    bundle = _bundle()
    items = bundle["items"]
    assert isinstance(items, list) and isinstance(items[0], dict)
    del items[0]["timestamp"]
    summary = integrity_summary(bundle)
    assert summary.rows[0].timestamp_status == "awaiting"
    assert summary.timestamped_count == 0
    assert summary.item_count == len(summary.rows)


def test_an_item_that_embeds_a_sealed_original_is_reported_as_one() -> None:
    bundle = _bundle()
    items = bundle["items"]
    assert isinstance(items, list) and isinstance(items[0], dict)
    items[0]["has_original"] = True
    appendix = bundle["appendix"]
    assert isinstance(appendix, dict)
    appendix["includes_originals"] = False  # the understatement that hid it
    assert cover_sheet(bundle).includes_originals is True


def test_the_timestamped_count_can_never_exceed_the_item_count() -> None:
    """``ItemExtent.awaiting`` is unclamped, so the invariant is asserted here.

    Both counts come from one pass over ``items`` and the stamped ones are a
    subset, so ``awaiting`` cannot go negative for any bundle shape -- including
    the malformed ones a recipient's bundle might carry. A clamp would be a
    branch no input reaches; this is the check that would actually fail if the
    two ever stopped being derived together.
    """
    shapes: list[JSONValue] = [
        {"capture_id": "a", "timestamp": {"kind": "rfc3161"}},
        {"capture_id": "b", "timestamp": None},
        {"capture_id": "c"},
        {"capture_id": "d", "timestamp": "not-a-mapping"},
        {"capture_id": "e", "timestamp": []},
        "not an item at all",
        None,
    ]
    for cut in range(len(shapes) + 1):
        extent = item_extent({"items": shapes[:cut]})
        assert extent.timestamped_count <= extent.item_count
        assert extent.awaiting >= 0
    full = item_extent({"items": shapes})
    assert full.item_count == 5  # the two non-dict entries are not items
    assert full.timestamped_count == 1  # only a mapping counts as a token
    assert full.awaiting == 4
