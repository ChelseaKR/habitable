# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Recipient-facing bundle views: cover sheet, chronology, integrity summary."""

from __future__ import annotations

from string import Formatter

from habitable.bundleview import (
    _REDUNDANCY_SENTENCES,
    chronology,
    cover_sheet,
    integrity_summary,
    item_extent,
    packet_redundancy,
    redundancy_sentence,
)
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


# ----------------------------------------------------------------------------------
# appendix.redundancy — "is this case on more than one device?" (issue #297, RR-07)
# ----------------------------------------------------------------------------------


def _with_redundancy(value: JSONValue) -> dict[str, JSONValue]:
    bundle = _bundle()
    appendix = bundle["appendix"]
    assert isinstance(appendix, dict)
    appendix["redundancy"] = value
    return bundle


def test_a_packet_that_says_nothing_about_copies_does_not_say_one_device() -> None:
    """The whole point of the fourth state.

    Every packet exported before this field existed omits it, including all six
    committed golden fixtures. Reading that omission as ``device_count == 1``
    would publish "the evidence existed in one place" -- this project's most
    alarming redundancy claim -- about a producer who claimed nothing at all.
    """
    redundancy = packet_redundancy(_bundle())
    assert redundancy.state == "not_stated"
    assert redundancy.device_count is None
    assert redundancy.acknowledged_by is None
    assert redundancy.stated is False
    sentence = redundancy_sentence(redundancy, "en")
    assert "not stated" in sentence
    assert "which is not the same as one" in sentence


def test_a_readable_count_is_carried_through_with_its_time() -> None:
    redundancy = packet_redundancy(
        _with_redundancy(
            {
                "state": "acknowledged",
                "device_count": 3,
                "acknowledged_by": 2,
                "identities_included": False,
                "as_of": "2026-01-02T00:05:00Z",
            }
        )
    )
    assert redundancy.state == "acknowledged"
    assert redundancy.device_count == 3
    assert redundancy.acknowledged_by == 2
    assert redundancy.as_of == "2026-01-02T00:05:00Z"
    assert redundancy.stated is True
    sentence = redundancy_sentence(redundancy, "en")
    assert "3 devices" in sentence
    assert "2026-01-02T00:05:00Z" in sentence
    assert "never named" in sentence


def test_a_count_with_no_recorded_time_gets_its_own_sentence() -> None:
    """Not an epoch date, and not the dated sentence with an empty slot in it."""
    redundancy = packet_redundancy(
        _with_redundancy(
            {
                "state": "acknowledged",
                "device_count": 2,
                "acknowledged_by": 1,
                "identities_included": False,
            }
        )
    )
    assert redundancy.as_of == ""
    for language in ("en", "es"):
        sentence = redundancy_sentence(redundancy, language)
        assert "1970" not in sentence
        assert "{as_of}" not in sentence
        assert "recorded no time" in sentence or "no registró la hora" in sentence


def test_a_single_device_case_says_so_in_both_languages() -> None:
    redundancy = packet_redundancy(
        _with_redundancy(
            {
                "state": "this_device_only",
                "device_count": 1,
                "acknowledged_by": 0,
                "identities_included": False,
            }
        )
    )
    assert redundancy.device_count == 1
    assert "1 device." in redundancy_sentence(redundancy, "en")
    assert "1 dispositivo." in redundancy_sentence(redundancy, "es")


def test_every_malformed_shape_reads_as_unreadable_and_never_as_one_device() -> None:
    """The asymmetry that decides this function's default.

    A reader that fell back to ``this_device_only`` on a parse failure would
    manufacture the alarming claim from a typo. Every rejection below therefore
    lands on ``unreadable``, which carries no count at all.

    The arithmetic rows are the ones a hand-edited packet would carry: a state
    and a count that disagree, or a device count that does not include the
    device that wrote it.
    """
    malformed: list[JSONValue] = [
        "not an object",
        [],
        {},
        {"state": "acknowledged"},
        {"state": "everyone", "device_count": 2, "acknowledged_by": 1},
        {"state": "acknowledged", "device_count": "2", "acknowledged_by": 1},
        {"state": "acknowledged", "device_count": True, "acknowledged_by": 1},
        {"state": "acknowledged", "device_count": -1, "acknowledged_by": -2},
        # device_count must count the producing device too.
        {"state": "acknowledged", "device_count": 2, "acknowledged_by": 2},
        # ... and the word must agree with the number.
        {"state": "this_device_only", "device_count": 3, "acknowledged_by": 2},
        {"state": "acknowledged", "device_count": 1, "acknowledged_by": 0},
    ]
    for shape in malformed:
        redundancy = packet_redundancy(_with_redundancy(shape))
        assert redundancy.state == "unreadable", shape
        assert redundancy.device_count is None, shape
        assert redundancy.acknowledged_by is None, shape
        assert redundancy.stated is False, shape
        for language in ("en", "es"):
            assert "verify" in redundancy_sentence(redundancy, language)


def test_the_cover_sheet_carries_the_sentence_in_the_packets_own_language() -> None:
    spanish = _with_redundancy(
        {
            "state": "this_device_only",
            "device_count": 1,
            "acknowledged_by": 0,
            "identities_included": False,
        }
    )
    spanish["language"] = "es"
    assert "dispositivo" in cover_sheet(spanish).copies
    english = dict(spanish)
    english["language"] = "en"
    assert "device" in cover_sheet(english).copies


def test_no_sentence_names_a_peer_or_carries_a_placeholder() -> None:
    """A count, never an identity -- asserted over every sentence, not by review.

    The fingerprint is the field that must never reach a packet. It is not in
    ``PacketRedundancy`` at all, so this is a check on the copy: a sentence that
    later grew a ``{peer}`` slot would have nothing to fill it from, and would
    ship the brace to a court.
    """
    for language, sentences in _REDUNDANCY_SENTENCES.items():
        assert language in {"en", "es"}
        assert set(sentences) == {
            "acknowledged",
            "acknowledged_undated",
            "this_device_only",
            "not_stated",
            "unreadable",
        }
        for key, sentence in sentences.items():
            fields = {name for _, name, _, _ in Formatter().parse(sentence) if name}
            assert fields <= {"devices", "acknowledged", "as_of"}, (language, key)
            assert "peer" not in sentence
            assert "fingerprint" not in sentence
