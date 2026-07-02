# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""CRDT case model: deterministic behaviour and property-based convergence."""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from habitable.clock import HybridLogicalClock
from habitable.errors import HabitableError
from habitable.model import CaseDocument, GrowLog, LWWRegister, ORSet

Op = tuple[str, ...]


def _counter_clock(start_ms: int) -> Callable[[], int]:
    state = {"t": start_ms}

    def tick() -> int:
        state["t"] += 1
        return state["t"]

    return tick


def _doc(node: str, start_ms: int) -> CaseDocument:
    return CaseDocument("case", HybridLogicalClock(node, time_source=_counter_clock(start_ms)))


def _apply(doc: CaseDocument, ops: Sequence[Op]) -> None:
    for op in ops:
        kind = op[0]
        if kind == "meta":
            doc.set_meta(op[1], op[2])
        elif kind == "issue" and op[1] not in {i.issue_id for i in doc.issues()}:
            doc.add_issue(category=op[2] or "uncategorized", issue_id=op[1])
        elif kind == "update" and op[1] in {i.issue_id for i in doc.issues()}:
            doc.update_issue(op[1], **{op[2]: op[3]})
        elif kind == "timeline":
            doc.add_timeline_entry(op[1], "note", op[2])


class TestCRDTPrimitives:
    def test_lww_keeps_later(self) -> None:
        a = LWWRegister("old", "000000000000001.000000.a")
        b = LWWRegister("new", "000000000000002.000000.b")
        assert a.merge(b).value == "new"
        assert b.merge(a).value == "new"

    def test_orset_add_wins(self) -> None:
        s = ORSet.empty().add("x", "t1")
        assert s.elements() == {"x"}
        # concurrent add (t2) survives a remove that only saw t1
        concurrent = s.add("x", "t2")
        removed = s.remove("x")  # removes only tag t1
        assert removed.merge(concurrent).elements() == {"x"}

    def test_growlog_is_append_only(self) -> None:
        log = GrowLog.empty().add("k", {"v": 1})
        merged = log.merge(GrowLog.empty().add("k2", {"v": 2}))
        assert set(merged.entries) == {"k", "k2"}


class TestConvergence:
    def test_concurrent_offline_edits_merge(self) -> None:
        a = _doc("A", 1_000_000)
        b = _doc("B", 2_000_000)
        a.add_issue(category="mold", issue_id="i1")
        b.merge(a.to_state())
        b.update_issue("i1", status="reported", severity="high")
        a.update_issue("i1", status="open-still")  # concurrent conflict on status
        b.add_issue(category="heat", issue_id="i2")

        merged = _doc("M", 9_000_000)
        merged.merge(a.to_state())
        merged.merge(b.to_state())
        ids = {i.issue_id for i in merged.issues()}
        assert ids == {"i1", "i2"}
        i1 = next(i for i in merged.issues() if i.issue_id == "i1")
        assert i1.severity == "high"  # uncontested write from B survives


class TestOpaqueIds:
    def test_same_salt_and_hlc_yield_the_same_id(self) -> None:
        doc = _doc("A", 1_000_000)
        doc.ensure_case_salt()
        hlc = "000000000000001.000000.node-a"
        # Deterministic per (salt, hlc): the same event always mints the same id.
        assert doc.opaque_id("issue", hlc) == doc.opaque_id("issue", hlc)
        # The prefix namespaces ids so an issue and a capture never collide.
        assert doc.opaque_id("issue", hlc) != doc.opaque_id("cap", hlc)

    def test_id_is_stable_across_devices_sharing_the_case_salt(self) -> None:
        doc = _doc("A", 1_000_000)
        doc.ensure_case_salt()
        hlc = "000000000000009.000004.node-a"
        # A peer that has synced the case (and thus the salt in meta) mints the
        # identical id for the same event, even on a different node/clock.
        peer = CaseDocument.from_state(
            doc.to_state(), HybridLogicalClock("B", time_source=_counter_clock(5_000_000))
        )
        assert peer.opaque_id("cap", hlc) == doc.opaque_id("cap", hlc)

    def test_minted_ids_do_not_encode_wall_clock_or_node_id(self) -> None:
        doc = _doc("secret-node-id", 1_767_312_000_000)
        issue = doc.add_issue(category="mold")
        entry = doc.add_timeline_entry(issue, "note", "leak")
        for ident in (issue, entry):
            assert ident.split("-", 1)[0] in {"issue", "tl"}
            assert "1767312000000" not in ident  # the device wall clock
            assert "secret-node-id" not in ident  # the HLC node id
            assert re.search(r"\d{15}\.\d{6}\.", ident) is None  # the raw HLC shape


class TestRecurrence:
    def _status(self, doc: CaseDocument, issue_id: str) -> str:
        return next(i for i in doc.issues() if i.issue_id == issue_id).status

    def test_records_recurrence_on_same_issue_and_reopens(self) -> None:
        doc = _doc("A", 1_000_000)
        doc.add_issue(category="mold", issue_id="i1")
        doc.update_issue("i1", status="resolved")
        assert self._status(doc, "i1") == "resolved"

        entry_id = doc.record_recurrence("i1", "mold is back in the same corner")

        recurrences = [e for e in doc.timeline("i1") if e.kind == "recurrence"]
        assert len(recurrences) == 1
        assert recurrences[0].entry_id == entry_id
        assert recurrences[0].issue_id == "i1"
        assert recurrences[0].text == "mold is back in the same corner"
        # No orphan issue was created and the same issue is reopened.
        assert {i.issue_id for i in doc.issues()} == {"i1"}
        assert self._status(doc, "i1") == "open"

    def test_unknown_issue_raises(self) -> None:
        doc = _doc("A", 1_000_000)
        with pytest.raises(HabitableError):
            doc.record_recurrence("nope")

    def test_survives_merge_round_trip(self) -> None:
        doc = _doc("A", 1_000_000)
        doc.add_issue(category="heat", issue_id="i1")
        doc.update_issue("i1", status="resolved")
        entry_id = doc.record_recurrence("i1", "no heat again")

        # to_state/from_state must preserve the recurrence and the reopened status.
        rebuilt = CaseDocument.from_state(
            doc.to_state(), HybridLogicalClock("R", time_source=_counter_clock(9_000_000))
        )
        rebuilt_recurrences = {e.entry_id for e in rebuilt.timeline("i1") if e.kind == "recurrence"}
        assert entry_id in rebuilt_recurrences
        assert self._status(rebuilt, "i1") == "open"

        # Merging that state into a fresh peer converges to the reopened issue too.
        peer = _doc("P", 2_000_000)
        peer.merge(doc.to_state())
        assert {e.entry_id for e in peer.timeline("i1") if e.kind == "recurrence"} == {entry_id}
        assert self._status(peer, "i1") == "open"


_ISSUE = st.sampled_from(["i1", "i2", "i3"])
_FIELD = st.sampled_from(["room", "title", "status", "severity", "description"])
_TEXT = st.text(alphabet="abcdef ", max_size=6)
_OP = st.one_of(
    st.tuples(st.just("meta"), st.sampled_from(["unit", "address"]), _TEXT),
    st.tuples(st.just("issue"), _ISSUE, _TEXT),
    st.tuples(st.just("update"), _ISSUE, _FIELD, _TEXT),
    st.tuples(st.just("timeline"), _ISSUE, _TEXT),
)
_OPS = st.lists(_OP, max_size=14)


@settings(max_examples=120, deadline=None)
@given(ops_a=_OPS, ops_b=_OPS)
def test_merge_is_commutative_and_idempotent(ops_a: list[Op], ops_b: list[Op]) -> None:
    a = _doc("A", 1_000_000)
    b = _doc("B", 50_000_000)
    _apply(a, ops_a)
    _apply(b, ops_b)

    ab = _doc("X", 100_000_000)
    ab.merge(a.to_state())
    ab.merge(b.to_state())

    ba = _doc("Y", 200_000_000)
    ba.merge(b.to_state())
    ba.merge(a.to_state())

    # Commutativity: merge order does not matter.
    assert ab.to_state() == ba.to_state()

    # Idempotence: re-merging the same states changes nothing.
    snapshot = ab.to_state()
    ab.merge(a.to_state())
    ab.merge(b.to_state())
    assert ab.to_state() == snapshot
