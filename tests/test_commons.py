# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""EXP-14 aggregate commons: k-anonymity, on-device reduction, and no telemetry."""

from __future__ import annotations

import inspect
import json
from collections.abc import Callable
from typing import cast

import pytest

from habitable import commons
from habitable.clock import HybridLogicalClock
from habitable.commons import (
    DEFAULT_K,
    MIN_K,
    CaseContribution,
    IssueObservation,
    build_commons,
    summarize_case,
)
from habitable.errors import HabitableError
from habitable.model import CaseDocument


def _counter_clock(start_ms: int) -> Callable[[], int]:
    state = {"t": start_ms}

    def tick() -> int:
        state["t"] += 1
        return state["t"]

    return tick


def _doc(case_id: str) -> CaseDocument:
    return CaseDocument(case_id, HybridLogicalClock(case_id, time_source=_counter_clock(1)))


def _case(case_id: str, building: str, issues: list[tuple[str, str]]) -> CaseContribution:
    """Build a contribution directly, dating each issue to a fixed period."""
    return CaseContribution(
        household_token=case_id,
        building_label=building,
        observations=tuple(IssueObservation(category=c, period=p) for c, p in issues),
    )


class TestKAnonymity:
    def test_cell_below_threshold_is_suppressed(self) -> None:
        # Two households report mold: below the default k of 5.
        cases = [
            _case("h1", "1200 Elm", [("mold", "2026-01")]),
            _case("h2", "1200 Elm", [("mold", "2026-01")]),
        ]
        export = build_commons(cases, k=5)
        assert export.cells == ()
        assert export.suppressed_cells == 1
        assert export.contributing_cases == 2

    def test_cell_at_threshold_is_published(self) -> None:
        cases = [_case(f"h{i}", "1200 Elm", [("mold", "2026-01")]) for i in range(5)]
        export = build_commons(cases, k=5)
        assert len(export.cells) == 1
        cell = export.cells[0]
        assert cell.building_label == "1200 Elm"
        assert cell.category == "mold"
        assert cell.household_count == 5
        assert cell.issue_count == 5
        assert export.suppressed_cells == 0

    def test_multiple_issues_one_household_do_not_defeat_threshold(self) -> None:
        # One prolific household filing many mold issues must NOT clear a k=3 cell:
        # the threshold is distinct households, not raw issue count.
        cases = [_case("h1", "1200 Elm", [("mold", "2026-01")] * 10)]
        export = build_commons(cases, k=3)
        assert export.cells == ()
        assert export.suppressed_cells == 1

    def test_issue_count_can_exceed_household_count(self) -> None:
        cases = [_case(f"h{i}", "1200 Elm", [("mold", "2026-01")] * 2) for i in range(3)]
        export = build_commons(cases, k=3)
        assert len(export.cells) == 1
        assert export.cells[0].household_count == 3
        assert export.cells[0].issue_count == 6

    def test_k_below_minimum_is_refused(self) -> None:
        cases = [_case(f"h{i}", "1200 Elm", [("mold", "2026-01")]) for i in range(3)]
        for bad_k in (0, 1, MIN_K - 1):
            with pytest.raises(HabitableError, match="at least"):
                build_commons(cases, k=bad_k)

    def test_default_k_meets_minimum(self) -> None:
        assert DEFAULT_K >= MIN_K


class TestAggregation:
    def test_groups_by_building_category_period(self) -> None:
        cases = [
            _case("a1", "1200 Elm", [("mold", "2026-01"), ("heat", "2026-02")]),
            _case("a2", "1200 Elm", [("mold", "2026-01")]),
            _case("a3", "1200 Elm", [("mold", "2026-01")]),
            _case("b1", "9 Oak", [("mold", "2026-01")]),
            _case("b2", "9 Oak", [("mold", "2026-01")]),
            _case("b3", "9 Oak", [("mold", "2026-01")]),
        ]
        export = build_commons(cases, k=3)
        keys = {(c.building_label, c.category, c.period) for c in export.cells}
        assert keys == {
            ("1200 Elm", "mold", "2026-01"),
            ("9 Oak", "mold", "2026-01"),
        }
        # Elm heat (1 household) and Elm Feb are suppressed.
        assert export.suppressed_cells == 1

    def test_output_is_sorted_deterministically(self) -> None:
        cases = [_case(f"z{i}", "Zeta", [("plumbing", "2026-03")]) for i in range(3)]
        cases += [_case(f"a{i}", "Alpha", [("mold", "2026-01")]) for i in range(3)]
        export = build_commons(cases, k=3)
        labels = [c.building_label for c in export.cells]
        assert labels == sorted(labels)


class TestNoPersonalData:
    def test_household_token_never_appears_in_output(self) -> None:
        token = "SENSITIVE-CASE-ID-4B-Dorothy"
        cases = [
            CaseContribution(
                household_token=f"{token}-{i}",
                building_label="1200 Elm",
                observations=(IssueObservation("mold", "2026-01"),),
            )
            for i in range(4)
        ]
        export = build_commons(cases, k=3)
        blob = json.dumps(export.to_json())
        assert token not in blob
        # No cell field leaks the token or any household identity.
        for cell in export.cells:
            assert token not in json.dumps(cell.to_json())

    def test_export_has_no_network_or_telemetry(self) -> None:
        # The provenance block must assert the invariants machine-readably.
        export = build_commons(
            [_case(f"h{i}", "1200 Elm", [("mold", "2026-01")]) for i in range(3)],
            k=3,
        )
        provenance = cast(dict[str, object], export.to_json()["provenance"])
        assert provenance["telemetry"] is False
        assert provenance["network_transmission"] is False
        assert provenance["opt_in"] is True
        assert provenance["on_device"] is True
        assert provenance["k_anonymity_threshold"] == 3

    def test_module_imports_nothing_network_capable(self) -> None:
        # A structural guard: the commons module must not import any network stack,
        # so it is incapable of phoning home even if misused.
        source = inspect.getsource(commons)
        for banned in ("import socket", "import http", "import urllib", "requests", "httpx"):
            assert banned not in source


class TestSummarizeCase:
    def test_reduces_issue_to_category_and_period_from_capture(self) -> None:
        doc = _doc("case-4B")
        issue = doc.add_issue(category="mold", room="bathroom", title="Black mold", severity="high")
        doc.add_capture(
            issue_id=issue,
            content_hash="deadbeef",
            media_type="image/jpeg",
            sealed_name="x.enc",
            captured_at="2026-01-02T09:15:00Z",
        )
        contribution = summarize_case(doc, building_label="1200 Elm", household_token="tok-1")
        assert contribution.building_label == "1200 Elm"
        assert contribution.household_token == "tok-1"
        assert contribution.observations == (IssueObservation("mold", "2026-01"),)

    def test_quarter_granularity(self) -> None:
        doc = _doc("case-4B")
        issue = doc.add_issue(category="heat")
        doc.add_capture(
            issue_id=issue,
            content_hash="h",
            media_type="image/jpeg",
            sealed_name="x.enc",
            captured_at="2026-05-11T00:00:00Z",
        )
        contribution = summarize_case(
            doc, building_label="Elm", household_token="t", granularity="quarter"
        )
        assert contribution.observations == (IssueObservation("heat", "2026-Q2"),)

    def test_issue_without_capture_is_unknown_period(self) -> None:
        doc = _doc("case-4B")
        doc.add_issue(category="mold")
        contribution = summarize_case(doc, building_label="Elm", household_token="t")
        assert contribution.observations == (IssueObservation("mold", "unknown"),)

    def test_blank_category_becomes_uncategorized(self) -> None:
        doc = _doc("case-4B")
        doc.add_issue(category="")
        contribution = summarize_case(doc, building_label="Elm", household_token="t")
        assert contribution.observations[0].category == "uncategorized"

    def test_removed_issue_is_excluded(self) -> None:
        doc = _doc("case-4B")
        issue = doc.add_issue(category="mold")
        doc.remove_issue(issue)
        contribution = summarize_case(doc, building_label="Elm", household_token="t")
        assert contribution.observations == ()

    def test_blank_building_label_is_rejected(self) -> None:
        doc = _doc("case-4B")
        with pytest.raises(HabitableError, match="building_label"):
            summarize_case(doc, building_label="   ", household_token="t")

    def test_blank_household_token_is_rejected(self) -> None:
        doc = _doc("case-4B")
        with pytest.raises(HabitableError, match="household_token"):
            summarize_case(doc, building_label="Elm", household_token="  ")


class TestEndToEnd:
    def test_two_buildings_month_summary(self) -> None:
        # Build real case docs, summarize each on-device, then aggregate.
        contributions = []
        for i in range(4):
            doc = _doc(f"elm-{i}")
            issue = doc.add_issue(category="mold")
            doc.add_capture(
                issue_id=issue,
                content_hash="h",
                media_type="image/jpeg",
                sealed_name="x.enc",
                captured_at="2026-01-15T12:00:00Z",
            )
            contributions.append(
                summarize_case(doc, building_label="1200 Elm", household_token=f"elm-{i}")
            )
        export = build_commons(contributions, k=3)
        assert len(export.cells) == 1
        assert export.cells[0].household_count == 4
        assert export.cells[0].period == "2026-01"
