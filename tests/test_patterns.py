# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif

from __future__ import annotations

from collections.abc import Callable

from habitable.model import CaseDocument
from habitable.patterns import build_no_heat_weekly_summary
from habitable.vault import Vault


def test_fixed_pattern_question_suppresses_small_cells_and_excludes_case_data(
    make_vault: Callable[..., Vault],
) -> None:
    cases: list[tuple[CaseDocument, str, str]] = []
    for index in range(3):
        vault = make_vault(f"v{index}", case_id=f"case-{index}")
        issue = vault.document.add_issue(
            category="no_heat",
            room=f"private-room-{index}",
            title=f"private-title-{index}",
        )
        vault.document.add_capture(
            issue_id=issue,
            content_hash="a" * 64,
            media_type="text/csv",
            sealed_name=f"sealed-{index}",
            captured_at="2026-01-08T00:00:00Z",
        )
        cases.append((vault.document, "Building A", f"consent-{index}"))

    exported = build_no_heat_weekly_summary(cases, k=3).to_json()
    text = str(exported)
    question = exported["question"]
    aggregate = exported["aggregate"]
    assert isinstance(question, dict)
    assert isinstance(aggregate, dict)
    cells = aggregate["cells"]
    assert isinstance(cells, list)
    first_cell = cells[0]
    assert isinstance(first_cell, dict)

    assert question["question_id"] == "consenting_households_no_heat_by_week"
    assert first_cell["household_count"] == 3
    assert first_cell["period"] == "2026-W02"
    assert "private-room" not in text
    assert "private-title" not in text
    assert "case-" not in text
    assert "consent-" not in text
