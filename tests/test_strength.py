# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""On-device record-strength self-assessment (EXP-03)."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from habitable.capture import capture
from habitable.strength import RecordStrengthLevel, assess_capture, assess_case, assess_issue
from habitable.tsa import LocalRfc3161TSA
from habitable.vault import Vault


def test_awaiting_timestamp_is_minimal(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path]
) -> None:
    vault = make_vault()
    issue = vault.document.add_issue(category="mold", issue_id="i1")
    result = capture(vault, make_jpeg("a.jpg"), issue_id=issue, tsa=None)
    assert result.timestamped is False

    item = assess_capture(vault, vault.document.captures(issue)[0])
    assert item.has_timestamp is False
    assert item.authority_count == 0
    assert item.level is RecordStrengthLevel.MINIMAL
    # Custody still records capture + fixity-check even with no timestamp yet.
    assert item.custody_entries >= 2


def test_single_authority_is_developing(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], local_tsa: LocalRfc3161TSA
) -> None:
    vault = make_vault()
    issue = vault.document.add_issue(category="mold", issue_id="i1")
    capture(vault, make_jpeg("a.jpg"), issue_id=issue, tsa=local_tsa)

    item = assess_capture(vault, vault.document.captures(issue)[0])
    assert item.has_timestamp is True
    assert item.authority_count == 1
    assert item.level is RecordStrengthLevel.DEVELOPING


def test_redundant_authorities_are_strong(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], local_tsa: LocalRfc3161TSA
) -> None:
    second = LocalRfc3161TSA("second-tsa")
    vault = make_vault()
    issue = vault.document.add_issue(category="mold", issue_id="i1")
    capture(vault, make_jpeg("a.jpg"), issue_id=issue, tsa=local_tsa, extra_tsas=[second])

    item = assess_capture(vault, vault.document.captures(issue)[0])
    assert item.authority_count == 2
    assert item.level is RecordStrengthLevel.STRONG


def test_corroborating_timeline_counted(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], local_tsa: LocalRfc3161TSA
) -> None:
    vault = make_vault()
    issue = vault.document.add_issue(category="mold", issue_id="i1")
    capture(vault, make_jpeg("a.jpg"), issue_id=issue, tsa=local_tsa)
    vault.document.add_timeline_entry(issue, "repair_request", "asked landlord to fix")
    vault.document.add_timeline_entry(issue, "landlord_response", "no response after 14 days")

    item = assess_capture(vault, vault.document.captures(issue)[0])
    assert item.corroborating_timeline_entries == 2


def test_issue_level_is_weakest_of_its_items(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], local_tsa: LocalRfc3161TSA
) -> None:
    vault = make_vault()
    issue = vault.document.add_issue(category="mold", issue_id="i1")
    capture(vault, make_jpeg("a.jpg"), issue_id=issue, tsa=local_tsa)  # developing
    capture(vault, make_jpeg("b.jpg"), issue_id=issue, tsa=None)  # minimal (awaiting)

    strength = assess_issue(vault, issue)
    assert strength.item_count == 2
    assert strength.developing_count == 1
    assert strength.minimal_count == 1
    assert strength.level is RecordStrengthLevel.MINIMAL


def test_issue_with_no_captures_is_minimal(make_vault: Callable[..., Vault]) -> None:
    vault = make_vault()
    issue = vault.document.add_issue(category="mold", issue_id="i1")

    strength = assess_issue(vault, issue)
    assert strength.item_count == 0
    assert strength.level is RecordStrengthLevel.MINIMAL


def test_issue_all_strong_items_is_strong(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], local_tsa: LocalRfc3161TSA
) -> None:
    second = LocalRfc3161TSA("second-tsa")
    vault = make_vault()
    issue = vault.document.add_issue(category="mold", issue_id="i1")
    capture(vault, make_jpeg("a.jpg"), issue_id=issue, tsa=local_tsa, extra_tsas=[second])
    capture(vault, make_jpeg("b.jpg"), issue_id=issue, tsa=local_tsa, extra_tsas=[second])

    strength = assess_issue(vault, issue)
    assert strength.strong_count == 2
    assert strength.level is RecordStrengthLevel.STRONG


def test_assess_case_covers_every_issue(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], local_tsa: LocalRfc3161TSA
) -> None:
    vault = make_vault()
    i1 = vault.document.add_issue(category="mold", issue_id="i1")
    i2 = vault.document.add_issue(category="heat", issue_id="i2")
    capture(vault, make_jpeg("a.jpg"), issue_id=i1, tsa=local_tsa)

    results = assess_case(vault)
    assert {r.issue_id for r in results} == {i1, i2}
