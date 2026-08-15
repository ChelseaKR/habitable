# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from habitable.cli import main
from habitable.model import CaseDocument
from habitable.patterns import (
    NO_HEAT_WEEKLY_QUESTION,
    ConsentMissingError,
    build_no_heat_weekly_summary,
    consent_meta_key,
    read_consent,
    record_consent,
)
from habitable.vault import Vault


def _no_heat_case(make_vault: Callable[..., Vault], index: int) -> Vault:
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
    return vault


def test_fixed_pattern_question_suppresses_small_cells_and_excludes_case_data(
    make_vault: Callable[..., Vault],
) -> None:
    cases: list[tuple[CaseDocument, str]] = []
    for index in range(3):
        vault = _no_heat_case(make_vault, index)
        record_consent(vault.document, NO_HEAT_WEEKLY_QUESTION, granted=True)
        cases.append((vault.document, "Building A"))

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
    # The distinct-household token is derived from the consent record and must
    # never reach the export.
    assert "pattern-consent" not in text


def test_export_does_not_claim_per_export_consent_and_counts_the_records(
    make_vault: Callable[..., Vault],
) -> None:
    """The consent block reports the mechanism that exists, not the one that does not."""
    cases: list[tuple[CaseDocument, str]] = []
    for index in range(3):
        vault = _no_heat_case(make_vault, index)
        record_consent(vault.document, NO_HEAT_WEEKLY_QUESTION, granted=True)
        cases.append((vault.document, "Building A"))

    exported = build_no_heat_weekly_summary(cases, k=3).to_json()
    consent = exported["consent"]
    aggregate = exported["aggregate"]
    assert isinstance(consent, dict)
    assert isinstance(aggregate, dict)

    assert consent["explicit_per_export"] is False
    assert consent["recorded_consent_required"] is True
    assert consent["mechanism"] == "per_case_record_in_household_vault"
    assert consent["cases_with_recorded_consent"] == 3
    assert consent["cases_with_recorded_consent"] == aggregate["contributing_cases"]
    assert exported["schema_version"] == 2


def test_a_case_with_no_recorded_consent_is_refused(
    make_vault: Callable[..., Vault],
) -> None:
    consenting = [_no_heat_case(make_vault, index) for index in range(3)]
    for vault in consenting:
        record_consent(vault.document, NO_HEAT_WEEKLY_QUESTION, granted=True)
    silent = _no_heat_case(make_vault, 3)

    cases: list[tuple[CaseDocument, str]] = [(v.document, "Building A") for v in consenting]
    cases.append((silent.document, "Building A"))

    with pytest.raises(ConsentMissingError, match="no recorded consent"):
        build_no_heat_weekly_summary(cases, k=3)


def test_a_withdrawn_case_is_refused_and_is_distinct_from_never_recorded(
    make_vault: Callable[..., Vault],
) -> None:
    vault = _no_heat_case(make_vault, 0)
    assert read_consent(vault.document, NO_HEAT_WEEKLY_QUESTION) is None

    record_consent(vault.document, NO_HEAT_WEEKLY_QUESTION, granted=True)
    granted = read_consent(vault.document, NO_HEAT_WEEKLY_QUESTION)
    assert granted is not None and granted.granted

    record_consent(vault.document, NO_HEAT_WEEKLY_QUESTION, granted=False)
    withdrawn = read_consent(vault.document, NO_HEAT_WEEKLY_QUESTION)
    assert withdrawn is not None
    assert withdrawn.state == "withdrawn"
    assert not withdrawn.granted

    with pytest.raises(ConsentMissingError, match="withdrawn"):
        build_no_heat_weekly_summary([(vault.document, "Building A")], k=3)


def test_a_recorded_consent_carries_signed_authorship_provenance(
    make_vault: Callable[..., Vault],
) -> None:
    vault = _no_heat_case(make_vault, 0)
    record_consent(vault.document, NO_HEAT_WEEKLY_QUESTION, granted=True)
    record = read_consent(vault.document, NO_HEAT_WEEKLY_QUESTION)
    assert record is not None
    assert record.signed
    assert record.actor == vault.identity.public().fingerprint
    assert record.recorded_at
    provenance = vault.document.meta_provenance(consent_meta_key(NO_HEAT_WEEKLY_QUESTION))
    assert provenance is not None
    assert provenance.ts == record.recorded_at


def test_cli_pattern_refuses_a_vault_with_no_consent_record(
    make_vault: Callable[..., Vault],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The regression the old command could not fail: no record, and it still wrote a file."""
    vaults = [_no_heat_case(make_vault, index) for index in range(3)]
    for vault in vaults[:2]:
        record_consent(vault.document, NO_HEAT_WEEKLY_QUESTION, granted=True)
    for vault in vaults:
        vault.save()

    out = tmp_path / "pattern.json"
    argv = ["pattern", "--out", str(out), "--k", "3", "--passphrase", "test-passphrase"]
    for vault in vaults:
        argv.extend(["--vault", str(vault.path)])
    argv.append("--confirm-consent")

    assert main(argv) == 1
    assert not out.exists()
    assert "no recorded consent" in capsys.readouterr().err


def test_cli_pattern_writes_an_export_that_does_not_claim_per_export_consent(
    make_vault: Callable[..., Vault],
    tmp_path: Path,
) -> None:
    vaults = [_no_heat_case(make_vault, index) for index in range(3)]
    for vault in vaults:
        record_consent(vault.document, NO_HEAT_WEEKLY_QUESTION, granted=True)
        vault.save()

    out = tmp_path / "pattern.json"
    argv = ["pattern", "--out", str(out), "--k", "3", "--passphrase", "test-passphrase"]
    for vault in vaults:
        argv.extend(["--vault", str(vault.path)])
    argv.append("--confirm-consent")

    assert main(argv) == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["consent"]["explicit_per_export"] is False
    assert payload["consent"]["cases_with_recorded_consent"] == 3


def test_cli_consent_record_show_and_withdraw_round_trip(
    make_vault: Callable[..., Vault],
    capsys: pytest.CaptureFixture[str],
) -> None:
    vault = _no_heat_case(make_vault, 0)
    vault.save()
    args = ["--vault", str(vault.path), "--passphrase", "test-passphrase"]

    assert main(["consent", "show", *args]) == 0
    assert "not recorded" in capsys.readouterr().out

    assert main(["consent", "record", *args]) == 0
    capsys.readouterr()
    assert main(["consent", "show", *args]) == 0
    shown = capsys.readouterr().out
    assert "consent: granted" in shown
    assert "signed authorship" in shown

    assert main(["consent", "record", *args, "--withdraw"]) == 0
    capsys.readouterr()
    assert main(["consent", "show", *args]) == 0
    assert "consent: withdrawn" in capsys.readouterr().out
