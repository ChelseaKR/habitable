# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from habitable.cli import main
from habitable.commons import canonical_category
from habitable.model import ISSUE_CATEGORIES, CaseDocument
from habitable.patterns import (
    CONSENT_META_PREFIX,
    HEAT_WEEKLY_QUESTION,
    SUPERSEDED_QUESTION_IDS,
    ConsentMissingError,
    build_heat_weekly_summary,
    consent_meta_key,
    read_consent,
    record_consent,
    superseded_consent_ids,
)
from habitable.vault import Vault

PASSPHRASE = "test-passphrase"


def _heat_case(make_vault: Callable[..., Vault], index: int) -> Vault:
    """A consenting household with one dated heat issue, seeded through the model.

    The category here is the one the product actually stores. That is not an
    incidental detail: until issue #276 this helper seeded ``no_heat``, a string
    no supported path could produce, which is why every assertion below passed
    against a cohort filter that could never match a real vault. Tests that are
    *about* consent use this fast path; the vocabulary itself is proved end to
    end through the CLI in :func:`test_the_counted_category_is_one_the_cli_stores`.
    """
    vault = make_vault(f"v{index}", case_id=f"case-{index}")
    issue = vault.document.add_issue(
        category="heat",
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


def _cli(*argv: str) -> int:
    return main([*argv])


def _consenting_household_via_cli(
    tmp_path: Path,
    make_jpeg: Callable[..., Path],
    capsys: pytest.CaptureFixture[str],
    index: int,
    *,
    typed_category: str,
    building: str = "1200 Elm",
) -> Path:
    """One household set up entirely through commands a person can type.

    ``init``, ``issue``, ``capture``, ``consent record`` -- nothing here reaches
    past the CLI into the model, so the category that ends up in the vault is
    the one the product produces rather than one the test asserts. That
    distinction is the whole of issue #276: the old fixture called ``add_issue``
    with ``no_heat``, a literal argparse rejects, so the suite proved the
    aggregate worked on data the product could not create.
    """
    path = tmp_path / f"case-{index}"
    assert (
        _cli(
            "init",
            str(path),
            "--case",
            f"case-{index}",
            "--unit",
            f"{index}A",
            "--building",
            building,
            "--passphrase",
            PASSPHRASE,
        )
        == 0
    )
    vault_args = ["--vault", str(path), "--passphrase", PASSPHRASE]
    capsys.readouterr()
    assert _cli("issue", *vault_args, "--category", typed_category, "--title", "cold flat") == 0
    # The command prints the id it just wrote; that print is the only handle a
    # person has on the issue, so the test takes the same one.
    issue_id = capsys.readouterr().out.split("added issue ", 1)[1].split(" ", 1)[0]
    media = make_jpeg(f"photo-{index}.jpg")
    assert _cli("capture", str(media), *vault_args, "--issue", issue_id, "--no-timestamp") == 0
    assert _cli("consent", "record", *vault_args) == 0
    capsys.readouterr()
    return path


def _run_pattern(out: Path, vault_paths: list[Path], *, k: int = 3) -> int:
    argv = ["pattern", "--out", str(out), "--k", str(k), "--passphrase", PASSPHRASE]
    for path in vault_paths:
        argv.extend(["--vault", str(path)])
    argv.append("--confirm-consent")
    return _cli(*argv)


def test_the_question_names_a_category_the_vocabulary_can_actually_store() -> None:
    """The structural guard for issue #276, independent of any seeded fixture.

    The defect was not a wrong line of code so much as a question and a
    vocabulary drifting apart with nothing watching the gap. #206 constrained
    ``--category`` to ``ISSUE_CATEGORIES``; the pattern question went on
    counting ``no_heat``, and every test stayed green because each one seeded
    the very string the product had stopped producing. A cohort filter naming a
    category no issue can be stored under yields an empty aggregate, and an
    empty consent-gated aggregate does not read as an error -- it reads as "no
    household reported this", which an organizer can act on.

    This assertion holds without a vault, a fixture, or a consent record, so it
    fails the moment the two drift again rather than after someone notices a
    building of zeroes.
    """
    category = HEAT_WEEKLY_QUESTION.category
    assert category in ISSUE_CATEGORIES, (
        f"the pattern question counts {category!r}, which `habitable issue "
        f"--category` will not accept; no supported path can store it"
    )
    assert canonical_category(category) == category, (
        f"{category!r} is normalised to something else before it is stored, so the "
        "cohort filter would never see it"
    )


def test_the_counted_category_is_one_the_cli_stores(
    tmp_path: Path,
    make_jpeg: Callable[..., Path],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The regression test issue #276 asks for: a path a user can actually take.

    Run against the pre-#276 filter (``category="no_heat"``) this fails, because
    the cohort comes back empty and the export publishes zero cells -- exactly
    the silent, publishable non-answer the issue is about, since an empty
    consent-gated aggregate reads as "no household reported this".

    Three households clear ``k=3`` in one building and one ISO week, so a
    published cell is the honest outcome here and its absence is a real failure
    rather than ordinary suppression.
    """
    vault_paths = [
        _consenting_household_via_cli(tmp_path, make_jpeg, capsys, index, typed_category="heat")
        for index in range(3)
    ]
    out = tmp_path / "pattern.json"
    assert _run_pattern(out, vault_paths) == 0

    payload = json.loads(out.read_text(encoding="utf-8"))
    cells = payload["aggregate"]["cells"]
    assert cells, (
        "the building aggregate is empty for three consenting households that each "
        "recorded a heat condition through the CLI; the question counts a category "
        "no supported path stores"
    )
    assert len(cells) == 1
    assert cells[0]["category"] == "heat"
    assert cells[0]["building_label"] == "1200 Elm"
    assert cells[0]["household_count"] == 3
    assert cells[0]["period"] == "2026-W01"
    assert payload["aggregate"]["suppressed_cells"] == 0


def test_the_cli_synonym_lands_in_the_same_cell_as_the_member_it_means(
    tmp_path: Path,
    make_jpeg: Callable[..., Path],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A household that typed ``--category no_heat`` is counted with the rest.

    #240 lets a tenant use their own word and normalises it to ``heat`` at
    entry, printing what it did. That normalisation is what makes the word safe
    to accept; this is the other half of the promise -- that using it does not
    quietly cost the household its place in the building's count. One of the
    three households below types the synonym and the cell still reads three.
    """
    vault_paths = [
        _consenting_household_via_cli(tmp_path, make_jpeg, capsys, index, typed_category=typed)
        for index, typed in enumerate(("heat", "no_heat", "heat"))
    ]
    out = tmp_path / "pattern.json"
    assert _run_pattern(out, vault_paths) == 0

    cells = json.loads(out.read_text(encoding="utf-8"))["aggregate"]["cells"]
    assert len(cells) == 1
    assert cells[0]["household_count"] == 3


def test_the_published_question_says_what_the_category_does_not_distinguish() -> None:
    """The prompt is a claim about a published number, so it may not overstate.

    ``heat`` is the vocabulary's finest grain and covers no heat at all,
    inadequate heat, and heat a household cannot control. A prompt that promised
    "reported no heat" would describe a number the record cannot produce, so the
    question was reworded to the condition the record holds and the caveat
    travels *in the file* -- a reviewer brief warning about it reaches whoever
    reads the brief, not whoever is handed the export.
    """
    exported = build_heat_weekly_summary([], k=3).to_json()
    question = exported["question"]
    assert isinstance(question, dict)

    prompt = question["prompt"]
    assert isinstance(prompt, str)
    assert "reported a heat condition" in prompt
    assert "no heat" not in prompt

    scope_note = question["scope_note"]
    assert isinstance(scope_note, str)
    assert "no heat at all" in scope_note
    assert "not a count of households with no heat" in scope_note
    assert question["supersedes"] == list(SUPERSEDED_QUESTION_IDS)


def test_fixed_pattern_question_suppresses_small_cells_and_excludes_case_data(
    make_vault: Callable[..., Vault],
) -> None:
    cases: list[tuple[CaseDocument, str]] = []
    for index in range(3):
        vault = _heat_case(make_vault, index)
        record_consent(vault.document, HEAT_WEEKLY_QUESTION, granted=True)
        cases.append((vault.document, "Building A"))

    exported = build_heat_weekly_summary(cases, k=3).to_json()
    text = str(exported)
    question = exported["question"]
    aggregate = exported["aggregate"]
    assert isinstance(question, dict)
    assert isinstance(aggregate, dict)
    cells = aggregate["cells"]
    assert isinstance(cells, list)
    first_cell = cells[0]
    assert isinstance(first_cell, dict)

    assert question["question_id"] == "consenting_households_heat_condition_by_week"
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
        vault = _heat_case(make_vault, index)
        record_consent(vault.document, HEAT_WEEKLY_QUESTION, granted=True)
        cases.append((vault.document, "Building A"))

    exported = build_heat_weekly_summary(cases, k=3).to_json()
    consent = exported["consent"]
    aggregate = exported["aggregate"]
    assert isinstance(consent, dict)
    assert isinstance(aggregate, dict)

    assert consent["explicit_per_export"] is False
    assert consent["recorded_consent_required"] is True
    assert consent["mechanism"] == "per_case_record_in_household_vault"
    assert consent["cases_with_recorded_consent"] == 3
    assert consent["cases_with_recorded_consent"] == aggregate["contributing_cases"]
    assert consent["superseded_records_honoured"] is False
    assert exported["schema_version"] == 3


def test_a_case_with_no_recorded_consent_is_refused(
    make_vault: Callable[..., Vault],
) -> None:
    consenting = [_heat_case(make_vault, index) for index in range(3)]
    for vault in consenting:
        record_consent(vault.document, HEAT_WEEKLY_QUESTION, granted=True)
    silent = _heat_case(make_vault, 3)

    cases: list[tuple[CaseDocument, str]] = [(v.document, "Building A") for v in consenting]
    cases.append((silent.document, "Building A"))

    with pytest.raises(ConsentMissingError, match="no recorded consent"):
        build_heat_weekly_summary(cases, k=3)


def test_a_withdrawn_case_is_refused_and_is_distinct_from_never_recorded(
    make_vault: Callable[..., Vault],
) -> None:
    vault = _heat_case(make_vault, 0)
    assert read_consent(vault.document, HEAT_WEEKLY_QUESTION) is None

    record_consent(vault.document, HEAT_WEEKLY_QUESTION, granted=True)
    granted = read_consent(vault.document, HEAT_WEEKLY_QUESTION)
    assert granted is not None and granted.granted

    record_consent(vault.document, HEAT_WEEKLY_QUESTION, granted=False)
    withdrawn = read_consent(vault.document, HEAT_WEEKLY_QUESTION)
    assert withdrawn is not None
    assert withdrawn.state == "withdrawn"
    assert not withdrawn.granted

    with pytest.raises(ConsentMissingError, match="withdrawn"):
        build_heat_weekly_summary([(vault.document, "Building A")], k=3)


def test_consent_to_the_retired_question_is_not_consent_to_this_one(
    make_vault: Callable[..., Vault],
) -> None:
    """The #276 migration, stated as a refusal rather than as a doc nobody read.

    Retiring ``consenting_households_no_heat_by_week`` orphans every stored
    consent record, and that is the point: the household answered a narrower
    sentence than the one now exported, and carrying their answer forward would
    make the export claim a consent nobody gave -- the #182 failure, committed
    once more with a straighter face. The refusal is the safe direction and it
    is loud, so the only cost is that each household is asked again.

    What the refusal must not be is mystifying. An organizer whose neighbours
    all consented last month needs the message to say *why* their export stopped
    working, or it looks like a bug, or like a neighbour who changed their mind.
    """
    vault = _heat_case(make_vault, 0)
    retired = SUPERSEDED_QUESTION_IDS[0]
    vault.document.set_meta(f"{CONSENT_META_PREFIX}{retired}", "granted")

    assert superseded_consent_ids(vault.document) == (retired,)
    assert read_consent(vault.document, HEAT_WEEKLY_QUESTION) is None

    with pytest.raises(ConsentMissingError) as raised:
        build_heat_weekly_summary([(vault.document, "Building A")], k=3)
    message = str(raised.value)
    assert "no recorded consent" in message
    assert retired in message
    assert "habitable consent record" in message


def test_a_case_with_no_history_at_all_gets_no_migration_hint(
    make_vault: Callable[..., Vault],
) -> None:
    """A household that simply never consented must not be told about a migration."""
    vault = _heat_case(make_vault, 0)
    assert superseded_consent_ids(vault.document) == ()
    with pytest.raises(ConsentMissingError) as raised:
        build_heat_weekly_summary([(vault.document, "Building A")], k=3)
    assert "retired question" not in str(raised.value)


def test_a_recorded_consent_carries_signed_authorship_provenance(
    make_vault: Callable[..., Vault],
) -> None:
    vault = _heat_case(make_vault, 0)
    record_consent(vault.document, HEAT_WEEKLY_QUESTION, granted=True)
    record = read_consent(vault.document, HEAT_WEEKLY_QUESTION)
    assert record is not None
    assert record.signed
    assert record.actor == vault.identity.public().fingerprint
    assert record.recorded_at
    provenance = vault.document.meta_provenance(consent_meta_key(HEAT_WEEKLY_QUESTION))
    assert provenance is not None
    assert provenance.ts == record.recorded_at


def test_cli_pattern_refuses_a_vault_with_no_consent_record(
    make_vault: Callable[..., Vault],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The regression the old command could not fail: no record, and it still wrote a file."""
    vaults = [_heat_case(make_vault, index) for index in range(3)]
    for vault in vaults[:2]:
        record_consent(vault.document, HEAT_WEEKLY_QUESTION, granted=True)
    for vault in vaults:
        vault.save()

    out = tmp_path / "pattern.json"
    argv = ["pattern", "--out", str(out), "--k", "3", "--passphrase", PASSPHRASE]
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
    vaults = [_heat_case(make_vault, index) for index in range(3)]
    for vault in vaults:
        record_consent(vault.document, HEAT_WEEKLY_QUESTION, granted=True)
        vault.save()

    out = tmp_path / "pattern.json"
    argv = ["pattern", "--out", str(out), "--k", "3", "--passphrase", PASSPHRASE]
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
    vault = _heat_case(make_vault, 0)
    vault.save()
    args = ["--vault", str(vault.path), "--passphrase", PASSPHRASE]

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
