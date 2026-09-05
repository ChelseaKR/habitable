# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""The readability report has to keep producing a number, and keep refusing to gate.

``docs/audits/plain-language-review.md`` states a reading-level target of roughly US
grade 6-8. Before ``scripts/report_readability.py`` that target was applied by
judgment and never measured (#246). A measurement nobody runs decays back into an
assertion, so these tests pin the three properties that make the script worth
having:

* it **produces a number** over the real English bundle, from a corpus that is
  actually populated — a script that silently scored zero strings would still print
  a tidy report;
* it **renders** the ICU subset a reader never sees, picking one plural branch
  rather than scoring ``=0``, ``one`` and ``other`` concatenated;
* it **never fails a build**. Deliberately unreadable copy still exits 0. This is
  the #246 decision: a hard threshold would press hardest on the legally sensitive
  strings, and the cheapest way to pass a threshold is to soften a warning. The
  honest-limits strings are therefore held out of the headline number, and the test
  below pins that they are held out via the list in
  ``docs/localization-guide.md`` rather than by a copy that can drift from it.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent.parent
_SCRIPT = _ROOT / "scripts" / "report_readability.py"

_FIXTURE_GUIDE = (
    "# fixture guide\n\n"
    "## Legally-sensitive strings\n\n"
    "| Key | English | Why it is sensitive |\n"
    "| --- | --- | --- |\n"
    "| `alpha_warning` | Alpha software | the core honesty caveat |\n\n"
    "## Something else\n\n"
    "| `not_a_sensitive_key` | ignored | outside the section |\n"
)


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(_SCRIPT), *args],
        capture_output=True,
        check=False,
        text=True,
    )


def _fixture(tmp_path: Path, bundle: dict[str, str]) -> tuple[str, str]:
    """Write a throwaway bundle + guide and return the CLI arguments for them."""
    bundle_path = tmp_path / "en.json"
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
    guide_path = tmp_path / "localization-guide.md"
    guide_path.write_text(_FIXTURE_GUIDE, encoding="utf-8")
    return f"--bundle={bundle_path}", f"--guide={guide_path}"


def _payload(result: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    assert result.returncode == 0, result.stdout + result.stderr
    parsed: dict[str, Any] = json.loads(result.stdout)
    return parsed


def test_real_english_bundle_yields_a_grade_from_a_populated_corpus() -> None:
    """The headline number exists, and it was computed over real sentences.

    The band is deliberately wide. This is not a threshold in disguise: it only
    catches the failure where the script keeps printing while the corpus has gone
    empty (a rendering change that swallows every string, a bundle that moved),
    which would otherwise look like a very good score.
    """
    payload = _payload(_run("--json"))
    ordinary = payload["ordinary_prose"]

    assert ordinary["strings"] >= 20
    assert ordinary["words"] >= 200
    assert ordinary["sentences"] >= 20
    assert 0.0 < ordinary["flesch_kincaid_grade"] < 20.0
    assert 0.0 < ordinary["smog_grade"] < 20.0
    assert 0.0 < ordinary["flesch_reading_ease"] < 120.0


def test_human_report_prints_the_score_and_names_the_honest_limits() -> None:
    """The printed report is the artifact a person reads, so pin its shape.

    Specifically: the honest-limits block must stay visible and captioned. If it
    ever silently merges into the headline number, the next person to chase a
    grade will chase it by softening a warning.
    """
    result = _run()
    assert result.returncode == 0, result.stderr
    # The caveats are wrapped for reading, so compare on normalized whitespace.
    printed = " ".join(result.stdout.split())
    assert "Flesch-Kincaid grade" in printed
    assert "Ordinary UI prose" in printed
    assert "Honest-limits strings" in printed
    assert "that is not a defect" in printed
    assert "report and not a gate" in printed
    assert "alpha_warning" in printed  # the exemption list is printed, not implied


def test_honest_limits_come_from_the_localization_guide_not_a_private_copy() -> None:
    """Adding a row to the guide's legally-sensitive table is enough to exempt a key.

    ``alpha_warning`` is named in ``docs/localization-guide.md``; it must show up in
    the resolved exemption list without being repeated inside the script.
    """
    payload = _payload(_run("--json"))
    exempt = payload["honest_limits_keys"]
    assert "alpha_warning" in exempt
    assert "verify_failed" in exempt
    assert "strength_caveat" in exempt  # from the script's own annotated additions


def test_icu_plurals_are_rendered_to_one_branch_not_scored_all_at_once(
    tmp_path: Path,
) -> None:
    """A user reads "3 timestamps waiting", never the ICU source around it.

    Scoring the raw value would count ``plural``, ``one`` and ``other`` as words and
    would count all three branches, inventing a sentence nobody is shown.
    """
    bundle = {
        "rail_awaiting": (
            "{count, plural, =0 {No timestamps waiting} "
            "one {# timestamp waiting} other {# timestamps waiting}}"
        )
    }
    payload = _payload(_run("--json", *_fixture(tmp_path, bundle)))

    assert payload["all_strings"]["words"] == 3  # "3 timestamps waiting"
    assert payload["placeholders"] == ["count"]


def test_simple_placeholders_are_replaced_rather_than_read_as_words(
    tmp_path: Path,
) -> None:
    """``{total}`` is one numeral to a reader, not a seven-letter word."""
    bundle = {"storage_summary": "{total} total files are sealed on this device."}
    payload = _payload(_run("--json", *_fixture(tmp_path, bundle)))

    assert payload["ordinary_prose"]["words"] == 8
    assert payload["ordinary_prose"]["sentences"] == 1


def test_a_sensitive_string_is_held_out_of_the_headline_number(tmp_path: Path) -> None:
    """The honest-limits corpus is separate arithmetic, not a footnote."""
    bundle = {
        "alpha_warning": (
            "Alpha software notwithstanding, the aforementioned instrumentation "
            "constitutes no adjudication of evidentiary admissibility whatsoever."
        ),
        "msg_issue_added": "We added the condition to your record.",
    }
    payload = _payload(_run("--json", *_fixture(tmp_path, bundle)))

    assert payload["ordinary_prose"]["strings"] == 1
    assert payload["honest_limits"]["strings"] == 1
    limits_grade = payload["honest_limits"]["flesch_kincaid_grade"]
    ordinary_grade = payload["ordinary_prose"]["flesch_kincaid_grade"]
    assert limits_grade > ordinary_grade


def test_unreadable_copy_still_exits_zero(tmp_path: Path) -> None:
    """The #246 decision, pinned: report, do not gate.

    This string is indefensible prose and the script must still succeed. If someone
    later turns this into a threshold, this test fails and they have to come back
    here, read why, and write the honest-limits exemption list into the gate.
    """
    bundle = {
        "atlas_lede": (
            "Notwithstanding the aforementioned considerations, the instrumentation "
            "facilitates the systematic corroboration of habitability deficiencies "
            "insofar as the documentary methodology remains uncompromised throughout "
            "the entirety of the evidentiary preservation lifecycle."
        )
    }
    result = _run("--json", *_fixture(tmp_path, bundle))

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["ordinary_prose"]["flesch_kincaid_grade"] > 15.0


def test_labels_are_counted_but_never_scored_into_the_target(tmp_path: Path) -> None:
    """Two hundred one-word buttons must not average the real prose down."""
    bundle = {f"label_{index}": "Heat" for index in range(50)}
    payload = _payload(_run("--json", *_fixture(tmp_path, bundle)))

    assert payload["ordinary_prose"] is None
    assert payload["labels_and_fragments"]["strings"] == 50


def test_a_missing_bundle_is_operator_error_not_a_score(tmp_path: Path) -> None:
    """Exit 2, like the sibling i18n gates: nothing was measured, so say nothing."""
    result = _run(f"--bundle={tmp_path / 'absent.json'}")
    assert result.returncode == 2
    assert "locale bundle not found" in result.stderr
