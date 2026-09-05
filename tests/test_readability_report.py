# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""The readability report has to keep computing the number it prints, and keep
refusing to gate.

``docs/audits/plain-language-review.md`` states a reading-level target of roughly US
grade 6-8. Before ``scripts/report_readability.py`` that target was applied by
judgment and never measured (#246). A measurement nobody runs decays back into an
assertion, so these tests pin the properties that make the script worth having:

* it **computes the formulas it names**. This is the point the first version of this
  file missed. Bands (``0.0 < grade < 20.0``) and relations ("the honest-limits row
  scores worse") pass just as happily when a Flesch-Kincaid coefficient is wrong by a
  factor of ten, so a suite made only of bands measures nothing — it re-asserts the
  target in a new place instead of checking the arithmetic behind it. The fixture
  corpus below therefore has hand-computed expected values, with the working shown, so
  that no coefficient, constant or counting rule can move without a failure;
* it **produces a number over the real bundle**, from a corpus that is actually
  populated — a script that silently scored zero strings would still print a tidy
  report. The real-corpus assertions stay deliberately **wide**: they must not fail
  every time a UI string is reworded, which is what would train the next person to
  loosen them. Everything narrow is on the fixtures;
* it **renders** the ICU subset a reader never sees, picking one plural branch rather
  than scoring ``=0``, ``one`` and ``other`` concatenated;
* a **declared honest-limits string is exempt whatever its length**. Bucketing on
  shape first would divert "Integrity NOT intact · not evidence-ready" into the
  unscored fragments bucket for being five words long, so the strings under the most
  pressure to be softened would be the ones dropped from the row that watches them;
* it **never fails a build**. Deliberately unreadable copy still exits 0. This is the
  #246 decision: a hard threshold would press hardest on the legally sensitive
  strings, and the cheapest way to pass a threshold is to soften a warning.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent.parent
_SCRIPT = _ROOT / "scripts" / "report_readability.py"

#: A guide with two tables: one inside the legally-sensitive section and one outside
#: it. ``not_a_sensitive_key`` is placed in a fixture *bundle* as well, because the
#: report intersects the declared keys with the bundle — a key naming nothing in the
#: bundle is dropped either way, so a guide-only decoy could never catch a parser that
#: stopped honouring section boundaries.
_FIXTURE_GUIDE = (
    "# fixture guide\n\n"
    "## Legally-sensitive strings\n\n"
    "| Key | English | Why it is sensitive |\n"
    "| --- | --- | --- |\n"
    "| `alpha_warning` | Alpha software | the core honesty caveat |\n\n"
    "## Something else\n\n"
    "| `not_a_sensitive_key` | ignored | outside the section |\n"
)

#: Five sentences, 25 words, 40 syllables, 6 polysyllables — counted by hand, and
#: chosen so the script's syllable heuristic and a human reading aloud agree on every
#: single word (document 3, evidence 3, condition 3, photograph 3, important 3;
#: landlord 2, window 2, damage 2; the other seventeen 1 each). No compound nouns, so
#: none of the "timestamp is heard as three syllables" over-count the real bundle
#: carries. That is what makes the expected scores below checkable by hand rather than
#: recorded from a run of the code they are supposed to be checking.
_HAND_COUNTED = (
    "The document holds your evidence. "
    "This app keeps the condition. "
    "The landlord broke your window. "
    "A photograph shows the damage. "
    "This document is important now."
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


# --- the arithmetic, pinned exactly on a hand-counted corpus ------------------------


def test_flesch_kincaid_matches_the_published_formula_on_a_hand_counted_corpus(
    tmp_path: Path,
) -> None:
    """Pin every coefficient of Flesch-Kincaid and Flesch reading ease.

    Counted by hand from ``_HAND_COUNTED`` (see its comment for the per-word
    syllables): **25 words, 5 sentences, 40 syllables**. So::

        words per sentence   = 25 / 5  = 5.0
        syllables per word   = 40 / 25 = 1.6

        Flesch-Kincaid grade = 0.39 x 5.0 + 11.8 x 1.6 - 15.59
                             = 1.95 + 18.88 - 15.59
                             = 5.24            -> reported as 5.2

        Flesch reading ease  = 206.835 - 1.015 x 5.0 - 84.6 x 1.6
                             = 206.835 - 5.075 - 135.36
                             = 66.40           -> reported as 66.4

    Every number on the right-hand side is load-bearing. Scaling the 0.39 gives 7.9,
    slipping the decimal point in 15.59 gives 19.3, and counting the string as one
    sentence instead of five gives 13.0 — all of which sit comfortably inside the
    "0 < grade < 20" band the real-corpus test uses, which is exactly why that band
    cannot be the only check.
    """
    payload = _payload(_run("--json", *_fixture(tmp_path, {"fixture_prose": _HAND_COUNTED})))
    prose = payload["ordinary_prose"]

    # The raw counts first: a score that came out right off wrong counts is luck.
    assert prose["strings"] == 1
    assert prose["sentences"] == 5
    assert prose["words"] == 25
    assert prose["syllables"] == 40
    assert prose["words_per_sentence"] == 5.0
    assert prose["syllables_per_word"] == 1.6

    assert prose["flesch_kincaid_grade"] == 5.2
    assert prose["flesch_reading_ease"] == 66.4


def test_smog_matches_the_published_formula_on_the_same_corpus(tmp_path: Path) -> None:
    """Pin SMOG's coefficient, its 30-sentence normalisation and its constant.

    ``_HAND_COUNTED`` holds **6 polysyllables** (document, evidence, condition,
    photograph, document, important — every word of three syllables or more) across
    **5 sentences**, and the sentence count is chosen so the square root is exact::

        SMOG grade = 1.0430 x sqrt(6 x (30 / 5)) + 3.1291
                   = 1.0430 x sqrt(36) + 3.1291
                   = 1.0430 x 6 + 3.1291
                   = 6.258 + 3.1291
                   = 9.3871          -> reported as 9.4

    The polysyllable count is asserted too, because SMOG's only input is that count:
    moving the three-syllable threshold to two would find nine of these words and
    quietly raise every SMOG number in the report.
    """
    payload = _payload(_run("--json", *_fixture(tmp_path, {"fixture_prose": _HAND_COUNTED})))
    prose = payload["ordinary_prose"]

    assert prose["polysyllables"] == 6
    assert prose["smog_grade"] == 9.4


def test_the_syllable_heuristic_keeps_its_named_rules(tmp_path: Path) -> None:
    """Silent final ``e`` is dropped except when consonant + ``l`` voices it, and
    ``y`` counts as a vowel.

    "A whole table is habitable in many rooms." is eight words and, read aloud,
    thirteen syllables: a(1) whole(1) table(2) is(1) habitable(4) in(1) many(2)
    rooms(1). Each rule has a word that depends on it — "whole" loses its final ``e``
    (the ``l`` there is preceded by the vowel ``o``), "table" and "habitable" keep
    theirs, and "many" has a syllable only because ``y`` is treated as a vowel. Drop
    the silent-``e`` correction and "whole" becomes two; drop the ``-le`` exception
    and "habitable" falls to three; drop ``y`` from the vowel set and "many" falls to
    one. Any of the three moves the reported grade of every corpus in the report, so
    the rules are pinned here rather than left to the docstring that describes them.
    """
    bundle = {"syllable_probe": "A whole table is habitable in many rooms."}
    payload = _payload(_run("--json", *_fixture(tmp_path, bundle)))
    prose = payload["ordinary_prose"]

    assert prose["words"] == 8
    assert prose["syllables"] == 13
    assert prose["polysyllables"] == 1  # "habitable" alone, at four syllables


def test_the_prose_boundary_sits_exactly_at_its_named_constant(tmp_path: Path) -> None:
    """Six words, or a full stop: either one makes a string prose, and nothing else.

    The threshold is a judgment call rather than a law, which is precisely why it has
    to be pinned — a silent change to it moves strings between the scored and unscored
    buckets and so moves the headline number without any copy being edited. The three
    fixtures straddle it: five words is a fragment, six words is prose, and three
    words with a full stop is prose because it is a sentence.
    """
    bundle = {
        "boundary_below": "Save document to this condition",  # 5 words, no full stop
        "boundary_at": "Start this repair trail right now",  # 6 words, no full stop
        "short_but_a_sentence": "Evidence relationship added.",  # 3 words, full stop
    }
    payload = _payload(_run("--json", *_fixture(tmp_path, bundle)))

    assert payload["ordinary_prose"]["strings"] == 2
    assert payload["ordinary_prose"]["words"] == 9  # the six-word one plus the sentence
    assert payload["labels_and_fragments"]["strings"] == 1
    assert payload["labels_and_fragments"]["words"] == 5


# --- rendering what a reader actually sees ------------------------------------------


def test_icu_plurals_are_rendered_to_one_branch_not_scored_all_at_once(
    tmp_path: Path,
) -> None:
    """A user reads "3 timestamps are waiting now", never the ICU source around it.

    The three branches are deliberately given **different lengths** so that the word
    count identifies which one was read: ``=0`` renders to 2 words, ``one`` to 3, the
    ``other`` branch this script wants to 5, and all three concatenated to 10 (plus
    the ICU keywords ``count``, ``plural``, ``one`` and ``other`` if the raw value
    were scored). Equal-length branches — the shape this test had first — cannot tell
    any of those apart, which left the property in its own name unchecked.
    """
    bundle = {
        "rail_awaiting": (
            "{count, plural, =0 {Nothing waits} "
            "one {# timestamp waits} other {# timestamps are waiting now}}"
        )
    }
    payload = _payload(_run("--json", *_fixture(tmp_path, bundle)))

    assert payload["all_strings"]["words"] == 5  # "3 timestamps are waiting now"
    assert payload["placeholders"] == ["count"]


def test_simple_placeholders_are_replaced_rather_than_read_as_words(
    tmp_path: Path,
) -> None:
    """``{total}`` is one numeral to a reader, not a seven-letter word."""
    bundle = {"storage_summary": "{total} total files are sealed on this device."}
    payload = _payload(_run("--json", *_fixture(tmp_path, bundle)))

    assert payload["ordinary_prose"]["words"] == 8
    assert payload["ordinary_prose"]["sentences"] == 1


# --- the honest-limits bucket --------------------------------------------------------


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


def test_a_short_sensitive_string_is_scored_and_not_filed_as_a_fragment(
    tmp_path: Path,
) -> None:
    """Declaring a string sensitive exempts it whatever its length. Regression.

    Before this was fixed, the shape test ran first, so a declared honest-limits
    string under six words fell into the unscored labels bucket instead — six real
    ones did, including ``verify_failed`` ("Integrity NOT intact · not
    evidence-ready") and both custody verdicts. That is the failure this whole bucket
    exists to prevent: the blunt, short, load-bearing warnings are exactly the strings
    that must stay on a row somebody watches, and the report was also printing two
    different totals for the same set because of it.

    ``alpha_warning`` is two words with no full stop here — a fragment by shape, an
    honest limit by declaration, and declaration wins.
    """
    bundle = {"alpha_warning": "Alpha software", "action_refresh": "Refresh"}
    payload = _payload(_run("--json", *_fixture(tmp_path, bundle)))

    assert payload["honest_limits"]["strings"] == 1
    assert payload["honest_limits"]["words"] == 2
    assert payload["labels_and_fragments"]["strings"] == 1  # "Refresh", and only that
    assert payload["ordinary_prose"] is None


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


def test_only_the_legally_sensitive_section_of_the_guide_declares_keys(
    tmp_path: Path,
) -> None:
    """A backticked key in some other section of the guide must not exempt anything.

    The guide is a long document full of tables of i18n keys. If the parser ignored
    section boundaries, most of the bundle would end up exempt from the headline
    number and nobody would see it happen — the report would simply get quieter.
    ``not_a_sensitive_key`` sits in the fixture guide's *other* table and in the
    fixture bundle, so the exemption list has to name ``alpha_warning`` and nothing
    else.
    """
    bundle = {
        "alpha_warning": "Alpha software",
        "not_a_sensitive_key": "This heading sits outside the sensitive table.",
    }
    payload = _payload(_run("--json", *_fixture(tmp_path, bundle)))

    assert payload["honest_limits_keys"] == ["alpha_warning"]
    assert payload["ordinary_prose"]["strings"] == 1  # not_a_sensitive_key, scored


def test_the_exemption_list_and_the_scored_row_report_the_same_total() -> None:
    """The report must not print two different sizes for one set of strings.

    It did: the corpus table said "23 strings" on the honest-limits row while the
    provenance paragraph said "29" keys were held out, because six declared keys had
    been filed as fragments. A reader has no way to tell which of the two numbers is
    the real exemption, so pin that there is only ever one. This is an invariant, not
    a value, so it survives any amount of copy churn.
    """
    payload = _payload(_run("--json"))

    assert payload["honest_limits"]["strings"] == len(payload["honest_limits_keys"])


# --- the real bundle: wide bands only ------------------------------------------------


def test_real_english_bundle_yields_a_grade_from_a_populated_corpus() -> None:
    """The headline number exists, and it was computed over real sentences.

    The band is deliberately wide, and stays wide. This is not a threshold in
    disguise: it only catches the failure where the script keeps printing while the
    corpus has gone empty (a rendering change that swallows every string, a bundle
    that moved), which would otherwise look like a very good score. The arithmetic
    behind the number is pinned on fixtures above, where a reworded button cannot
    break it.
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


# --- reporting, never gating ---------------------------------------------------------


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
