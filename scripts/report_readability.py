#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Measure the readability of the English app copy — report it, never gate on it (#246).

``docs/audits/plain-language-review.md`` states a reading-level target of roughly
US grade 6-8 for ordinary UI copy. Until this script existed that target was
applied by judgment: no score was ever computed. Stating a target you do not
measure is exactly the kind of unverified claim this repository refuses to make
about anything else, so this script computes the number and prints it.

It is named ``report_`` and not ``check_`` on purpose: every ``scripts/check_*.py``
is a blocking gate that can fail a build, and this one structurally cannot.

What it scores
--------------
The **rendered** English strings, not the raw JSON. ``app/i18n/en.json`` carries
the ICU-MessageFormat subset the app renders (``{count}`` placeholders and
``{count, plural, =0 {…} one {…} other {…}}``), and a reader never sees that
syntax. This script renders it the way ``src/habitable/i18n.py`` and
``app/app.js`` do — **one** plural branch (``other``, the general prose form),
with ``#`` and every simple placeholder replaced by a single-digit stand-in — so
the corpus is what a person actually reads. Scoring the raw values would count
ICU keywords as words and would score every plural branch at once, as though a
user read "No timestamps waiting 1 timestamp waiting 3 timestamps waiting".

The rendered strings are then split three ways, because one pooled number over
the whole bundle would be dominated by one-word button labels:

* **ordinary prose** — the copy the grade 6-8 target is actually about. This is
  the headline number.
* **honest-limits strings** — the strings that say what habitable cannot prove
  (every key named in ``docs/localization-guide.md`` §"Legally-sensitive
  strings", plus the limit-stating strings in ``_ADDITIONAL_HONEST_LIMITS``
  below). These score worse, and **that is not a defect**: "not evidence-ready",
  "authority trust is checked separately" and "this does not decide
  admissibility" are dense because they are precise, and the precision is the
  whole point. They are scored on their own line so that nobody can ever improve
  the headline number by softening a limitation.
* **labels and fragments** — every remaining string shorter than
  ``_PROSE_MIN_WORDS`` words that does not end a sentence. Most are one-word
  buttons ("Heat", "Refresh", "Language"), but the bucket also holds short
  headings and imperative labels ("Start this repair trail"). Counted, never
  scored: a grade level for a phrase with no sentence in it is arithmetic rather
  than a measurement, and pooling hundreds of them flatters the average.

A string declared legally sensitive is bucketed as an honest limit **before** its
shape is considered, so that "Integrity NOT intact · not evidence-ready" is
scored on the honest-limits row rather than disappearing into fragments for being
five words long. Declaring a string is therefore sufficient to exempt it,
whatever its length — which is what the audit document promises.

Why it reports instead of gating
--------------------------------
This is the recommendation in #246 and it is deliberate. A hard threshold would
apply pressure in exactly the wrong place: the sentences under the most pressure
to score well would be the legally sensitive ones, and the cheapest way to pass
a threshold is to soften them. So the exit status is 0 whether the copy reads at
grade 6 or grade 16; only operator error exits non-zero. If a threshold is ever
added, the honest-limits set resolved below is the exemption list it must use,
and it must stay a list a person can read.

How precise the number is
-------------------------
Not very, and the report says so out loud. English syllable counting has no
exact algorithm without a pronunciation dictionary; this uses the standard
vowel-run heuristic with a silent-final-``e`` correction, which is right for
most words and wrong for compounds — it reads "timestamp" as three syllables
where a person says two, and that word is everywhere in this bundle. The
heuristic therefore **over**-estimates the grade slightly. Treat the result as
good to about a grade, not to a decimal place; the report prints the most
frequent long words so a reader can see what is driving the number rather than
having to trust it.

Flesch-Kincaid and SMOG are English formulas. ``app/i18n/es.json`` is
deliberately **not** scored here: Spanish needs a Spanish formula (Fernández
Huerta / INFLESZ), and a Flesch-Kincaid number for Spanish would be a wrong
number wearing a right number's clothes.

Standard library only, offline and deterministic, like the sibling check
scripts, so it runs before project dependencies are installed.

Exit codes:
    0  a score was computed and printed — always, whatever the score.
    2  operator error (bundle missing, not JSON, or an unrenderable message).
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
import textwrap
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parent.parent
_EN_BUNDLE = _REPO_ROOT / "app" / "i18n" / "en.json"
_GUIDE = _REPO_ROOT / "docs" / "localization-guide.md"

# --- what a reader sees in place of an ICU argument --------------------------------

#: Every placeholder in today's EN bundle is a count, so one numeral stands in for
#: all of them. A numeral is what the app really substitutes, and it costs one word
#: and one syllable ("3" is read "three") rather than distorting the sentence with an
#: invented noun. The report prints the placeholder names it met, so a future
#: non-count placeholder (a unit name, a filename) becomes visible here instead of
#: silently being scored as a digit.
_COUNT_STAND_IN = "3"

#: Which plural branch to read. ``other`` is the general prose form and the one a
#: reader meets for every count but one; ``=0`` and ``one`` branches are often
#: differently shaped ("No timestamps waiting"). Scoring one branch is the point.
_PLURAL_BRANCH = "other"

# --- honest-limits strings: reported separately, never a target --------------------

#: Strings that state a limit, a warning, a privacy property, or an evidence verdict
#: but which ``docs/localization-guide.md`` does not (yet) name in its table. Each
#: carries its reason so a reader can judge the call rather than take it on faith.
#: This list exists so the honest-limits score can never be laundered into the
#: headline number, and so a future threshold has a named exemption list.
_ADDITIONAL_HONEST_LIMITS: dict[str, str] = {
    "capture_awaiting_reassure": "says token validity and authority trust are checked separately",
    "export_failed_next": "instructs the reader not to send a copy that failed its checks",
    "export_scope_help": "states a live limitation: issue-scoped exports are blocked",
    "field_dev_tsa_help": "says a practice timestamp is untrusted and never evidence-ready",
    "field_include_originals_help": "residual-metadata disclosure (R-27)",
    "msg_export_done_awaiting": "verdict: the packet is not evidence-ready yet",
    "msg_export_done_ok": "says the export does not decide admissibility",
    "msg_export_done_untrusted": "verdict: authority trust not established",
    "msg_export_done_warn": "verdict: an integrity or timestamp check failed",
    "proof_timestamped": "verdict plus the 'authority trust is checked separately' limit",
    "resolve_help": "privacy claim: only a file fingerprint leaves the device",
    "share_fact_local": "privacy property of the export",
    "share_fact_metadata": "privacy property of shared copies",
    "share_fact_scope": "scope property: the packet covers the whole unit",
    "status_awaiting_help": "says validity and authority trust are separate checks",
    "status_timestamped_help": "says the recipient must still verify token and authority",
    "status_unreachable": "says every value shown is unknown, not zero, when the server is down",
    "storage_doubling_note": "states the by-design storage cost rather than reassuring",
    "strength_caveat": "says what record strength is NOT — not validity, not admissibility",
}

#: Deliberately **not** in the list above: ``status_unreachable_next`` ("Check that
#: habitable is still running on this device, then choose 'Try again'."). It is the
#: recovery step for the limit that ``status_unreachable`` states, not a limit of its
#: own — it makes no claim about what habitable can or cannot establish. Leaving it in
#: the ordinary bucket is the conservative call: a recovery instruction is exactly the
#: copy the grade 6-8 target exists for, and exempting it would quietly lift it out of
#: the number that target watches.

_GUIDE_SECTION = "## Legally-sensitive strings"
_GUIDE_KEY = re.compile(r"`([a-z][a-z0-9_]*)`")

# --- text shape --------------------------------------------------------------------

#: A string is scored as prose when it ends a sentence or runs to at least this many
#: words. Below the line it is a label ("Heat", "Refresh") and a grade level for it
#: would be noise. The threshold is a judgment call, which is why it is one named
#: constant and why the report prints how many strings fell on each side of it.
_PROSE_MIN_WORDS = 6

#: Words of this many syllables or more are SMOG's "polysyllables".
_POLYSYLLABLE = 3

#: Shortest string worth ranking on its own in the "hardest strings" list.
_HARDEST_MIN_WORDS = 10

_WORD = re.compile(r"[0-9A-Za-z]+(?:['\u2019\-][0-9A-Za-z]+)*")
_SENTENCE_BREAK = re.compile(r"(?<=[.!?…])\s+")
_TERMINAL = re.compile(r"[.!?…]")
_VOWEL_RUN = re.compile(r"[aeiouy]+")


class ReportError(Exception):
    """Operator error: the corpus could not be read or rendered."""


# --- ICU rendering (the subset src/habitable/i18n.py and app/app.js implement) ------


def _match_brace(text: str, start: int) -> int:
    """Index of the ``}`` matching the ``{`` at *start*."""
    depth = 0
    for index in range(start, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    raise ReportError(f"unbalanced braces in message: {text!r}")


def _parse_plural_branches(source: str) -> dict[str, str]:
    """``one {…} other {…}`` → ``{selector: content}``."""
    branches: dict[str, str] = {}
    i = 0
    while i < len(source):
        if source[i].isspace():
            i += 1
            continue
        start = i
        while i < len(source) and not source[i].isspace() and source[i] != "{":
            i += 1
        selector = source[start:i]
        while i < len(source) and source[i].isspace():
            i += 1
        if not selector or i >= len(source) or source[i] != "{":
            raise ReportError(f"malformed plural branches near {source[start:][:40]!r}")
        end = _match_brace(source, i)
        branches[selector] = source[i + 1 : end]
        i = end + 1
    return branches


def render(message: str, seen_placeholders: set[str] | None = None) -> str:
    """Render one ICU-subset message into the words a reader sees."""
    out: list[str] = []
    i = 0
    while i < len(message):
        char = message[i]
        if char == "{":
            end = _match_brace(message, i)
            out.append(_render_argument(message[i + 1 : end], seen_placeholders))
            i = end + 1
        elif char == "}":
            raise ReportError(f"unbalanced '}}' in message: {message!r}")
        else:
            out.append(char)
            i += 1
    return "".join(out)


def _render_argument(body: str, seen: set[str] | None) -> str:
    head, _, rest = body.partition(",")
    name = head.strip()
    if seen is not None:
        seen.add(name)
    if not rest:
        return _COUNT_STAND_IN
    kind, _, branch_source = rest.partition(",")
    if kind.strip() != "plural":
        raise ReportError(f"unsupported ICU argument type {kind.strip()!r} in {body!r}")
    branches = _parse_plural_branches(branch_source)
    if _PLURAL_BRANCH not in branches:
        raise ReportError(f"plural for {name!r} has no {_PLURAL_BRANCH!r} branch")
    return render(branches[_PLURAL_BRANCH].replace("#", _COUNT_STAND_IN), seen)


# --- counting words, sentences and (approximately) syllables -----------------------


def syllables(word: str) -> int:
    """Approximate the syllables in one English word.

    Vowel runs, minus a silent final ``e`` unless that ``e`` is voiced by a
    preceding consonant + ``l`` ("habitable", "table" keep it; "whole", "evidence"
    do not). This is the standard heuristic and it is wrong on compounds — it
    hears three syllables in "timestamp" — so it biases the reported grade
    slightly upward. Numerals count as one word of one syllable, which is how "3"
    is read aloud.
    """
    letters = re.sub(r"[^a-z]", "", word.lower())
    if not letters:
        return 1
    count = len(_VOWEL_RUN.findall(letters))
    if count > 1 and letters.endswith("e"):
        voiced_le = letters.endswith("le") and len(letters) > 2 and letters[-3] not in "aeiouy"
        if not voiced_le:
            count -= 1
    return max(count, 1)


def _sentence_count(text: str) -> int:
    """How many sentences a reader parses out of one rendered string.

    A string with no terminal punctuation ("Waiting for timestamp token") is one
    unit, not zero, or the words-per-sentence ratio would divide by nothing.
    """
    pieces = [piece for piece in _SENTENCE_BREAK.split(text.strip()) if piece.strip()]
    return max(len(pieces), 1)


@dataclass(frozen=True)
class Rendered:
    """One bundle string as a reader meets it, with its shape already counted."""

    key: str
    text: str
    words: tuple[str, ...]
    sentences: int
    syllables: int
    polysyllables: int

    @property
    def is_prose(self) -> bool:
        """True when this reads as a sentence rather than as a button label."""
        return len(self.words) >= _PROSE_MIN_WORDS or bool(_TERMINAL.search(self.text))


@dataclass(frozen=True)
class Metrics:
    """Readability of one corpus, plus the raw counts the formulas ran on."""

    strings: int
    sentences: int
    words: int
    syllables: int
    polysyllables: int

    @property
    def words_per_sentence(self) -> float:
        return self.words / self.sentences

    @property
    def syllables_per_word(self) -> float:
        return self.syllables / self.words

    @property
    def flesch_kincaid_grade(self) -> float:
        return 0.39 * self.words_per_sentence + 11.8 * self.syllables_per_word - 15.59

    @property
    def flesch_reading_ease(self) -> float:
        return 206.835 - 1.015 * self.words_per_sentence - 84.6 * self.syllables_per_word

    @property
    def smog_grade(self) -> float:
        return 1.0430 * math.sqrt(self.polysyllables * (30 / self.sentences)) + 3.1291

    def as_dict(self) -> dict[str, float | int]:
        return {
            "strings": self.strings,
            "sentences": self.sentences,
            "words": self.words,
            "syllables": self.syllables,
            "polysyllables": self.polysyllables,
            "words_per_sentence": round(self.words_per_sentence, 2),
            "syllables_per_word": round(self.syllables_per_word, 3),
            "flesch_kincaid_grade": round(self.flesch_kincaid_grade, 1),
            "flesch_reading_ease": round(self.flesch_reading_ease, 1),
            "smog_grade": round(self.smog_grade, 1),
        }


def measure(items: Sequence[Rendered]) -> Metrics | None:
    """Aggregate a corpus, or None when there is nothing there to score."""
    words = sum(len(item.words) for item in items)
    if not words:
        return None
    return Metrics(
        strings=len(items),
        sentences=sum(item.sentences for item in items),
        words=words,
        syllables=sum(item.syllables for item in items),
        polysyllables=sum(item.polysyllables for item in items),
    )


def analyze_string(key: str, message: str, seen_placeholders: set[str]) -> Rendered:
    """Render one bundle value and count its shape."""
    text = render(message, seen_placeholders)
    words = tuple(_WORD.findall(text))
    per_word = [syllables(word) for word in words]
    return Rendered(
        key=key,
        text=text,
        words=words,
        sentences=_sentence_count(text),
        syllables=sum(per_word),
        polysyllables=sum(1 for count in per_word if count >= _POLYSYLLABLE),
    )


# --- resolving the honest-limits set -----------------------------------------------


def guide_declared_keys(guide: Path) -> set[str]:
    """The i18n keys the localization guide's legally-sensitive table names.

    Read from the guide rather than copied, so that adding a row there is enough
    to move a string into the honest-limits bucket here. If this ever returns
    nothing the report says so out loud instead of quietly scoring warnings as
    ordinary copy.
    """
    try:
        text = guide.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ReportError(f"localization guide not found: {guide}") from exc
    keys: set[str] = set()
    inside = False
    for line in text.splitlines():
        if line.startswith("## "):
            inside = line.startswith(_GUIDE_SECTION)
            continue
        if inside and line.startswith("|"):
            first_cell = line.strip().strip("|").split("|")[0]
            keys.update(_GUIDE_KEY.findall(first_cell))
    return keys


# --- the report --------------------------------------------------------------------


def load_bundle(path: Path) -> dict[str, str]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ReportError(f"locale bundle not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ReportError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise ReportError(f"{path} must be a JSON object, got {type(raw).__name__}")
    return {str(key): str(value) for key, value in raw.items()}


@dataclass(frozen=True)
class Report:
    """Everything the printed report and the ``--json`` payload are built from."""

    bundle: Path
    ordinary: list[Rendered]
    honest_limits: list[Rendered]
    fragments: list[Rendered]
    sensitive_keys: set[str]
    guide_keys: set[str]
    stale_guide_keys: set[str]
    placeholders: set[str]

    @property
    def everything(self) -> list[Rendered]:
        return [*self.ordinary, *self.honest_limits, *self.fragments]


def build_report(bundle_path: Path, guide_path: Path) -> Report:
    """Render, bucket and count the bundle. Raises ReportError on operator error."""
    bundle = load_bundle(bundle_path)
    placeholders: set[str] = set()
    rendered = [analyze_string(key, value, placeholders) for key, value in sorted(bundle.items())]

    guide_keys = guide_declared_keys(guide_path)
    sensitive = (guide_keys | set(_ADDITIONAL_HONEST_LIMITS)) & set(bundle)

    ordinary: list[Rendered] = []
    honest_limits: list[Rendered] = []
    fragments: list[Rendered] = []
    # The order of these three tests is load-bearing, not incidental. Testing shape
    # first would divert every declared honest-limits string shorter than
    # _PROSE_MIN_WORDS into the unscored fragments bucket — "Integrity NOT intact ·
    # not evidence-ready" is five words — so the strings under the most pressure to
    # be softened would be the ones quietly dropped from the row that watches them,
    # and the printed exemption count would not match the row it describes. Declaring
    # a string sensitive therefore wins over its shape, unconditionally: adding a row
    # to the guide is sufficient to exempt it, which is what the audit promises.
    for item in rendered:
        if item.key in sensitive:
            honest_limits.append(item)
        elif not item.is_prose:
            fragments.append(item)
        else:
            ordinary.append(item)

    return Report(
        bundle=bundle_path,
        ordinary=ordinary,
        honest_limits=honest_limits,
        fragments=fragments,
        sensitive_keys=sensitive,
        guide_keys=guide_keys,
        stale_guide_keys=guide_keys - set(bundle),
        placeholders=placeholders,
    )


def _metrics_lines(title: str, metrics: Metrics | None) -> list[str]:
    if metrics is None:
        return [f"{title}: nothing to score"]
    return [
        f"{title}",
        f"    Flesch-Kincaid grade   {metrics.flesch_kincaid_grade:5.1f}",
        f"    Flesch reading ease    {metrics.flesch_reading_ease:5.1f}",
        f"    SMOG grade             {metrics.smog_grade:5.1f}",
        f"    {metrics.words_per_sentence:.1f} words/sentence, "
        f"{metrics.syllables_per_word:.2f} syllables/word",
    ]


def _corpus_lines(report: Report) -> list[str]:
    rows = (
        ("ordinary prose", report.ordinary),
        ("honest limits", report.honest_limits),
        ("labels/fragments", report.fragments),
    )
    lines = [f"Corpus — {report.bundle}, rendered as a reader sees it:"]
    for label, items in rows:
        counts = measure(items)
        words = counts.words if counts else 0
        sentences = counts.sentences if counts else 0
        lines.append(
            f"    {label:<18} {len(items):>4} strings  {sentences:>4} sentences  {words:>5} words"
        )
    return lines


def _hardest_lines(items: Sequence[Rendered], limit: int = 5) -> list[str]:
    """Where to look first when the headline number drifts.

    Only strings of at least ``_HARDEST_MIN_WORDS`` words are ranked. A per-string
    Flesch-Kincaid over three words is arithmetic, not a measurement — "Evidence
    relationship added." scores grade 21 and tells you nothing you could act on.
    """
    scored = []
    for item in items:
        metrics = measure([item])
        if metrics is not None and metrics.words >= _HARDEST_MIN_WORDS:
            scored.append((metrics.flesch_kincaid_grade, item.key))
    scored.sort(reverse=True)
    lines = [
        f"Hardest ordinary strings of {_HARDEST_MIN_WORDS}+ words "
        "(highest Flesch-Kincaid grade, scored alone):"
    ]
    lines.extend(f"    {grade:5.1f}  {key}" for grade, key in scored[:limit])
    return lines


def _long_word_lines(items: Sequence[Rendered], limit: int = 8) -> list[str]:
    counter: Counter[str] = Counter()
    for item in items:
        counter.update(word.lower() for word in item.words if syllables(word) >= _POLYSYLLABLE)
    common = ", ".join(f"{word} x{count}" for word, count in counter.most_common(limit))
    return textwrap.wrap(
        f"Long words driving the ordinary-prose score: {common}",
        width=96,
        subsequent_indent="    ",
    )


def format_report(report: Report) -> str:
    """The human-readable report. Deterministic, so it can be pasted into a doc."""
    lines: list[str] = ["readability report — English app copy (Flesch-Kincaid + SMOG)", ""]
    lines.extend(_corpus_lines(report))
    lines.append("")
    lines.extend(
        _metrics_lines(
            "Ordinary UI prose — the copy the grade 6-8 target is about:", measure(report.ordinary)
        )
    )
    lines.append("")
    lines.extend(
        _metrics_lines(
            "Honest-limits strings — reported, never a target:", measure(report.honest_limits)
        )
    )
    lines.extend(
        textwrap.wrap(
            "These say what habitable cannot prove. They score higher because they are "
            "precise, and that is not a defect. Never improve the headline number by "
            "softening one of them.",
            width=96,
            initial_indent="    ",
            subsequent_indent="    ",
        )
    )
    lines.append("")
    lines.extend(
        _metrics_lines(
            "Every string pooled — depressed by short labels, do not quote it alone:",
            measure(report.everything),
        )
    )
    lines.append("")
    lines.extend(_hardest_lines(report.ordinary))
    lines.append("")
    lines.extend(_long_word_lines(report.ordinary))
    lines.append("")
    lines.extend(_provenance_lines(report))
    lines.append("")
    lines.extend(
        textwrap.wrap(
            "Syllables are counted by heuristic, not by dictionary; compounds such as "
            "'timestamp' are over-counted, so these grades run slightly high. Read them "
            "to about a grade, not to a decimal place. This is a report and not a gate: "
            "the exit status is 0 whatever the score.",
            width=96,
        )
    )
    return "\n".join(lines)


def _provenance_lines(report: Report) -> list[str]:
    lines: list[str] = []
    if not report.guide_keys:
        lines.append(
            "NOTE: docs/localization-guide.md declared no legally-sensitive keys — "
            "the honest-limits bucket is running on the in-script list alone."
        )
    if report.stale_guide_keys:
        lines.append(
            "NOTE: the guide names key(s) absent from this bundle: "
            + ", ".join(sorted(report.stale_guide_keys))
        )
    lines.extend(
        textwrap.wrap(
            "Honest-limits keys held out of the headline number ("
            f"{len(report.sensitive_keys)}, from docs/localization-guide.md plus "
            "_ADDITIONAL_HONEST_LIMITS): " + ", ".join(sorted(report.sensitive_keys)),
            width=96,
            subsequent_indent="    ",
        )
    )
    lines.extend(
        textwrap.wrap(
            "ICU placeholders met (all counts today; a non-count placeholder would show "
            "up here): " + ", ".join(sorted(report.placeholders)),
            width=96,
            subsequent_indent="    ",
        )
    )
    return lines


def as_json(report: Report) -> dict[str, Any]:
    """Machine-readable payload — what the regression test asserts against."""
    payload: dict[str, Any] = {"bundle": str(report.bundle)}
    for name, items in (
        ("ordinary_prose", report.ordinary),
        ("honest_limits", report.honest_limits),
        ("labels_and_fragments", report.fragments),
        ("all_strings", report.everything),
    ):
        metrics = measure(items)
        payload[name] = metrics.as_dict() if metrics is not None else None
    payload["honest_limits_keys"] = sorted(report.sensitive_keys)
    payload["placeholders"] = sorted(report.placeholders)
    return payload


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--bundle",
        type=Path,
        default=_EN_BUNDLE,
        help="locale bundle to score (defaults to app/i18n/en.json; English only)",
    )
    parser.add_argument(
        "--guide",
        type=Path,
        default=_GUIDE,
        help="localization guide whose legally-sensitive table names the exempt keys",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit the numbers as JSON instead of the human report",
    )
    args = parser.parse_args(argv)

    try:
        report = build_report(args.bundle, args.guide)
    except ReportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(as_json(report), indent=2, sort_keys=True))
    else:
        print(format_report(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
