# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""The dead-key report has to keep finding keys, and keep seeing the dynamic route.

``scripts/check_i18n_parity.py`` makes every locale carry every key in
``app/i18n/en.json``. A key the app never renders therefore becomes permanent
work for every translator, for a string no reader will ever see — and #250 is
about to ask a volunteer to do that work in a third language.
``scripts/report_i18n_key_usage.py`` measures how much of the bundle that is.

The tests here pin the properties that make the report worth trusting:

* it **produces a count from a populated corpus**. A scan whose regexes stopped
  matching would report the whole bundle as dead, or nothing as dead, and either
  way it would print a tidy report. Both failure directions are asserted against.
* it **sees keys built by concatenation**. This is the one route a naive scan
  gets wrong, and in this codebase it is not hypothetical: ``app/app.js`` builds
  ``"event_" + entry.event_type`` and ``"source_" + source`` before looking them
  up. A report blind to that would call fifteen live strings dead, and someone
  would delete them. It is the same defect class as a fuzz assertion that cannot
  fail (#257) — output that reassures without proving — so the dynamic route is
  tested on the real app as well as on fixtures.
* it **does not mistake a CSS class for a key**. ``"strength-" + level`` builds a
  class name. The report must not count it as a key prefix, and must still show
  it, because "I checked for dynamic keys and found only a CSS class" is a claim
  a reader should be able to verify rather than take on faith.
* it **keeps the two findings apart**. "Nothing renders this" and "the CLI
  catalogue in ``src/habitable/i18n.py`` defines this too" need different fixes,
  and merging them invites deleting the copy the CLI still uses.
* it **never fails a build**. A fixture where every key is dead still exits 0.
  That is the #271 decision: the backlog predates the report, and a red build on
  every unrelated branch would not help anyone clear it.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent.parent
_SCRIPT = _ROOT / "scripts" / "report_i18n_key_usage.py"


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(_SCRIPT), *args],
        capture_output=True,
        check=False,
        text=True,
    )


def _fixture(
    tmp_path: Path,
    bundle: dict[str, str],
    *,
    markup: str = "",
    script: str = "",
    server: str = "_CLI_MESSAGES: dict[str, dict[str, str]] = {'en': {}}\n",
) -> list[str]:
    """Write a throwaway app and return the CLI arguments pointing at it."""
    bundle_path = tmp_path / "en.json"
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
    markup_path = tmp_path / "index.html"
    markup_path.write_text(markup, encoding="utf-8")
    script_path = tmp_path / "app.js"
    script_path.write_text(script, encoding="utf-8")
    server_path = tmp_path / "i18n.py"
    server_path.write_text(server, encoding="utf-8")
    return [
        f"--bundle={bundle_path}",
        f"--markup={markup_path}",
        f"--script={script_path}",
        f"--server-catalogue={server_path}",
    ]


def _payload(result: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    assert result.returncode == 0, result.stdout + result.stderr
    parsed: dict[str, Any] = json.loads(result.stdout)
    return parsed


def test_real_app_yields_a_count_from_a_populated_corpus() -> None:
    """The headline count exists, and it was computed over a corpus that matched.

    The bands are deliberately wide, and they are bands rather than equalities on
    purpose: #269/#270 are actively adding and rewording keys, so an exact count
    would be a tripwire for unrelated work. What must not drift is that both
    static routes still resolve hundreds of keys between them. If a regex stopped
    matching, one of these floors catches it — and the ceiling on the dead count
    catches the opposite failure, where a broken scan declares the whole bundle
    unreferenced and invites someone to delete it.
    """
    payload = _payload(_run("--json"))

    assert payload["total_keys"] >= 200
    assert payload["reached_by_markup"] >= 100
    assert payload["reached_by_literal_call"] >= 50

    # The ceiling catches the opposite failure -- a broken scan declaring the whole
    # bundle unreferenced and inviting someone to delete it.
    #
    # There is deliberately NO lower bound. An earlier version asserted `0 < dead`
    # as its anti-vacuity check, which encoded "this project always has dead keys"
    # into the suite: clearing the backlog completely would have failed the test
    # that exists to help clear it, and the agent wiring up the last four keys in
    # #274 had to work around it. Emptiness is the goal, not the alarm. The three
    # floors above are what prove the scan actually ran on a populated corpus,
    # which is the property that assertion was reaching for.
    dead = len(payload["unreferenced"]) + len(payload["server_duplicates"])
    assert dead < payload["total_keys"] // 2


def test_the_dynamic_route_is_really_exercised_by_the_real_app() -> None:
    """Route 3 is live code here, not a defensive hypothetical.

    ``app/app.js`` looks up ``"event_" + entry.event_type`` and
    ``"source_" + source``. If this assertion ever fails, either the app stopped
    building keys — in which case the report got simpler — or the detection
    broke, in which case the report is about to call live strings dead. Both are
    worth a human look, which is why this is pinned rather than assumed.
    """
    payload = _payload(_run("--json"))

    assert payload["variable_keyed_calls"], "no variable-keyed t()/fm() call was detected"
    assert payload["key_prefix_fragments"], "no concatenation-built key prefix was detected"
    assert all(fragment.endswith("_") for fragment in payload["key_prefix_fragments"])


def test_a_key_built_only_by_concatenation_is_not_reported_as_dead(tmp_path: Path) -> None:
    """The whole point. No literal names ``event_repair``; the script still builds it."""
    bundle = {"event_repair": "Repair", "event_other": "Other", "never_used": "Nobody renders me."}
    script = 'var key = "event_" + (entry.event_type || "other");\nreturn t(key);\n'
    payload = _payload(_run("--json", *_fixture(tmp_path, bundle, script=script)))

    assert payload["unreferenced"] == ["never_used"]
    assert sorted(payload["reached_by_concatenation"]) == ["event_other", "event_repair"]
    assert payload["key_prefix_fragments"] == ["event_"]


def test_a_css_class_prefix_is_shown_but_never_counted_as_a_key(tmp_path: Path) -> None:
    """``"strength-" + level`` builds a class name, and the report must say so.

    The near miss is reported rather than silently dropped: the claim "I looked
    for dynamic keys and found only a CSS class" is exactly the claim a reader
    should be able to check, and a scan that discards the evidence makes that
    impossible.
    """
    bundle = {"strength_level_strong": "Strong", "strength_level_minimal": "Minimal"}
    script = 'var li = badge(label, "strength-" + level);\n'
    result = _run("--json", *_fixture(tmp_path, bundle, script=script))
    payload = _payload(result)

    assert payload["key_prefix_fragments"] == []
    assert payload["near_miss_fragments"] == ["strength-"]
    assert payload["unreferenced"] == ["strength_level_minimal", "strength_level_strong"]

    printed = " ".join(_run(*_fixture(tmp_path, bundle, script=script)).stdout.split())
    assert "Near misses" in printed
    assert '"strength-" — as "strength_"' in printed


def test_every_translated_attribute_counts_as_a_reference(tmp_path: Path) -> None:
    """``applyTranslations()`` reads three attributes, so the report must read three.

    Missing one would report a live aria-label or datalist option label as dead —
    and those are the strings a screen-reader user depends on, so they are the
    worst ones to delete by accident.
    """
    bundle = {"a_text": "Text", "b_aria": "Aria", "c_label": "Label", "d_dead": "Dead"}
    markup = (
        '<p data-i18n="a_text">Text</p>'
        '<button data-i18n-aria="b_aria"></button>'
        "<option data-i18n-label='c_label' value='mold'></option>"
    )
    payload = _payload(_run("--json", *_fixture(tmp_path, bundle, markup=markup)))

    assert payload["unreferenced"] == ["d_dead"]
    assert payload["reached_by_markup"] == 3


def test_a_key_the_cli_catalogue_also_defines_is_bucketed_separately(tmp_path: Path) -> None:
    """Two catalogues, two different fixes — so two different buckets.

    ``strength_level_minimal`` is unreferenced by the app *and* defined in
    ``src/habitable/i18n.py`` for CLI output. Filing it under "delete me" would
    put the CLI's copy one careless commit away from removal, so it is reported
    as a decision to make rather than a key to drop.
    """
    bundle = {"strength_level_minimal": "Minimal", "orphan": "Nothing renders me."}
    server = (
        "_CLI_MESSAGES: dict[str, dict[str, str]] = {\n"
        '    "en": {"strength_level_minimal": "minimal"},\n'
        '    "es": {"strength_level_minimal": "m\\u00ednima"},\n'
        "}\n"
    )
    args = _fixture(tmp_path, bundle, server=server)
    payload = _payload(_run("--json", *args))

    assert payload["server_duplicates"] == ["strength_level_minimal"]
    assert payload["unreferenced"] == ["orphan"]

    printed = " ".join(_run(*args).stdout.split())
    assert "app 'Minimal'" in printed
    assert "server 'minimal'" in printed


def test_a_key_the_app_asks_for_but_the_bundle_lacks_is_reported(tmp_path: Path) -> None:
    """The mirror defect, and the more urgent one.

    ``t()`` returns the key when lookup fails, so a ``data-i18n`` naming a key the
    bundle does not define renders the literal string ``missing_key`` to a reader
    where a sentence belongs. That is shipping now, not backlog.
    """
    markup = '<p data-i18n="missing_key">fallback</p>'
    payload = _payload(_run("--json", *_fixture(tmp_path, {"present": "Here"}, markup=markup)))

    assert payload["referenced_but_undefined"] == ["missing_key"]
    assert payload["unreferenced"] == ["present"]


def test_an_entirely_dead_bundle_still_exits_zero(tmp_path: Path) -> None:
    """The #271 decision, pinned: report, do not gate.

    If someone later turns this into a blocking gate, this test fails and they
    have to come back here, read why, and make that choice deliberately rather
    than as a side effect.
    """
    bundle = {f"dead_{index}": "Nobody renders me." for index in range(30)}
    result = _run("--json", *_fixture(tmp_path, bundle))

    assert result.returncode == 0, result.stderr
    assert len(json.loads(result.stdout)["unreferenced"]) == 30


def test_the_report_names_the_routes_it_cannot_see() -> None:
    """A scan that hides its blind spots is worse than no scan.

    The report is read by someone deciding whether to delete a string. It has to
    say, in its own output, that a key assembled entirely from data or reached
    through an alias will look dead to it.
    """
    printed = " ".join(_run().stdout.split())

    assert "Routes this report CAN see" in printed
    assert "Routes this report CANNOT see" in printed
    assert "arrives entirely from data" in printed
    assert "through an alias" in printed
    assert "report and not a gate" in printed


def test_a_missing_file_is_operator_error_not_a_finding(tmp_path: Path) -> None:
    """Exit 2, like the sibling i18n scripts: nothing was scanned, so claim nothing."""
    result = _run(f"--bundle={tmp_path / 'absent.json'}")

    assert result.returncode == 2
    assert "file not found" in result.stderr
