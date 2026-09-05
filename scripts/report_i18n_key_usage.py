#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Find app translation keys with no rendering path — report them, never gate (#271).

``scripts/check_i18n_parity.py`` enforces that every locale bundle carries every
key in ``app/i18n/en.json``. That gate is right, and it has a cost nobody was
measuring: a key the app never renders is still work every translator must do,
forever, for a string no user will ever see. #250 asks for a third language, and
``docs/localization-guide.md`` asks contributors to give legally sensitive
strings particular care. Care is finite. Spending it on a string with no
rendering path is the wrong place for a volunteer's attention, so this script
computes which keys those are instead of leaving it to a hand scan.

Why it reports instead of gating
--------------------------------
Every ``scripts/check_*.py`` here is a blocking merge gate. This is named
``report_`` for the same reason ``scripts/report_readability.py`` is: it
structurally cannot fail a build, and it must not until the backlog it found is
cleared. Turning it into a gate on day one would mean either deleting 48 strings
in a hurry or wiring a red build into every unrelated branch. Exit status is 0
whatever it finds; only operator error exits non-zero.

The three routes a key can be live by
-------------------------------------
1. **Markup names it** — ``data-i18n``, ``data-i18n-aria`` or ``data-i18n-label``
   in ``app/index.html``. ``applyTranslations()`` substitutes these.
2. **A literal call names it** — ``t("key")`` or ``fm("key", {...})`` in
   ``app/app.js``.
3. **The script builds it by concatenation** — ``t("event_" + entry.event_type)``.

The third route is the one a naive scan gets wrong, and it is not hypothetical
here: ``app/app.js`` really does build ``"event_" + …`` and ``"source_" + …``
before looking them up. A report that could not see route 3 would be the same
class of defect as a fuzz assertion that can never fail (#257) — reassuring
output that proves nothing — so route 3 is modelled explicitly, and the routes
this script *cannot* see are printed on every run rather than left implied.

How route 3 is modelled, and why it errs toward "live"
------------------------------------------------------
Without a JavaScript parser (stdlib only, no dependency) the honest move is a
conservative textual one. Any string literal adjacent to a ``+`` is collected as
a *concatenation fragment*. A fragment is treated as a key prefix only when it
ends with ``_``, because that is what building a key out of parts actually looks
like in this codebase — ``"event_"``, ``"source_"``. Fragments that do not are
listed too, under their own heading, so the reader can see them and judge: this
is how ``"strength-" + level`` shows up as what it is, a CSS class name, rather
than being silently ignored or silently counted.

The bias is deliberate and one-directional. A false "dead" gets a string deleted
that somebody needed; a false "live" only leaves one key sitting in a backlog.
So a fragment covers every key it prefixes, and the report prints the coverage
so an over-broad fragment is visible rather than load-bearing.

Two findings that need different fixes
--------------------------------------
The report separates them, because merging them would invite the wrong repair:

* **unreferenced** — no route reaches it. Decide: delete it, or wire it up.
* **also in the server catalogue** — the key is also defined in
  ``src/habitable/i18n.py`` (``_CLI_MESSAGES``), which is a *separate* catalogue
  for CLI output. These are not obviously dead; they may be a split that was
  never finished, and the two copies are often deliberately different (the CLI
  wants ``"minimal"`` mid-sentence, a badge wants ``"Minimal"``). Deleting the
  wrong copy breaks the CLI, so the report prints both strings side by side and
  asks for a decision rather than implying one.

It also reports the mirror-image defect for free: a key the app **references but
the bundle does not define**. ``t()`` returns the key itself when lookup fails,
so that ships a user the raw string ``export_scope_help`` where a sentence
belongs.

Standard library only, offline and deterministic, like the sibling scripts, so
it runs before project dependencies are installed.

Exit codes:
    0  the scan ran and printed its findings — always, whatever it found.
    2  operator error (a scanned file is missing, or the bundle is not JSON).
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
import textwrap
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parent.parent
_EN_BUNDLE = _REPO_ROOT / "app" / "i18n" / "en.json"
_MARKUP = _REPO_ROOT / "app" / "index.html"
_SCRIPT = _REPO_ROOT / "app" / "app.js"
_SERVER_CATALOGUE = _REPO_ROOT / "src" / "habitable" / "i18n.py"

#: The attributes ``applyTranslations()`` in ``app/app.js`` reads. Kept in step
#: with that function: a new attribute there without one here makes live keys
#: look dead.
_KEY_ATTRIBUTES = ("data-i18n", "data-i18n-aria", "data-i18n-label")

#: The lookup helpers. ``fm()`` delegates to ``t()``, but both are matched so a
#: direct ``fm("key", …)`` is not missed.
_LOOKUP_FUNCTIONS = ("t", "fm")

#: The name of the CLI catalogue inside ``src/habitable/i18n.py``.
_SERVER_CATALOGUE_NAME = "_CLI_MESSAGES"

#: Keys are ``lower_snake_case``, so a concatenation fragment that builds one
#: ends at a word boundary — an underscore. See the module docstring: fragments
#: that fail this are reported rather than dropped.
_KEY_WORD_SEPARATOR = "_"

#: Shortest fragment worth treating as a key prefix. Two characters would prefix
#: half the bundle and turn the report into reassurance.
_MIN_FRAGMENT = 3

#: A fragment shaped like a key stem but ending in one of these builds something
#: else — a CSS class, an element id. ``"strength-" + level`` is the live example
#: in ``app/app.js``, and it is the exact construct a hand scan has to rule out,
#: so the report re-checks each of these against ``_`` and prints what it *would*
#: have covered. Showing the near miss is how the reader knows the scan looked.
_NEAR_MISS_SEPARATOR = re.compile(r"^([a-z][a-z0-9_]*)[-.:]$")

_ATTRIBUTE_REFERENCE = re.compile(
    r"(?:" + "|".join(_KEY_ATTRIBUTES) + r")\s*=\s*(\"([^\"]*)\"|'([^']*)')"
)
_LITERAL_CALL = re.compile(
    r"\b(?:" + "|".join(_LOOKUP_FUNCTIONS) + r")\(\s*(\"([^\"]*)\"|'([^']*)')"
)
_VARIABLE_CALL = re.compile(
    r"\b(?:" + "|".join(_LOOKUP_FUNCTIONS) + r")\(\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*[,)]"
)
_CONCATENATION_FRAGMENT = re.compile(
    r"(?:\"([^\"\n]*)\"|'([^'\n]*)')\s*\+|\+\s*(?:\"([^\"\n]*)\"|'([^']*)')"
)


class ReportError(Exception):
    """Operator error: something the report needs could not be read."""


# Bound to a name so `ruff format` under `target-version = "py314"` cannot rewrite
# it to the PEP 758 parenthesis-free form, which is a SyntaxError on Python < 3.14.
# This script runs under uv today, but `check_i18n_utf8.py` shipped exactly this
# rewrite and broke the merge gate, which runs the i18n scripts with the runner's
# bare `python3`. Same precaution as `tsa.py`'s `_SIG_HASH_ERRORS`.
_LITERAL_ERRORS = (ValueError, TypeError, SyntaxError)


def _first_group(match: re.Match[str], groups: Iterable[int]) -> str | None:
    """The first non-None alternative of a quoted-string match.

    The patterns above accept either quote style, so each yields two (or four)
    capture slots of which exactly one is populated.
    """
    for index in groups:
        value = match.group(index)
        if value is not None:
            return value
    return None


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ReportError(f"file not found: {path}") from exc


def load_bundle(path: Path) -> dict[str, str]:
    """The English bundle as a flat mapping, or operator error."""
    try:
        raw = json.loads(_read(path))
    except json.JSONDecodeError as exc:
        raise ReportError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise ReportError(f"{path} must be a JSON object, got {type(raw).__name__}")
    return {str(key): str(value) for key, value in raw.items()}


# --- route 1: the markup names the key ---------------------------------------------


def markup_keys(text: str) -> set[str]:
    """Keys named by a translated attribute in the markup."""
    found: set[str] = set()
    for match in _ATTRIBUTE_REFERENCE.finditer(text):
        value = _first_group(match, (2, 3))
        if value:
            found.add(value.strip())
    return found


# --- route 2: a literal call names the key -----------------------------------------


def literal_call_keys(text: str) -> set[str]:
    """Keys named by a literal ``t("…")`` / ``fm("…", …)`` argument."""
    found: set[str] = set()
    for match in _LITERAL_CALL.finditer(text):
        value = _first_group(match, (2, 3))
        if value:
            found.add(value.strip())
    return found


# --- route 3: the script builds the key --------------------------------------------


def concatenation_fragments(text: str) -> set[str]:
    """Every string literal that sits next to a ``+`` in the script.

    Deliberately not scoped to ``t()``/``fm()`` arguments: proving a fragment
    reaches a lookup would need a JavaScript parser, and the failure mode of
    guessing wrong here is a deleted string somebody needed. Over-collecting is
    the safe direction, and the report prints what each fragment covered so an
    over-broad one is visible rather than load-bearing.
    """
    found: set[str] = set()
    for match in _CONCATENATION_FRAGMENT.finditer(text):
        value = _first_group(match, (1, 2, 3, 4))
        if value:
            found.add(value)
    return found


def variable_call_sites(text: str) -> list[str]:
    """Identifiers passed to a lookup as a variable, e.g. ``t(key)``.

    Counted and named so the report can say how much of its own blind spot is
    actually exercised. A variable-keyed call whose key never appears as a
    literal fragment anywhere is a route this script genuinely cannot follow.
    """
    return sorted({match.group(1) for match in _VARIABLE_CALL.finditer(text)})


@dataclass(frozen=True)
class FragmentCoverage:
    """One concatenation fragment and the bundle keys it could build."""

    fragment: str
    covered: tuple[str, ...]
    near_miss_covered: tuple[str, ...]

    @property
    def is_key_prefix(self) -> bool:
        """Whether this fragment looks like it builds a key rather than a class."""
        return (
            len(self.fragment) >= _MIN_FRAGMENT
            and self.fragment.endswith(_KEY_WORD_SEPARATOR)
            and bool(self.covered)
        )

    @property
    def is_near_miss(self) -> bool:
        """Key-stem-shaped, but its separator says it builds a class or an id."""
        return not self.is_key_prefix and bool(self.near_miss_covered)


def _prefixed(prefix: str, keys: Sequence[str]) -> tuple[str, ...]:
    return tuple(key for key in keys if key != prefix and key.startswith(prefix))


def cover_fragments(fragments: Iterable[str], keys: Iterable[str]) -> list[FragmentCoverage]:
    """Pair every fragment with the bundle keys it prefixes, and with its near miss."""
    key_list = sorted(keys)
    coverage: list[FragmentCoverage] = []
    for fragment in sorted(fragments):
        near_miss = _NEAR_MISS_SEPARATOR.match(fragment)
        coverage.append(
            FragmentCoverage(
                fragment=fragment,
                covered=_prefixed(fragment, key_list),
                near_miss_covered=(
                    _prefixed(near_miss.group(1) + _KEY_WORD_SEPARATOR, key_list)
                    if near_miss
                    else ()
                ),
            )
        )
    return coverage


# --- the other catalogue -----------------------------------------------------------


def server_catalogue_keys(path: Path, locale: str = "en") -> dict[str, str]:
    """The CLI catalogue in ``src/habitable/i18n.py`` for *locale*.

    Parsed with ``ast`` rather than matched with a regex: this decides whether a
    key gets classified as "someone else already owns this string" instead of
    "delete me", and that call should not turn on quoting or line wrapping.
    Returns an empty mapping when the catalogue cannot be found, and the report
    says so out loud rather than reporting every key as unique to the app.
    """
    tree = ast.parse(_read(path))
    for node in ast.walk(tree):
        target = getattr(node, "target", None)
        if not isinstance(node, ast.AnnAssign) or not isinstance(target, ast.Name):
            continue
        if target.id != _SERVER_CATALOGUE_NAME or not isinstance(node.value, ast.Dict):
            continue
        return _locale_entries(node.value, locale)
    return {}


def _locale_entries(catalogue: ast.Dict, locale: str) -> dict[str, str]:
    """``{locale: {key: message}}`` → the requested locale's messages."""
    for locale_node, messages in zip(catalogue.keys, catalogue.values, strict=False):
        if not isinstance(locale_node, ast.Constant) or locale_node.value != locale:
            continue
        if not isinstance(messages, ast.Dict):
            continue
        entries: dict[str, str] = {}
        for key_node, value_node in zip(messages.keys, messages.values, strict=False):
            if not isinstance(key_node, ast.Constant):
                continue
            try:
                value = ast.literal_eval(value_node)
            except _LITERAL_ERRORS:
                continue
            if isinstance(value, str):
                entries[str(key_node.value)] = value
        return entries
    return {}


# --- assembling the report ---------------------------------------------------------


@dataclass(frozen=True)
class Report:
    """Everything the printed report and the ``--json`` payload are built from."""

    bundle_path: Path
    bundle: dict[str, str]
    from_markup: set[str]
    from_literal_call: set[str]
    coverage: list[FragmentCoverage]
    variable_calls: list[str]
    server: dict[str, str]
    server_catalogue_path: Path

    @property
    def key_prefixes(self) -> list[FragmentCoverage]:
        return [item for item in self.coverage if item.is_key_prefix]

    @property
    def near_miss_fragments(self) -> list[FragmentCoverage]:
        """Fragments that read like a key stem but build a class name or an id."""
        return [item for item in self.coverage if item.is_near_miss]

    @property
    def from_concatenation(self) -> set[str]:
        """Keys no literal names, but a key-shaped fragment could build."""
        built: set[str] = set()
        for item in self.key_prefixes:
            built.update(item.covered)
        return built - self.from_markup - self.from_literal_call

    @property
    def live(self) -> set[str]:
        return self.from_markup | self.from_literal_call | self.from_concatenation

    @property
    def referenced(self) -> set[str]:
        """Every key the app names, whether or not the bundle defines it."""
        return self.from_markup | self.from_literal_call

    @property
    def undefined(self) -> list[str]:
        """Referenced by the app, absent from the bundle — the mirror defect."""
        return sorted(self.referenced - set(self.bundle))

    @property
    def unreachable(self) -> set[str]:
        return set(self.bundle) - self.live

    @property
    def unreferenced(self) -> list[str]:
        """No route reaches it, and no other catalogue claims it."""
        return sorted(self.unreachable - set(self.server))

    @property
    def server_duplicates(self) -> list[str]:
        """No route reaches it here, but ``src/habitable/i18n.py`` defines it too."""
        return sorted(self.unreachable & set(self.server))


def build_report(
    bundle_path: Path,
    markup_path: Path,
    script_path: Path,
    server_path: Path,
) -> Report:
    """Scan every route and bucket the bundle. Raises ReportError on operator error."""
    bundle = load_bundle(bundle_path)
    markup = _read(markup_path)
    script = _read(script_path)

    return Report(
        bundle_path=bundle_path,
        bundle=bundle,
        # Markup can appear in either file: index.html holds it today, and app.js
        # is free to grow a data-i18n attribute in a string it injects.
        from_markup=markup_keys(markup) | markup_keys(script),
        from_literal_call=literal_call_keys(script) | literal_call_keys(markup),
        coverage=cover_fragments(concatenation_fragments(script), bundle),
        variable_calls=variable_call_sites(script),
        server=server_catalogue_keys(server_path),
        server_catalogue_path=server_path,
    )


# --- rendering ---------------------------------------------------------------------


def _wrap(text: str, indent: str = "    ") -> list[str]:
    return textwrap.wrap(text, width=96, subsequent_indent=indent)


def _summary_lines(report: Report) -> list[str]:
    total = len(report.bundle)
    dead = len(report.unreachable)
    share = (dead / total * 100) if total else 0.0
    return [
        f"Corpus — {report.bundle_path}",
        f"    {total:>4} keys in the bundle",
        f"    {len(report.from_markup):>4} named by a translated attribute (route 1)",
        f"    {len(report.from_literal_call):>4} named by a literal t()/fm() call (route 2)",
        f"    {len(report.from_concatenation):>4} reachable only by concatenation (route 3)",
        f"    {dead:>4} reached by no route at all  ({share:.0f}% of the bundle)",
    ]


def _route_lines(report: Report) -> list[str]:
    """What the scan can see, and — the part that matters — what it cannot."""
    lines = ["Routes this report CAN see:"]
    lines.extend(
        [
            f"    1. {', '.join(_KEY_ATTRIBUTES)} attributes in the markup",
            '    2. a literal t("key") / fm("key", …) call',
            '    3. a key built by concatenation from a literal fragment ending in "_"',
        ]
    )
    lines.append("")
    lines.append("Routes this report CANNOT see — a key reached only this way looks dead:")
    lines.extend(
        [
            "    - a key name that arrives entirely from data (an API field used as a key",
            "      with no literal fragment in the source at all)",
            "    - a lookup reached through an alias or an indirect reference",
            "      (var translate = t; translate(key))",
            "    - any file this report does not read; it reads only the markup, the app",
            "      script, and the server catalogue named below",
        ]
    )
    if report.variable_calls:
        lines.append("")
        lines.extend(
            _wrap(
                "Variable-keyed lookups actually present in the script (each one is a place "
                "route 3 is really exercised, so the fragment list below is load-bearing "
                "rather than theoretical): "
                + ", ".join(f"t({name})" for name in report.variable_calls)
            )
        )
    return lines


def _fragment_lines(report: Report) -> list[str]:
    lines = ['Concatenation fragments treated as key prefixes (end in "_", cover a key):']
    if not report.key_prefixes:
        lines.append("    (none — no key in this bundle is built by concatenation)")
    for item in report.key_prefixes:
        lines.append(f'    "{item.fragment}" covers {len(item.covered)} key(s):')
        lines.extend(
            textwrap.wrap(
                ", ".join(item.covered),
                width=96,
                initial_indent="        ",
                subsequent_indent="        ",
            )
        )
    if report.near_miss_fragments:
        lines.append("")
        lines.extend(
            _wrap(
                "Near misses — fragments shaped like a key stem whose separator says "
                "otherwise. These build a CSS class or an element id, not a key, so they "
                "are NOT treated as route 3. Listed because ruling them out by hand is "
                "exactly the step a scan is trusted to have done:"
            )
        )
        for item in report.near_miss_fragments:
            stem = item.fragment[:-1] + _KEY_WORD_SEPARATOR
            lines.extend(
                textwrap.wrap(
                    f'"{item.fragment}" — as "{stem}" it would have covered '
                    f"{len(item.near_miss_covered)} key(s): "
                    f"{', '.join(item.near_miss_covered)}",
                    width=96,
                    initial_indent="    ",
                    subsequent_indent="        ",
                )
            )
    return lines


def _finding_lines(report: Report) -> list[str]:
    lines: list[str] = []
    unreferenced = report.unreferenced
    lines.append(f"UNREFERENCED — {len(unreferenced)} key(s) no route reaches:")
    lines.extend(
        _wrap(
            "Every locale must carry each of these to pass the parity gate, and no user "
            "will ever be shown one. Decide per key: delete it, or wire it up. Deleting a "
            "string somebody meant to show is its own kind of loss, so check the history "
            "before removing one."
        )
    )
    for key in unreferenced:
        lines.append(f"    {key:<28} {report.bundle[key][:56]!r}")
    lines.append("")

    duplicates = report.server_duplicates
    lines.append(f"ALSO IN THE SERVER CATALOGUE — {len(duplicates)} key(s) defined twice:")
    lines.extend(
        _wrap(
            "No route in the app reaches these, but "
            f"{report.server_catalogue_path.name} defines them too, for CLI output. That is "
            "a different fix: decide which copy is canonical before deleting either. The "
            "two values are often deliberately different, and the difference is the "
            "evidence — a lowercase CLI phrase and a Title Case badge label are two "
            "surfaces, not one string duplicated by accident."
        )
    )
    for key in duplicates:
        lines.append(f"    {key}")
        lines.append(f"        app    {report.bundle[key]!r}")
        lines.append(f"        server {report.server[key]!r}")
    return lines


def _undefined_lines(report: Report) -> list[str]:
    if not report.undefined:
        return ["REFERENCED BUT UNDEFINED — none. Every key the app names, the bundle defines."]
    lines = [f"REFERENCED BUT UNDEFINED — {len(report.undefined)} key(s):"]
    lines.extend(
        _wrap(
            "The app asks for these and the bundle does not define them. t() returns the "
            "key itself when lookup fails, so this ships a reader the raw string where a "
            "sentence belongs. This is the mirror of the finding above and it is a defect "
            "now, not a backlog item."
        )
    )
    lines.extend(f"    {key}" for key in report.undefined)
    return lines


def format_report(report: Report) -> str:
    """The human-readable report. Deterministic, so it can be pasted into an issue."""
    lines = ["i18n key usage report — which app strings have a rendering path (#271)", ""]
    lines.extend(_summary_lines(report))
    lines.append("")
    lines.extend(_route_lines(report))
    lines.append("")
    lines.extend(_fragment_lines(report))
    lines.append("")
    lines.extend(_finding_lines(report))
    lines.append("")
    lines.extend(_undefined_lines(report))
    lines.append("")
    if not report.server:
        lines.extend(
            _wrap(
                f"NOTE: no {_SERVER_CATALOGUE_NAME} catalogue was found in "
                f"{report.server_catalogue_path}, so nothing could be classified as a "
                "duplicate. Every finding above is in the unreferenced bucket by default."
            )
        )
        lines.append("")
    lines.extend(
        _wrap(
            "This is a report and not a gate: the exit status is 0 whatever it finds, "
            "because the backlog it describes predates it and a red build on every "
            "unrelated branch would not help anyone clear it. Route 3 errs toward calling "
            "a key live — a wrong 'dead' deletes a string a reader needed, a wrong 'live' "
            "only leaves a key in the backlog one more day."
        )
    )
    return "\n".join(lines)


def as_json(report: Report) -> dict[str, Any]:
    """Machine-readable payload — what the regression test asserts against."""
    return {
        "bundle": str(report.bundle_path),
        "total_keys": len(report.bundle),
        "reached_by_markup": len(report.from_markup),
        "reached_by_literal_call": len(report.from_literal_call),
        "reached_by_concatenation": sorted(report.from_concatenation),
        "key_prefix_fragments": [item.fragment for item in report.key_prefixes],
        "near_miss_fragments": [item.fragment for item in report.near_miss_fragments],
        "variable_keyed_calls": report.variable_calls,
        "unreferenced": report.unreferenced,
        "server_duplicates": report.server_duplicates,
        "referenced_but_undefined": report.undefined,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Report app i18n keys with no rendering path.")
    parser.add_argument("--bundle", type=Path, default=_EN_BUNDLE, help="the English app bundle")
    parser.add_argument("--markup", type=Path, default=_MARKUP, help="the app markup to scan")
    parser.add_argument("--script", type=Path, default=_SCRIPT, help="the app script to scan")
    parser.add_argument(
        "--server-catalogue",
        type=Path,
        default=_SERVER_CATALOGUE,
        help="the Python module holding the CLI message catalogue",
    )
    parser.add_argument(
        "--json", action="store_true", help="emit the findings as JSON instead of the report"
    )
    args = parser.parse_args(argv)

    try:
        report = build_report(args.bundle, args.markup, args.script, args.server_catalogue)
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
