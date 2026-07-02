#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Locale parity gate: the EN and ES bundles must stay in lockstep.

habitable ships an English and a Spanish UI bundle (``app/i18n/en.json`` and
``app/i18n/es.json``). EN/ES parity is a design goal: every key present in one
locale must exist in the other, and no Spanish string may be blank. A drifting
bundle silently ships English text to Spanish speakers, so this check is wired
into ``make verify`` as a blocking merge gate.

Beyond key parity (G6), this gate also enforces **plural-category and
placeholder parity (G5)** for the ICU-MessageFormat subset the app renders
(``{name}`` and ``{name, plural, =N {...} one {...} other {...}}``):

* every plural message must parse, and must carry an ``other`` branch plus the
  locale's required CLDR cardinal categories (en: one+other; es: one+other);
* a category outside CLDR's ``zero/one/two/few/many/other`` (or an ``=N``
  exact) is rejected — a typo like ``once`` would otherwise ship silently;
* both locales must pluralize the *same variables* and use the *same simple
  placeholders* per key, so a locale cannot quietly drop a count.

This is intentionally dependency-light: standard library only, no network, no
config. It is deterministic (all findings are emitted sorted) so CI output is
stable. Keys are compared recursively, so nested objects are supported even
though today's bundles are flat.

Exit codes:
    0  bundles are at parity, every value is non-empty, plurals are sound.
    1  a real mismatch (missing/extra key, empty value, plural problem).
    2  a bundle is missing or is not valid JSON (operator error).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

# app/i18n lives two levels up from this file: <repo>/scripts/<this>.
_REPO_ROOT = Path(__file__).resolve().parent.parent
_I18N_DIR = _REPO_ROOT / "app" / "i18n"
_EN = _I18N_DIR / "en.json"
_ES = _I18N_DIR / "es.json"


def _flatten(data: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    """Flatten a (possibly nested) locale mapping to dotted-path leaf keys."""
    flat: dict[str, Any] = {}
    for key, value in data.items():
        path = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(value, dict):
            flat.update(_flatten(value, path))
        else:
            flat[path] = value
    return flat


def _load(path: Path) -> dict[str, Any]:
    """Read and flatten one locale bundle, exiting 2 on operator error."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"error: locale bundle not found: {path}", file=sys.stderr)
        raise SystemExit(2) from None
    except json.JSONDecodeError as exc:
        print(f"error: {path} is not valid JSON: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
    if not isinstance(raw, dict):
        print(f"error: {path} must be a JSON object, got {type(raw).__name__}", file=sys.stderr)
        raise SystemExit(2)
    return _flatten(raw)


# --- ICU plural/placeholder analysis (G5) --------------------------------------

# CLDR plural categories that may ever appear in a cardinal message.
_VALID_CATEGORIES = frozenset({"zero", "one", "two", "few", "many", "other"})

# Cardinal categories every plural message MUST spell out, per locale. CLDR
# defines more (es also has "many" for millions), but these are the ones a UI
# count can actually hit; "other" is always mandatory.
_REQUIRED_CATEGORIES: dict[str, frozenset[str]] = {
    "en": frozenset({"one", "other"}),
    "es": frozenset({"one", "other"}),
}


def _match_brace(text: str, start: int) -> int:
    """Index of the ``}`` matching the ``{`` at *start* (raises if unbalanced)."""
    depth = 0
    for idx in range(start, len(text)):
        if text[idx] == "{":
            depth += 1
        elif text[idx] == "}":
            depth -= 1
            if depth == 0:
                return idx
    raise ValueError("unbalanced braces")


def _parse_plural_branches(source: str) -> dict[str, str]:
    """``one {...} other {...}`` → ``{selector: content}`` (raises if malformed)."""
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
            raise ValueError(f"malformed plural branches near {source[start:][:30]!r}")
        end = _match_brace(source, i)
        branches[selector] = source[i + 1 : end]
        i = end + 1
    return branches


def _analyze_message(message: str) -> tuple[set[str], dict[str, set[str]]]:
    """(simple placeholders, {plural var: categories}) for an ICU-subset message.

    Raises ValueError when the message is not valid under the subset.
    """
    placeholders: set[str] = set()
    plurals: dict[str, set[str]] = {}
    i = 0
    while i < len(message):
        ch = message[i]
        if ch == "}":
            raise ValueError("unbalanced '}'")
        if ch != "{":
            i += 1
            continue
        end = _match_brace(message, i)
        body = message[i + 1 : end]
        i = end + 1
        head, _, rest = body.partition(",")
        name = head.strip()
        if not rest:
            placeholders.add(name)
            continue
        kind, _, branch_src = rest.partition(",")
        if kind.strip() != "plural":
            raise ValueError(f"unsupported ICU argument type {kind.strip()!r}")
        branches = _parse_plural_branches(branch_src)
        categories: set[str] = set()
        for selector, content in branches.items():
            if selector.startswith("="):
                if not selector[1:].isdigit():
                    raise ValueError(f"bad exact selector {selector!r}")
            elif selector in _VALID_CATEGORIES:
                categories.add(selector)
            else:
                raise ValueError(f"unknown plural category {selector!r}")
            sub_placeholders, sub_plurals = _analyze_message(content)
            placeholders |= sub_placeholders
            for sub_name, sub_categories in sub_plurals.items():
                plurals.setdefault(sub_name, set()).update(sub_categories)
        if "other" not in categories:
            raise ValueError(f"plural for {name!r} has no 'other' branch")
        plurals.setdefault(name, set()).update(categories)
    return placeholders, plurals


def _plural_problems(en: dict[str, Any], es: dict[str, Any]) -> list[str]:
    """Sorted G5 findings across the keys the two bundles share."""
    problems: list[str] = []
    analyzed: dict[str, dict[str, tuple[set[str], dict[str, set[str]]]]] = {"en": {}, "es": {}}
    for locale, bundle in (("en", en), ("es", es)):
        for key in sorted(set(en) & set(es)):
            value = bundle.get(key)
            if not isinstance(value, str):
                continue
            try:
                analyzed[locale][key] = _analyze_message(value)
            except ValueError as exc:
                problems.append(f"{locale}.json {key}: invalid ICU message ({exc})")
    for key in sorted(set(analyzed["en"]) & set(analyzed["es"])):
        en_ph, en_plurals = analyzed["en"][key]
        es_ph, es_plurals = analyzed["es"][key]
        if en_ph != es_ph:
            problems.append(
                f"{key}: placeholder mismatch — en {sorted(en_ph)} vs es {sorted(es_ph)}"
            )
        if set(en_plurals) != set(es_plurals):
            problems.append(
                f"{key}: plural variables differ — en {sorted(en_plurals)} "
                f"vs es {sorted(es_plurals)}"
            )
        for locale, plural_vars in (("en", en_plurals), ("es", es_plurals)):
            required = _REQUIRED_CATEGORIES[locale]
            for var, categories in sorted(plural_vars.items()):
                missing = sorted(required - categories)
                if missing:
                    problems.append(
                        f"{locale}.json {key}: plural {var!r} is missing required "
                        f"CLDR categor{'y' if len(missing) == 1 else 'ies'}: "
                        f"{', '.join(missing)}"
                    )
    return sorted(problems)


def _empty_value_keys(bundle: dict[str, Any]) -> list[str]:
    """Keys whose value is not a non-blank string."""
    bad: list[str] = []
    for key, value in bundle.items():
        if not isinstance(value, str) or not value.strip():
            bad.append(key)
    return sorted(bad)


def check_parity(en_path: Path = _EN, es_path: Path = _ES) -> int:
    """Return 0 if EN/ES are at parity with no empty values, else 1."""
    en = _load(en_path)
    es = _load(es_path)

    missing_in_es = sorted(set(en) - set(es))
    extra_in_es = sorted(set(es) - set(en))
    empty_en = _empty_value_keys(en)
    empty_es = _empty_value_keys(es)
    plural_findings = _plural_problems(en, es)

    problems = False
    if missing_in_es:
        problems = True
        print(f"FAIL: {len(missing_in_es)} key(s) present in en.json but missing in es.json:")
        for key in missing_in_es:
            print(f"  - {key}")
    if extra_in_es:
        problems = True
        print(f"FAIL: {len(extra_in_es)} key(s) present in es.json but missing in en.json:")
        for key in extra_in_es:
            print(f"  - {key}")
    if empty_es:
        problems = True
        print(f"FAIL: {len(empty_es)} empty/blank value(s) in es.json:")
        for key in empty_es:
            print(f"  - {key}")
    if empty_en:
        problems = True
        print(f"FAIL: {len(empty_en)} empty/blank value(s) in en.json:")
        for key in empty_en:
            print(f"  - {key}")
    if plural_findings:
        problems = True
        print(f"FAIL: {len(plural_findings)} plural/placeholder parity problem(s) (G5):")
        for finding in plural_findings:
            print(f"  - {finding}")

    if problems:
        print("\ni18n parity gate: FAILED — fix the keys above so EN and ES stay in lockstep.")
        return 1

    print(
        f"i18n parity gate: OK — {len(en)} keys, EN and ES in lockstep, "
        "no empty values, plural categories and placeholders at parity."
    )
    return 0


def main() -> int:
    return check_parity()


if __name__ == "__main__":
    raise SystemExit(main())
