#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Locale key-parity gate: the EN and ES bundles must stay in lockstep.

habitable ships an English and a Spanish UI bundle (``app/i18n/en.json`` and
``app/i18n/es.json``). EN/ES parity is a design goal: every key present in one
locale must exist in the other, and no Spanish string may be blank. A drifting
bundle silently ships English text to Spanish speakers, so this check is wired
into ``make verify`` as a blocking merge gate.

This is intentionally dependency-light: standard library only, no network, no
config. It is deterministic (all findings are emitted sorted) so CI output is
stable. Keys are compared recursively, so nested objects are supported even
though today's bundles are flat.

Exit codes:
    0  bundles are at parity and every value is non-empty.
    1  a real mismatch (missing/extra key or empty value) was found.
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

    if problems:
        print("\ni18n parity gate: FAILED — fix the keys above so EN and ES stay in lockstep.")
        return 1

    print(f"i18n parity gate: OK — {len(en)} keys, EN and ES in lockstep, no empty values.")
    return 0


def main() -> int:
    return check_parity()


if __name__ == "__main__":
    raise SystemExit(main())
