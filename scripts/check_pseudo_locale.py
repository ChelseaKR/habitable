#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Pseudo-locale generation and text-expansion gate (G9).

Generates an ``en-XA``-style pseudo-locale from ``app/i18n/en.json`` and then
checks two properties of the result. Both can fail; ``main`` returns 1 when
either does.

``RULE A`` -- the transform must not corrupt an ICU message.
    A pseudo-locale exists to be loaded into the running app, so a generator
    that mangles ``{count, plural, ...}`` would report a layout break that is
    really its own bug. Every generated string is re-analysed with
    ``check_i18n_parity._analyze_message`` -- the same parser the EN/ES parity
    gate uses -- and must carry exactly the placeholders and plural categories
    of its English source.

``RULE B`` -- compact chrome must survive real expansion.
    ``tests/test_app_i18n.py::test_pseudo_locale_expansion_fits_compact_ui``
    already models expansion as ``len(value) * 1.4``. This checks the text the
    generator actually emits, whose measured ratio reaches 2.0x on the current
    bundle -- so a label that fits the model can still fail here, which is the
    point of generating the locale rather than multiplying a number.

Why this file exists rather than one more test: it is also the way to *get* the
bundle (``--out``), so someone can load a genuinely expanded locale in the app.
A generator whose output nothing checks is how the previous version of this file
came to print ``Successfully generated`` and return 0 unconditionally.

Standard library only, like ``check_i18n_parity.py``, so it runs in the offline
merge gate on the runner's built-in ``python3`` with nothing installed.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

# Ensure scripts directory is in sys.path for parity imports
sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_i18n_parity import _EN, _analyze_message, _load, _match_brace, _parse_plural_branches

ACCENT_MAP = {
    "a": "å",
    "b": "ƀ",
    "c": "ç",
    "d": "ð",
    "e": "é",
    "f": "ƒ",
    "g": "ğ",
    "h": "ħ",
    "i": "î",
    "j": "ĵ",
    "k": "ķ",
    "l": "ĺ",
    "m": "ɱ",
    "n": "ñ",
    "o": "ö",
    "p": "þ",
    "q": "ɋ",
    "r": "ŕ",
    "s": "š",
    "t": "ţ",
    "u": "û",
    "v": "ṽ",
    "w": "ŵ",
    "x": "ẋ",
    "y": "ý",
    "z": "ž",
    "A": "Å",
    "B": "Ɓ",
    "C": "Ç",
    "D": "Ð",
    "E": "Ê",
    "F": "Ƒ",
    "G": "Ğ",
    "H": "Ħ",
    "I": "Î",
    "J": "Ĵ",
    "K": "Ķ",
    "L": "Ĺ",
    "M": "Ɱ",
    "N": "Ñ",
    "O": "Ö",
    "P": "Þ",
    "Q": "Ɋ",
    "R": "Ŕ",
    "S": "Š",
    "T": "Ţ",
    "U": "Û",
    "V": "Ṽ",
    "W": "Ŵ",
    "X": "Ẋ",
    "Y": "Ý",
    "Z": "Ž",
}


def pseudo_localize_text(text: str) -> str:
    """Transform plain text with pseudo-accents and ~35% length expansion."""
    result = []
    for char in text:
        transformed = ACCENT_MAP.get(char, char)
        result.append(transformed)
        # Pad vowels to simulate text expansion (~35-40%)
        if char.lower() in "aeiou":
            result.append(transformed)
    return f"[{''.join(result)}]"


def transform_icu_message(message: str) -> str:
    """Pseudo-localize message text while preserving ICU structure.

    The first version tracked brace depth and copied *everything* at depth > 0
    verbatim. That preserved placeholders, but it also left the literal text
    inside a plural branch -- ``one {# photo} other {# photos}`` -- in English,
    so six shipped keys came back from the generator byte-identical to their
    source while being counted as pseudo-localized. Plural messages are exactly
    the strings whose length varies most between languages, so the generator was
    silent about the strings a text-expansion pass most needs to see.

    This walks the same ICU subset ``_analyze_message`` accepts and recurses into
    branch bodies, so branch content expands while the argument name, the
    ``plural`` keyword, the category selectors and ``#`` are preserved.
    """
    _analyze_message(message)  # reject anything outside the subset up front
    return _transform(message)


def _transform(message: str) -> str:
    output: list[str] = []
    literal: list[str] = []
    i = 0
    while i < len(message):
        if message[i] != "{":
            literal.append(message[i])
            i += 1
            continue
        if literal:
            output.append(pseudo_localize_text("".join(literal)))
            literal = []
        end = _match_brace(message, i)
        body = message[i + 1 : end]
        i = end + 1
        head, _, rest = body.partition(",")
        if not rest:
            output.append("{" + body + "}")  # a bare placeholder is a name, not text
            continue
        kind, _, branch_src = rest.partition(",")
        branches = _parse_plural_branches(branch_src)
        rendered = " ".join(
            f"{selector} {{{_transform(content)}}}" for selector, content in branches.items()
        )
        output.append("{" + head + "," + kind + ", " + rendered + "}")

    if literal:
        output.append(pseudo_localize_text("".join(literal)))

    return "".join(output)


def generate_pseudo_locale(en_bundle: dict[str, Any]) -> dict[str, Any]:
    """Generate pseudo-localized strings bundle from flattened EN data."""
    pseudo_bundle = {}
    for key, val in en_bundle.items():
        if isinstance(val, str):
            pseudo_bundle[key] = transform_icu_message(val)
        else:
            pseudo_bundle[key] = val
    return pseudo_bundle


#: Keys whose values render in compact / near-fixed-width chrome (buttons, badges,
#: short field labels), where expansion overflows first. Kept identical to
#: ``tests/test_app_i18n.py`` on purpose: that test models the expansion, this gate
#: measures it, and they must be talking about the same strings for the pair to mean
#: anything.
_COMPACT_KEY = re.compile(r"(?:^|_)(?:label|badge)(?:_|$)|_label$|^lang_")
#: Prose that merely matches the pattern above is not fixed-width UI.
_PROSE_PREFIX = ("error_", "msg_", "help_")
#: The widest a compact label may get once pseudo-localized.
_COMPACT_CAP = 60


def check_pseudo_locale(bundle: dict[str, Any]) -> list[str]:
    """Return one line per violation; an empty list means the locale is safe."""
    problems: list[str] = []
    for key, value in sorted(bundle.items()):
        if not isinstance(value, str):
            continue
        try:
            source_placeholders, source_plurals = _analyze_message(value)
        except ValueError as exc:
            # The English bundle itself is malformed. `check_i18n_parity.py` owns
            # that verdict; say so here rather than blaming the transform.
            problems.append(f"{key}: english source is not a valid ICU message ({exc})")
            continue
        try:
            pseudo = transform_icu_message(value)
        except ValueError as exc:
            problems.append(f"{key}: pseudo-localizing raised {exc}")
            continue
        try:
            pseudo_placeholders, pseudo_plurals = _analyze_message(pseudo)
        except ValueError as exc:
            problems.append(f"{key}: generated pseudo-locale is not parseable ICU ({exc})")
            continue
        if pseudo_placeholders != source_placeholders:
            problems.append(
                f"{key}: RULE A -- placeholders changed, "
                f"{sorted(source_placeholders)} -> {sorted(pseudo_placeholders)}"
            )
        if pseudo_plurals != source_plurals:
            problems.append(
                f"{key}: RULE A -- plural categories changed, "
                f"{ {k: sorted(v) for k, v in source_plurals.items()} } -> "
                f"{ {k: sorted(v) for k, v in pseudo_plurals.items()} }"
            )
        is_compact = bool(_COMPACT_KEY.search(key)) and not key.startswith(_PROSE_PREFIX)
        if is_compact and len(pseudo) > _COMPACT_CAP:
            problems.append(
                f"{key}: RULE B -- compact label is {len(pseudo)} chars once "
                f"pseudo-localized (cap {_COMPACT_CAP}), from {len(value)}: {pseudo!r}"
            )
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate and check the pseudo-locale.")
    parser.add_argument(
        "--bundle",
        type=Path,
        default=_EN,
        help="source English bundle (defaults to app/i18n/en.json). This is the seam "
        "the test suite injects a deliberately broken string through.",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="write the generated pseudo-locale bundle here, for loading in the app.",
    )
    args = parser.parse_args(argv)

    en_bundle = _load(args.bundle)
    if not en_bundle:
        print(f"habitable: {args.bundle} produced no keys; this gate is checking nothing")
        return 1

    # Checked before generated, so a malformed source is reported as a violation
    # rather than raised as a traceback out of the generator.
    problems = check_pseudo_locale(en_bundle)
    if problems:
        print(f"habitable: pseudo-locale gate failed on {len(problems)} string(s):")
        for problem in problems:
            print(f"  - {problem}")
        return 1

    pseudo_bundle = generate_pseudo_locale(en_bundle)
    if args.out is not None:
        args.out.write_text(
            json.dumps(pseudo_bundle, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    print(
        f"habitable: {len(pseudo_bundle)} keys pseudo-localize with their ICU "
        f"structure intact and every compact label within {_COMPACT_CAP} chars"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
