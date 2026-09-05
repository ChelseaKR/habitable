#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Pseudo-locale generation and text-expansion validation gate."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

# Ensure scripts directory is in sys.path for parity imports
sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_i18n_parity import _EN, _analyze_message, _load

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
    """Pseudo-localize message text while preserving ICU placeholders."""
    _analyze_message(message)

    output: list[str] = []
    i = 0
    depth = 0
    buffer: list[str] = []

    while i < len(message):
        ch = message[i]
        if ch == "{":
            if depth == 0 and buffer:
                output.append(pseudo_localize_text("".join(buffer)))
                buffer = []
            depth += 1
            output.append(ch)
        elif ch == "}":
            depth -= 1
            output.append(ch)
        else:
            if depth > 0:
                output.append(ch)
            else:
                buffer.append(ch)
        i += 1

    if buffer:
        output.append(pseudo_localize_text("".join(buffer)))

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


def main() -> int:
    en_bundle = _load(_EN)
    pseudo_bundle = generate_pseudo_locale(en_bundle)
    print(f"Successfully generated {len(pseudo_bundle)} pseudo-localized keys.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
