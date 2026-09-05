# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Issue #268: the app must not ship two English copies of itself.

`app/index.html` carries fallback text inside every `data-i18n` element, and
`app/app.js` overwrites it once `i18n/<lang>.json` loads. When the fetch fails --
a flaky connection, a first paint before the bundle arrives, `wireLang()`'s
explicit "keep current language" path -- the reader sees the markup instead.

That is fine only while the two say the same thing. They had drifted in 26 places,
and not randomly: the markup held the wording from *before* the plain-language
review (R-41/R-04) and the bundle held the reviewed wording, so the copy a reader
got on a bad connection was the copy the review had already rejected. Several of
the divergences weakened an honest-limits string outright -- `field_dev_tsa_help`
lost "never evidence-ready", `resolve_help` lost "Authority trust is checked
separately", `export_scope_help` lost the entire reason the export is blocked.

Softening what habitable cannot prove is the one thing the copy is never allowed
to do, and there was a rendering path that did it. This guard closes the class.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

_APP = Path(__file__).resolve().parent.parent / "app"
_INDEX = _APP / "index.html"
_EN = _APP / "i18n" / "en.json"

#: `data-i18n="key">text<` for elements whose content is a single text node.
#: Elements containing nested markup are skipped: their fallback is not one
#: string, so it cannot be compared to one bundle value.
_ELEMENT = re.compile(r'data-i18n="([a-z0-9_]+)"[^>]*>([^<>]*)<')


def _collapse(text: str) -> str:
    """HTML collapses runs of whitespace; compare the way a browser renders."""
    return " ".join(text.split())


def test_every_fallback_string_matches_the_english_bundle() -> None:
    """The markup and `en.json` must be the same words, not merely similar ones."""
    html = _INDEX.read_text(encoding="utf-8")
    english = json.loads(_EN.read_text(encoding="utf-8"))

    elements = _ELEMENT.findall(html)
    assert len(elements) > 100, (
        f"only {len(elements)} data-i18n elements matched; the markup or this "
        "regex changed shape and the guard is no longer reading the page"
    )

    drifted: list[str] = []
    for key, fallback in elements:
        rendered = _collapse(fallback)
        if not rendered:
            continue  # an empty element is filled entirely by the bundle
        if key not in english:
            drifted.append(f"{key}: no such key in en.json (fallback {rendered!r})")
            continue
        if rendered != _collapse(english[key]):
            drifted.append(f"{key}:\n    markup: {rendered!r}\n    en.json: {english[key]!r}")

    assert not drifted, (
        "the app's markup and its English bundle disagree, so a reader whose "
        "translation fetch fails sees different copy from everyone else. English "
        "is a translation here like any other -- make the markup say exactly what "
        "the bundle says. If a fallback reads better short, shorten the bundle "
        "string, not the markup only.\n\n" + "\n".join(drifted)
    )


def test_every_translation_hook_in_the_markup_is_applied_by_the_script() -> None:
    """A `data-i18n-*` attribute the script never reads is a dead translation.

    `applyTranslations()` handles three hooks: `data-i18n` (text), `data-i18n-aria`
    (`aria-label`), and `data-i18n-label` (an `<option>`'s `label`, added for the
    Condition datalist in issue #239). The markup and the script have to agree on
    the set, in both directions -- an attribute the script ignores renders the
    English fallback to every Spanish reader and looks translated in review, and a
    handler with no markup is dead code that hides the next missing one.
    """
    html = _INDEX.read_text(encoding="utf-8")
    script = (_APP / "app.js").read_text(encoding="utf-8")

    in_markup = set(re.findall(r"\b(data-i18n(?:-[a-z]+)?)=", html))
    read_by_script = set(re.findall(r'querySelectorAll\("\[(data-i18n(?:-[a-z]+)?)\]"\)', script))

    assert in_markup, "no translation hooks in the markup; this guard reads nothing"
    assert in_markup == read_by_script, (
        "the markup and applyTranslations() disagree about which translation hooks "
        f"exist.\n  only in markup (never applied): {sorted(in_markup - read_by_script)}"
        f"\n  only in script (no markup uses it): {sorted(read_by_script - in_markup)}"
    )
