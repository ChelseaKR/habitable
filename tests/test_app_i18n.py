# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""The app's English and Spanish bundles must stay at parity."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

_APP = Path(__file__).resolve().parent.parent / "app"
_EN = _APP / "i18n" / "en.json"
_ES = _APP / "i18n" / "es.json"
_STYLES = _APP / "styles.css"
_APP_JS = _APP / "app.js"


def _load(path: Path) -> dict[str, str]:
    assert path.is_file(), f"missing translation bundle: {path}"
    data = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return {str(k): str(v) for k, v in data.items()}


def test_en_and_es_have_identical_keys() -> None:
    en, es = _load(_EN), _load(_ES)
    assert set(en) == set(es), (
        f"missing in es: {sorted(set(en) - set(es))}; extra in es: {sorted(set(es) - set(en))}"
    )


def test_no_empty_translations() -> None:
    for path in (_EN, _ES):
        for key, value in _load(path).items():
            assert value.strip(), f"{path.name}: empty translation for {key!r}"


def test_awaiting_timestamp_copy_is_reassuring() -> None:
    """RR-01: the offline 'awaiting timestamp' state must read as already-safe, not a
    dead-end, and must say what to do next — in both languages."""
    en, es = _load(_EN), _load(_ES)
    for bundle in (en, es):
        assert "status_awaiting_help" in bundle, "missing reassuring status help copy"
        assert "capture_awaiting_reassure" in bundle, "missing capture reassurance copy"
    # English reassurance names the already-safe state and the concrete next step.
    assert any(
        word in en["status_awaiting_help"].lower() for word in ("sealed", "safe", "protected")
    )
    assert "Resolve awaiting timestamps" in en["capture_awaiting_reassure"]
    # Spanish reassurance is genuinely translated and names the safe state + next step.
    assert any(
        word in es["status_awaiting_help"].lower() for word in ("sellad", "salvo", "protegid")
    )
    assert "Resolver marcas de tiempo pendientes" in es["capture_awaiting_reassure"]


def test_spanish_is_actually_translated() -> None:
    """A sanity check that es is not just a copy of en (most strings differ)."""
    en, es = _load(_EN), _load(_ES)
    shared = set(en) & set(es)
    if not shared:
        pytest.skip("no shared keys")
    differing = sum(1 for k in shared if en[k] != es[k])
    assert differing >= len(shared) // 2


# --- RTL readiness + text-expansion robustness (R-48) ----------------------
#
# Static-analysis-style guards (matching the repo's JS-test convention): the
# app never bundles a headless browser at test time, so we assert on the source
# text directly.

# Strip line/block comments so a physical-direction word inside a comment is not
# mistaken for a real declaration.
_CSS_COMMENTS = re.compile(r"/\*.*?\*/", re.DOTALL)

# Physical-direction declarations that break under `dir="rtl"`. Logical
# equivalents (margin-inline-*, padding-inline-*, inset-inline-*, text-align:
# start|end) contain none of these substrings, so they never match.
_PHYSICAL_CSS = re.compile(
    r"\b(?:margin|padding)-(?:left|right)\b"  # margin-left / padding-right / ...
    r"|\btext-align:\s*(?:left|right)\b"  # text-align: left|right
    r"|(?<![-\w])(?:left|right)\s*:",  # bare `left:` / `right:` (not inset-inline-*)
)


def test_styles_css_uses_only_logical_direction_properties() -> None:
    """No physical-direction CSS survives — the layout must mirror under RTL."""
    css = _CSS_COMMENTS.sub("", _STYLES.read_text(encoding="utf-8"))
    offenders = _PHYSICAL_CSS.findall(css)
    assert not offenders, (
        "styles.css still uses physical-direction properties (use "
        "margin-inline-*/padding-inline-*/inset-inline-*/text-align:start|end): "
        f"{offenders}"
    )


def test_set_language_sets_dir_alongside_lang() -> None:
    """setLanguage flips `dir` to rtl/ltr next to the `lang` attribute."""
    js = _APP_JS.read_text(encoding="utf-8")
    # The direction map and both directions must be present.
    assert "RTL_LANGS" in js
    for tag in ("ar", "he", "fa", "ur"):
        assert f'"{tag}"' in js, f"RTL map missing {tag!r}"
    # dir is set on the document element in the same code path that sets lang.
    assert re.search(r'setAttribute\(\s*"dir"', js), "dir attribute never set"
    assert '"rtl"' in js and '"ltr"' in js, "both rtl and ltr directions required"
    # Guard against regression: dir must be wired next to the lang attribute.
    lang_idx = js.index('setAttribute("lang"')
    dir_idx = js.index('"dir"')
    assert abs(dir_idx - lang_idx) < 400, "dir should be set beside lang in setLanguage"


# Keys whose values render in compact / near-fixed-width chrome (buttons,
# badges, short field labels) where text expansion is most likely to overflow.
_COMPACT_KEY = re.compile(r"(?:^|_)(?:label|badge)(?:_|$)|_label$|^lang_")
# Prose that merely happens to match the pattern (full-sentence messages) is not
# fixed-width UI, so it is exempt from the compact cap.
_PROSE_PREFIX = ("error_", "msg_", "help_")
# Pseudo-locale growth factor and the widest a compact label may get afterwards.
_EXPANSION = 1.4
_COMPACT_CAP = 60


def test_pseudo_locale_expansion_fits_compact_ui() -> None:
    """Every bundle string pseudo-expands cleanly; compact labels stay bounded.

    Emulates a ~40%-longer pseudo-locale (the classic text-expansion check)
    without a browser: compact UI strings, once padded, must stay under a
    fixed-width sanity cap so they wrap rather than blow out the 320px layout.
    """
    en = _load(_EN)
    assert en, "en.json is empty"
    too_long: list[str] = []
    for key, value in en.items():
        padded = round(len(value) * _EXPANSION)  # exercise every string
        is_compact = bool(_COMPACT_KEY.search(key)) and not key.startswith(_PROSE_PREFIX)
        if is_compact and padded > _COMPACT_CAP:
            too_long.append(f"{key} ({len(value)}->{padded} chars): {value!r}")
    assert not too_long, (
        "compact-UI strings exceed the fixed-width sanity cap once pseudo-"
        f"expanded (>{_COMPACT_CAP} chars); shorten them or make the UI wrap: "
        + "; ".join(too_long)
    )
