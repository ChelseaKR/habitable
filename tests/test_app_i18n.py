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


def test_export_scope_copy_is_whole_unit_and_fail_closed_in_both_languages() -> None:
    en, es = _load(_EN), _load(_ES)
    assert "whole unit only" in en["field_issue_optional"].casefold()
    assert "unidad completa" in es["field_issue_optional"].casefold()
    assert "temporarily blocked" in en["export_scope_help"].casefold()
    assert "bloqueadas temporalmente" in es["export_scope_help"].casefold()
    assert "outside the selected issue" in en["export_scope_help"].casefold()
    assert "fuera del problema seleccionado" in es["export_scope_help"].casefold()


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
    assert "Add missing timestamp tokens" in en["capture_awaiting_reassure"]
    # Spanish reassurance is genuinely translated and names the safe state + next step.
    assert any(
        word in es["status_awaiting_help"].lower() for word in ("sellad", "salvo", "protegid")
    )
    assert "Agregar sellos de tiempo faltantes" in es["capture_awaiting_reassure"]


def test_missing_timestamp_action_copy_is_plain_and_consistent() -> None:
    """R-41: use an action instead of "resolve" jargon and one Spanish term."""
    en, es = _load(_EN), _load(_ES)
    for key in ("resolve_deferred", "resolve_help", "msg_resolved"):
        assert "resolve" not in en[key].casefold()
        assert "resolver" not in es[key].casefold()
        assert "marca de tiempo" not in es[key].casefold()
    assert "missing timestamp" in en["resolve_deferred"].casefold()
    assert "sellos de tiempo faltantes" in es["resolve_deferred"].casefold()


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


# --- No screen is a dead end (issue #244) -----------------------------------


def test_copy_that_tells_you_to_press_a_button_quotes_that_button_s_real_label() -> None:
    """A next action is only a next action if the control it names exists.

    ``export_awaiting_next`` told the reader to use "Resolve awaiting timestamps"
    long after R-41 renamed that button to "Add missing timestamp tokens" — and
    the Spanish still said "Resolver marcas de tiempo pendientes", carrying both
    the dead label and the ``marca de tiempo`` wording the same pass retired. The
    screen therefore ended in an instruction to press something that is not on it,
    which is a dead end wearing the costume of a next step.

    ``test_missing_timestamp_action_copy_is_plain_and_consistent`` above checks the
    button's own strings; nothing checked the copy that quotes them. This does:
    every string that points at the resolve button must contain its current label,
    so renaming the button again fails here instead of shipping a phantom.
    """
    en, es = _load(_EN), _load(_ES)
    for bundle, key in ((en, "resolve_deferred"), (es, "resolve_deferred")):
        assert bundle[key].strip(), "the resolve button has no label to quote"
    pointing = ("capture_awaiting_reassure", "export_awaiting_next")
    for key in pointing:
        assert en["resolve_deferred"] in en[key], (
            f"en.{key} points at the timestamp button but does not use its label "
            f"{en['resolve_deferred']!r}: {en[key]!r}"
        )
        assert es["resolve_deferred"] in es[key], (
            f"es.{key} points at the timestamp button but does not use its label "
            f"{es['resolve_deferred']!r}: {es[key]!r}"
        )


def test_failed_export_names_a_next_action_without_softening_the_verdict() -> None:
    """The app's worst outcome was the only one with nowhere to go.

    An export whose integrity or timestamp check fails printed the verdict and
    stopped: the awaiting and untrusted branches both got a "next step" paragraph,
    the failure branch got none. R-02's whole point is that a person under threat
    of retaliation, at midnight, on a phone, abandons the case at exactly that
    screen.

    The fix is a next action *added to* the verdict, never a softening of it —
    so this test pins both halves: the new copy must tell the reader not to send
    the copy, and the verdicts themselves must still say "not evidence-ready".
    """
    en, es = _load(_EN), _load(_ES)
    for bundle in (en, es):
        assert "export_failed_next" in bundle, "the failed-export state names no next action"
        assert bundle["export_failed_next"].strip()
    assert "do not send" in en["export_failed_next"].casefold()
    assert "no envíes" in es["export_failed_next"].casefold()
    # The honest limit is untouched by the added next action.
    assert "not evidence-ready" in en["verify_failed"].casefold()
    assert "no lista como prueba" in es["verify_failed"].casefold()


def test_the_sync_found_nothing_state_does_not_overclaim() -> None:
    """ "Nothing was missing" is not the same fact as "everything is stamped".

    ``/api/resolve`` walks this device's stamp-later queue only. A capture that
    arrived in the vault already unstamped is counted in ``awaiting`` but is not in
    ``deferred``, so the button reports zero while the status grid still shows
    photos waiting (the asymmetry issue #180 named). The old ``=0`` copy, "No
    timestamp tokens were missing.", read as a clean bill of health for a vault
    that may still hold unstamped evidence.

    The replacement is scoped to this device and says plainly that anything still
    waiting cannot be stamped from here — the "you cannot do this yet, and here is
    why" answer, which is a valid next action and not a softened one.
    """
    en, es = _load(_EN), _load(_ES)
    zero_en = en["msg_resolved"].split("=0 {", 1)[1].split("}", 1)[0]
    zero_es = es["msg_resolved"].split("=0 {", 1)[1].split("}", 1)[0]
    assert "this device" in zero_en.casefold(), zero_en
    assert "dispositivo" in zero_es.casefold(), zero_es
    for text in (zero_en, zero_es):
        assert len(text.split(".")) >= 2, (
            f"the zero case still stops at one flat sentence: {text!r}"
        )


def test_recoverable_failures_and_empty_lists_say_what_to_do() -> None:
    """A file that would not read, and a link list with nothing in it.

    ``error_file_read`` said only "Could not read the selected file." — true, and
    no help: try again? try a different file? was anything saved? And the "Related
    captures" listbox rendered with zero options and zero words when the chosen
    condition had no photos yet, which reads as a broken control rather than an
    empty one.
    """
    en, es = _load(_EN), _load(_ES)
    for bundle in (en, es):
        assert "link_no_captures" in bundle, "the empty capture-link list explains nothing"
        assert bundle["link_no_captures"].strip()
    assert "again" in en["error_file_read"].casefold(), en["error_file_read"]
    assert "otra vez" in es["error_file_read"].casefold(), es["error_file_read"]
    # Nothing was written, and saying so is the difference between a retry and a fear.
    assert "nothing was saved" in en["error_file_read"].casefold()
    assert "no se guardó nada" in es["error_file_read"].casefold()


def test_empty_states_point_at_controls_the_app_actually_shows() -> None:
    """ "Add a capture" named a button the interface does not have.

    The entry dock, the capture dialog heading and the markup's own fallback text
    all call it a *photo*; only ``readiness_empty`` still said *capture*, which is
    model vocabulary the plain-language pass deliberately kept in the CLI and the
    packet but not on a button. An empty state that names a control by a word that
    appears nowhere on screen sends the reader looking for something that is not
    there.
    """
    en, es = _load(_EN), _load(_ES)
    assert en["capture_heading"].casefold() in en["readiness_empty"].casefold(), (
        f"readiness_empty must name the control the app shows "
        f"({en['capture_heading']!r}): {en['readiness_empty']!r}"
    )
    assert es["capture_heading"].casefold() in es["readiness_empty"].casefold(), (
        f"readiness_empty must name the control the app shows "
        f"({es['capture_heading']!r}): {es['readiness_empty']!r}"
    )


def test_status_transition_announcement_carries_its_limit() -> None:
    """The awaiting -> timestamped announcement (issue #243) ships in both locales.

    Good news in this app never travels alone: a token attached is not a token
    verified, and the sentence a screen-reader user hears has to say so, exactly
    as the visible ``status_timestamped_help`` does.
    """
    en, es = _load(_EN), _load(_ES)
    for bundle in (en, es):
        assert "msg_timestamp_attached" in bundle, "the status transition has nothing to say"
    assert "no longer waiting" in en["msg_timestamp_attached"].casefold()
    assert "authority" in en["msg_timestamp_attached"].casefold()
    assert "autoridad" in es["msg_timestamp_attached"].casefold()
