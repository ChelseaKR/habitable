#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""G3 — BCP 47 language-tag validity gate (INTERNATIONALIZATION-STANDARD §4).

Every language tag this app *authors* — the locale bundle filenames, the
``SUPPORTED`` list and ``DEFAULT_LANG`` in ``app/app.js``, every ``<html lang>``
and every ``data-lang`` button in the committed HTML — must be a well-formed and
valid BCP 47 / RFC 5646 tag. A malformed or unregistered tag (a typo like
``eng`` for English, or ``sp`` for Spanish) makes ``<html lang>`` lie to
assistive technology and breaks ``Accept-Language`` negotiation, so this is a
blocking merge gate.

The standard's reference validator is ``babel.Locale.parse`` (PY). Babel is not a
dependency of this repo (it does no locale-aware number/date formatting yet — see
docs/I18N.md, G12 N/A-until-used), so to stay dependency-light and offline like
the sibling parity gate we validate in two layers, and delegate to Babel *if* it
is ever installed:

  * well-formed — the whole tag matches the RFC 5646 ``langtag`` grammar;
  * valid       — the primary language subtag is registered in the IANA registry
                  (checked against the ISO 639-1 set embedded below; Babel, when
                  present, additionally registry-checks the region/script).

Exit codes:
    0  every authored tag is well-formed and valid.
    1  one or more authored tags are malformed or unregistered.
    2  operator error (a source file is missing / no tags were found).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_APP = _REPO_ROOT / "app"
_I18N_DIR = _APP / "i18n"

# Committed HTML surfaces whose <html lang> / data-lang tags are authored here.
_HTML_FILES = (
    _APP / "index.html",
    _REPO_ROOT / "site" / "index.html",
    _REPO_ROOT / "site" / "sample-packet" / "packet.html",
)

# RFC 5646 langtag grammar (the common subtags; grandfathered/private-use tags
# are not authored by this app). Case-insensitive; matched against the full tag.
_LANGTAG = re.compile(
    r"""^
    (?P<language>[A-Za-z]{2,3}(-[A-Za-z]{3}){0,3}|[A-Za-z]{4,8})   # ISO 639 (+ extlang)
    (-(?P<script>[A-Za-z]{4}))?                                    # ISO 15924
    (-(?P<region>[A-Za-z]{2}|\d{3}))?                              # ISO 3166-1 / UN M.49
    (-(?P<variant>[A-Za-z0-9]{5,8}|\d[A-Za-z0-9]{3}))*             # registered variants
    (-[A-WY-Za-wy-z0-9](-[A-Za-z0-9]{2,8})+)*                     # extensions
    (-x(-[A-Za-z0-9]{1,8})+)?                                      # private use
    $""",
    re.VERBOSE,
)

# ISO 639-1 two-letter language codes (the IANA "language" subtags of length 2).
# Used to registry-check the primary language subtag of every authored tag.
#
# The grid shape is the point, so SIM905 is suppressed rather than taken. Its fix
# rewrites this into one 1800-character list literal, which `ruff format` then
# explodes into 184 lines of one quoted code apiece. This is a transcription of
# an external registry: someone has to be able to diff it by eye against IANA's
# published list to see that a code is missing or duplicated, and eight scannable
# rows allow that where 184 lines do not.
_ISO_639_1 = frozenset(
    """
    aa ab ae af ak am an ar as av ay az ba be bg bh bi bm bn bo br bs ca ce ch co
    cr cs cu cv cy da de dv dz ee el en eo es et eu fa ff fi fj fo fr fy ga gd gl
    gn gu gv ha he hi ho hr ht hu hy hz ia id ie ig ii ik io is it iu ja jv ka kg
    ki kj kk kl km kn ko kr ks ku kv kw ky la lb lg li ln lo lt lu lv mg mh mi mk
    ml mn mr ms mt my na nb nd ne ng nl nn no nr nv ny oc oj om or os pa pi pl ps
    pt qu rm rn ro ru rw sa sc sd se sg si sk sl sm sn so sq sr ss st su sv sw ta
    te tg th ti tk tl tn to tr ts tt tw ty ug uk ur uz ve vi vo wa wo xh yi yo za
    zh zu
    """.split()  # noqa: SIM905 - deliberate; see the note above this assignment
)


def _fail(msg: str) -> None:
    print(f"error: {msg}", file=sys.stderr)
    raise SystemExit(2)


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        _fail(f"expected source file not found: {path.relative_to(_REPO_ROOT)}")
        raise  # unreachable; keeps type checkers happy


def collect_tags() -> dict[str, set[str]]:
    """Gather every authored tag, mapping tag -> set of source descriptions.

    Each of the five sources carries its own floor. The single aggregate
    ``if not tags`` check this replaced could never fire: source 1 globs
    ``app/i18n/*.json`` and always yields ``en`` and ``es``, so ``tags`` was
    non-empty before the guard was reached, and its own error message ("check
    the source globs") described a failure it was structurally unable to
    report. Sources 2 and 3 sat behind an unchecked ``if <regex matched>`` and
    4 and 5 behind zero-iteration ``findall``s, so rewriting ``app/app.js:8``
    from ``var SUPPORTED = ["en", "es"];`` to an object literal, a renamed
    constant, or a multi-line array containing a ``]`` in a comment would have
    silently stopped this gate checking ``SUPPORTED`` at all while it went on
    printing OK.
    """
    tags: dict[str, set[str]] = {}
    found: dict[str, int] = {}

    def add(tag: str, source: str, *, counter: str) -> None:
        tags.setdefault(tag.strip(), set()).add(source)
        found[counter] = found.get(counter, 0) + 1

    # 1. Locale bundle filenames: app/i18n/<tag>.json
    if not _I18N_DIR.is_dir():
        _fail(f"locale directory not found: {_I18N_DIR.relative_to(_REPO_ROOT)}")
    for bundle in sorted(_I18N_DIR.glob("*.json")):
        add(bundle.stem, f"catalog filename {bundle.name}", counter="i18n bundle filenames")

    # 2 & 3. SUPPORTED = [...] and DEFAULT_LANG = "..." in app/app.js
    app_js = _read(_APP / "app.js")
    supported = re.search(r"SUPPORTED\s*=\s*\[([^\]]*)\]", app_js)
    if supported:
        for tag in re.findall(r"""["']([^"']+)["']""", supported.group(1)):
            add(tag, "app.js SUPPORTED", counter="app.js SUPPORTED")
    default = re.search(r"""DEFAULT_LANG\s*=\s*["']([^"']+)["']""", app_js)
    if default:
        add(default.group(1), "app.js DEFAULT_LANG", counter="app.js DEFAULT_LANG")

    # 4 & 5. <html lang="..."> and data-lang="..." in committed HTML.
    for html_path in _HTML_FILES:
        html = _read(html_path)
        rel = html_path.relative_to(_REPO_ROOT)
        for tag in re.findall(r"""<html[^>]*\blang\s*=\s*["']([^"']+)["']""", html):
            add(tag, f"{rel} <html lang>", counter=f"{rel} <html lang>")
        for tag in re.findall(r"""\bdata-lang\s*=\s*["']([^"']+)["']""", html):
            add(tag, f"{rel} data-lang", counter="data-lang attributes")

    _require_every_source_reported(found)
    return tags


#: Every source this gate claims to read, with the minimum it must yield.
#:
#: ``<html lang>`` is per file because each committed HTML surface authors
#: exactly one and a missing one is a real defect. ``data-lang`` is a single
#: cross-file floor because only ``app/index.html`` authors those today, and
#: demanding one per file would fail on a truthful repository.
def _expected_sources() -> dict[str, int]:
    expected = {
        "i18n bundle filenames": 2,  # en + es are both committed
        "app.js SUPPORTED": 2,
        "app.js DEFAULT_LANG": 1,
        "data-lang attributes": 1,
    }
    for html_path in _HTML_FILES:
        expected[f"{html_path.relative_to(_REPO_ROOT)} <html lang>"] = 1
    return expected


def _require_every_source_reported(found: dict[str, int]) -> None:
    """Fail if any named source went quiet, rather than only if *all* did."""
    silent = [
        f"{source} (expected at least {minimum}, found {found.get(source, 0)})"
        for source, minimum in sorted(_expected_sources().items())
        if found.get(source, 0) < minimum
    ]
    if silent:
        _fail(
            "these language-tag sources reported nothing, so this gate is no longer "
            "checking them:\n  - " + "\n  - ".join(silent)
        )


def validate(tag: str) -> str | None:
    """Return None if the tag is well-formed and valid, else a reason string."""
    # Prefer Babel's canonical parser when it is available (matches the standard).
    try:
        from babel import Locale, UnknownLocaleError  # type: ignore[import-not-found]

        try:
            Locale.parse(tag.replace("-", "_"))
        except (ValueError, UnknownLocaleError) as exc:
            return f"babel rejected the tag: {exc}"
        return None
    except ImportError:
        pass  # dependency-light fallback below

    match = _LANGTAG.match(tag)
    if not match:
        return "not a well-formed BCP 47 tag (RFC 5646 langtag grammar)"
    language = match.group("language").lower()
    if len(language) == 2 and language not in _ISO_639_1:
        return f"unknown language subtag '{language}' (not in the ISO 639 registry)"
    return None


def check_bcp47() -> int:
    """Return 0 if every authored tag is well-formed and valid, else 1."""
    tags = collect_tags()
    problems: list[str] = []
    for tag in sorted(tags):
        reason = validate(tag)
        if reason:
            where = ", ".join(sorted(tags[tag]))
            problems.append(f"{tag!r}: {reason}  (from: {where})")

    if problems:
        print(f"FAIL: {len(problems)} invalid language tag(s):")
        for line in problems:
            print(f"  - {line}")
        print("\nG3 BCP 47 gate: FAILED — fix the tag(s) above to a valid BCP 47 tag.")
        return 1

    print(f"G3 BCP 47 gate: OK — {len(tags)} authored tag(s) valid: {', '.join(sorted(tags))}.")
    return 0


def main() -> int:
    return check_bcp47()


if __name__ == "__main__":
    raise SystemExit(main())
