# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Pluralization and locale-aware formatting for the shipped locales (FIX-12).

Bilingual reach is a project invariant, and "correct but English-shaped"
Spanish undercuts it: hardcoded ``(s)`` suffixes and untranslated count
grammar read as an afterthought to the Spanish-speaking tenant the tool
exists for. This module gives the CLI (and any Python-side surface) the same
mechanism the web app gets from the browser's ``Intl`` APIs:

* **CLDR cardinal plural rules** for ``en`` and ``es`` (``plural_category``);
* a tiny **ICU-MessageFormat subset** — ``{name}`` placeholders and
  ``{name, plural, =N {...} one {...} many {...} other {...}}`` with ``#``
  standing for the formatted count (``format_message``);
* **locale date/number formatting** (``format_number``, ``format_date``,
  ``format_datetime``) with hand-rolled per-locale patterns;
* the **CLI message catalog** (``cli_text``) for every count-bearing line.

Deliberately standard-library only: habitable's engine must run on a low-end
device with no network and no extra wheels, so a minimal hand-rolled
formatter is preferred over pulling in Babel/PyICU (see docs/I18N.md, G12).
The web app implements the same ICU subset in ``app/app.js`` on top of the
browser-native ``Intl.PluralRules`` / ``Intl.NumberFormat`` /
``Intl.DateTimeFormat``; ``scripts/check_i18n_parity.py`` keeps the two
sides' plural categories and placeholders in lockstep.

Adding a locale: add its tag to ``SUPPORTED_LOCALES``, its plural rule to
``_plural_category_for``, its separators/patterns to the formatting tables,
and its catalog to ``_CLI_MESSAGES`` — the tests in
``tests/test_i18n_format.py`` sweep every supported locale.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from decimal import Decimal

__all__ = [
    "DEFAULT_LOCALE",
    "SUPPORTED_LOCALES",
    "cli_text",
    "format_date",
    "format_datetime",
    "format_message",
    "format_number",
    "normalize_locale",
    "plural_category",
    "resolve_locale",
]

SUPPORTED_LOCALES: tuple[str, ...] = ("en", "es")
DEFAULT_LOCALE = "en"

Number = int | float | Decimal


# --- locale resolution ----------------------------------------------------------


def normalize_locale(tag: str | None) -> str:
    """The supported primary language subtag for *tag*, else the default.

    ``"es-MX"`` → ``"es"``; anything unsupported falls back to English rather
    than failing — a wrong-language message beats no message.
    """
    if not tag:
        return DEFAULT_LOCALE
    primary = tag.replace("_", "-").split("-", 1)[0].strip().lower()
    return primary if primary in SUPPORTED_LOCALES else DEFAULT_LOCALE


def resolve_locale(vault_language: str | None = None) -> str:
    """The locale for CLI output: ``HABITABLE_LANG`` beats the vault's language.

    The vault records the case's language (``habitable init --lang``); the
    environment variable lets a helper (an organizer at someone else's
    keyboard) override it for one session without touching the case.
    """
    env = os.environ.get("HABITABLE_LANG", "").strip()
    if env:
        return normalize_locale(env)
    return normalize_locale(vault_language)


# --- CLDR cardinal plural rules --------------------------------------------------


def _operands(value: Number | str) -> tuple[float, int, int]:
    """CLDR plural operands ``(n, i, v)`` for a numeric value.

    n: absolute numeric value; i: integer digits; v: count of visible
    fraction digits (so ``1`` is *one* in English but ``"1.0"`` is *other*,
    exactly as CLDR specifies).
    """
    if isinstance(value, str):
        text = value.strip().lstrip("+-")
        frac = text.split(".", 1)[1] if "." in text else ""
        number = float(text) if text else 0.0
        return abs(number), int(abs(number)), len(frac)
    if isinstance(value, int):
        return abs(float(value)), abs(value), 0
    dec = value if isinstance(value, Decimal) else Decimal(repr(value))
    exponent = dec.as_tuple().exponent
    v = -exponent if isinstance(exponent, int) and exponent < 0 else 0
    n = abs(float(dec))
    return n, int(n), v


def plural_category(value: Number | str, locale: str) -> str:
    """The CLDR cardinal category (``one``/``many``/``other``…) for *value*."""
    return _plural_category_for(normalize_locale(locale), *_operands(value))


def _plural_category_for(locale: str, n: float, i: int, v: int) -> str:
    if locale == "es":
        # CLDR es cardinal: one: n = 1; many: e = 0 and i != 0 and
        # i % 1000000 = 0 and v = 0; other otherwise.
        if n == 1:
            return "one"
        if i != 0 and i % 1_000_000 == 0 and v == 0:
            return "many"
        return "other"
    # CLDR en cardinal: one: i = 1 and v = 0; other otherwise.
    if i == 1 and v == 0 and n == 1:
        return "one"
    return "other"


# --- number / date / time formatting ---------------------------------------------

# (group separator, decimal separator) per locale, per CLDR.
_SEPARATORS: dict[str, tuple[str, str]] = {"en": (",", "."), "es": (".", ",")}

_MONTHS_ABBR: dict[str, tuple[str, ...]] = {
    "en": ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"),
    "es": ("ene", "feb", "mar", "abr", "may", "jun", "jul", "ago", "sept", "oct", "nov", "dic"),
}


def format_number(value: Number, locale: str) -> str:
    """*value* with the locale's grouping and decimal separators.

    ``1234.5`` → ``"1,234.5"`` (en) / ``"1.234,5"`` (es).
    """
    group, decimal = _SEPARATORS[normalize_locale(locale)]
    raw = f"{value:,}"
    trans: dict[int, int | None] = {ord(","): ord(group), ord("."): ord(decimal)}
    return raw.translate(trans)


def _coerce_datetime(value: datetime | str) -> datetime:
    if isinstance(value, datetime):
        return value
    # gen_time and friends are ISO 8601 UTC ("2026-01-02T03:04:05Z").
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def format_date(value: datetime | str, locale: str) -> str:
    """A medium locale date: ``Jan 2, 2026`` (en) / ``2 ene 2026`` (es)."""
    loc = normalize_locale(locale)
    dt = _coerce_datetime(value)
    month = _MONTHS_ABBR[loc][dt.month - 1]
    if loc == "es":
        return f"{dt.day} {month} {dt.year}"
    return f"{month} {dt.day}, {dt.year}"


def format_datetime(value: datetime | str, locale: str) -> str:
    """A medium locale date-time; UTC values keep an explicit UTC suffix.

    ``Jan 2, 2026, 3:04 AM UTC`` (en) / ``2 ene 2026, 3:04 UTC`` (es —
    24-hour, per CLDR).
    """
    loc = normalize_locale(locale)
    dt = _coerce_datetime(value)
    date = format_date(dt, loc)
    minute = f"{dt.minute:02d}"
    if loc == "es":
        time = f"{dt.hour}:{minute}"
    else:
        hour12 = dt.hour % 12 or 12
        half = "AM" if dt.hour < 12 else "PM"
        time = f"{hour12}:{minute} {half}"
    is_utc = dt.tzinfo is not None and dt.utcoffset() == UTC.utcoffset(dt)
    suffix = " UTC" if is_utc else ""
    return f"{date}, {time}{suffix}"


# --- ICU MessageFormat subset -----------------------------------------------------


class MessageFormatError(ValueError):
    """A message is not valid under the supported ICU subset."""


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
    raise MessageFormatError(f"unbalanced braces in message: {text!r}")


def _parse_plural_branches(source: str) -> dict[str, str]:
    """``one {...} other {...}`` → ``{"one": "...", "other": "..."}``."""
    branches: dict[str, str] = {}
    i = 0
    n = len(source)
    while i < n:
        if source[i].isspace():
            i += 1
            continue
        start = i
        while i < n and not source[i].isspace() and source[i] != "{":
            i += 1
        selector = source[start:i]
        while i < n and source[i].isspace():
            i += 1
        if not selector or i >= n or source[i] != "{":
            raise MessageFormatError(f"malformed plural branches: {source!r}")
        end = _match_brace(source, i)
        branches[selector] = source[i + 1 : end]
        i = end + 1
    if "other" not in branches:
        raise MessageFormatError(f"plural without an 'other' branch: {source!r}")
    return branches


def format_message(
    message: str,
    locale: str,
    values: dict[str, object] | None = None,
    *,
    _hash: str | None = None,
) -> str:
    """Render an ICU-subset *message* with *values* in *locale*.

    Supports ``{name}`` interpolation (numbers locale-formatted) and
    ``{name, plural, ...}`` with ``=N`` exact matches, CLDR categories, and
    ``#`` for the formatted count. Unknown placeholders are left verbatim so
    a catalog slip degrades visibly instead of crashing a capture.
    """
    vals = values or {}
    out: list[str] = []
    i = 0
    n = len(message)
    while i < n:
        ch = message[i]
        if ch == "{":
            end = _match_brace(message, i)
            out.append(_render_argument(message[i + 1 : end], locale, vals))
            i = end + 1
        elif ch == "}":
            raise MessageFormatError(f"unbalanced braces in message: {message!r}")
        elif ch == "#" and _hash is not None:
            out.append(_hash)
            i += 1
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _render_argument(body: str, locale: str, values: dict[str, object]) -> str:
    head, _, rest = body.partition(",")
    name = head.strip()
    if not rest:
        if name not in values:
            return "{" + body + "}"
        value = values[name]
        if isinstance(value, int | float | Decimal) and not isinstance(value, bool):
            return format_number(value, locale)
        return str(value)
    kind, _, branch_src = rest.partition(",")
    if kind.strip() != "plural":
        raise MessageFormatError(f"unsupported argument type {kind.strip()!r} in {body!r}")
    branches = _parse_plural_branches(branch_src)
    raw = values.get(name, 0)
    number: Number = raw if isinstance(raw, int | float | Decimal) else float(str(raw))
    exact = f"={number}"
    if exact in branches:
        selected = branches[exact]
    else:
        category = plural_category(number, locale)
        selected = branches.get(category, branches["other"])
    return format_message(selected, locale, values, _hash=format_number(number, locale))


# --- the CLI message catalog ------------------------------------------------------

# Every count-bearing CLI line lives here so no call site can hardcode "(s)".
# Keys must exist in every locale with matching placeholders and plural
# variables (enforced by tests/test_i18n_format.py).
_CLI_MESSAGES: dict[str, dict[str, str]] = {
    "en": {
        "status_summary": (
            "unit {unit} — {issues, plural, one {# issue} other {# issues}}, "
            "{captures, plural, one {# capture} other {# captures}}, "
            "{timeline, plural, one {# timeline entry} other {# timeline entries}}"
        ),
        "status_issue_line": (
            "{issue_id}: {title} [{status}] — "
            "{captures, plural, one {# capture} other {# captures}}"
        ),
        "status_timestamps": (
            "timestamps: {timestamped}/{total} present; "
            "{awaiting, plural, one {# awaiting} other {# awaiting}}"
        ),
        "status_custody": (
            "chain of custody: {verdict} ({links, plural, one {# entry} other {# entries}})"
        ),
        "custody_intact": "intact",
        "custody_broken": "BROKEN",
        "capture_timestamped": "timestamped ({when})",
        "capture_awaiting": "awaiting timestamp (queued)",
        "capture_also_timestamped": (
            "also timestamped by {count, plural, one {# more authority} "
            "other {# more authorities}}: {names}"
        ),
        "resolve_done": (
            "timestamped {count, plural, =0 {no queued items} "
            "one {# previously-queued item} other {# previously-queued items}}"
        ),
        "retimestamp_done": (
            "archive-timestamped {count, plural, =0 {no items} one {# item} other {# items}}"
        ),
        "export_timestamped_line": (
            "{timestamped} of {total, plural, one {# media item} other {# media items}}: "
            "content hash present, trusted timestamp attached"
        ),
        "export_awaiting_hint": (
            "{awaiting, plural, "
            "one {# item is still awaiting a trusted timestamp, so this packet does not "
            "verify as complete yet. Its content hash already anchors it at capture. "
            "Run `habitable resolve` when online, then export again.} "
            "other {# items are still awaiting a trusted timestamp, so this packet does "
            "not verify as complete yet. Their content hashes already anchor them at "
            "capture. Run `habitable resolve` when online, then export again.}}"
        ),
        "sync_done": (
            "synced — merged {messages, plural, one {# message} other {# messages}}, "
            "imported {captures, plural, one {# capture} other {# captures}}"
        ),
        "campaign_summary": (
            "building roll-up — {units, plural, one {# unit} other {# units}}, "
            "{ready, plural, one {# export-ready} other {# export-ready}}, "
            "{broken, plural, one {# broken custody chain} other {# broken custody chains}}, "
            "{awaiting, plural, one {# capture awaiting a timestamp} "
            "other {# captures awaiting a timestamp}}"
        ),
        "campaign_unit_line": (
            "{unit}: {issues, plural, one {# issue} other {# issues}}, "
            "{timestamped}/{captures, plural, one {# capture} other {# captures}} "
            "timestamped, custody {custody} — {flag}"
        ),
        "campaign_flag_ready": "export-ready",
        "campaign_flag_broken": "custody broken",
        "campaign_flag_awaiting": "needs timestamps",
        "campaign_flag_empty": "no captures yet",
        "campaign_export_done": (
            "{units, plural, one {# unit} other {# units}} packaged into one "
            "building packet at {out}"
        ),
    },
    "es": {
        "status_summary": (
            "vivienda {unit} — {issues, plural, one {# problema} other {# problemas}}, "
            "{captures, plural, one {# captura} other {# capturas}}, "
            "{timeline, plural, one {# entrada de cronología} other {# entradas de cronología}}"
        ),
        "status_issue_line": (
            "{issue_id}: {title} [{status}] — "
            "{captures, plural, one {# captura} other {# capturas}}"
        ),
        "status_timestamps": (
            "sellos de tiempo: {timestamped}/{total} presentes; "
            "{awaiting, plural, one {# pendiente} other {# pendientes}}"
        ),
        "status_custody": (
            "cadena de custodia: {verdict} ({links, plural, one {# entrada} other {# entradas}})"
        ),
        "custody_intact": "intacta",
        "custody_broken": "ROTA",
        "capture_timestamped": "con sello de tiempo ({when})",
        "capture_awaiting": "pendiente de sello de tiempo (en cola)",
        "capture_also_timestamped": (
            "también sellado por {count, plural, one {# autoridad más} "
            "other {# autoridades más}}: {names}"
        ),
        "resolve_done": (
            "{count, plural, =0 {no había elementos en cola} "
            "one {se selló # elemento que estaba en cola} "
            "other {se sellaron # elementos que estaban en cola}}"
        ),
        "retimestamp_done": (
            "{count, plural, =0 {ningún elemento re-sellado} "
            "one {# elemento re-sellado para archivo} "
            "other {# elementos re-sellados para archivo}}"
        ),
        "export_timestamped_line": (
            "{timestamped} de {total, plural, one {# elemento multimedia} "
            "other {# elementos multimedia}}: "
            "hash del contenido presente, sello de tiempo confiable adjunto"
        ),
        "export_awaiting_hint": (
            "{awaiting, plural, "
            "one {# elemento sigue pendiente de un sello de tiempo confiable, así que "
            "este paquete aún no se verifica como completo. Su hash de contenido ya lo "
            "ancla en el momento de la captura. Ejecute `habitable resolve` cuando tenga "
            "conexión y vuelva a exportar.} "
            "other {# elementos siguen pendientes de un sello de tiempo confiable, así "
            "que este paquete aún no se verifica como completo. Sus hashes de contenido "
            "ya los anclan en el momento de la captura. Ejecute `habitable resolve` "
            "cuando tenga conexión y vuelva a exportar.}}"
        ),
        "sync_done": (
            "sincronizado — {messages, plural, one {se fusionó # mensaje} "
            "other {se fusionaron # mensajes}}, "
            "{captures, plural, one {se importó # captura} other {se importaron # capturas}}"
        ),
        "campaign_summary": (
            "resumen del edificio — {units, plural, one {# vivienda} other {# viviendas}}, "
            "{ready, plural, one {# lista para exportar} other {# listas para exportar}}, "
            "{broken, plural, one {# cadena de custodia rota} "
            "other {# cadenas de custodia rotas}}, "
            "{awaiting, plural, one {# captura pendiente de sello de tiempo} "
            "other {# capturas pendientes de sello de tiempo}}"
        ),
        "campaign_unit_line": (
            "{unit}: {issues, plural, one {# problema} other {# problemas}}, "
            "{timestamped}/{captures, plural, one {# captura} other {# capturas}} "
            "con sello de tiempo, custodia {custody} — {flag}"
        ),
        "campaign_flag_ready": "lista para exportar",
        "campaign_flag_broken": "cadena de custodia rota",
        "campaign_flag_awaiting": "necesita sellos de tiempo",
        "campaign_flag_empty": "sin capturas todavía",
        "campaign_export_done": (
            "{units, plural, one {# vivienda empaquetada} "
            "other {# viviendas empaquetadas}} en un solo paquete del edificio en {out}"
        ),
    },
}


def cli_text(key: str, locale: str, **values: object) -> str:
    """The rendered CLI message *key* for *locale* (falling back to English)."""
    loc = normalize_locale(locale)
    catalog = _CLI_MESSAGES.get(loc, _CLI_MESSAGES[DEFAULT_LOCALE])
    message = catalog.get(key) or _CLI_MESSAGES[DEFAULT_LOCALE][key]
    return format_message(message, loc, values)
