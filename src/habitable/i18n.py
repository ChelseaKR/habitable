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
    "language_name",
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
        "status_issue_strength": (
            "record strength: {level} — {strong} strong, {developing} developing, "
            "{minimal} minimal; "
            "{timeline, plural, one {# linked timeline entry} "
            "other {# linked timeline entries}}"
        ),
        "strength_level_minimal": "minimal",
        "strength_level_developing": "developing",
        "strength_level_strong": "strong",
        "status_strength_caveat": (
            "record strength reflects token presence, custody, and corroborating timeline — "
            "not token validity, authority trust, a legal judgment, or admissibility"
        ),
        "custody_intact": "intact",
        "custody_broken": "BROKEN",
        "capture_timestamped": "timestamp token attached ({when})",
        "capture_awaiting": "no timestamp token yet",
        "capture_trust_unassessed": (
            "timestamp token attached; authority trust is assessed only by `habitable verify` "
            "with an independently trusted certificate"
        ),
        "capture_dev_untrusted": (
            "development timestamp only; it is untrusted and never evidence-ready"
        ),
        "capture_also_timestamped": (
            "also timestamped by {count, plural, one {# more authority} "
            "other {# more authorities}}: {names}"
        ),
        "resolve_done": (
            "attached timestamp tokens to {count, plural, =0 {no queued items} "
            "one {# previously-queued item} other {# previously-queued items}}"
        ),
        "retimestamp_done": (
            "archive-timestamped {count, plural, =0 {no items} one {# item} other {# items}}"
        ),
        "export_timestamped_line": (
            "{timestamped} of {total, plural, one {# media item} other {# media items}}: "
            "content hash present, timestamp token attached; authority trust not assessed"
        ),
        "export_awaiting_hint": (
            "{awaiting, plural, "
            "one {# item is still awaiting a timestamp token, so this packet is not "
            "evidence-ready. Its content hash already identifies the sealed bytes. "
            "Run `habitable resolve` when online, then export again.} "
            "other {# items are still awaiting timestamp tokens, so this packet is not "
            "evidence-ready. Their content hashes already identify the sealed bytes. "
            "Run `habitable resolve` when online, then export again.}}"
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
            "with timestamp tokens attached, custody {custody} — {flag}"
        ),
        "campaign_flag_ready": "export-ready",
        "campaign_flag_broken": "custody broken",
        "campaign_flag_awaiting": "needs timestamps",
        "campaign_flag_empty": "no captures yet",
        "campaign_export_done": (
            "{units, plural, one {# unit} other {# units}} packaged into one "
            "building packet at {out}"
        ),
        "joint_index_presentation_only": (
            "This index is presentation only. It merges no chain of custody: every "
            "packet listed here is still its own record and must be verified on its own."
        ),
        "joint_index_unsigned": (
            "The packets are signed; this index is not. Anyone who can edit this file can "
            "add or remove a row. What it does show is that no listed packet was swapped: "
            "`habitable joint check` recomputes every digest below from the packets."
        ),
        "joint_index_no_common_cause": (
            "Listing several households together does not make them one case, and says "
            "nothing about whether their conditions share a cause."
        ),
        "joint_html_title": "Joint submission index",
        "joint_html_generated": "Index built {at}.",
        "joint_html_counts": (
            "{members, plural, one {# packet} other {# packets}} listed, {ready} "
            "evidence-ready at the time this index was built."
        ),
        "joint_html_caption": "Packets in this submission, each verifiable on its own",
        "joint_col_label": "Unit",
        "joint_col_packet": "Packet",
        "joint_col_items": "Items verified",
        "joint_col_state": "State when indexed",
        "joint_col_digest": "bundle.json SHA-256",
        "joint_html_limits": "What this index does not do",
        "joint_state_ready": "evidence-ready",
        "joint_state_broken": "integrity check failed",
        "joint_state_unanchored": "intact, no trusted timestamp anchor",
        "joint_build_done": (
            "{members, plural, one {# packet} other {# packets}} indexed at {out} "
            "({ready} evidence-ready). No chain of custody was merged."
        ),
        "joint_check_ok": (
            "joint index checks out: {members, plural, one {# packet} other {# packets}}, "
            "every digest unchanged and every packet evidence-ready"
        ),
        "joint_check_failed": (
            "joint index did NOT check out: {matched}/{members} digests unchanged, "
            "{ready}/{members} evidence-ready, "
            "{unlisted, plural, one {# packet} other {# packets}} present but unlisted"
        ),
        "joint_member_line": "{label} ({path}): {state}",
        "joint_state_changed": "CHANGED SINCE INDEXING",
        "joint_state_missing": "MISSING",
        "joint_unlisted_line": (
            "present in the submission folder but absent from the index: {path}"
        ),
        "sync_data_cost": "data: sent {sent}, received {received}",
        "network_data_cost": "network used: sent {sent}, received {received}",
        "status_storage": (
            "storage: {total} total — {sealed} sealed originals + {shared} shared copies "
            "(originals are kept twice by design)"
        ),
        # Issue #161: the repair-request letter is the one surface that is not
        # bilingual. It says so instead of relabelling English prose.
        "letter_language_unavailable": (
            "note: this letter is written in English. habitable does not yet ship a "
            "reviewed {requested} translation of the repair-request letter, and will not "
            "machine-translate a document that carries legal framing and your name. The "
            'file declares lang="en" so it is not announced as {requested}.'
        ),
        # ADR 0013: the [letter] header/footer is where a union puts a locally
        # verified statutory citation, and a citation is the one string here that
        # can stop being true on a date nobody watches.
        "letter_local_law_expired": (
            "note: the wording your union verified for this jurisdiction expired on "
            "{expires_at} and was left out of this letter. Re-check it against current "
            "local law, then update local_law_reviewed_at and local_law_expires_at in "
            "config.toml. The letter went out with the built-in framing, which claims less."
        ),
        "letter_local_law_undated": (
            "note: the wording your union verified for this jurisdiction carries no review "
            "date, so nothing can tell you when it stopped being true. Set "
            "local_law_reviewed_at and local_law_expires_at in config.toml."
        ),
        "letter_framing_expired": (
            "note: the {requested} framing's review has expired, so this letter uses the "
            "{used} framing instead."
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
        "status_issue_strength": (
            "solidez del registro: {level} — {strong} sólidas, {developing} en desarrollo, "
            "{minimal} mínimas; "
            "{timeline, plural, one {# entrada de cronología vinculada} "
            "other {# entradas de cronología vinculadas}}"
        ),
        "strength_level_minimal": "mínima",
        "strength_level_developing": "en desarrollo",
        "strength_level_strong": "sólida",
        "status_strength_caveat": (
            "la solidez del registro refleja la presencia de tokens, la custodia y la "
            "cronología corroborante; no afirma la validez del token, la confianza en la "
            "autoridad, un juicio legal ni la admisibilidad"
        ),
        "custody_intact": "intacta",
        "custody_broken": "ROTA",
        "capture_timestamped": "token de sello de tiempo adjunto ({when})",
        "capture_awaiting": "aún sin token de sello de tiempo",
        "capture_trust_unassessed": (
            "token de sello adjunto; la confianza en la autoridad solo se evalúa con "
            "`habitable verify` y un certificado de confianza independiente"
        ),
        "capture_dev_untrusted": (
            "solo sello de desarrollo; no es confiable ni puede estar listo como prueba"
        ),
        "capture_also_timestamped": (
            "también sellado por {count, plural, one {# autoridad más} "
            "other {# autoridades más}}: {names}"
        ),
        "resolve_done": (
            "{count, plural, =0 {no había elementos en cola} "
            "one {se adjuntó un token a # elemento que estaba en cola} "
            "other {se adjuntaron tokens a # elementos que estaban en cola}}"
        ),
        "retimestamp_done": (
            "{count, plural, =0 {ningún elemento re-sellado} "
            "one {# elemento re-sellado para archivo} "
            "other {# elementos re-sellados para archivo}}"
        ),
        "export_timestamped_line": (
            "{timestamped} de {total, plural, one {# elemento multimedia} "
            "other {# elementos multimedia}}: "
            "hash del contenido presente, token de sello adjunto; confianza no evaluada"
        ),
        "export_awaiting_hint": (
            "{awaiting, plural, "
            "one {# elemento sigue pendiente de un token de sello de tiempo, así que "
            "este paquete no está listo como prueba. Su hash ya identifica los bytes "
            "sellados. Ejecute `habitable resolve` cuando tenga "
            "conexión y vuelva a exportar.} "
            "other {# elementos siguen pendientes de tokens de sello de tiempo, así "
            "que este paquete no está listo como prueba. Sus hashes ya identifican los "
            "bytes sellados. Ejecute `habitable resolve` "
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
            "con tokens de sello adjuntos, custodia {custody} — {flag}"
        ),
        "campaign_flag_ready": "lista para exportar",
        "campaign_flag_broken": "cadena de custodia rota",
        "campaign_flag_awaiting": "necesita sellos de tiempo",
        "campaign_flag_empty": "sin capturas todavía",
        "campaign_export_done": (
            "{units, plural, one {# vivienda empaquetada} "
            "other {# viviendas empaquetadas}} en un solo paquete del edificio en {out}"
        ),
        "joint_index_presentation_only": (
            "Este índice es solo de presentación. No fusiona ninguna cadena de custodia: "
            "cada paquete de la lista sigue siendo su propio registro y debe verificarse "
            "por separado."
        ),
        "joint_index_unsigned": (
            "Los paquetes están firmados; este índice no lo está. Cualquiera que pueda "
            "editar este archivo puede añadir o quitar una fila. Lo que sí demuestra es "
            "que ningún paquete de la lista fue sustituido: `habitable joint check` "
            "recalcula cada resumen a partir de los paquetes."
        ),
        "joint_index_no_common_cause": (
            "Reunir varias viviendas en una lista no las convierte en un solo caso, y no "
            "dice nada sobre si sus condiciones tienen una causa común."
        ),
        "joint_html_title": "Índice de presentación conjunta",
        "joint_html_generated": "Índice creado el {at}.",
        "joint_html_counts": (
            "{members, plural, one {# paquete} other {# paquetes}} en la lista, {ready} "
            "listos como prueba en el momento de crear el índice."
        ),
        "joint_html_caption": ("Paquetes de esta presentación, cada uno verificable por separado"),
        "joint_col_label": "Vivienda",
        "joint_col_packet": "Paquete",
        "joint_col_items": "Elementos verificados",
        "joint_col_state": "Estado al indexar",
        "joint_col_digest": "SHA-256 de bundle.json",
        "joint_html_limits": "Lo que este índice no hace",
        "joint_state_ready": "listo como prueba",
        "joint_state_broken": "falló la comprobación de integridad",
        "joint_state_unanchored": "íntegro, sin sello de tiempo de autoridad de confianza",
        "joint_build_done": (
            "{members, plural, one {# paquete indexado} other {# paquetes indexados}} en "
            "{out} ({ready} listos como prueba). No se fusionó ninguna cadena de custodia."
        ),
        "joint_check_ok": (
            "el índice conjunto se comprueba: "
            "{members, plural, one {# paquete} other {# paquetes}}, "
            "todos los resúmenes sin cambios y todos los paquetes listos como prueba"
        ),
        "joint_check_failed": (
            "el índice conjunto NO se comprueba: {matched}/{members} resúmenes sin "
            "cambios, {ready}/{members} listos como prueba, "
            "{unlisted, plural, one {# paquete presente} other {# paquetes presentes}} "
            "fuera de la lista"
        ),
        "joint_member_line": "{label} ({path}): {state}",
        "joint_state_changed": "CAMBIÓ DESDE LA INDEXACIÓN",
        "joint_state_missing": "FALTA",
        "joint_unlisted_line": (
            "presente en la carpeta de presentación pero ausente del índice: {path}"
        ),
        "sync_data_cost": "datos: enviados {sent}, recibidos {received}",
        "network_data_cost": "red utilizada: enviados {sent}, recibidos {received}",
        "status_storage": (
            "almacenamiento: {total} en total — {sealed} originales sellados + "
            "{shared} copias compartidas (los originales se guardan por duplicado por diseño)"
        ),
        "letter_language_unavailable": (
            "aviso: esta carta está escrita en inglés. habitable todavía no incluye una "
            "traducción revisada al {requested} de la carta de solicitud de reparaciones, "
            "y no traducirá automáticamente un documento que lleva lenguaje legal y su "
            'nombre. El archivo declara lang="en", así que no se anuncia como {requested}.'
        ),
        "letter_local_law_expired": (
            "aviso: el texto que su sindicato verificó para esta jurisdicción caducó el "
            "{expires_at} y quedó fuera de esta carta. Vuelva a comprobarlo con la ley local "
            "vigente y luego actualice local_law_reviewed_at y local_law_expires_at en "
            "config.toml. La carta salió con el texto integrado, que afirma menos."
        ),
        "letter_local_law_undated": (
            "aviso: el texto que su sindicato verificó para esta jurisdicción no tiene fecha "
            "de revisión, así que nada puede avisarle de cuándo dejó de ser cierto. Ponga "
            "local_law_reviewed_at y local_law_expires_at en config.toml."
        ),
        "letter_framing_expired": (
            "aviso: la revisión del texto {requested} caducó, así que esta carta usa el "
            "texto {used} en su lugar."
        ),
    },
}


# Endonym-free display names for the shipped locales, in each shipped locale.
# Small enough to be a table; a third locale adds a row and a column, and
# `test_i18n_format.py` sweeps SUPPORTED_LOCALES so an omission fails the build.
_LANGUAGE_NAMES: dict[str, dict[str, str]] = {
    "en": {"en": "English", "es": "Spanish"},
    "es": {"en": "inglés", "es": "español"},
}


def language_name(tag: str, locale: str) -> str:
    """The name of language *tag*, written in *locale* (falls back to the tag)."""
    loc = normalize_locale(locale)
    names = _LANGUAGE_NAMES.get(loc, _LANGUAGE_NAMES[DEFAULT_LOCALE])
    return names.get(normalize_locale(tag), tag)


def cli_text(key: str, locale: str, **values: object) -> str:
    """The rendered CLI message *key* for *locale* (falling back to English)."""
    loc = normalize_locale(locale)
    catalog = _CLI_MESSAGES.get(loc, _CLI_MESSAGES[DEFAULT_LOCALE])
    message = catalog.get(key) or _CLI_MESSAGES[DEFAULT_LOCALE][key]
    return format_message(message, loc, values)
