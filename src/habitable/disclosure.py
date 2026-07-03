# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Plain-language statement of what an evidence packet proves — and what it does not.

A packet is handed to people who are not cryptographers — a housing-court clerk, an
inspector, an opposing attorney. The recipient needs the *upper-bound* semantics of a
trusted timestamp, and the difference between "this record was not altered" and "this
condition was as described", stated plainly and up front. This module is the single,
localized source of that framing so the HTML and PDF renderers cannot drift apart.

Realizes the recipient-facing disclosure (items R-26 / R-29 / R-40) from
``docs/research/synthetic-personas-feedback.md``; the verbatim legal reasoning is in
``docs/legal/foundation-guidance.md``.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["ProofStatement", "ScopeStatement", "proof_statement", "scope_statement"]

_DEFAULT_LANG = "en"


@dataclass(frozen=True, slots=True)
class ProofStatement:
    """The localized 'what this proves / what it does not' text for a packet."""

    heading: str
    proves_heading: str
    proves: tuple[str, ...]
    not_heading: str
    not_proves: tuple[str, ...]
    verify_line: str
    privacy_heading: str
    privacy_stripped: str
    privacy_originals_warning: str
    awaiting_timestamp_note: str


_STATEMENTS: dict[str, ProofStatement] = {
    "en": ProofStatement(
        heading="What this packet proves — and what it does not",
        proves_heading="What this packet proves",
        proves=(
            "Each photo's content has not been altered since it was captured "
            "(a SHA-256 content hash that can be re-checked against the file).",
            "Each item existed no later than the date on its trusted timestamp "
            "(an RFC 3161 token over the hash) — an upper bound on when it was created.",
            "The record of events was not reordered or edited after the fact "
            "(an append-only, hash-linked chain of custody).",
        ),
        not_heading="What this packet does not prove",
        not_proves=(
            "Who took a photo, or that it depicts a particular home or unit.",
            "That the underlying condition was as described — that rests on the "
            "tenant's own account, not on the cryptography.",
            "That a timestamp is the exact moment of capture — it is only an upper "
            "bound (the content existed by then).",
            "Admissibility or any legal outcome. This is documentation, not legal advice.",
        ),
        verify_line=(
            "How to verify: run `habitable verify` against the accompanying bundle.json, "
            "or cross-check the hashes and RFC 3161 tokens with standard tools. The "
            "accessible reading of this packet is packet.html."
        ),
        privacy_heading="What this packet discloses",
        privacy_stripped=(
            "The shared photos in this packet have had location (GPS) removed, so they "
            "do not reveal where the tenant lives."
        ),
        privacy_originals_warning=(
            "This packet also embeds the sealed original files, which retain their full "
            "metadata (including any location). Handle and file accordingly."
        ),
        awaiting_timestamp_note=(
            "{awaiting} of {total} media item(s) are awaiting a trusted timestamp. Their "
            "content hashes still anchor them at capture (the record has not been altered), "
            "but no independent authority has yet fixed an upper-bound date. Re-export after "
            "syncing to attach the timestamps."
        ),
    ),
    "es": ProofStatement(
        heading="Lo que este expediente demuestra y lo que no",
        proves_heading="Lo que este expediente demuestra",
        proves=(
            "Que el contenido de cada foto no se ha modificado desde que se capturó "
            "(un hash SHA-256 que se puede volver a comprobar contra el archivo).",
            "Que cada elemento existía a más tardar en la fecha de su sello de tiempo "
            "confiable (un token RFC 3161 sobre el hash): un límite máximo de cuándo se creó.",
            "Que el registro de los hechos no se reordenó ni se editó después "
            "(una cadena de custodia enlazada por hash y de solo anexar).",
        ),
        not_heading="Lo que este expediente no demuestra",
        not_proves=(
            "Quién tomó una foto, ni que muestre una vivienda o unidad en particular.",
            "Que la condición fuera tal como se describe: eso depende del testimonio "
            "de la persona inquilina, no de la criptografía.",
            "Que el sello de tiempo sea el momento exacto de la captura: es solo un "
            "límite máximo (el contenido ya existía para entonces).",
            "Admisibilidad ni ningún resultado legal. Esto es documentación, no asesoría legal.",
        ),
        verify_line=(
            "Cómo verificar: ejecute `habitable verify` con el archivo bundle.json, o "
            "compruebe los hashes y los tokens RFC 3161 con herramientas estándar. La "
            "versión accesible de este expediente es packet.html."
        ),
        privacy_heading="Lo que este expediente revela",
        privacy_stripped=(
            "A las fotos compartidas de este expediente se les quitó la ubicación (GPS), "
            "por lo que no revelan dónde vive la persona inquilina."
        ),
        privacy_originals_warning=(
            "Este expediente también incluye los archivos originales sellados, que "
            "conservan todos sus metadatos (incluida cualquier ubicación). Manéjelo y "
            "preséntelo en consecuencia."
        ),
        awaiting_timestamp_note=(
            "{awaiting} de {total} elemento(s) multimedia están a la espera de un sello de "
            "tiempo confiable. Sus hashes de contenido aún los anclan en el momento de la "
            "captura (el registro no se ha modificado), pero ninguna autoridad independiente "
            "ha fijado todavía una fecha como límite máximo. Vuelva a exportar tras "
            "sincronizar para adjuntar los sellos de tiempo."
        ),
    ),
}


def proof_statement(lang: str) -> ProofStatement:
    """Return the proof statement for ``lang``, falling back to English."""
    return _STATEMENTS.get(lang, _STATEMENTS[_DEFAULT_LANG])


@dataclass(frozen=True, slots=True)
class ScopeStatement:
    """The localized 'what this export covers, and what it deliberately omits' text.

    A produced packet is scoped — to one issue or one unit — so it can be handed over
    without dumping a union's whole vault. This states that scope, and the categories
    of vault content it excludes, so an over-broad discovery demand meets an on-the-record
    minimal-disclosure boundary (item R-35). See ``docs/legal/minimal-disclosure.md``.
    """

    heading: str
    statement: str
    exclusions: tuple[str, ...]

    def lines(self) -> tuple[str, ...]:
        """The scope statement followed by its exclusions, for list rendering."""
        return (self.statement, *self.exclusions)


def scope_statement(
    lang: str, *, scope_type: str, issue_id: str = "", since: str = ""
) -> ScopeStatement:
    """Return the localized scope statement for a packet, falling back to English.

    ``scope_type`` is ``"issue"`` (a single issue, named by ``issue_id``) or ``"unit"``
    (the whole unit). ``since`` — if set — is the lower bound on capture time; items
    captured before it are excluded and that exclusion is stated explicitly.
    """
    resolved = lang if lang in _SCOPE else _DEFAULT_LANG
    strings = _SCOPE[resolved]
    if scope_type == "issue" and issue_id:
        statement = strings["issue"].format(issue_id=issue_id)
    else:
        statement = strings["unit"]
    exclusions: list[str] = []
    if since:
        exclusions.append(strings["since"].format(since=since))
    exclusions.append(strings["outside"])
    return ScopeStatement(
        heading=strings["heading"], statement=statement, exclusions=tuple(exclusions)
    )


_SCOPE: dict[str, dict[str, str]] = {
    "en": {
        "heading": "Scope of this export",
        "issue": (
            "Scope: issue {issue_id} only — captures, timeline entries, and custody "
            "records from other issues in this vault are not included."
        ),
        "unit": "Scope: the whole unit — every issue recorded in this vault is included.",
        "since": "Items captured before {since} are not included.",
        "outside": (
            "Vault contents outside this scope (other issues, drafts, and sync or custody "
            "records not pertaining to the included items) are not exported."
        ),
    },
    "es": {
        "heading": "Alcance de esta exportación",
        "issue": (
            "Alcance: solo el problema {issue_id} — las capturas, las entradas de la "
            "cronología y los registros de custodia de otros problemas de esta bóveda no "
            "se incluyen."
        ),
        "unit": (
            "Alcance: la unidad completa — se incluye cada problema registrado en esta bóveda."
        ),
        "since": "Los elementos capturados antes de {since} no se incluyen.",
        "outside": (
            "El contenido de la bóveda fuera de este alcance (otros problemas, borradores y "
            "registros de sincronización o custodia que no correspondan a los elementos "
            "incluidos) no se exporta."
        ),
    },
}
