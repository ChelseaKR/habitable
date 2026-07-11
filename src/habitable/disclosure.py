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

from collections.abc import Iterable
from dataclasses import dataclass

__all__ = [
    "PacketTrustText",
    "ProofStatement",
    "ScopeStatement",
    "packet_trust_text",
    "proof_statement",
    "scope_statement",
    "shared_metadata_may_be_retained",
]

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
    privacy_metadata_warning: str
    privacy_originals_warning: str
    awaiting_timestamp_note: str


@dataclass(frozen=True, slots=True)
class PacketTrustText:
    """Localized trust-status copy shared by the HTML and PDF renderers."""

    timestamp_summary: str
    view_notice: str
    attached_unassessed: str
    dev_untrusted: str
    awaiting: str
    appendix_intro: str
    appendix_caption: str
    timestamp_heading: str
    authority_heading: str
    accessible_note: str


_STATEMENTS: dict[str, ProofStatement] = {
    "en": ProofStatement(
        heading="What this packet proves — and what it does not",
        proves_heading="What successful verification can establish",
        proves=(
            "If integrity reports intact, the shared files match their recorded SHA-256 "
            "hashes and the signed, hash-linked custody record has not changed.",
            "If the timestamp authority reports trusted, the item existed no later than "
            "the verified RFC 3161 time — an upper bound on when it was created.",
            "Integrity and timestamp-authority trust are separate checks; both must pass "
            "before Habitable reports the item technically evidence-ready.",
        ),
        not_heading="What this packet does not prove",
        not_proves=(
            "Who took a photo, or that it depicts a particular home or unit.",
            "That the underlying condition was as described — that rests on the "
            "tenant's own account, not on the cryptography.",
            "That a timestamp is the exact moment of capture — it is only an upper "
            "bound (the content existed by then).",
            "That an attached timestamp token comes from a trusted authority. That requires "
            "verification against a certificate you independently trust; development "
            "timestamps are never evidence-ready.",
            "Admissibility or any legal outcome. This is documentation, not legal advice.",
        ),
        verify_line=(
            "How to verify: run `habitable verify PACKET --trusted-cert AUTHORITY.pem`, "
            "using a certificate you independently trust, or cross-check the hashes and "
            "RFC 3161 tokens with standard tools. The accessible reading is packet.html."
        ),
        privacy_heading="What this packet discloses",
        privacy_stripped=(
            "The packet reports embedded location metadata removed from its shared media "
            "copies. Item records state the metadata transformation applied to each copy."
        ),
        privacy_metadata_warning=(
            "The configured sharing policy allows some or all embedded metadata to remain "
            "in supported shared copies, possibly including location. Review each item's "
            "metadata handling before sharing or filing the packet."
        ),
        privacy_originals_warning=(
            "This packet also embeds the sealed original files, which retain their full "
            "metadata (including any location). Handle and file accordingly."
        ),
        awaiting_timestamp_note=(
            "{awaiting} of {total} media item(s) are awaiting a timestamp token. The items "
            "are sealed and hashed locally, but no independent time bound is attached yet. "
            "Re-export after syncing to attach the timestamps."
        ),
    ),
    "es": ProofStatement(
        heading="Lo que este expediente demuestra y lo que no",
        proves_heading="Lo que puede establecer una verificación satisfactoria",
        proves=(
            "Si la integridad figura como intacta, los archivos compartidos coinciden con "
            "sus hashes SHA-256 y el registro de custodia firmado y enlazado no cambió.",
            "Si la autoridad del sello figura como confiable, el elemento existía a más "
            "tardar en la hora RFC 3161 verificada: un límite máximo de cuándo se creó.",
            "La integridad y la confianza en la autoridad son comprobaciones separadas; "
            "ambas deben pasar para que Habitable indique que el elemento está listo.",
        ),
        not_heading="Lo que este expediente no demuestra",
        not_proves=(
            "Quién tomó una foto, ni que muestre una vivienda o unidad en particular.",
            "Que la condición fuera tal como se describe: eso depende del testimonio "
            "de la persona inquilina, no de la criptografía.",
            "Que el sello de tiempo sea el momento exacto de la captura: es solo un "
            "límite máximo (el contenido ya existía para entonces).",
            "Que un token adjunto provenga de una autoridad confiable. Eso requiere "
            "verificarlo con un certificado de confianza independiente; los sellos de "
            "desarrollo nunca están listos como prueba.",
            "Admisibilidad ni ningún resultado legal. Esto es documentación, no asesoría legal.",
        ),
        verify_line=(
            "Cómo verificar: ejecute `habitable verify PAQUETE --trusted-cert AUTORIDAD.pem` "
            "con un certificado de confianza independiente, o compruebe los hashes y tokens "
            "RFC 3161 con herramientas estándar. La versión accesible es packet.html."
        ),
        privacy_heading="Lo que este expediente revela",
        privacy_stripped=(
            "El expediente informa que se quitaron los metadatos de ubicación incrustados "
            "de sus copias multimedia compartidas. Los registros indican la transformación "
            "aplicada a cada copia."
        ),
        privacy_metadata_warning=(
            "La política configurada permite conservar algunos o todos los metadatos "
            "incrustados en las copias compartidas compatibles, posiblemente incluso la "
            "ubicación. Revise el tratamiento de cada elemento antes de compartir o presentar."
        ),
        privacy_originals_warning=(
            "Este expediente también incluye los archivos originales sellados, que "
            "conservan todos sus metadatos (incluida cualquier ubicación). Manéjelo y "
            "preséntelo en consecuencia."
        ),
        awaiting_timestamp_note=(
            "{awaiting} de {total} elemento(s) multimedia están a la espera de un token de "
            "sello de tiempo. Los elementos están sellados y tienen hash local, pero todavía "
            "no llevan un límite de tiempo independiente. Vuelva a exportar tras sincronizar "
            "para adjuntar los sellos de tiempo."
        ),
    ),
}


_TRUST_TEXT: dict[str, PacketTrustText] = {
    "en": PacketTrustText(
        timestamp_summary=(
            "Timestamp tokens attached: {attached}/{total}. Authority trust is not assessed "
            "by this human-readable view."
        ),
        view_notice=(
            "This human-readable view is not a verification result and is not legal advice. "
            "Use `habitable verify` with an independently trusted authority certificate. "
            "Only the verifier can report integrity, timestamp-authority trust, and technical "
            "evidence readiness; none guarantees admissibility."
        ),
        attached_unassessed="timestamp attached; authority trust not assessed",
        dev_untrusted="development timestamp; untrusted and not evidence-ready",
        awaiting="awaiting timestamp; not evidence-ready",
        appendix_intro=(
            "Each row reports token presence only. It does not claim the token is valid or its "
            "authority trusted; verify independently against bundle.json."
        ),
        appendix_caption="Per-item timestamp-token presence and named authority.",
        timestamp_heading="Timestamp status",
        authority_heading="Named authority",
        accessible_note="See packet.html for an accessible version.",
    ),
    "es": PacketTrustText(
        timestamp_summary=(
            "Tokens de sello de tiempo adjuntos: {attached}/{total}. Esta vista legible no "
            "evalúa la confianza en la autoridad."
        ),
        view_notice=(
            "Esta vista legible no es un resultado de verificación ni asesoría legal. Use "
            "`habitable verify` con un certificado de autoridad de confianza independiente. "
            "Solo el verificador informa la integridad, la confianza en la autoridad y la "
            "preparación técnica; ninguna garantiza la admisibilidad."
        ),
        attached_unassessed="sello adjunto; confianza en la autoridad no evaluada",
        dev_untrusted="sello de desarrollo; no confiable ni listo como prueba",
        awaiting="sello de tiempo pendiente; no listo como prueba",
        appendix_intro=(
            "Cada fila indica solo la presencia del token. No afirma que sea válido ni que la "
            "autoridad sea confiable; verifique por separado contra bundle.json."
        ),
        appendix_caption="Presencia del token y autoridad indicada por elemento.",
        timestamp_heading="Estado del sello",
        authority_heading="Autoridad indicada",
        accessible_note="Consulte packet.html para una versión accesible.",
    ),
}


def proof_statement(lang: str) -> ProofStatement:
    """Return the proof statement for ``lang``, falling back to English."""
    return _STATEMENTS.get(lang.lower().split("-", 1)[0], _STATEMENTS[_DEFAULT_LANG])


def shared_metadata_may_be_retained(disclosures: Iterable[object]) -> bool:
    """Whether signed disclosure notes warn that shared-copy metadata may remain.

    The older ``location RETAINED`` spelling is recognized so a historical packet is
    never rendered with the stronger metadata-removed copy.
    """
    markers = ("location retained", "metadata may be retained", "permits embedded metadata")
    return any(
        isinstance(note, str) and any(marker in note.casefold() for marker in markers)
        for note in disclosures
    )


@dataclass(frozen=True, slots=True)
class ScopeStatement:
    """Localized scope text for current and historical packets.

    Current construction uses the whole-unit form. Issue/date forms remain only so
    previously emitted packets keep their signed meaning when rendered (item R-35).
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

    Current construction passes ``"unit"`` with no ``since``. ``"issue"`` and
    ``since`` remain compatibility inputs for rendering previously emitted packets;
    they are not available packet-v3 export modes.
    """
    resolved = lang if lang in _SCOPE else _DEFAULT_LANG
    strings = _SCOPE[resolved]
    is_issue_scope = scope_type == "issue" and issue_id
    statement = strings["issue"].format(issue_id=issue_id) if is_issue_scope else strings["unit"]
    exclusions: list[str] = []
    if since:
        exclusions.append(strings["since"].format(since=since))
    # Historical compatibility: only state that content "outside this scope" was
    # withheld for an old partial scope. Current construction is whole-unit only.
    if is_issue_scope or since:
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


def packet_trust_text(lang: str) -> PacketTrustText:
    """Return localized human-view trust text, falling back to English."""
    return _TRUST_TEXT.get(lang.lower().split("-", 1)[0], _TRUST_TEXT[_DEFAULT_LANG])
