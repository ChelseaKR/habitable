# SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0
# Copyright 2026 Chelsea Kelly-Reif
"""Versioned, language-neutral semantics for habitability timeline events.

``packet_version`` 1 and 2 exposed a free-form ``kind`` plus an HLC ordering
token.  Packet v3 deliberately does not reinterpret either field: it records the
time a person says an event happened separately from the device time at which the
entry was added, names how the fact is known, and carries typed links to related
records.  This module contains the small pure vocabulary shared by the model,
renderers, and verifier-facing tests.
"""

from __future__ import annotations

from datetime import UTC, date, datetime

from .errors import HabitableError

__all__ = [
    "EVENT_TYPES",
    "SOURCES",
    "event_label",
    "normalize_occurred_at",
    "recorded_at_from_hlc",
    "source_label",
]

EVENT_TYPES = (
    "condition_observed",
    "notice_sent",
    "delivery_confirmed",
    "response_received",
    "inspection",
    "repair",
    "recurrence",
    "impact",
    "other",
)

SOURCES = (
    "firsthand",
    "message",
    "document",
    "official_record",
    "other",
    "unspecified",
)

_EVENT_LABELS = {
    "en": {
        "condition_observed": "Condition observed",
        "notice_sent": "Repair notice sent",
        "delivery_confirmed": "Delivery confirmed",
        "response_received": "Response received",
        "inspection": "Inspection",
        "repair": "Repair or attempted repair",
        "recurrence": "Condition happened again",
        "impact": "Impact recorded",
        "other": "Other",
    },
    "es": {
        "condition_observed": "Condición observada",
        "notice_sent": "Aviso de reparación enviado",
        "delivery_confirmed": "Entrega confirmada",
        "response_received": "Respuesta recibida",
        "inspection": "Inspección",
        "repair": "Reparación o intento de reparación",
        "recurrence": "La condición ocurrió de nuevo",
        "impact": "Impacto registrado",
        "other": "Otro",
    },
}

_SOURCE_LABELS = {
    "en": {
        "firsthand": "Firsthand observation",
        "message": "Message or conversation",
        "document": "Document or receipt",
        "official_record": "Inspector or official record",
        "other": "Other source",
        "unspecified": "Source not recorded (legacy entry)",
    },
    "es": {
        "firsthand": "Observación directa",
        "message": "Mensaje o conversación",
        "document": "Documento o recibo",
        "official_record": "Registro de inspección u oficial",
        "other": "Otra fuente",
        "unspecified": "Fuente no registrada (entrada anterior)",
    },
}

# Named so the py314-targeting formatter cannot rewrite a portable tuple except
# into PEP 758's parenthesis-free form, which does not parse on Python 3.12/3.13.
_RECORDED_AT_ERRORS = (ValueError, OSError, OverflowError)


def event_label(language: str, event_type: str, other_label: str = "") -> str:
    """Return the reviewed display label, using ``other_label`` only for Other."""
    lang = "es" if language.lower().startswith("es") else "en"
    if event_type == "other" and other_label.strip():
        return other_label.strip()
    return _EVENT_LABELS[lang].get(event_type, _EVENT_LABELS[lang]["other"])


def source_label(language: str, source: str, source_detail: str = "") -> str:
    """Return a deterministic, localized source description."""
    lang = "es" if language.lower().startswith("es") else "en"
    label = _SOURCE_LABELS[lang].get(source, _SOURCE_LABELS[lang]["unspecified"])
    if source == "other" and source_detail.strip():
        return f"{label}: {source_detail.strip()}"
    return label


def normalize_occurred_at(value: str) -> str:
    """Validate and normalize a claimed occurrence date/time.

    A calendar date is accepted when the exact time is not known.  A timestamp
    must include a UTC offset; otherwise a recipient cannot know which instant it
    names.  The empty string is allowed for migrated v1 case entries and means
    "not recorded", never "same as recorded_at".
    """
    raw = value.strip()
    if not raw:
        return ""
    try:
        if len(raw) == 10:
            parsed_date = date.fromisoformat(raw)
            return parsed_date.isoformat()
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HabitableError(
            "occurred_at must be an ISO date or an ISO timestamp with a UTC offset"
        ) from exc
    if parsed.tzinfo is None:
        raise HabitableError("occurred_at timestamps must include a UTC offset")
    return parsed.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def recorded_at_from_hlc(hlc: str) -> str:
    """Derive the device-recorded UTC instant from an internal raw HLC stamp."""
    head = hlc.split(".", 1)[0]
    if not head.isdigit():
        return ""
    try:
        moment = datetime.fromtimestamp(int(head) / 1000, tz=UTC)
    except _RECORDED_AT_ERRORS:
        return ""
    return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")
