# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Versioned, built-in housing evidence workflow profiles.

Profiles are presentation and prompting policy, never legal logic.  They do not
change hashing, custody, timestamping, sync, or verifier verdicts.  A profile's
review state travels with exports so an experimental workflow cannot be mistaken
for lawyer-, clinician-, inspector-, or accessibility-reviewed guidance.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import cast

from .canonical import JSONValue
from .errors import HabitableError

__all__ = [
    "ARTIFACT_TYPES",
    "RELATIONSHIP_ENDPOINT_KINDS",
    "RELATIONSHIP_TYPES",
    "UseCaseProfile",
    "get_profile",
    "list_profiles",
    "profile_expired",
]

PROFILE_SCHEMA_VERSION = 1

ARTIFACT_TYPES = frozenset(
    {
        "repair_request",
        "delivery_receipt",
        "landlord_response",
        "inspection_report",
        "utility_notice",
        "accommodation_request",
        "supporting_letter",
        "clinician_letter",
        "expense_receipt",
        "deduction_itemization",
        "relocation_record",
        "partner_export",
        "other_document",
    }
)

RELATIONSHIP_TYPES = frozenset(
    {
        "documents_condition",
        "sent_via",
        "delivery_receipt_for",
        "response_to",
        "before_of",
        "after_of",
        "inspection_finding_for",
        "repair_claim_for",
        "expense_caused_by",
        "deduction_for",
        "supports",
    }
)

RELATIONSHIP_ENDPOINT_KINDS: dict[str, frozenset[tuple[str, str]]] = {
    "documents_condition": frozenset(
        {(source, "issue") for source in ("capture", "artifact", "timeline")}
    ),
    "sent_via": frozenset({("artifact", "artifact"), ("timeline", "timeline")}),
    "delivery_receipt_for": frozenset(
        {
            ("artifact", "artifact"),
            ("artifact", "timeline"),
            ("timeline", "artifact"),
            ("timeline", "timeline"),
        }
    ),
    "response_to": frozenset(
        {
            ("artifact", "artifact"),
            ("artifact", "timeline"),
            ("timeline", "artifact"),
            ("timeline", "timeline"),
        }
    ),
    "before_of": frozenset({("capture", "capture")}),
    "after_of": frozenset({("capture", "capture")}),
    "inspection_finding_for": frozenset(
        {
            ("artifact", "issue"),
            ("artifact", "capture"),
            ("timeline", "issue"),
            ("timeline", "capture"),
        }
    ),
    "repair_claim_for": frozenset(
        {
            ("artifact", "issue"),
            ("artifact", "capture"),
            ("timeline", "issue"),
            ("timeline", "capture"),
        }
    ),
    "expense_caused_by": frozenset(
        {
            ("artifact", "issue"),
            ("artifact", "artifact"),
            ("artifact", "capture"),
            ("artifact", "timeline"),
        }
    ),
    # Deliberately the same endpoint shape as ``repair_claim_for``: both record
    # somebody else's *claim about* a documented condition, so both point from
    # the document (or the timeline entry recording its arrival) at the issue or
    # the specific capture the claim is made against. A deduction can therefore
    # never point at another deduction, and never carries a counter-assertion:
    # the tenant's own rebuttal is a separate record joined with ``supports``.
    "deduction_for": frozenset(
        {
            ("artifact", "issue"),
            ("artifact", "capture"),
            ("timeline", "issue"),
            ("timeline", "capture"),
        }
    ),
    "supports": frozenset(
        {
            (source, target)
            for source in ("capture", "artifact", "timeline")
            for target in ("issue", "capture", "artifact", "timeline")
        }
    ),
}


@dataclass(frozen=True, slots=True)
class UseCaseProfile:
    """One immutable workflow/presentation profile."""

    profile_id: str
    version: int
    name_en: str
    name_es: str
    summary_en: str
    summary_es: str
    artifact_types: tuple[str, ...]
    relationship_types: tuple[str, ...]
    handoff_sections: tuple[str, ...]
    disclosures: tuple[str, ...]
    review_state: str = "maintainer_reviewed"
    reviewer: str = "Habitable maintainers"
    jurisdiction: str = "generic"
    reviewed_at: str = "2026-07-23"
    expires_at: str = ""

    @property
    def external_review_required(self) -> bool:
        return self.review_state == "external_review_required"

    def to_json(self) -> dict[str, JSONValue]:
        return {
            "profile_schema": PROFILE_SCHEMA_VERSION,
            "profile_id": self.profile_id,
            "version": self.version,
            "name": {"en": self.name_en, "es": self.name_es},
            "summary": {"en": self.summary_en, "es": self.summary_es},
            "artifact_types": cast(JSONValue, list(self.artifact_types)),
            "relationship_types": cast(JSONValue, list(self.relationship_types)),
            "handoff_sections": cast(JSONValue, list(self.handoff_sections)),
            "disclosures": cast(JSONValue, list(self.disclosures)),
            "review_state": self.review_state,
            "external_review_required": self.external_review_required,
            "review": {
                "reviewer": self.reviewer,
                "jurisdiction": self.jurisdiction,
                "reviewed_at": self.reviewed_at,
                "expires_at": self.expires_at,
            },
        }


def _profile(
    profile_id: str,
    name_en: str,
    name_es: str,
    summary_en: str,
    summary_es: str,
    *,
    artifacts: tuple[str, ...],
    relationships: tuple[str, ...],
    sections: tuple[str, ...],
    disclosures: tuple[str, ...],
    external: bool = False,
    reviewed_at: str = "2026-07-23",
) -> UseCaseProfile:
    unknown_artifacts = set(artifacts) - ARTIFACT_TYPES
    unknown_relationships = set(relationships) - RELATIONSHIP_TYPES
    if unknown_artifacts or unknown_relationships:
        raise RuntimeError(
            f"invalid built-in profile {profile_id}: "
            f"artifacts={unknown_artifacts}, relationships={unknown_relationships}"
        )
    return UseCaseProfile(
        profile_id=profile_id,
        version=1,
        name_en=name_en,
        name_es=name_es,
        summary_en=summary_en,
        summary_es=summary_es,
        artifact_types=artifacts,
        relationship_types=relationships,
        handoff_sections=sections,
        disclosures=disclosures,
        review_state="external_review_required" if external else "maintainer_reviewed",
        reviewer="unassigned external reviewer" if external else "Habitable maintainers",
        reviewed_at="" if external else reviewed_at,
    )


_PROFILES = (
    _profile(
        "repair_delivery",
        "Repair notice and delivery ledger",
        "Registro de aviso y entrega de reparación",
        "Connect a condition, repair request, delivery record, response, and follow-up.",
        "Conecta una condición, solicitud de reparación, entrega, respuesta y seguimiento.",
        artifacts=("repair_request", "delivery_receipt", "landlord_response"),
        relationships=("documents_condition", "sent_via", "delivery_receipt_for", "response_to"),
        sections=("condition", "notice", "delivery", "response", "follow_up"),
        disclosures=("Delivery and receipt remain assertions unless independently authenticated.",),
    ),
    _profile(
        "repair_comparison",
        "Before and after repair comparison",
        "Comparación antes y después de una reparación",
        "Pair observations to document change without claiming cause or repair quality.",
        "Relaciona observaciones para documentar cambios sin afirmar causa ni calidad.",
        artifacts=("inspection_report", "landlord_response"),
        relationships=("before_of", "after_of", "repair_claim_for"),
        sections=("before", "repair_claim", "after", "proof_limits"),
        disclosures=("Comparison does not establish cause, completeness, or code compliance.",),
    ),
    _profile(
        "inspector_handoff",
        "Inspector handoff",
        "Entrega para inspección",
        "Organize room, condition, chronology, and support for an inspector.",
        "Organiza habitación, condición, cronología y respaldo para una inspección.",
        artifacts=("inspection_report", "repair_request", "delivery_receipt"),
        relationships=("inspection_finding_for", "documents_condition", "supports"),
        sections=("rooms", "conditions", "chronology", "supporting_artifacts"),
        disclosures=("This profile is not an inspector finding or code determination.",),
        external=True,
    ),
    _profile(
        "utility_outage",
        "Utility and environmental outage diary",
        "Diario de servicios y condiciones ambientales",
        "Join observations, sensor readings, notices, and restoration events.",
        "Une observaciones, lecturas, avisos y eventos de restablecimiento.",
        artifacts=("utility_notice", "repair_request", "delivery_receipt"),
        relationships=("documents_condition", "sent_via", "supports"),
        sections=("outage", "measurements", "notice", "restoration"),
        disclosures=("Measurements do not by themselves establish a legal violation.",),
    ),
    _profile(
        "accommodation_request",
        "Accommodation request record",
        "Registro de solicitud de adaptación",
        "Preserve a request, optional support, delivery, response, and follow-up.",
        "Conserva una solicitud, respaldo opcional, entrega, respuesta y seguimiento.",
        artifacts=("accommodation_request", "supporting_letter", "delivery_receipt"),
        relationships=("sent_via", "delivery_receipt_for", "response_to", "supports"),
        sections=("request", "optional_support", "delivery", "response"),
        disclosures=(
            "Technical integrity does not establish disability, entitlement, "
            "receipt, or compliance.",
        ),
        external=True,
    ),
    _profile(
        "public_housing_remediation",
        "Public-housing remediation trail",
        "Seguimiento de reparación en vivienda pública",
        "Connect an inspection finding, repairs, tenant observations, and reinspection.",
        "Conecta una inspección, reparaciones, observaciones y reinspección.",
        artifacts=("inspection_report", "landlord_response", "repair_request"),
        relationships=("inspection_finding_for", "repair_claim_for", "supports"),
        sections=("finding", "repair", "tenant_observation", "reinspection"),
        disclosures=("Agency status is reported or imported, never silently refreshed.",),
        external=True,
    ),
    _profile(
        "health_corroboration",
        "Health corroboration handoff",
        "Entrega de corroboración de salud",
        "Preserve tenant-chosen supporting material without inferring medical causation.",
        "Conserva material elegido por la persona sin inferir causalidad médica.",
        artifacts=("clinician_letter", "supporting_letter"),
        relationships=("supports", "documents_condition"),
        sections=("condition", "tenant_statement", "optional_support", "limits"),
        disclosures=(
            "Habitable is not a medical record and does not infer diagnosis or causation.",
        ),
        external=True,
    ),
    _profile(
        "displacement_expense",
        "Temporary displacement and expense log",
        "Registro de desplazamiento y gastos",
        "Organize relocation events and supporting receipts after an unsafe-unit event.",
        "Organiza desplazamiento y recibos después de un evento de vivienda insegura.",
        artifacts=("expense_receipt", "relocation_record", "other_document"),
        relationships=("expense_caused_by", "supports"),
        sections=("event", "relocation", "expenses", "return"),
        disclosures=("Arithmetic totals do not establish reimbursement eligibility.",),
    ),
    _profile(
        "move_out_deposit",
        "Move-out condition and deposit-dispute record",
        "Registro de condición de salida y disputa de depósito",
        "Pair move-in and move-out condition records with an itemized deduction, "
        "without deciding what is owed.",
        "Une registros de condición de entrada y salida con una deducción detallada, "
        "sin determinar lo que se adeuda.",
        artifacts=(
            "deduction_itemization",
            "inspection_report",
            "landlord_response",
            "expense_receipt",
        ),
        relationships=(
            "before_of",
            "after_of",
            "deduction_for",
            "documents_condition",
            "supports",
        ),
        sections=(
            "move_in_condition",
            "move_out_condition",
            "deduction_claim",
            "tenant_records",
            "proof_limits",
        ),
        disclosures=(
            "An itemized deduction is the landlord's assertion; recording it here "
            "neither accepts nor rebuts it.",
            "Condition records do not establish wear and tear, damage, cost, or "
            "what a deposit is owed.",
        ),
        reviewed_at="2026-08-26",
    ),
    _profile(
        "building_pattern",
        "Consented building pattern summary",
        "Resumen consentido de patrones del edificio",
        "Answer a fixed organizing question with threshold-suppressed local aggregates.",
        "Responde una pregunta organizativa con agregados locales y umbral de privacidad.",
        artifacts=("other_document",),
        relationships=("supports",),
        sections=("question", "cohort", "suppressed_summary", "privacy_limits"),
        disclosures=(
            "Published aggregates cannot be remotely revoked and may permit differencing.",
        ),
        external=True,
    ),
    _profile(
        "partner_capsule",
        "Partner evidence capsule",
        "Cápsula de evidencia para organizaciones",
        "Exchange a small conforming evidence object with another civic tool.",
        "Intercambia un objeto de evidencia compatible con otra herramienta cívica.",
        artifacts=("partner_export", "other_document"),
        relationships=("supports", "documents_condition"),
        sections=("source_tool", "evidence", "verification", "limits"),
        disclosures=(
            "A conforming capsule does not imply the partner or source is authenticated.",
        ),
        external=True,
    ),
)

_BY_ID = {profile.profile_id: profile for profile in _PROFILES}


def list_profiles() -> tuple[UseCaseProfile, ...]:
    """Return every profile in stable display order."""
    return _PROFILES


def get_profile(profile_id: str) -> UseCaseProfile:
    """Resolve a built-in profile or fail closed."""
    try:
        return _BY_ID[profile_id]
    except KeyError as exc:
        raise HabitableError(f"unknown use-case profile: {profile_id!r}") from exc


def profile_expired(profile: UseCaseProfile, *, today: date | None = None) -> bool:
    """Whether *profile*'s review window has passed.

    A profile with no ``expires_at`` never expires -- none of the built-in
    profiles sets one today, so this is presently inert, forward-looking
    infrastructure for the jurisdiction- and community-contributed profiles the
    roadmap's product-expansion workstream plans to add next. ``today`` is
    injectable so callers and tests can pin the comparison instead of reading
    the wall clock; it defaults to the real local date. Comparison is by
    calendar date, matching the plain ``YYYY-MM-DD`` shape of ``expires_at``, so
    a profile expires at the start of its named day rather than partway through
    it in some timezone.

    A profile that is already expired must never be silently presented as
    current: see ``get_profile`` callers in ``model.py`` (selection refuses an
    already-expired profile) and ``packet.py`` (export falls back to no profile
    if one that was valid at selection time has since expired), and
    ``docs/adr/0012-profile-review-expiry-enforcement.md``.
    """
    if not profile.expires_at:
        return False
    if today is None:
        today = datetime.now(tz=UTC).date()
    return today >= date.fromisoformat(profile.expires_at)
