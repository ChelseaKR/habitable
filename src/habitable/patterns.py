# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Fixed-question building-pattern summaries over recorded per-case consent.

This module deliberately exposes one organizing question. It filters locally,
coarsens dates to ISO weeks, applies the commons household threshold, and never
opens a network connection or emits household identifiers.

Consent is a **recorded, per-case, per-question** fact, stored in that
household's own vault by :func:`record_consent` and read back by
:func:`read_consent`. It is *not* a per-export consent step: nobody is asked
again at export time, so the export says so rather than claiming otherwise.
See ``docs/commons.md`` for the withdrawal model — withdrawal stops future
exports and cannot recall an aggregate that has already been published.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import cast

from .canonical import JSONValue
from .commons import DEFAULT_K, CaseContribution, IssueObservation, build_commons, summarize_case
from .errors import HabitableError
from .model import CaseDocument

__all__ = [
    "CONSENT_META_PREFIX",
    "CONSENT_STATE_GRANTED",
    "CONSENT_STATE_WITHDRAWN",
    "NO_HEAT_WEEKLY_QUESTION",
    "ConsentMissingError",
    "ConsentRecord",
    "PatternQuestion",
    "PatternSummary",
    "build_no_heat_weekly_summary",
    "consent_meta_key",
    "household_token_for",
    "read_consent",
    "record_consent",
]


@dataclass(frozen=True, slots=True)
class PatternQuestion:
    question_id: str
    prompt: str
    category: str
    time_bucket: str


NO_HEAT_WEEKLY_QUESTION = PatternQuestion(
    question_id="consenting_households_no_heat_by_week",
    prompt=(
        "In each building and ISO week, how many households that recorded consent "
        "to this question reported no heat?"
    ),
    category="no_heat",
    time_bucket="week",
)

#: Meta-key namespace for stored consent records. One register per question id,
#: so a household consents to (and withdraws from) each question separately.
CONSENT_META_PREFIX = "pattern_consent:"

CONSENT_STATE_GRANTED = "granted"
CONSENT_STATE_WITHDRAWN = "withdrawn"


@dataclass(frozen=True, slots=True)
class ConsentRecord:
    """One household's recorded answer for one fixed question.

    ``recorded_at`` and ``actor`` come from the CRDT register's own provenance,
    not from anything the exporting operator supplies: they are the hybrid
    logical timestamp the write was stamped with and the fingerprint of the
    device key that signed it. ``signed`` is false only for a record written by
    a vault with no device identity (the legacy/unsigned path).
    """

    question_id: str
    state: str
    recorded_at: str
    actor: str
    signed: bool

    @property
    def granted(self) -> bool:
        return self.state == CONSENT_STATE_GRANTED


def consent_meta_key(question: PatternQuestion) -> str:
    return f"{CONSENT_META_PREFIX}{question.question_id}"


def record_consent(document: CaseDocument, question: PatternQuestion, *, granted: bool) -> None:
    """Record (or withdraw) this household's consent for one fixed question.

    Writes a signed, timestamped register into the household's own case
    document, so the record merges to paired devices like any other case fact
    and carries the authorship provenance ``habitable provenance`` already
    prints. Withdrawal is a write, not a delete: the register keeps its history
    and a later grant wins by CRDT order, never by silent absence.
    """
    state = CONSENT_STATE_GRANTED if granted else CONSENT_STATE_WITHDRAWN
    document.set_meta(consent_meta_key(question), state)


def read_consent(document: CaseDocument, question: PatternQuestion) -> ConsentRecord | None:
    """Return this case's consent record for ``question``, or ``None`` if absent.

    Absent means absent: no record was ever written. That is deliberately
    distinct from a recorded withdrawal, which returns a record whose
    ``granted`` is false.
    """
    key = consent_meta_key(question)
    state = document.get_meta(key)
    if not state:
        return None
    provenance = document.meta_provenance(key)
    return ConsentRecord(
        question_id=question.question_id,
        state=state,
        recorded_at=provenance.ts if provenance is not None else "",
        actor=provenance.actor if provenance is not None else "",
        signed=bool(provenance is not None and provenance.signed),
    )


def household_token_for(document: CaseDocument, record: ConsentRecord) -> str:
    """An opaque, never-emitted handle for distinct-household thresholding.

    Derived from the consent record's own provenance rather than from the
    export command's arguments, so it cannot be produced for a case that has no
    record. It is used only in memory, only to count distinct households, and is
    asserted absent from the export by ``tests/test_patterns.py``.
    """
    material = "::".join(
        (
            "pattern-consent",
            document.case_id,
            record.question_id,
            record.state,
            record.recorded_at,
            record.actor,
        )
    )
    return hashlib.sha256(material.encode()).hexdigest()


class ConsentMissingError(HabitableError):
    """Raised when a case is offered for aggregation without recorded consent."""


@dataclass(frozen=True, slots=True)
class PatternSummary:
    question: PatternQuestion
    commons: dict[str, object]
    #: How many contributing cases held a granted consent record for this
    #: question. Counted from the records actually read out of the vaults, so a
    #: reader can compare it against ``aggregate.contributing_cases``.
    cases_with_recorded_consent: int = 0

    def to_json(self) -> dict[str, JSONValue]:
        return {
            "kind": "habitable/building-pattern",
            "schema_version": 2,
            "question": {
                "question_id": self.question.question_id,
                "prompt": self.question.prompt,
                "category": self.question.category,
                "time_bucket": self.question.time_bucket,
            },
            "consent": {
                # What this tool actually captures: a standing, per-question
                # consent record stored in each household's own vault, checked
                # before that case is allowed to contribute.
                "mechanism": "per_case_record_in_household_vault",
                "recorded_consent_required": True,
                "cases_with_recorded_consent": self.cases_with_recorded_consent,
                # What it does NOT capture. There is no per-export consent step:
                # no household is asked again when this file is written, so this
                # is false for every export this tool can produce today. It is
                # stated rather than dropped because earlier versions of this
                # format asserted the opposite.
                "explicit_per_export": False,
                "published_aggregates_remotely_revocable": False,
                "withdrawal": (
                    "A household can withdraw consent in its own vault, which "
                    "excludes it from later exports. It cannot recall an "
                    "aggregate that has already been published."
                ),
            },
            "release_limits": {
                "fixed_question_only": True,
                "cross_building_joins": False,
                "exact_locations": False,
                "narrative_text": False,
                "media_or_hashes": False,
                "warning": (
                    "Repeated or overlapping releases can permit differencing; "
                    "a human must review each export before publication."
                ),
            },
            "aggregate": cast(JSONValue, self.commons),
        }


def build_no_heat_weekly_summary(
    cases: list[tuple[CaseDocument, str]],
    *,
    k: int = DEFAULT_K,
) -> PatternSummary:
    """Answer the sole reviewed question from cases that recorded consent.

    Each tuple is ``(document, coarse_building_label)``. The consent record and
    the distinct-household token are read from the document itself: a caller
    cannot hand in a token, so no case can contribute without a record. A case
    with no record, or with a recorded withdrawal, raises
    :class:`ConsentMissingError` rather than being silently dropped -- a
    silently smaller cohort would still publish, under a heading that claims
    consent.
    """
    contributions: list[CaseContribution] = []
    for document, building_label in cases:
        record = read_consent(document, NO_HEAT_WEEKLY_QUESTION)
        if record is None:
            raise ConsentMissingError(
                f"case {document.case_id} has no recorded consent for "
                f"{NO_HEAT_WEEKLY_QUESTION.question_id}"
            )
        if not record.granted:
            raise ConsentMissingError(
                f"case {document.case_id} recorded {record.state!r} for "
                f"{NO_HEAT_WEEKLY_QUESTION.question_id}"
            )
        coarse = summarize_case(
            document,
            building_label=building_label,
            household_token=household_token_for(document, record),
            granularity="week",
        )
        contributions.append(
            CaseContribution(
                household_token=coarse.household_token,
                building_label=coarse.building_label,
                observations=tuple(
                    IssueObservation(category=item.category, period=item.period)
                    for item in coarse.observations
                    if item.category == NO_HEAT_WEEKLY_QUESTION.category
                ),
            )
        )
    aggregate = build_commons(contributions, k=k, granularity="week")
    return PatternSummary(
        question=NO_HEAT_WEEKLY_QUESTION,
        commons=aggregate.to_json(),
        cases_with_recorded_consent=len(contributions),
    )
