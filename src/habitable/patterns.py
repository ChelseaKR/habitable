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
See ``docs/commons.md`` for the withdrawal model -- withdrawal stops future
exports and cannot recall an aggregate that has already been published.

**The question this module asks changed in issue #276, and so did its id.**
It used to ask how many consenting households "reported no heat" and count
issues stored under the category ``no_heat``. No supported path ever stored
that string: #206 constrained ``--category`` to a vocabulary whose heat member
is ``heat``, #240 made ``no_heat`` an *alias* normalised to ``heat`` before
storage, and the app's condition datalist offers ``heat``. The cohort was
therefore structurally empty, and a consent-gated, k-anonymous aggregate that
publishes an empty answer does not read as an error -- it reads as "no
household reported this", which is a finding an organizer could act on.

The vocabulary's finest grain is ``heat``, which covers no heat at all,
inadequate heat, and heat a household cannot control alike. The question was
therefore reworded to the one the record can answer, and
``question_id`` was retired with it: see
``docs/adr/0019-the-building-pattern-question-must-be-one-the-record-can-answer.md``
for the argument and the migration note. Every household that had consented to
the retired question must be asked the new one; :data:`SUPERSEDED_QUESTION_IDS`
is what makes that refusal explain itself instead of merely happening.
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
    "HEAT_WEEKLY_QUESTION",
    "SUPERSEDED_QUESTION_IDS",
    "ConsentMissingError",
    "ConsentRecord",
    "PatternQuestion",
    "PatternSummary",
    "build_heat_weekly_summary",
    "consent_meta_key",
    "household_token_for",
    "read_consent",
    "record_consent",
    "superseded_consent_ids",
]


@dataclass(frozen=True, slots=True)
class PatternQuestion:
    """One fixed question, stated in the terms the stored record can answer.

    ``category`` must be a member of ``model.ISSUE_CATEGORIES`` as
    ``commons.canonical_category`` would resolve it, because that is the only
    vocabulary a stored issue can be reduced to. ``scope_note`` says what the
    category does *not* distinguish, so a reader cannot mistake a coarse count
    for a fine one; it is published beside the prompt rather than left to a
    reviewer brief nobody receives with the file.
    """

    question_id: str
    prompt: str
    category: str
    time_bucket: str
    scope_note: str = ""


HEAT_WEEKLY_QUESTION = PatternQuestion(
    question_id="consenting_households_heat_condition_by_week",
    prompt=(
        "In each building and ISO week, how many households that recorded consent "
        "to this question reported a heat condition?"
    ),
    category="heat",
    time_bucket="week",
    scope_note=(
        "habitable records every heat problem under one condition category. This "
        "counts no heat at all, inadequate heat, and heat a household cannot "
        "control as the same condition, because the record does not distinguish "
        "them. It is not a count of households with no heat."
    ),
)

#: Question ids this module has retired, newest last.
#:
#: A consent record stored under one of these is **not** carried forward to the
#: current question, and no code path here reads one as consent. It is named so
#: that a refusal can say why: a household that consented to a retired question
#: answered a different sentence, and reusing that answer for a wider one would
#: be the export claiming a consent nobody gave. Issue #182 is what that looks
#: like when it ships.
SUPERSEDED_QUESTION_IDS: tuple[str, ...] = ("consenting_households_no_heat_by_week",)

#: Meta-key namespace for stored consent records. One register per question id,
#: so a household consents to (and withdraws from) each question separately.
CONSENT_META_PREFIX = "pattern_consent:"

CONSENT_STATE_GRANTED = "granted"
CONSENT_STATE_WITHDRAWN = "withdrawn"

# `cli.py` imports the module's question and builder under their former names.
# They are kept as aliases, and only as aliases: there is exactly one question
# here, and a second spelling of it must never be a second question. The names
# still say `no_heat` because renaming their import site is a change to a file
# this work does not own; the identifiers that reach a household or a published
# file -- `question_id`, `prompt`, `category` -- are the ones issue #276 is
# about, and those are corrected above.
NO_HEAT_WEEKLY_QUESTION = HEAT_WEEKLY_QUESTION


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
    ``granted`` is false. A record stored under a retired question id
    (:data:`SUPERSEDED_QUESTION_IDS`) is absent for this purpose too, because it
    is an answer to a question this tool no longer asks.
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


def superseded_consent_ids(document: CaseDocument) -> tuple[str, ...]:
    """Retired question ids this case still holds a stored consent record for.

    Reported, never honoured. The value exists so that "this household has no
    consent record" can be distinguished, in a message a person reads, from
    "this household consented to a question that no longer exists" -- which is
    the state every mid-campaign vault is in after issue #276, and which would
    otherwise look like a household that never answered at all.
    """
    return tuple(
        question_id
        for question_id in SUPERSEDED_QUESTION_IDS
        if document.get_meta(f"{CONSENT_META_PREFIX}{question_id}")
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
            "schema_version": 3,
            "question": {
                "question_id": self.question.question_id,
                "prompt": self.question.prompt,
                "category": self.question.category,
                "time_bucket": self.question.time_bucket,
                # What the counted category does not distinguish. Published
                # beside the prompt because a coarse number read as a fine one
                # is the failure this format exists to prevent.
                "scope_note": self.question.scope_note,
                # The lineage of the question, so a reader holding an older
                # export can tell that it asked something else rather than
                # assuming the two files are comparable. Kept for the same
                # reason `explicit_per_export` is: this format has corrected
                # itself before, and says so.
                "supersedes": list(SUPERSEDED_QUESTION_IDS),
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
                # A record stored against a retired question id is not consent
                # to this one. Said in the file so a recipient can see that the
                # cohort was not quietly topped up from older answers.
                "superseded_records_honoured": False,
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


def build_heat_weekly_summary(
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

    The cohort filter compares against the *canonical* category, which is what
    ``commons.summarize_case`` produces, so an issue stored under a spelling the
    vocabulary knows to be the same condition (a pre-#206 free-text ``no_heat``,
    say) counts once, in the right cell. Matching the raw stored string instead
    is how this question came to have an empty cohort in the first place.
    """
    contributions: list[CaseContribution] = []
    for document, building_label in cases:
        record = read_consent(document, HEAT_WEEKLY_QUESTION)
        if record is None:
            raise ConsentMissingError(
                f"case {document.case_id} has no recorded consent for "
                f"{HEAT_WEEKLY_QUESTION.question_id}"
                f"{_retired_record_hint(document)}"
            )
        if not record.granted:
            raise ConsentMissingError(
                f"case {document.case_id} recorded {record.state!r} for "
                f"{HEAT_WEEKLY_QUESTION.question_id}"
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
                    if item.category == HEAT_WEEKLY_QUESTION.category
                ),
            )
        )
    aggregate = build_commons(contributions, k=k, granularity="week")
    return PatternSummary(
        question=HEAT_WEEKLY_QUESTION,
        commons=aggregate.to_json(),
        cases_with_recorded_consent=len(contributions),
    )


def _retired_record_hint(document: CaseDocument) -> str:
    """The sentence a mid-campaign vault needs appended to its refusal.

    Silence here would be correct but cruel: the household did answer, the
    organizer remembers them answering, and the refusal would look like a bug or
    like a neighbour who changed their mind. Naming the retired question turns a
    blocked export into an instruction.
    """
    retired = superseded_consent_ids(document)
    if not retired:
        return ""
    return (
        ". It holds a record for the retired question "
        + ", ".join(sorted(retired))
        + ", which asked something narrower than this one and is deliberately not "
        "read as consent to it. Ask this household the current question again "
        "with `habitable consent record` on their own device."
    )


# See the note beside NO_HEAT_WEEKLY_QUESTION: an alias for `cli.py`'s import.
build_no_heat_weekly_summary = build_heat_weekly_summary
