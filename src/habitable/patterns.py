# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Fixed-question, consented building-pattern summaries.

This module deliberately exposes one organizing question. It filters locally,
coarsens dates to ISO weeks, applies the commons household threshold, and never
opens a network connection or emits household identifiers.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from .canonical import JSONValue
from .commons import DEFAULT_K, CaseContribution, IssueObservation, build_commons, summarize_case
from .model import CaseDocument

__all__ = [
    "NO_HEAT_WEEKLY_QUESTION",
    "PatternQuestion",
    "PatternSummary",
    "build_no_heat_weekly_summary",
]


@dataclass(frozen=True, slots=True)
class PatternQuestion:
    question_id: str
    prompt: str
    category: str
    time_bucket: str


NO_HEAT_WEEKLY_QUESTION = PatternQuestion(
    question_id="consenting_households_no_heat_by_week",
    prompt="How many consenting households reported no heat in each building and ISO week?",
    category="no_heat",
    time_bucket="week",
)


@dataclass(frozen=True, slots=True)
class PatternSummary:
    question: PatternQuestion
    commons: dict[str, object]

    def to_json(self) -> dict[str, JSONValue]:
        return {
            "kind": "habitable/building-pattern",
            "schema_version": 1,
            "question": {
                "question_id": self.question.question_id,
                "prompt": self.question.prompt,
                "category": self.question.category,
                "time_bucket": self.question.time_bucket,
            },
            "consent": {
                "explicit_per_export": True,
                "published_aggregates_remotely_revocable": False,
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
    cases: list[tuple[CaseDocument, str, str]],
    *,
    k: int = DEFAULT_K,
) -> PatternSummary:
    """Answer the sole reviewed question from explicit local case contributions.

    Each tuple is ``(document, coarse_building_label, one_export_consent_token)``.
    The tokens are used only in memory for distinct-household thresholding.
    """
    contributions: list[CaseContribution] = []
    for document, building_label, consent_token in cases:
        coarse = summarize_case(
            document,
            building_label=building_label,
            household_token=consent_token,
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
    return PatternSummary(question=NO_HEAT_WEEKLY_QUESTION, commons=aggregate.to_json())
