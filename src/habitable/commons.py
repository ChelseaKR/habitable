# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Opt-in, on-device, k-anonymous aggregate housing-conditions commons (EXP-14).

Funders and organizers want population-level evidence of housing conditions, but
the project measures *nothing* about users by principle: no telemetry, no central
case store, no phone-home. This module is the one place that squares that circle,
and it does so only under strict, checkable constraints:

* **Opt-in and deliberate.** Nothing here runs in the background or on a timer.
  A union computes a summary by explicitly invoking ``habitable commons``; the
  result is written to a local file the union chooses to publish (or not).
* **On-device.** This module imports only the standard library and the local case
  model. It has **no network capability** — it cannot open a socket, make an HTTP
  request, or contact any server. Publication is a separate, manual act by a human.
* **Aggregate-only, never per-person.** The output is coarse counts grouped by a
  union-chosen *building* label, an issue *category*, and a coarsened *time
  period*. It never contains a case id, unit label, room, title, description,
  photo, hash, timestamp token, actor, device identity, or any free text.
* **k-anonymous by suppression.** A cell is emitted only if it is backed by at
  least ``k`` distinct contributing cases (households). Any cell below the
  threshold is dropped, not rounded, so no published number reflects fewer than
  ``k`` households. ``k`` may not be set below :data:`MIN_K`.

The invariant argument for *why this is not telemetry* — and the residual risks it
does not eliminate (e.g. complementary cell inference) — is written up in
``docs/commons.md`` and logged in the "Requests we should decline" analysis in
``docs/research/synthetic-personas-feedback.md``. If any of these constraints
cannot be met for a proposed use, the correct answer is to decline it.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date
from typing import Literal

from .errors import HabitableError
from .model import CaseDocument

__all__ = [
    "COMMONS_SCHEMA_VERSION",
    "DEFAULT_K",
    "MIN_K",
    "AggregateCell",
    "CaseContribution",
    "CommonsExport",
    "IssueObservation",
    "Period",
    "build_commons",
    "summarize_case",
]

COMMONS_SCHEMA_VERSION = 1

#: The lowest anonymity threshold this module will ever accept. A cell must be
#: backed by at least this many distinct households to be published; the module
#: refuses to build an export with a smaller ``k`` because the re-identification
#: risk of one- or two-household cells is not acceptable at any callsite.
MIN_K = 3

#: A conservative default anonymity threshold when the caller does not choose one.
DEFAULT_K = 5

Period = Literal["week", "month", "quarter"]

_UNKNOWN_PERIOD = "unknown"


@dataclass(frozen=True, slots=True)
class IssueObservation:
    """One issue reduced to the only three things the commons will ever see.

    Category and period are the *only* fields carried forward; everything else
    about the issue (room, title, description, severity, captures, custody) is
    dropped here, on-device, before aggregation.
    """

    category: str
    period: str


@dataclass(frozen=True, slots=True)
class CaseContribution:
    """One union case's coarse, de-identified contribution to the commons.

    ``household_token`` is an opaque handle used *only* to count distinct
    households when applying the k-anonymity threshold. It is never emitted in an
    export. ``building_label`` is a union-chosen coarse label (a building, never a
    person and never a unit number).
    """

    household_token: str
    building_label: str
    observations: tuple[IssueObservation, ...]


@dataclass(frozen=True, slots=True)
class AggregateCell:
    """A single published, k-anonymous cell of the commons."""

    building_label: str
    category: str
    period: str
    issue_count: int
    household_count: int

    def to_json(self) -> dict[str, str | int]:
        return {
            "building_label": self.building_label,
            "category": self.category,
            "period": self.period,
            "issue_count": self.issue_count,
            "household_count": self.household_count,
        }


@dataclass(frozen=True, slots=True)
class CommonsExport:
    """A complete, self-describing commons export ready to be written to a file."""

    schema_version: int
    k: int
    period_granularity: Period
    cells: tuple[AggregateCell, ...]
    suppressed_cells: int
    contributing_cases: int

    def to_json(self) -> dict[str, object]:
        """A deterministic, self-documenting JSON-serializable mapping.

        The ``provenance`` block travels with the data so a recipient can read the
        constraints the numbers were produced under without trusting the sender's
        prose.
        """
        return {
            "kind": "habitable/commons",
            "schema_version": self.schema_version,
            "provenance": {
                "opt_in": True,
                "on_device": True,
                "telemetry": False,
                "network_transmission": False,
                "k_anonymity_threshold": self.k,
                "aggregation": (
                    "counts grouped by building label, issue category, and "
                    "coarsened time period; cells backed by fewer than k distinct "
                    "households are suppressed, not rounded"
                ),
                "excludes": (
                    "case ids, unit labels, rooms, titles, descriptions, severity, "
                    "photos, hashes, timestamp tokens, actors, and device identity"
                ),
            },
            "period_granularity": self.period_granularity,
            "contributing_cases": self.contributing_cases,
            "suppressed_cells": self.suppressed_cells,
            "cells": [cell.to_json() for cell in self.cells],
        }


def _period_bucket(captured_at: str, granularity: Period) -> str:
    """Coarsen an ISO ``YYYY-MM-DD...`` string to a month or quarter bucket.

    Anything that does not start with a parseable ``YYYY-MM`` is bucketed as
    :data:`_UNKNOWN_PERIOD` rather than guessed, so a malformed date never becomes
    a precise, misleading period.
    """
    if len(captured_at) < 7 or captured_at[4] != "-":
        return _UNKNOWN_PERIOD
    year, month = captured_at[:4], captured_at[5:7]
    if not (year.isdigit() and month.isdigit()):
        return _UNKNOWN_PERIOD
    month_num = int(month)
    if not 1 <= month_num <= 12:
        return _UNKNOWN_PERIOD
    if granularity == "week":
        try:
            parsed = date.fromisoformat(captured_at[:10])
        except ValueError:
            return _UNKNOWN_PERIOD
        iso_year, iso_week, _ = parsed.isocalendar()
        return f"{iso_year}-W{iso_week:02d}"
    if granularity == "quarter":
        quarter = (month_num - 1) // 3 + 1
        return f"{year}-Q{quarter}"
    return f"{year}-{month:0>2}"


def _issue_period(doc: CaseDocument, issue_id: str, granularity: Period) -> str:
    """The coarse period for an issue: the earliest capture date, else unknown.

    The commons deliberately dates an issue by its evidence (captures), not by the
    device's clock, and coarsens it. An issue with no captured evidence contributes
    an ``unknown`` period rather than leaking the case's internal HLC wall-clock.
    """
    dates = [c.captured_at for c in doc.captures(issue_id) if c.captured_at]
    if not dates:
        return _UNKNOWN_PERIOD
    return _period_bucket(min(dates), granularity)


def summarize_case(
    doc: CaseDocument,
    *,
    building_label: str,
    household_token: str,
    granularity: Period = "month",
) -> CaseContribution:
    """Reduce one decrypted case, on-device, to a coarse commons contribution.

    Only ``category`` and a coarsened ``period`` survive per issue; the building
    label is the caller's coarse choice and the household token is opaque. Removed
    issues (not in the live set) are excluded. Blank categories are bucketed as
    ``uncategorized`` so they aggregate rather than fragment.
    """
    label = building_label.strip()
    if not label:
        raise HabitableError("commons: building_label must be a non-empty label")
    token = household_token.strip()
    if not token:
        raise HabitableError("commons: household_token must be non-empty")
    observations = tuple(
        IssueObservation(
            category=(issue.category.strip() or "uncategorized"),
            period=_issue_period(doc, issue.issue_id, granularity),
        )
        for issue in doc.issues()
    )
    return CaseContribution(
        household_token=token,
        building_label=label,
        observations=observations,
    )


def build_commons(
    contributions: Iterable[CaseContribution],
    *,
    k: int = DEFAULT_K,
    granularity: Period = "month",
) -> CommonsExport:
    """Aggregate per-case contributions into a k-anonymous commons export.

    Cells are grouped by ``(building_label, category, period)``. A cell is emitted
    only when it is backed by at least ``k`` distinct households; smaller cells are
    counted in ``suppressed_cells`` and dropped. ``k`` must be at least
    :data:`MIN_K`.

    Raising rather than silently clamping a too-small ``k`` is deliberate: a caller
    that asked for ``k=1`` has asked for something the privacy model forbids, and
    should see an error, not a weaker-than-requested guarantee.
    """
    if k < MIN_K:
        raise HabitableError(
            f"commons: k must be at least {MIN_K} to publish (got {k}); "
            "a smaller threshold risks re-identifying a single household"
        )

    issue_counts: Counter[tuple[str, str, str]] = Counter()
    households: dict[tuple[str, str, str], set[str]] = {}
    all_cases: set[str] = set()

    for contribution in contributions:
        all_cases.add(contribution.household_token)
        for obs in contribution.observations:
            key = (contribution.building_label, obs.category, obs.period)
            issue_counts[key] += 1
            households.setdefault(key, set()).add(contribution.household_token)

    published: list[AggregateCell] = []
    suppressed = 0
    for key, issue_count in issue_counts.items():
        household_count = len(households[key])
        if household_count < k:
            suppressed += 1
            continue
        building_label, category, period = key
        published.append(
            AggregateCell(
                building_label=building_label,
                category=category,
                period=period,
                issue_count=issue_count,
                household_count=household_count,
            )
        )

    published.sort(key=lambda c: (c.building_label, c.category, c.period))
    return CommonsExport(
        schema_version=COMMONS_SCHEMA_VERSION,
        k=k,
        period_granularity=granularity,
        cells=tuple(published),
        suppressed_cells=suppressed,
        contributing_cases=len(all_cases),
    )
