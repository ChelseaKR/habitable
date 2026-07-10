# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""On-device, honest record-strength self-assessment (EXP-03).

A tenant deciding what to capture next, or whether an item is ready to hand to
an inspector, has had no way to tell a well-documented item from a thin one
until a recipient runs ``verify``. This module gives that feedback locally,
before anything is shared, from data already sitting in the vault:

* whether a trusted timestamp is present at all;
* how many *independent* timestamp authorities cover the item (redundancy,
  item R-16) — read from token presence, not re-verified cryptographically,
  since ``verify``/``habitable verify`` already owns that check;
* how deep the chain of custody is for the item (captured, fixity-checked,
  timestamped, viewed, shared, packeted — each an attested handling event);
* how many timeline entries corroborate the issue the item belongs to.

This is deliberately **not** a re-implementation of :mod:`habitable.verify` —
it reads presence and counts, never re-validates a cryptographic signature,
and it runs with no network call, so it is safe to compute on every
``status`` call.

Framing is load-bearing: this is *record strength*, not a legal or
admissibility judgment. Callers (the CLI, the app server) are expected to
pair this with the plain-language caveat text in their own i18n catalog
(``status_strength_caveat`` in :mod:`habitable.i18n`, the matching key in
``app/i18n/*.json``) — never render a level without it nearby. See EXP-03 and
the "Requests we should decline" table in
``docs/research/synthetic-personas-feedback.md``: no admissibility promises,
ever.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .evidence import CustodyLog
from .model import Capture
from .vault import Vault

__all__ = [
    "IssueStrength",
    "ItemStrength",
    "RecordStrengthLevel",
    "assess_capture",
    "assess_case",
    "assess_issue",
]


class RecordStrengthLevel(StrEnum):
    """How well-documented one item or issue is, *as a record* — not a legal claim.

    * ``MINIMAL`` — no trusted timestamp yet; only a content hash and whatever
      custody/timeline exists so far. Still real evidence of content, with no
      upper-bound time claim.
    * ``DEVELOPING`` — a trusted timestamp from a single authority.
    * ``STRONG`` — a trusted timestamp corroborated by two or more independent
      authorities (item R-16's redundancy target).
    """

    MINIMAL = "minimal"
    DEVELOPING = "developing"
    STRONG = "strong"


@dataclass(frozen=True, slots=True)
class ItemStrength:
    """The record-strength assessment for one captured item."""

    capture_id: str
    issue_id: str
    has_timestamp: bool
    authority_count: int
    custody_entries: int
    corroborating_timeline_entries: int
    level: RecordStrengthLevel


@dataclass(frozen=True, slots=True)
class IssueStrength:
    """The record-strength assessment for one issue, aggregated over its items."""

    issue_id: str
    item_count: int
    strong_count: int
    developing_count: int
    minimal_count: int
    timeline_entries: int
    level: RecordStrengthLevel


def _authority_count(vault: Vault, capture_id: str) -> int:
    """The number of distinct timestamp authorities that have stamped this item.

    Counts the primary token plus any independently-stamped additional tokens
    (:meth:`Vault.get_additional_tokens`) by distinct ``tsa_name`` — presence,
    not a fresh cryptographic re-verification (``habitable verify`` already
    owns that).
    """
    names: set[str] = set()
    primary = vault.get_token(capture_id)
    if primary is not None:
        names.add(primary.tsa_name)
    for extra in vault.get_additional_tokens(capture_id):
        names.add(extra.tsa_name)
    return len(names)


def _custody_entries_for(custody: CustodyLog, item_id: str) -> int:
    return sum(1 for entry in custody.entries if entry.item_id == item_id)


def _level_for(*, has_timestamp: bool, authority_count: int) -> RecordStrengthLevel:
    if not has_timestamp:
        return RecordStrengthLevel.MINIMAL
    if authority_count >= 2:
        return RecordStrengthLevel.STRONG
    return RecordStrengthLevel.DEVELOPING


def assess_capture(vault: Vault, capture: Capture) -> ItemStrength:
    """The record-strength assessment for one already-captured item."""
    has_timestamp = vault.get_token(capture.capture_id) is not None
    authority_count = _authority_count(vault, capture.capture_id)
    custody_entries = _custody_entries_for(vault.custody, capture.capture_id)
    corroborating = len(vault.document.timeline(capture.issue_id))
    return ItemStrength(
        capture_id=capture.capture_id,
        issue_id=capture.issue_id,
        has_timestamp=has_timestamp,
        authority_count=authority_count,
        custody_entries=custody_entries,
        corroborating_timeline_entries=corroborating,
        level=_level_for(has_timestamp=has_timestamp, authority_count=authority_count),
    )


def assess_issue(vault: Vault, issue_id: str) -> IssueStrength:
    """The record-strength assessment for an issue, aggregated over its items.

    An issue is only as strong as its weakest documented item: any item still
    awaiting a timestamp pulls the issue to ``MINIMAL``; otherwise any
    single-authority item pulls it to ``DEVELOPING``; only when every item has
    redundant-authority timestamps does the issue read as ``STRONG``. An issue
    with no captures yet is ``MINIMAL`` — there is nothing to corroborate.
    """
    items = [assess_capture(vault, c) for c in vault.document.captures(issue_id)]
    strong = sum(1 for i in items if i.level is RecordStrengthLevel.STRONG)
    developing = sum(1 for i in items if i.level is RecordStrengthLevel.DEVELOPING)
    minimal = sum(1 for i in items if i.level is RecordStrengthLevel.MINIMAL)
    timeline_entries = len(vault.document.timeline(issue_id))

    if not items or minimal:
        level = RecordStrengthLevel.MINIMAL
    elif developing:
        level = RecordStrengthLevel.DEVELOPING
    else:
        level = RecordStrengthLevel.STRONG

    return IssueStrength(
        issue_id=issue_id,
        item_count=len(items),
        strong_count=strong,
        developing_count=developing,
        minimal_count=minimal,
        timeline_entries=timeline_entries,
        level=level,
    )


def assess_case(vault: Vault) -> list[IssueStrength]:
    """The record-strength assessment for every issue in the case, issue order."""
    return [assess_issue(vault, issue.issue_id) for issue in vault.document.issues()]
