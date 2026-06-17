# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""The case data model: a conflict-free replicated document (CRDT).

A case is one CRDT document. Two organizers can edit the same case on different
phones with no network and, when they reconnect, their states merge with no
conflict and no lost edits — :meth:`CaseDocument.merge` is commutative,
associative, and idempotent (exercised by property-based tests).

Three CRDT shapes cover the domain:

* :class:`LWWRegister` — last-writer-wins fields (a unit label, an issue's
  category) ordered by hybrid logical clock, so the most recent edit wins
  deterministically.
* :class:`ORSet` — an add-wins set of issue ids (concurrent add/remove resolves
  to present).
* :class:`GrowLog` — an append-only, grow-only log for the timeline and captures,
  whose entries are immutable evidence and therefore never conflict.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import cast

from .canonical import JSONValue, canonical_json
from .clock import HLCTimestamp, HybridLogicalClock
from .errors import HabitableError

__all__ = [
    "Capture",
    "CaseDocument",
    "GrowLog",
    "Issue",
    "LWWRegister",
    "ORSet",
    "TimelineEntry",
]

CASE_SCHEMA_VERSION = 1


def _greater(a: JSONValue, b: JSONValue) -> bool:
    """Deterministic tiebreaker for equal-timestamp writes."""
    return canonical_json(a) > canonical_json(b)


@dataclass(frozen=True, slots=True)
class LWWRegister:
    """A last-writer-wins register: a value tagged with an HLC timestamp."""

    value: JSONValue
    ts: str  # encoded HLCTimestamp

    def merge(self, other: LWWRegister) -> LWWRegister:
        mine, theirs = HLCTimestamp.decode(self.ts), HLCTimestamp.decode(other.ts)
        if theirs > mine:
            return other
        if mine > theirs:
            return self
        # Equal timestamps (same node+counter): break ties deterministically.
        return other if _greater(other.value, self.value) else self

    def to_json(self) -> dict[str, JSONValue]:
        return {"value": self.value, "ts": self.ts}

    @classmethod
    def from_json(cls, raw: Mapping[str, JSONValue]) -> LWWRegister:
        ts = raw.get("ts")
        if not isinstance(ts, str):
            raise HabitableError("LWWRegister 'ts' must be a string")
        return cls(value=raw.get("value"), ts=ts)


@dataclass(frozen=True, slots=True)
class ORSet:
    """An observed-remove set (add-wins). Elements carry unique add tags."""

    adds: Mapping[str, frozenset[str]]
    removes: frozenset[str]

    @classmethod
    def empty(cls) -> ORSet:
        return cls(adds={}, removes=frozenset())

    def elements(self) -> set[str]:
        return {element for element, tags in self.adds.items() if tags - self.removes}

    def add(self, element: str, tag: str) -> ORSet:
        existing = self.adds.get(element, frozenset())
        new_adds = {**self.adds, element: existing | {tag}}
        return replace(self, adds=new_adds)

    def remove(self, element: str) -> ORSet:
        live = self.adds.get(element, frozenset()) - self.removes
        return replace(self, removes=self.removes | live)

    def merge(self, other: ORSet) -> ORSet:
        merged: dict[str, frozenset[str]] = dict(self.adds)
        for element, tags in other.adds.items():
            merged[element] = merged.get(element, frozenset()) | tags
        return ORSet(adds=merged, removes=self.removes | other.removes)

    def to_json(self) -> dict[str, JSONValue]:
        adds: dict[str, JSONValue] = {
            element: cast(JSONValue, sorted(tags)) for element, tags in self.adds.items()
        }
        return {"adds": adds, "removes": cast(JSONValue, sorted(self.removes))}

    @classmethod
    def from_json(cls, raw: Mapping[str, JSONValue]) -> ORSet:
        adds_raw = raw.get("adds", {})
        removes_raw = raw.get("removes", [])
        if not isinstance(adds_raw, dict) or not isinstance(removes_raw, list):
            raise HabitableError("malformed ORSet")
        adds = {
            str(element): frozenset(str(tag) for tag in _as_list(tags))
            for element, tags in adds_raw.items()
        }
        return cls(adds=adds, removes=frozenset(str(tag) for tag in removes_raw))


@dataclass(frozen=True, slots=True)
class GrowLog:
    """An append-only log keyed by immutable id (grow-only set)."""

    entries: Mapping[str, JSONValue]

    @classmethod
    def empty(cls) -> GrowLog:
        return cls(entries={})

    def add(self, key: str, payload: JSONValue) -> GrowLog:
        if key in self.entries and self.entries[key] != payload:
            raise HabitableError(f"append-only log entry {key!r} cannot be modified")
        return GrowLog(entries={**self.entries, key: payload})

    def merge(self, other: GrowLog) -> GrowLog:
        merged: dict[str, JSONValue] = dict(self.entries)
        for key, payload in other.entries.items():
            if key in merged and merged[key] != payload:
                # Immutable entries should never diverge; converge deterministically.
                merged[key] = payload if _greater(payload, merged[key]) else merged[key]
            else:
                merged[key] = payload
        return GrowLog(entries=merged)

    def to_json(self) -> dict[str, JSONValue]:
        return dict(self.entries)

    @classmethod
    def from_json(cls, raw: Mapping[str, JSONValue]) -> GrowLog:
        return cls(entries=dict(raw))


# --- read-model views (what callers see) --------------------------------------


@dataclass(frozen=True, slots=True)
class Issue:
    issue_id: str
    category: str
    room: str
    title: str
    status: str
    severity: str
    description: str


@dataclass(frozen=True, slots=True)
class TimelineEntry:
    entry_id: str
    issue_id: str
    kind: str
    text: str
    hlc: str


@dataclass(frozen=True, slots=True)
class Capture:
    capture_id: str
    issue_id: str
    content_hash: str
    media_type: str
    sealed_name: str
    hlc: str
    captured_at: str


_ISSUE_FIELDS = ("category", "room", "title", "status", "severity", "description")


class CaseDocument:
    """A single case as a mergeable CRDT document."""

    __slots__ = (
        "_captures",
        "_case_id",
        "_clock",
        "_issue_fields",
        "_issues",
        "_meta",
        "_timeline",
    )

    def __init__(self, case_id: str, clock: HybridLogicalClock) -> None:
        self._case_id = case_id
        self._clock = clock
        self._meta: dict[str, LWWRegister] = {}
        self._issues = ORSet.empty()
        self._issue_fields: dict[str, dict[str, LWWRegister]] = {}
        self._timeline = GrowLog.empty()
        self._captures = GrowLog.empty()

    @property
    def case_id(self) -> str:
        return self._case_id

    @property
    def clock(self) -> HybridLogicalClock:
        return self._clock

    # --- mutations ------------------------------------------------------------

    def set_meta(self, key: str, value: str) -> None:
        ts = self._clock.now().encode()
        self._meta[key] = LWWRegister(value=value, ts=ts)

    def get_meta(self, key: str, default: str = "") -> str:
        register = self._meta.get(key)
        if register is None or not isinstance(register.value, str):
            return default
        return register.value

    def add_issue(
        self,
        *,
        category: str,
        room: str = "",
        title: str = "",
        status: str = "open",
        severity: str = "",
        description: str = "",
        issue_id: str | None = None,
    ) -> str:
        stamp = self._clock.now()
        tag = stamp.encode()
        resolved_id = issue_id or f"issue-{tag}"
        self._issues = self._issues.add(resolved_id, tag)
        fields = {
            "category": category,
            "room": room,
            "title": title,
            "status": status,
            "severity": severity,
            "description": description,
        }
        self._issue_fields[resolved_id] = {
            name: LWWRegister(value=value, ts=tag) for name, value in fields.items()
        }
        return resolved_id

    def update_issue(self, issue_id: str, **fields: str) -> None:
        if issue_id not in self._issues.elements():
            raise HabitableError(f"unknown issue: {issue_id!r}")
        registers = self._issue_fields.setdefault(issue_id, {})
        for name, value in fields.items():
            if name not in _ISSUE_FIELDS:
                raise HabitableError(f"unknown issue field: {name!r}")
            registers[name] = LWWRegister(value=value, ts=self._clock.now().encode())

    def remove_issue(self, issue_id: str) -> None:
        self._issues = self._issues.remove(issue_id)

    def add_timeline_entry(self, issue_id: str, kind: str, text: str) -> str:
        stamp = self._clock.now()
        entry_id = f"tl-{stamp.encode()}"
        self._timeline = self._timeline.add(
            entry_id,
            {"issue_id": issue_id, "kind": kind, "text": text, "hlc": stamp.encode()},
        )
        return entry_id

    def add_capture(
        self,
        *,
        issue_id: str,
        content_hash: str,
        media_type: str,
        sealed_name: str,
        captured_at: str,
        capture_id: str | None = None,
    ) -> str:
        stamp = self._clock.now()
        resolved_id = capture_id or f"cap-{stamp.encode()}"
        self._captures = self._captures.add(
            resolved_id,
            {
                "issue_id": issue_id,
                "content_hash": content_hash,
                "media_type": media_type,
                "sealed_name": sealed_name,
                "hlc": stamp.encode(),
                "captured_at": captured_at,
            },
        )
        return resolved_id

    # --- read model -----------------------------------------------------------

    def issues(self) -> list[Issue]:
        out: list[Issue] = []
        for issue_id in sorted(self._issues.elements()):
            fields = self._issue_fields.get(issue_id, {})
            out.append(
                Issue(
                    issue_id=issue_id,
                    category=_reg_str(fields, "category"),
                    room=_reg_str(fields, "room"),
                    title=_reg_str(fields, "title"),
                    status=_reg_str(fields, "status", "open"),
                    severity=_reg_str(fields, "severity"),
                    description=_reg_str(fields, "description"),
                )
            )
        return out

    def timeline(self, issue_id: str | None = None) -> list[TimelineEntry]:
        entries: list[TimelineEntry] = []
        for entry_id, payload in self._timeline.entries.items():
            if not isinstance(payload, dict):
                continue
            entry = TimelineEntry(
                entry_id=entry_id,
                issue_id=str(payload.get("issue_id", "")),
                kind=str(payload.get("kind", "")),
                text=str(payload.get("text", "")),
                hlc=str(payload.get("hlc", "")),
            )
            if issue_id is None or entry.issue_id == issue_id:
                entries.append(entry)
        entries.sort(key=lambda e: e.hlc)
        return entries

    def captures(self, issue_id: str | None = None) -> list[Capture]:
        out: list[Capture] = []
        for capture_id, payload in self._captures.entries.items():
            if not isinstance(payload, dict):
                continue
            capture = Capture(
                capture_id=capture_id,
                issue_id=str(payload.get("issue_id", "")),
                content_hash=str(payload.get("content_hash", "")),
                media_type=str(payload.get("media_type", "")),
                sealed_name=str(payload.get("sealed_name", "")),
                hlc=str(payload.get("hlc", "")),
                captured_at=str(payload.get("captured_at", "")),
            )
            if issue_id is None or capture.issue_id == issue_id:
                out.append(capture)
        out.sort(key=lambda c: c.hlc)
        return out

    # --- merge + serialization ------------------------------------------------

    def merge(self, state: Mapping[str, JSONValue]) -> None:
        """Merge another replica's state into this document (CRDT join)."""
        other = CaseDocument.from_state(state, self._clock)
        for key, register in other._meta.items():
            self._meta[key] = self._meta[key].merge(register) if key in self._meta else register
        self._issues = self._issues.merge(other._issues)
        for issue_id, registers in other._issue_fields.items():
            local = self._issue_fields.setdefault(issue_id, {})
            for name, register in registers.items():
                local[name] = local[name].merge(register) if name in local else register
        self._timeline = self._timeline.merge(other._timeline)
        self._captures = self._captures.merge(other._captures)
        self._advance_clock_past(other)

    def to_state(self) -> dict[str, JSONValue]:
        return {
            "schema_version": CASE_SCHEMA_VERSION,
            "case_id": self._case_id,
            "meta": {key: register.to_json() for key, register in self._meta.items()},
            "issues": self._issues.to_json(),
            "issue_fields": {
                issue_id: {name: register.to_json() for name, register in registers.items()}
                for issue_id, registers in self._issue_fields.items()
            },
            "timeline": self._timeline.to_json(),
            "captures": self._captures.to_json(),
        }

    @classmethod
    def from_state(cls, state: Mapping[str, JSONValue], clock: HybridLogicalClock) -> CaseDocument:
        case_id = state.get("case_id")
        if not isinstance(case_id, str):
            raise HabitableError("case state missing case_id")
        doc = cls(case_id, clock)
        doc._meta = {
            key: LWWRegister.from_json(value)
            for key, value in _as_dict(state, "meta").items()
            if isinstance(value, dict)
        }
        doc._issues = ORSet.from_json(_as_dict(state, "issues"))
        doc._issue_fields = {
            issue_id: {
                name: LWWRegister.from_json(register)
                for name, register in registers.items()
                if isinstance(register, dict)
            }
            for issue_id, registers in _as_dict(state, "issue_fields").items()
            if isinstance(registers, dict)
        }
        doc._timeline = GrowLog.from_json(_as_dict(state, "timeline"))
        doc._captures = GrowLog.from_json(_as_dict(state, "captures"))
        return doc

    def catch_up_clock(self) -> None:
        """Advance this device's clock past every timestamp already in the document.

        Call after loading a persisted case so new local events sort after the
        existing history.
        """
        self._advance_clock_past(self)

    def _advance_clock_past(self, other: CaseDocument) -> None:
        """Pull this device's clock forward past everything merged in."""
        max_ts: HLCTimestamp | None = None
        for register in other._meta.values():
            max_ts = _max_ts(max_ts, register.ts)
        for registers in other._issue_fields.values():
            for register in registers.values():
                max_ts = _max_ts(max_ts, register.ts)
        for payload in (*other._timeline.entries.values(), *other._captures.entries.values()):
            if isinstance(payload, dict) and isinstance(payload.get("hlc"), str):
                max_ts = _max_ts(max_ts, str(payload["hlc"]))
        if max_ts is not None:
            self._clock.update(max_ts)


# --- helpers ------------------------------------------------------------------


def _reg_str(fields: Mapping[str, LWWRegister], name: str, default: str = "") -> str:
    register = fields.get(name)
    if register is None or not isinstance(register.value, str):
        return default
    return register.value


def _max_ts(current: HLCTimestamp | None, candidate: str) -> HLCTimestamp:
    parsed = HLCTimestamp.decode(candidate)
    if current is None or parsed > current:
        return parsed
    return current


def _as_dict(state: Mapping[str, JSONValue], key: str) -> dict[str, JSONValue]:
    value = state.get(key, {})
    if not isinstance(value, dict):
        raise HabitableError(f"case state field {key!r} must be an object")
    return value


def _as_list(value: JSONValue) -> list[JSONValue]:
    if not isinstance(value, list):
        raise HabitableError("expected a list")
    return value
