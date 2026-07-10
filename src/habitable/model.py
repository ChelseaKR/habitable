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

import base64
import hashlib
import hmac
import secrets
from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import cast

from .canonical import JSONValue, canonical_json
from .clock import HLCTimestamp, HybridLogicalClock
from .crypto import Identity
from .crypto import verify as verify_signature
from .errors import HabitableError

__all__ = [
    "Capture",
    "CaseDocument",
    "FieldProvenance",
    "GrowLog",
    "Issue",
    "LWWRegister",
    "ORSet",
    "TimelineEntry",
    "verify_state_provenance",
]

CASE_SCHEMA_VERSION = 1

# The per-case id salt lives in the document meta under this key, so it merges and
# syncs to peers exactly like ``unit`` (an LWWRegister). It is the secret that turns a
# wall-clock/node-bearing HLC into an opaque exported id — see :meth:`CaseDocument.opaque_id`.
_CASE_SALT_META = "case_salt"


def _greater(a: JSONValue, b: JSONValue) -> bool:
    """Deterministic tiebreaker for equal-timestamp writes."""
    return canonical_json(a) > canonical_json(b)


def _provenance_payload(case_id: str, target: str, value: JSONValue, ts: str, kind: str) -> bytes:
    """Canonical bytes binding a field write to its case, target, value, and clock."""
    return canonical_json(
        cast(
            JSONValue,
            {"case_id": case_id, "kind": kind, "target": target, "ts": ts, "value": value},
        )
    )


@dataclass(frozen=True, slots=True)
class FieldProvenance:
    """The device attribution carried by the current value of one field."""

    actor: str
    ts: str
    signed: bool
    kind: str


@dataclass(frozen=True, slots=True)
class LWWRegister:
    """A last-writer-wins value with optional signed device provenance."""

    value: JSONValue
    ts: str  # encoded HLCTimestamp
    actor: str = ""
    sig: str = ""
    provenance_kind: str = ""

    def merge(self, other: LWWRegister) -> LWWRegister:
        mine, theirs = HLCTimestamp.decode(self.ts), HLCTimestamp.decode(other.ts)
        if theirs > mine:
            return other
        if mine > theirs:
            return self
        # Equal timestamps (same node+counter): break ties over the whole
        # register, including provenance. Two legacy replicas can attest the
        # same old value with different device keys; merge order must still not
        # decide which attestation survives.
        mine_json = cast(JSONValue, self.to_json())
        other_json = cast(JSONValue, other.to_json())
        return other if _greater(other_json, mine_json) else self

    def to_json(self) -> dict[str, JSONValue]:
        payload: dict[str, JSONValue] = {"value": self.value, "ts": self.ts}
        if self.actor:
            payload["actor"] = self.actor
        if self.sig:
            payload["sig"] = self.sig
        if self.provenance_kind:
            payload["provenance_kind"] = self.provenance_kind
        return payload

    @classmethod
    def from_json(cls, raw: Mapping[str, JSONValue]) -> LWWRegister:
        ts = raw.get("ts")
        if not isinstance(ts, str):
            raise HabitableError("LWWRegister 'ts' must be a string")
        actor = raw.get("actor", "")
        signature = raw.get("sig", "")
        kind = raw.get("provenance_kind", "")
        if (
            not isinstance(actor, str)
            or not isinstance(signature, str)
            or not isinstance(kind, str)
        ):
            raise HabitableError("LWWRegister provenance fields must be strings")
        return cls(
            value=raw.get("value"),
            ts=ts,
            actor=actor,
            sig=signature,
            provenance_kind=kind,
        )

    def verify(self, case_id: str, target: str, public_key: bytes) -> bool:
        if not self.sig or self.provenance_kind not in {"authored", "attested_legacy"}:
            return False
        try:
            signature = base64.b64decode(self.sig, validate=True)
        except ValueError, TypeError:
            return False
        payload = _provenance_payload(case_id, target, self.value, self.ts, self.provenance_kind)
        return verify_signature(public_key, payload, signature)


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
    transcript: str = ""
    """Plain-text description of a video/audio recording (EXP-07): the
    accessible fallback for temporal evidence, analogous to a photo's alt text."""


_ISSUE_FIELDS = ("category", "room", "title", "status", "severity", "description")


class CaseDocument:
    """A single case as a mergeable CRDT document."""

    __slots__ = (
        "_captures",
        "_case_id",
        "_clock",
        "_identity",
        "_issue_fields",
        "_issues",
        "_meta",
        "_timeline",
    )

    def __init__(
        self, case_id: str, clock: HybridLogicalClock, identity: Identity | None = None
    ) -> None:
        self._case_id = case_id
        self._clock = clock
        self._identity = identity
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

    def set_identity(self, identity: Identity | None) -> None:
        """Set the device key used to sign subsequent mutable field writes."""
        self._identity = identity

    # --- mutations ------------------------------------------------------------

    def _stamp(
        self, target: str, value: JSONValue, ts: str, *, kind: str = "authored"
    ) -> LWWRegister:
        if self._identity is None:
            return LWWRegister(value=value, ts=ts)
        actor = self._identity.public().fingerprint
        signature = self._identity.sign(_provenance_payload(self._case_id, target, value, ts, kind))
        return LWWRegister(
            value=value,
            ts=ts,
            actor=actor,
            sig=base64.b64encode(signature).decode("ascii"),
            provenance_kind=kind,
        )

    def attest_unsigned_fields(self) -> int:
        """Sign legacy mutable values without changing their CRDT timestamps.

        This is an explicit migration attestation, not a claim that this device
        originally authored the value. Protocol v2 rejects unsigned mutable
        fields on import, so a peer cannot strip provenance and call it legacy.
        """
        if self._identity is None:
            raise HabitableError("cannot attest legacy fields without a device identity")
        changed = 0
        for key, register in tuple(self._meta.items()):
            if not register.actor and not register.sig and not register.provenance_kind:
                self._meta[key] = self._stamp(
                    f"meta:{key}", register.value, register.ts, kind="attested_legacy"
                )
                changed += 1
        for issue_id, registers in self._issue_fields.items():
            for name, register in tuple(registers.items()):
                if not register.actor and not register.sig and not register.provenance_kind:
                    registers[name] = self._stamp(
                        f"issue:{issue_id}:{name}",
                        register.value,
                        register.ts,
                        kind="attested_legacy",
                    )
                    changed += 1
        return changed

    def set_meta(self, key: str, value: str) -> None:
        ts = self._clock.now().encode()
        self._meta[key] = self._stamp(f"meta:{key}", value, ts)

    def get_meta(self, key: str, default: str = "") -> str:
        register = self._meta.get(key)
        if register is None or not isinstance(register.value, str):
            return default
        return register.value

    # --- opaque identifiers ---------------------------------------------------

    def ensure_case_salt(self) -> None:
        """Generate and store this case's id salt if the document lacks one.

        Called at case creation so exported ids are opaque from the first mint;
        documents that predate the salt get one lazily on their next mint.
        """
        self._case_salt()

    def opaque_id(self, prefix: str, hlc_str: str) -> str:
        """Mint a stable, opaque id for an event from the per-case salt.

        The id is ``f"{prefix}-{HMAC(salt, hlc)[:16]}"`` — deterministic per
        ``(salt, hlc)`` and therefore identical on every device that shares the case
        salt, yet it reveals neither the device wall clock nor the node id encoded in
        ``hlc_str``. HLC stays the internal ordering key for CRDT merge; this is only
        the externally visible name.
        """
        digest = hmac.new(self._case_salt(), hlc_str.encode(), hashlib.sha256).hexdigest()
        return f"{prefix}-{digest[:16]}"

    def _case_salt(self) -> bytes:
        salt_hex = self.get_meta(_CASE_SALT_META)
        if not salt_hex:
            salt_hex = secrets.token_bytes(16).hex()
            self.set_meta(_CASE_SALT_META, salt_hex)
        return bytes.fromhex(salt_hex)

    def meta_provenance(self, key: str) -> FieldProvenance | None:
        register = self._meta.get(key)
        if register is None:
            return None
        return FieldProvenance(
            register.actor, register.ts, bool(register.sig), register.provenance_kind
        )

    def field_provenance(self, issue_id: str, field: str) -> FieldProvenance | None:
        register = self._issue_fields.get(issue_id, {}).get(field)
        if register is None:
            return None
        return FieldProvenance(
            register.actor, register.ts, bool(register.sig), register.provenance_kind
        )

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
        resolved_id = issue_id or self.opaque_id("issue", tag)
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
            name: self._stamp(f"issue:{resolved_id}:{name}", value, tag)
            for name, value in fields.items()
        }
        return resolved_id

    def update_issue(self, issue_id: str, **fields: str) -> None:
        if issue_id not in self._issues.elements():
            raise HabitableError(f"unknown issue: {issue_id!r}")
        registers = self._issue_fields.setdefault(issue_id, {})
        for name, value in fields.items():
            if name not in _ISSUE_FIELDS:
                raise HabitableError(f"unknown issue field: {name!r}")
            ts = self._clock.now().encode()
            registers[name] = self._stamp(f"issue:{issue_id}:{name}", value, ts)

    def remove_issue(self, issue_id: str) -> None:
        self._issues = self._issues.remove(issue_id)

    def add_timeline_entry(self, issue_id: str, kind: str, text: str) -> str:
        stamp = self._clock.now()
        entry_id = self.opaque_id("tl", stamp.encode())
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
        transcript: str = "",
    ) -> str:
        stamp = self._clock.now()
        resolved_id = capture_id or self.opaque_id("cap", stamp.encode())
        self._captures = self._captures.add(
            resolved_id,
            {
                "issue_id": issue_id,
                "content_hash": content_hash,
                "media_type": media_type,
                "sealed_name": sealed_name,
                "hlc": stamp.encode(),
                "captured_at": captured_at,
                "transcript": transcript,
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
                transcript=str(payload.get("transcript", "")),
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

    def subset_state(
        self, issue_ids: set[str] | None, *, redact_meta: bool = False
    ) -> dict[str, JSONValue]:
        """A :meth:`to_state`-shaped CRDT state filtered to ``issue_ids`` (a redactable share).

        ``issue_ids`` of ``None`` selects every issue (the whole case). The result is a
        well-formed state — a *subset* of the same grow-only / observed-remove / LWW
        state — so merging it on a recipient's device is still a valid, commutative,
        idempotent CRDT join. With ``redact_meta`` the case-level metadata (e.g. the
        unit label) is dropped, so a shared subset need not disclose which unit it
        concerns. Captures and timeline entries are filtered to the selected issues,
        and only their issue-field registers travel.
        """
        if issue_ids is None and not redact_meta:
            return self.to_state()
        selected = self._issues.elements() if issue_ids is None else set(issue_ids)

        issues = ORSet(
            adds={i: tags for i, tags in self._issues.adds.items() if i in selected},
            removes=self._issues.removes,
        )
        issue_fields = {
            issue_id: {name: register.to_json() for name, register in registers.items()}
            for issue_id, registers in self._issue_fields.items()
            if issue_id in selected
        }
        timeline = {
            entry_id: payload
            for entry_id, payload in self._timeline.entries.items()
            if isinstance(payload, dict) and str(payload.get("issue_id", "")) in selected
        }
        captures = {
            capture_id: payload
            for capture_id, payload in self._captures.entries.items()
            if isinstance(payload, dict) and str(payload.get("issue_id", "")) in selected
        }
        return {
            "schema_version": CASE_SCHEMA_VERSION,
            "case_id": self._case_id,
            "meta": ({} if redact_meta else {k: r.to_json() for k, r in self._meta.items()}),
            "issues": issues.to_json(),
            "issue_fields": cast(JSONValue, issue_fields),
            "timeline": dict(timeline),
            "captures": dict(captures),
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


def verify_state_provenance(
    case_id: str, state: Mapping[str, JSONValue], actor: str, public_key: bytes
) -> list[str]:
    """Return every field claiming ``actor`` whose signature is invalid."""
    failures: list[str] = []
    for key, raw in _as_dict(state, "meta").items():
        if isinstance(raw, dict):
            _check_provenance(case_id, f"meta:{key}", raw, actor, public_key, failures)
    for issue_id, registers in _as_dict(state, "issue_fields").items():
        if not isinstance(registers, dict):
            continue
        for name, raw in registers.items():
            if isinstance(raw, dict):
                _check_provenance(
                    case_id,
                    f"issue:{issue_id}:{name}",
                    raw,
                    actor,
                    public_key,
                    failures,
                )
    return failures


def _check_provenance(
    case_id: str,
    target: str,
    raw: Mapping[str, JSONValue],
    actor: str,
    public_key: bytes,
    failures: list[str],
) -> None:
    register = LWWRegister.from_json(raw)
    if register.actor == actor and not register.verify(case_id, target, public_key):
        failures.append(target)


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
