# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Derive the court-ready *views* of a packet bundle, shared by every renderer.

A court-ready evidence bundle presents the same machine-verifiable ``bundle.json``
three ways — a **cover sheet** (what this is, who produced it, what it covers), a
single **chronological timeline** that interleaves logged notes with captured
photos across every issue, and a **chain-of-custody / integrity summary** (content
hashes, RFC 3161 attestations, and the append-only custody proof). Putting the
derivation here — as pure functions over the bundle mapping, with no reportlab or
HTML — keeps the PDF and the accessible HTML rendering from drifting apart and
makes the court-ready logic testable on its own.

Nothing here reads a file or mutates state; it only reshapes data already present
in (and signed as part of) the bundle, so the views are as reproducible as the
bundle itself.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime

from .canonical import JSONValue
from .timeline import event_label, source_label

__all__ = [
    "ChronologyEntry",
    "CoverSheet",
    "IntegrityRow",
    "IntegritySummary",
    "chronology",
    "cover_sheet",
    "integrity_summary",
]


@dataclass(frozen=True, slots=True)
class CoverSheet:
    """The front-matter facts a recipient needs before reading the evidence."""

    title: str
    case_id: str
    unit: str
    scope: str
    generated_at: str
    producer_fingerprint: str
    issue_count: int
    item_count: int
    timestamped_count: int
    custody_length: int
    includes_originals: bool
    earliest: str
    latest: str


@dataclass(frozen=True, slots=True)
class ChronologyEntry:
    """One row of the unified, chronological evidence timeline."""

    when: str  # ISO 8601 UTC; "" if unknown
    when_label: str  # localized: Occurred / Recorded / Captured
    kind: str  # "note" | "event" | "photo"
    label: str  # note kind (e.g. "observed") or "photo"
    issue_id: str
    issue_title: str
    text: str  # note text, or a photo caption
    detail: str  # extra facts (hash + timestamp status for a photo)


@dataclass(frozen=True, slots=True)
class IntegrityRow:
    """The integrity facts for one media item."""

    capture_id: str
    content_hash: str
    timestamp_status: str  # "verified" | "awaiting"
    authorities: tuple[str, ...]
    archive_count: int
    custody_entries: int
    custody_head: str
    shared_hash: str


@dataclass(frozen=True, slots=True)
class IntegritySummary:
    """The whole-bundle integrity picture: custody proof + per-item attestations."""

    algorithm: str
    custody_length: int
    custody_head: str
    timestamped_count: int
    item_count: int
    rows: tuple[IntegrityRow, ...] = field(default_factory=tuple)


def cover_sheet(bundle: Mapping[str, JSONValue]) -> CoverSheet:
    """Derive the cover-sheet facts from ``bundle``."""
    appendix = _map(bundle, "appendix")
    scope = _map(bundle, "scope")
    unit = _s(bundle, "unit")
    title = "Habitability evidence bundle"
    if unit:
        title = f"{title} — unit {unit}"
    times = sorted(e.when for e in chronology(bundle) if e.when)
    return CoverSheet(
        title=title,
        case_id=_s(bundle, "case_id"),
        unit=unit,
        scope=_scope_text(scope),
        generated_at=_s(bundle, "generated_at"),
        producer_fingerprint=_s(bundle, "producer_fingerprint"),
        issue_count=len(_list(bundle, "issues")),
        item_count=_i(appendix, "item_count"),
        timestamped_count=_i(appendix, "timestamped_count"),
        custody_length=_i(_map(bundle, "custody_proof"), "length"),
        includes_originals=appendix.get("includes_originals") is True,
        earliest=times[0] if times else "",
        latest=times[-1] if times else "",
    )


def chronology(bundle: Mapping[str, JSONValue]) -> tuple[ChronologyEntry, ...]:
    """A single timeline interleaving notes and photos across all issues, in time order.

    Notes are placed at the time they were logged (decoded from their hybrid logical
    clock); photos at the time they were captured. Sorting is by the ISO time string
    (which sorts chronologically), with the capture/entry id as a stable tiebreaker so
    the order is deterministic and reproducible.
    """
    titles = {
        _s(issue, "issue_id"): _issue_title(issue)
        for issue in _list(bundle, "issues")
        if isinstance(issue, dict)
    }
    entries: list[ChronologyEntry] = []
    version = _i(bundle, "packet_version") or 1
    language = _s(bundle, "language") or "en"
    spanish = language.lower().startswith("es")
    included_capture_ids = {
        _s(item, "capture_id")
        for item in _list(bundle, "items")
        if isinstance(item, dict) and _s(item, "capture_id")
    }

    for raw in _list(bundle, "timeline"):
        if not isinstance(raw, dict):
            continue
        issue_id = _s(raw, "issue_id")
        if version == 3:
            occurred_at = _s(raw, "occurred_at")
            recorded_at = _s(raw, "recorded_at")
            entries.append(
                ChronologyEntry(
                    when=occurred_at or recorded_at,
                    when_label=(
                        ("Ocurrió" if spanish else "Occurred")
                        if occurred_at
                        else ("Registrado" if spanish else "Recorded")
                    ),
                    kind="event",
                    label=event_label(language, _s(raw, "event_type"), _s(raw, "other_label")),
                    issue_id=issue_id,
                    issue_title=titles.get(issue_id, issue_id),
                    text=_s(raw, "text"),
                    detail=_v3_timeline_detail(raw, language, included_capture_ids),
                )
            )
        else:
            # v1 carried a raw HLC whose wall clock could be rendered. v2 made
            # that field opaque for privacy. Never reinterpret the v2 token as a
            # date; an unknown date is more honest than a guessed one.
            entries.append(
                ChronologyEntry(
                    when=_hlc_to_iso(_s(raw, "hlc")) if version == 1 else "",
                    when_label="Registrado" if spanish else "Recorded",
                    kind="note",
                    label=_s(raw, "kind") or ("nota" if spanish else "note"),
                    issue_id=issue_id,
                    issue_title=titles.get(issue_id, issue_id),
                    text=_s(raw, "text"),
                    detail="",
                )
            )

    for raw in _list(bundle, "items"):
        if not isinstance(raw, dict):
            continue
        issue_id = _s(raw, "issue_id")
        token = raw.get("timestamp")
        stamp = "trusted-timestamped" if isinstance(token, dict) else "awaiting timestamp"
        content_hash = _s(raw, "content_hash")
        detail = f"hash {content_hash[:16]}… · {stamp}"
        entries.append(
            ChronologyEntry(
                when=_s(raw, "captured_at"),
                when_label="Capturado" if spanish else "Captured",
                kind="photo",
                label="foto" if spanish else "photo",
                issue_id=issue_id,
                issue_title=titles.get(issue_id, issue_id),
                text=(
                    f"Evidencia capturada para {titles.get(issue_id, issue_id)}"
                    if spanish
                    else f"Evidence captured for {titles.get(issue_id, issue_id)}"
                ),
                detail=detail,
            )
        )

    entries.sort(key=lambda e: (e.when or "9999", e.kind, e.text))
    return tuple(entries)


def _v3_timeline_detail(
    entry: Mapping[str, JSONValue], language: str, included_capture_ids: set[str]
) -> str:
    """Deterministic EN/ES explanation of source, recording time, and links."""
    spanish = language.lower().startswith("es")
    integrity = _map(entry, "integrity")
    links = _map(entry, "links")
    stage = _s(integrity, "binding_stage")
    stage_labels = {
        "recorded": "protegido por custodia al registrarse"
        if spanish
        else "custody-bound when recorded",
        "backfill": "protección de custodia agregada después"
        if spanish
        else "custody binding added later",
        "migration": "protección de custodia agregada durante la migración"
        if spanish
        else "custody binding added during migration",
    }
    parts = [
        ("Fuente" if spanish else "Source")
        + ": "
        + source_label(language, _s(entry, "source"), _s(entry, "source_detail")),
        ("Registrado" if spanish else "Recorded") + ": " + (_s(entry, "recorded_at") or "—"),
    ]
    if not _s(entry, "occurred_at"):
        parts.append(
            "fecha de ocurrencia no registrada" if spanish else "occurrence date not recorded"
        )
    if stage:
        parts.append(stage_labels.get(stage, stage))
    raw_capture_ids = links.get("capture_ids")
    if isinstance(raw_capture_ids, list):
        for capture_id in raw_capture_ids:
            if isinstance(capture_id, str):
                capture_link = ("captura" if spanish else "capture") + f" {capture_id}"
                if capture_id not in included_capture_ids:
                    capture_link += (
                        " (no incluida en este paquete)"
                        if spanish
                        else " (not included in this packet)"
                    )
                parts.append(capture_link)
    link_labels = {
        "notice_entry_id": "aviso" if spanish else "notice",
        "receipt_entry_id": "entrega" if spanish else "delivery",
        "response_entry_id": "respuesta" if spanish else "response",
    }
    for key, label in link_labels.items():
        target = _s(links, key)
        if target:
            parts.append(f"{label} {target}")
    return " · ".join(parts)


def integrity_summary(bundle: Mapping[str, JSONValue]) -> IntegritySummary:
    """Derive the chain-of-custody + per-item RFC 3161 attestation summary."""
    proof = _map(bundle, "custody_proof")
    custody_items = _map(proof, "items")
    appendix = _map(bundle, "appendix")

    rows: list[IntegrityRow] = []
    for raw in _list(bundle, "items"):
        if not isinstance(raw, dict):
            continue
        capture_id = _s(raw, "capture_id")
        token = raw.get("timestamp")
        authorities: list[str] = []
        status = "awaiting"
        if isinstance(token, dict):
            status = "verified"
            authorities.append(_s(token, "tsa_name"))
        for extra in _list(raw, "additional_timestamps"):
            if isinstance(extra, dict):
                authorities.append(_s(extra, "tsa_name"))
        item_custody = _map(custody_items, capture_id)
        rows.append(
            IntegrityRow(
                capture_id=capture_id,
                content_hash=_s(raw, "content_hash"),
                timestamp_status=status,
                authorities=tuple(a for a in authorities if a),
                archive_count=len(_list(raw, "archive_timestamps")),
                custody_entries=_i(item_custody, "entries"),
                custody_head=_s(item_custody, "head_hash"),
                shared_hash=_s(raw, "shared_hash"),
            )
        )

    return IntegritySummary(
        algorithm=_s(proof, "algorithm") or _s(bundle, "hash_algorithm") or "sha256",
        custody_length=_i(proof, "length"),
        custody_head=_s(proof, "head_hash"),
        timestamped_count=_i(appendix, "timestamped_count"),
        item_count=_i(appendix, "item_count"),
        rows=tuple(rows),
    )


# --- helpers ------------------------------------------------------------------


def _scope_text(scope: Mapping[str, JSONValue]) -> str:
    kind = _s(scope, "type") or "unit"
    if kind == "issue" and _s(scope, "issue_id"):
        text = f"a single issue ({_s(scope, 'issue_id')})"
    else:
        text = "the whole unit"
    since = _s(scope, "since")
    if since:
        text = f"{text}, items on/after {since}"
    return text


def _issue_title(issue: Mapping[str, JSONValue]) -> str:
    return _s(issue, "title") or _s(issue, "category") or _s(issue, "issue_id")


def _hlc_to_iso(hlc: str) -> str:
    """Render the wall-clock part of a hybrid-logical-clock stamp as ISO 8601 UTC.

    A stamp encodes ``<wall_ms>.<counter>.<node_id>``; the leading field is Unix
    milliseconds. We surface only the wall time for human reading — the proof of
    *order* is the append-only custody chain, not this rendered timestamp.
    """
    head = hlc.split(".", 1)[0]
    if not head.isdigit():
        return ""
    try:
        moment = datetime.fromtimestamp(int(head) / 1000, tz=UTC)
    except ValueError, OSError, OverflowError:
        return ""
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _s(mapping: Mapping[str, JSONValue], key: str) -> str:
    value = mapping.get(key)
    return value if isinstance(value, str) else ""


def _i(mapping: Mapping[str, JSONValue], key: str) -> int:
    value = mapping.get(key)
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _list(mapping: Mapping[str, JSONValue], key: str) -> list[JSONValue]:
    value = mapping.get(key)
    return value if isinstance(value, list) else []


def _map(mapping: Mapping[str, JSONValue], key: str) -> Mapping[str, JSONValue]:
    value = mapping.get(key)
    return value if isinstance(value, dict) else {}
