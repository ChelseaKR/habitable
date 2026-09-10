# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Derive recipient-facing views of a packet bundle, shared by every renderer.

An evidence bundle presents the same machine-verifiable ``bundle.json``
three ways — a **cover sheet** (what this is, who produced it, what it covers), a
single **chronological timeline** that interleaves logged notes with captured
photos across every issue, and a **chain-of-custody / integrity summary** (content
hashes, RFC 3161 attestations, and the append-only custody proof). Putting the
derivation here — as pure functions over the bundle mapping, with no reportlab or
HTML — keeps the PDF and the accessible HTML rendering from drifting apart and
makes the presentation logic testable on its own.

Nothing here reads a file or mutates state; it only reshapes data already present
in (and signed as part of) the bundle, so the views are as reproducible as the
bundle itself.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TypeGuard

from .canonical import JSONValue
from .timeline import event_label, source_label
from .verify import REDUNDANCY_STATES

__all__ = [
    "REDUNDANCY_STATES",
    "ChronologyEntry",
    "CoverSheet",
    "IntegrityRow",
    "IntegritySummary",
    "PacketRedundancy",
    "chronology",
    "cover_sheet",
    "integrity_summary",
    "packet_redundancy",
    "redundancy_sentence",
]

#: The two states a *reader* can reach that no producer can write: a packet that
#: says nothing, and a packet that says something unparseable. Neither carries a
#: count, and neither is ``this_device_only``.
_READER_STATES = ("not_stated", "unreadable")


@dataclass(frozen=True, slots=True)
class PacketRedundancy:
    """How many devices are known to hold this case, as this packet states it.

    Issue #297 (RR-07). A recipient asking "if the tenant loses her phone, does
    this case still exist?" has, until now, had nowhere to look. The answer is a
    **count and never an identity**: naming the peers would put a social graph of
    a tenant union into a document that goes to a landlord's solicitor.

    Four states, because the three obvious ones collapse the distinction this
    project keeps making. ``acknowledged`` and ``this_device_only`` are
    measurements a producer wrote down. ``not_stated`` is a packet that predates
    the field -- every bundle exported before this shipped, and the six committed
    golden fixtures -- and it is not the same fact as "one device": rendering it
    as ``1`` would publish a redundancy claim nobody made. ``unreadable`` is a
    packet that carries the field in a shape this reader cannot parse, which is
    also not "one device", and which a verifier is entitled to complain about
    while a renderer still has to print something.

    ``device_count`` and ``acknowledged_by`` are therefore ``None`` rather than
    ``0`` in both reader states. There is no number to round down to.
    """

    state: str
    device_count: int | None
    acknowledged_by: int | None
    as_of: str

    @property
    def stated(self) -> bool:
        """True when the packet actually carries a readable count."""
        return self.state in REDUNDANCY_STATES


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
    redundancy: PacketRedundancy
    copies: str


@dataclass(frozen=True, slots=True)
class ItemExtent:
    """How many media records this packet holds, and how many carry a token.

    Derived from ``items``, never from ``appendix``. The appendix declares the
    same three facts, and the verifier now re-derives them, so a mismatch is a
    verification failure rather than a silent one. But a renderer must not
    depend on having been handed a *verified* bundle: an absent or zeroed
    ``appendix.item_count`` used to render as "Media items: 0" beside an
    appendix table listing several, and -- worse -- to suppress two disclosures
    outright, because both are printed only when a difference is positive.

    Absence therefore does not reach a renderer as a number here. It reaches it
    as the records themselves, which are the same records the appendix table,
    the chronology, and the integrity rows are already built from. One source,
    the one the reader can check against the page.
    """

    item_count: int
    timestamped_count: int
    includes_originals: bool

    @property
    def awaiting(self) -> int:
        """Items with no timestamp token.

        Cannot be negative, and deliberately not clamped to say so: both counts
        come from one pass over the same list, and ``timestamped_count`` counts
        a subset of what ``item_count`` counts. A ``max(0, ...)`` here would be
        a guard no input can reach, which is worse than none -- it would read as
        protection against a case that cannot arise, and it would hide a real
        contradiction if the two ever stopped being derived together. The
        invariant is asserted in ``test_bundleview`` instead.
        """
        return self.item_count - self.timestamped_count


def item_extent(bundle: Mapping[str, JSONValue]) -> ItemExtent:
    """Count the packet's media records, its tokens, and its sealed originals."""
    item_count = 0
    timestamped_count = 0
    includes_originals = False
    for raw in _list(bundle, "items"):
        if not isinstance(raw, dict):
            continue
        item_count += 1
        if isinstance(raw.get("timestamp"), Mapping):
            timestamped_count += 1
        if raw.get("has_original") is True:
            includes_originals = True
    return ItemExtent(
        item_count=item_count,
        timestamped_count=timestamped_count,
        includes_originals=includes_originals,
    )


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
    timestamp_status: str  # "attached-unassessed" | "awaiting"
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
    extent = item_extent(bundle)
    scope = _map(bundle, "scope")
    unit = _s(bundle, "unit")
    title = "Habitability evidence bundle"
    if unit:
        title = f"{title} — unit {unit}"
    times = sorted(e.when for e in chronology(bundle) if e.when)
    redundancy = packet_redundancy(bundle)
    return CoverSheet(
        title=title,
        case_id=_s(bundle, "case_id"),
        unit=unit,
        scope=_scope_text(scope),
        generated_at=_s(bundle, "generated_at"),
        producer_fingerprint=_s(bundle, "producer_fingerprint"),
        issue_count=len(_list(bundle, "issues")),
        item_count=extent.item_count,
        timestamped_count=extent.timestamped_count,
        custody_length=_custody_length(_map(bundle, "custody_proof")),
        includes_originals=extent.includes_originals,
        earliest=times[0] if times else "",
        latest=times[-1] if times else "",
        redundancy=redundancy,
        copies=redundancy_sentence(redundancy, _s(bundle, "language") or "en"),
    )


_REDUNDANCY_SENTENCES: dict[str, dict[str, str]] = {
    "en": {
        "acknowledged": (
            "{devices} devices, as of {as_of}: the device that produced this packet, "
            "and {acknowledged} paired device(s) that returned a signed acknowledgement "
            "of holding this case. Devices are counted, never named."
        ),
        "acknowledged_undated": (
            "{devices} devices: the device that produced this packet, and {acknowledged} "
            "paired device(s) that returned a signed acknowledgement of holding this "
            "case. The producing device recorded no time for the most recent one. "
            "Devices are counted, never named."
        ),
        "this_device_only": (
            "1 device. When this packet was produced, no other device had acknowledged "
            "holding the case, so the evidence existed in one place."
        ),
        "not_stated": (
            "not stated. This packet was produced before habitable recorded a device "
            "count, so the number of copies is unknown here — which is not the same as "
            "one."
        ),
        "unreadable": (
            "not readable. This packet carries a device count in a shape this reader "
            "does not understand, so no number is shown rather than a wrong one. Run "
            "`habitable verify`, which reports the malformed field."
        ),
    },
    "es": {
        "acknowledged": (
            "{devices} dispositivos, al {as_of}: el dispositivo que generó este "
            "expediente y {acknowledged} dispositivo(s) vinculado(s) que devolvieron "
            "una confirmación firmada de que tienen este caso. Los dispositivos se "
            "cuentan, nunca se nombran."
        ),
        "acknowledged_undated": (
            "{devices} dispositivos: el dispositivo que generó este expediente y "
            "{acknowledged} dispositivo(s) vinculado(s) que devolvieron una confirmación "
            "firmada de que tienen este caso. El dispositivo emisor no registró la hora "
            "de la más reciente. Los dispositivos se cuentan, nunca se nombran."
        ),
        "this_device_only": (
            "1 dispositivo. Cuando se generó este expediente, ningún otro dispositivo "
            "había confirmado que tuviera el caso, así que las pruebas existían en un "
            "solo lugar."
        ),
        "not_stated": (
            "no se indica. Este expediente se generó antes de que habitable registrara "
            "un recuento de dispositivos, así que aquí se desconoce el número de copias, "
            "lo cual no es lo mismo que uno."
        ),
        "unreadable": (
            "no se puede leer. Este expediente trae un recuento de dispositivos en un "
            "formato que este lector no entiende, así que no se muestra ningún número en "
            "lugar de uno equivocado. Ejecute `habitable verify`, que informa del campo "
            "mal formado."
        ),
    },
}


def redundancy_sentence(redundancy: PacketRedundancy, language: str) -> str:
    """Say how many devices hold the case, in words, without naming any of them.

    The undated variant is a separate sentence rather than a formatted-in "" or
    an epoch date: a count with no time beside it is a weaker claim than a
    current one, and a reader has to be able to tell them apart.
    """
    lang = "es" if language.lower().startswith("es") else "en"
    sentences = _REDUNDANCY_SENTENCES[lang]
    if redundancy.state == "acknowledged":
        key = "acknowledged" if redundancy.as_of else "acknowledged_undated"
        return sentences[key].format(
            devices=redundancy.device_count,
            acknowledged=redundancy.acknowledged_by,
            as_of=redundancy.as_of,
        )
    if redundancy.state in sentences:
        return sentences[redundancy.state]
    return sentences["unreadable"]


def packet_redundancy(bundle: Mapping[str, JSONValue]) -> PacketRedundancy:
    """Read ``appendix.redundancy``, distinguishing absent from unreadable.

    Every rejection below lands on ``unreadable`` rather than on a default,
    because the two failure directions are not symmetric: a reader that quietly
    substituted ``this_device_only`` for a field it could not parse would publish
    the project's worst redundancy claim -- "the evidence exists in one place" --
    on the strength of a parse error.
    """
    appendix = _map(bundle, "appendix")
    if "redundancy" not in appendix:
        return _reader_redundancy("not_stated")
    raw = appendix.get("redundancy")
    if not isinstance(raw, Mapping):
        return _reader_redundancy("unreadable")
    state = raw.get("state")
    devices = raw.get("device_count")
    acknowledged = raw.get("acknowledged_by")
    if not isinstance(state, str) or state not in REDUNDANCY_STATES:
        return _reader_redundancy("unreadable")
    if not _is_count(devices) or not _is_count(acknowledged):
        return _reader_redundancy("unreadable")
    # The two halves have to agree, or the sentence is arithmetic nobody did:
    # the producing device is always one of the devices it is counting.
    if devices != acknowledged + 1:
        return _reader_redundancy("unreadable")
    if (state == "this_device_only") != (acknowledged == 0):
        return _reader_redundancy("unreadable")
    as_of = raw.get("as_of")
    return PacketRedundancy(
        state=state,
        device_count=devices,
        acknowledged_by=acknowledged,
        as_of=as_of if isinstance(as_of, str) else "",
    )


def _reader_redundancy(state: str) -> PacketRedundancy:
    """A state a reader reached, which therefore carries no counts at all."""
    assert state in _READER_STATES
    return PacketRedundancy(state=state, device_count=None, acknowledged_by=None, as_of="")


def _is_count(value: object) -> TypeGuard[int]:
    """An integer this can render. ``True`` is an ``int`` in Python and is not one."""
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


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
        if version >= 3:
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
        stamp = (
            "timestamp token attached; authority trust not assessed"
            if isinstance(token, dict)
            else "awaiting timestamp token"
        )
        content_hash = _s(raw, "content_hash")
        detail = f"hash {content_hash[:16]}… · {stamp}"
        artifact = _map(raw, "artifact")
        is_artifact = _s(raw, "record_kind") == "artifact"
        entries.append(
            ChronologyEntry(
                when=_s(raw, "captured_at"),
                when_label=(
                    ("Documento" if spanish else "Document")
                    if is_artifact
                    else ("Capturado" if spanish else "Captured")
                ),
                kind="artifact" if is_artifact else "photo",
                label=(
                    _s(artifact, "artifact_type").replace("_", " ")
                    if is_artifact
                    else ("foto" if spanish else "photo")
                ),
                issue_id=issue_id,
                issue_title=titles.get(issue_id, issue_id),
                text=(
                    _s(artifact, "title")
                    if is_artifact
                    else (
                        f"Evidencia capturada para {titles.get(issue_id, issue_id)}"
                        if spanish
                        else f"Evidence captured for {titles.get(issue_id, issue_id)}"
                    )
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
    # Derived from the same rows this summary builds below, so the totals and
    # the per-item statuses cannot disagree.
    extent = item_extent(bundle)

    rows: list[IntegrityRow] = []
    for raw in _list(bundle, "items"):
        if not isinstance(raw, dict):
            continue
        capture_id = _s(raw, "capture_id")
        token = raw.get("timestamp")
        authorities: list[str] = []
        status = "awaiting"
        if isinstance(token, dict):
            status = "attached-unassessed"
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
        custody_length=_custody_length(proof),
        custody_head=_s(proof, "head_hash"),
        timestamped_count=extent.timestamped_count,
        item_count=extent.item_count,
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


def _custody_length(proof: Mapping[str, JSONValue]) -> int:
    """How many custody entries there are — counted, not taken on the proof's word.

    This number is printed on a cover sheet and in an integrity summary, next to
    numbers a verifier vouches for. Until issue #278 it was ``proof["length"]``,
    the *declared* value, and `habitable.verify` never looked at it: a renderer
    was showing a reader a figure nothing had checked. ``verify._verify_custody``
    now refuses a packet whose declared length disagrees with its entries, and
    this counts the entries itself, so the two readers of this structure agree
    and the rendered figure is one of them rather than neither.

    The declared value remains the fallback for a summary-only proof (one carrying
    no ``entries`` at all), which is the only shape where there is nothing to
    count. That is a view of less evidence, not a more permissive view of the
    same evidence.
    """
    entries = _list(proof, "entries")
    return len(entries) if entries else _i(proof, "length")


def _issue_title(issue: Mapping[str, JSONValue]) -> str:
    return _s(issue, "title") or _s(issue, "category") or _s(issue, "issue_id")


def _hlc_to_iso(hlc: str) -> str:
    """Render the wall-clock part of a hybrid-logical-clock stamp as ISO 8601 UTC.

    A stamp encodes ``<wall_ms>.<counter>.<node_id>``; the leading field is Unix
    milliseconds. We surface only the wall time for human reading. The signed
    ``bundle.json`` commits to the rendered sequence; timeline notes are not
    individually timestamped or custody-logged.
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
