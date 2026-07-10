# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""EXP-08: an on-device evidence-health roll-up across several vaults.

An organizer (P-07) who already holds the keys to several cases -- one vault
per unit in a building -- cannot tell, case by case, which units still need a
timestamp, are export-ready, or have a broken chain of custody. This module
opens the vaults an organizer *already legitimately holds keys to*, reads
each one's own already-computed state (the same facts ``habitable status``
shows for one case), and rolls them up into a building-level view and,
optionally, a combined multi-unit packet.

Nothing here becomes a new central store (invariant #1/#3): computing a
roll-up (:func:`build_campaign_report`) never writes anything, to any vault or
anywhere else -- it only reads. Assembling a combined packet
(:func:`build_campaign_packet`) has exactly the disclosure profile of running
``habitable export`` once per vault (each vault records its own
``INCLUDED_IN_PACKET`` custody entry, as it always does for an export) plus
one small manifest/index written to the *output* directory the organizer
chose; no case data is combined into a new shared store, and no vault learns
about any other vault.

This deliberately reuses the tested single-case core (:mod:`habitable.vault`,
:mod:`habitable.model`, :mod:`habitable.packet`) rather than forking it: a
unit's health is exactly the numbers ``habitable status`` already computes,
and a unit's packet is exactly what ``habitable export`` already produces.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from html import escape
from pathlib import Path
from typing import cast

from .canonical import JSONValue, canonical_json
from .errors import CustodyError
from .packet import PacketResult, build_packet
from .vault import Vault

__all__ = [
    "CAMPAIGN_VERSION",
    "CampaignPacketResult",
    "CampaignReport",
    "UnitHealth",
    "UnitPacketResult",
    "build_campaign_packet",
    "build_campaign_report",
    "health_for",
]

CAMPAIGN_VERSION = 1
_MANIFEST = "campaign_manifest.json"
_INDEX = "index.html"


@dataclass(frozen=True, slots=True)
class UnitHealth:
    """Read-only evidence-health for one vault -- one building unit/case."""

    vault_path: Path
    case_id: str
    unit: str
    issue_count: int
    capture_count: int
    timestamped_count: int
    awaiting_count: int
    timeline_count: int
    custody_intact: bool
    custody_length: int
    custody_error: str = ""

    @property
    def export_ready(self) -> bool:
        """No captures awaiting a timestamp, an intact chain, and something to show."""
        return self.custody_intact and self.awaiting_count == 0 and self.capture_count > 0

    def to_json(self) -> dict[str, JSONValue]:
        return {
            "vault_path": str(self.vault_path),
            "case_id": self.case_id,
            "unit": self.unit,
            "issue_count": self.issue_count,
            "capture_count": self.capture_count,
            "timestamped_count": self.timestamped_count,
            "awaiting_count": self.awaiting_count,
            "timeline_count": self.timeline_count,
            "custody_intact": self.custody_intact,
            "custody_length": self.custody_length,
            "custody_error": self.custody_error,
            "export_ready": self.export_ready,
        }


@dataclass(frozen=True, slots=True)
class CampaignReport:
    """A building-level roll-up across every vault an organizer opened."""

    units: tuple[UnitHealth, ...]

    @property
    def unit_count(self) -> int:
        return len(self.units)

    @property
    def export_ready_count(self) -> int:
        return sum(1 for u in self.units if u.export_ready)

    @property
    def broken_custody_count(self) -> int:
        return sum(1 for u in self.units if not u.custody_intact)

    @property
    def awaiting_timestamp_count(self) -> int:
        return sum(u.awaiting_count for u in self.units)

    def to_json(self) -> dict[str, JSONValue]:
        return {
            "campaign_version": CAMPAIGN_VERSION,
            "unit_count": self.unit_count,
            "export_ready_count": self.export_ready_count,
            "broken_custody_count": self.broken_custody_count,
            "awaiting_timestamp_count": self.awaiting_timestamp_count,
            "units": cast(JSONValue, [u.to_json() for u in self.units]),
        }


@dataclass(frozen=True, slots=True)
class UnitPacketResult:
    """Where one unit's own packet landed inside a combined building export."""

    health: UnitHealth
    out_dir: Path
    packet: PacketResult


@dataclass(frozen=True, slots=True)
class CampaignPacketResult:
    """A combined, multi-unit building packet: one sub-packet per vault."""

    out_dir: Path
    manifest_path: Path
    index_path: Path
    report: CampaignReport
    units: tuple[UnitPacketResult, ...] = field(default_factory=tuple)


def health_for(vault: Vault, *, vault_path: Path | None = None) -> UnitHealth:
    """This vault's evidence-health, read-only -- the numbers behind ``status``.

    A broken chain of custody does not raise here: the whole point of a
    building roll-up is to surface *which* unit has a broken chain rather than
    aborting on the first one, so :class:`~habitable.errors.CustodyError` is
    caught and folded into ``custody_intact=False`` / ``custody_error``.
    """
    document = vault.document
    issues = document.issues()
    captures = document.captures()
    timeline = document.timeline()
    timestamped = sum(1 for c in captures if vault.get_token(c.capture_id) is not None)
    custody_length = len(vault.custody)
    custody_intact: bool
    custody_error = ""
    try:
        verification = vault.custody.verify()
    except CustodyError as exc:
        custody_intact = False
        custody_error = str(exc)
    else:
        custody_intact = verification.ok
        custody_length = verification.length
    return UnitHealth(
        vault_path=vault_path if vault_path is not None else vault.path,
        case_id=document.case_id,
        unit=document.get_meta("unit") or document.case_id,
        issue_count=len(issues),
        capture_count=len(captures),
        timestamped_count=timestamped,
        awaiting_count=len(vault.deferred()),
        timeline_count=len(timeline),
        custody_intact=custody_intact,
        custody_length=custody_length,
        custody_error=custody_error,
    )


def build_campaign_report(vaults: list[tuple[Path, Vault]]) -> CampaignReport:
    """Roll up read-only health across every already-open vault.

    ``vaults`` pairs each vault's own path (used only to label its row -- for
    a picture of which *unit* needs attention) with the already-opened
    :class:`~habitable.vault.Vault`. Nothing is written; opening the vaults is
    the caller's responsibility (see ``habitable campaign status``).
    """
    return CampaignReport(units=tuple(health_for(vault, vault_path=path) for path, vault in vaults))


def build_campaign_packet(
    vaults: list[tuple[Path, Vault]],
    out_dir: Path,
    *,
    include_originals: bool = False,
    make_pdf: bool = True,
    generated_at: str | None = None,
) -> CampaignPacketResult:
    """Assemble one packet per vault plus a building-level manifest + index.

    Each unit's packet is produced by the unmodified, tested
    :func:`habitable.packet.build_packet` -- this function only aggregates.
    Combining packets on disk this way (rather than merging case data into a
    single new store) keeps every unit's evidence independently verifiable
    with the existing ``habitable verify``, and keeps custody accountable to
    its own vault: each unit's export is recorded in *that* unit's own chain
    of custody, exactly as a standalone ``habitable export`` would record it.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    report = build_campaign_report(vaults)
    health_by_path = {health.vault_path: health for health in report.units}

    used_slugs: set[str] = set()
    unit_results: list[UnitPacketResult] = []
    for vault_path, vault in vaults:
        health = health_by_path[vault_path]
        slug = _unique_slug(health.unit or health.case_id, used_slugs)
        unit_dir = out_dir / slug
        packet = build_packet(
            vault,
            unit_dir,
            include_originals=include_originals,
            make_pdf=make_pdf,
            generated_at=generated_at,
        )
        unit_results.append(UnitPacketResult(health=health, out_dir=unit_dir, packet=packet))

    stamp = generated_at or _now_iso()
    manifest: dict[str, JSONValue] = {
        **report.to_json(),
        "generated_at": stamp,
        "units": cast(
            JSONValue,
            [
                {**result.health.to_json(), "packet_dir": result.out_dir.name}
                for result in unit_results
            ],
        ),
    }
    manifest_path = out_dir / _MANIFEST
    manifest_path.write_bytes(canonical_json(manifest))

    index_path = out_dir / _INDEX
    index_path.write_text(_render_index_html(report, unit_results, stamp), encoding="utf-8")

    return CampaignPacketResult(
        out_dir=out_dir,
        manifest_path=manifest_path,
        index_path=index_path,
        report=report,
        units=tuple(unit_results),
    )


def _unique_slug(label: str, used: set[str]) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", label.strip().lower()).strip("-") or "unit"
    slug = base
    n = 2
    while slug in used:
        slug = f"{base}-{n}"
        n += 1
    used.add(slug)
    return slug


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _render_index_html(
    report: CampaignReport, units: list[UnitPacketResult], generated_at: str
) -> str:
    """A small, self-contained, semantic HTML index for the combined packet.

    No color-only status (R-06/EXP-09 bar): readiness is stated in the row's
    own text, not conveyed by a swatch. Everything needed to read the roll-up
    is in the table itself -- no script, no external resource.
    """
    rows = []
    for result in units:
        h = result.health
        flag = (
            "export-ready"
            if h.export_ready
            else "custody broken"
            if not h.custody_intact
            else "awaiting timestamp"
            if h.awaiting_count
            else "no captures yet"
        )
        rows.append(
            "<tr>"
            f"<td>{escape(h.unit)}</td>"
            f"<td>{h.issue_count}</td>"
            f"<td>{h.timestamped_count}/{h.capture_count}</td>"
            f"<td>{'intact' if h.custody_intact else 'BROKEN'}</td>"
            f"<td>{escape(flag)}</td>"
            f'<td><a href="{escape(result.out_dir.name)}/packet.html">packet</a></td>'
            "</tr>"
        )
    summary = (
        f"{report.unit_count} unit(s): {report.export_ready_count} export-ready, "
        f"{report.broken_custody_count} with a broken chain of custody, "
        f"{report.awaiting_timestamp_count} capture(s) still awaiting a timestamp."
    )
    return (
        "<!doctype html>\n"
        '<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        "<title>Building evidence-health roll-up</title>\n</head>\n<body>\n"
        "<h1>Building evidence-health roll-up</h1>\n"
        f"<p>Generated on-device {escape(generated_at)}. {escape(summary)}</p>\n"
        "<table>\n<caption>Per-unit evidence health</caption>\n"
        "<thead><tr>"
        '<th scope="col">Unit</th><th scope="col">Issues</th>'
        '<th scope="col">Timestamp tokens attached</th><th scope="col">Custody</th>'
        '<th scope="col">Status</th><th scope="col">Packet</th>'
        "</tr></thead>\n<tbody>\n" + "\n".join(rows) + "\n</tbody>\n</table>\n"
        "</body>\n</html>\n"
    )
