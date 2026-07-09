# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Interpret a sensor/instrument CSV as independent corroboration (EXP-09).

A tenant's own photo can be waved away by opposing counsel as staged. A cheap
temperature logger's or moisture meter's CSV export — sealed, hashed, and
RFC 3161 timestamped exactly like any other capture — is a second, independent
instrument's record of the same condition. This module only *interprets* that
CSV for rendering (a small chart, a readings table, summary statistics); the
hashing/sealing/timestamping is unchanged and shared with every other capture
type (see :mod:`habitable.capture`).

Parsing is deliberately conservative: a two-column ``label,value`` CSV (header
optional) with a numeric value column. Anything else is reported as unparsed
rather than guessed at, so the packet never silently fabricates a chart from
data it misread.
"""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field

__all__ = ["SensorReading", "SensorSeries", "parse_sensor_csv"]

# A packet renders at most this many readings as an explicit table/chart; beyond
# that the series is summarized and marked truncated rather than bloating the
# packet with thousands of rows (the full data is still in the sealed original
# and, when included, the embedded originals directory).
_MAX_READINGS = 500


@dataclass(frozen=True, slots=True)
class SensorReading:
    """One row: an independent instrument's label (often a timestamp) and value."""

    label: str
    value: float


@dataclass(frozen=True, slots=True)
class SensorSeries:
    """A parsed instrument CSV, ready to render as a chart + accessible table."""

    label_header: str
    value_header: str
    unit: str | None
    readings: tuple[SensorReading, ...]
    total_rows: int
    truncated: bool
    minimum: float
    maximum: float
    mean: float
    warnings: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, object]:
        return {
            "label_header": self.label_header,
            "value_header": self.value_header,
            "unit": self.unit,
            "readings": [{"label": r.label, "value": r.value} for r in self.readings],
            "total_rows": self.total_rows,
            "truncated": self.truncated,
            "minimum": self.minimum,
            "maximum": self.maximum,
            "mean": self.mean,
            "warnings": list(self.warnings),
        }


def parse_sensor_csv(raw: bytes, *, max_readings: int = _MAX_READINGS) -> SensorSeries | None:
    """Parse a two-column instrument CSV, or return ``None`` if it cannot be read.

    Returns ``None`` (never raises) on anything that isn't confidently a
    ``label,value[,unit]`` table with at least one numeric reading — malformed
    input degrades to "no chart rendered" rather than a failed packet build or a
    misleading guess.
    """
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None

    try:
        rows = list(csv.reader(io.StringIO(text)))
    except csv.Error:
        return None
    rows = [row for row in rows if any(cell.strip() for cell in row)]
    if not rows:
        return None

    label_header, value_header, unit, data_rows = _split_header(rows)
    if len(data_rows) < 1:
        return None

    readings, skipped = _read_rows(data_rows)
    if not readings:
        return None

    warnings: list[str] = []
    if skipped:
        warnings.append(f"{skipped} row(s) skipped (non-numeric or malformed)")

    total_rows = len(readings)
    truncated = total_rows > max_readings
    shown = readings[:max_readings] if truncated else readings
    if truncated:
        warnings.append(f"showing first {max_readings} of {total_rows} reading(s)")

    values = [r.value for r in readings]
    return SensorSeries(
        label_header=label_header,
        value_header=value_header,
        unit=unit,
        readings=tuple(shown),
        total_rows=total_rows,
        truncated=truncated,
        minimum=min(values),
        maximum=max(values),
        mean=sum(values) / len(values),
        warnings=tuple(warnings),
    )


def _read_rows(data_rows: list[list[str]]) -> tuple[list[SensorReading], int]:
    """Parse ``label,value`` rows; return the readings and the count skipped.

    A row is skipped (not fatal) when it lacks a second column or its value
    column is non-numeric — the packet degrades gracefully rather than failing."""
    readings: list[SensorReading] = []
    skipped = 0
    for row in data_rows:
        if len(row) < 2:
            skipped += 1
            continue
        try:
            value = float(row[1].strip())
        except ValueError:
            skipped += 1
            continue
        readings.append(SensorReading(label=row[0].strip(), value=value))
    return readings, skipped


def _split_header(rows: list[list[str]]) -> tuple[str, str, str | None, list[list[str]]]:
    """Detect an optional header row and an optional unit in the value column name.

    A header is assumed when the second cell of the first row cannot be parsed as
    a number (a genuine reading's value column always can be)."""
    first = rows[0]
    has_header = len(first) >= 2 and not _is_number(first[1])
    if has_header:
        label_header = first[0].strip() or "Reading"
        raw_value_header = first[1].strip() or "Value"
        value_header, unit = _split_unit(raw_value_header)
        return label_header, value_header, unit, rows[1:]
    return "Reading", "Value", None, rows


def _split_unit(header: str) -> tuple[str, str | None]:
    """Pull a trailing ``(unit)`` off a header like ``Temperature (F)``."""
    if header.endswith(")") and "(" in header:
        name, _, rest = header.rpartition("(")
        unit = rest[:-1].strip()
        name = name.strip()
        if name and unit:
            return name, unit
    return header, None


def _is_number(cell: str) -> bool:
    try:
        float(cell.strip())
    except ValueError:
        return False
    return True
