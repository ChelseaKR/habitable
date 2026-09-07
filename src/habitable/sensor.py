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

__all__ = [
    "SensorExtent",
    "SensorLoss",
    "SensorReading",
    "SensorSeries",
    "parse_sensor_csv",
    "series_extent",
    "series_loss",
    "series_summary",
]

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
    #: Numeric readings the parser *understood*, before truncation. It is not the
    #: number of rows the source file held: rows that could not be read are in
    #: :attr:`skipped_rows` and in neither this count nor :attr:`mean`.
    total_rows: int
    truncated: bool
    minimum: float
    maximum: float
    mean: float
    warnings: tuple[str, ...] = field(default_factory=tuple)
    #: Data rows the parser could not read (no second column, or a non-numeric
    #: value). Carried structurally so a renderer can name it without reading it
    #: back out of an English sentence in ``warnings`` (issue #311).
    skipped_rows: int = 0

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
            "skipped_rows": self.skipped_rows,
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
        skipped_rows=skipped,
    )


@dataclass(frozen=True, slots=True)
class SensorExtent:
    """How much of an instrument series a rendering is actually showing.

    Both renderers reduce a series twice: ``parse_sensor_csv`` keeps at most
    :data:`_MAX_READINGS` of what the CSV held, and the PDF table then shows at most
    forty of those. A rendering that names one of those numbers as though it were the
    other tells a recipient the record is smaller, or more complete, than it is.

    ``total`` is ``None`` when the packet says it is carrying a prefix but does not say
    of what. That is a real state -- a bundle built by an older or a hostile producer --
    and it is reported as unknown rather than resolved to a number, because a count a
    reader would take at face value is exactly what is missing.
    """

    kept: int
    total: int | None

    @property
    def complete(self) -> bool:
        """True when the rendering carries every reading the instrument recorded."""
        return self.total is not None and self.total <= self.kept

    def table_label(self) -> str:
        """The control that opens the readings table, which may not claim to be all."""
        if self.complete:
            return f"Show all {self.kept} reading(s)"
        if self.total is None:
            return f"Show the first {self.kept} reading(s) of a longer series"
        return f"Show the first {self.kept} of {self.total} reading(s)"

    def table_note(self, shown: int) -> str:
        """For a rendering that shows fewer rows again than the packet carries.

        ``shown`` is that rendering's own limit. The note has to name three different
        numbers without conflating any two: how many rows are on the page, how many
        readings the instrument recorded, and how many of them ``bundle.json`` holds.
        Empty when the page is showing everything there is.
        """
        if shown >= self.kept and self.complete:
            return ""
        of_what = "a longer series" if self.total is None else f"{self.total} readings"
        head = (
            f"(showing {min(shown, self.kept)} rows of {of_what}"
            if not self.complete
            else f"(showing {shown} of {self.kept} readings"
        )
        if self.complete:
            return f"{head}; the rest are in bundle.json)"
        return (
            f"{head}; bundle.json carries the first {self.kept}, and the remainder is "
            "in the sealed original)"
        )

    def notice(self) -> str:
        """Said in full where a reader meets the chart, not only behind the table."""
        if self.complete:
            return ""
        scope = (
            f"the first {self.kept} readings of a longer series"
            if self.total is None
            else f"the first {self.kept} of {self.total} readings"
        )
        return (
            f"This chart and table show {scope}. The remainder is in the sealed "
            "original, not in this packet or in bundle.json."
        )


@dataclass(frozen=True, slots=True)
class SensorLoss:
    """What a series could not read at all, and whether the record even says.

    ``parse_sensor_csv`` drops a data row it cannot evaluate -- no second column, or a
    non-numeric value column -- and every figure downstream is then computed over the
    survivors. ``total_rows`` is that survivor count and ``mean`` is a ratio whose
    denominator excludes the dropped rows, so a 600-row export with 90 unreadable rows
    was reported as "510 reading(s) ... averaging X" with the 90 named nowhere a
    recipient would see them.

    ``skipped`` is ``None`` when the record does not carry ``skipped_rows`` -- a bundle
    written before that field existed. That is *unknown*, not zero, and the difference
    is the whole point of this class: a missing integer arrives from JSON as absent,
    ``dict.get`` turns it into ``None``, and an int coercion would turn it into ``0``,
    which is a sentence ("nothing was lost") that the record never said. An unrecorded
    loss is therefore rendered as silence, exactly as it rendered before the field
    existed, and the old bundle's own ``warnings`` prose keeps carrying the count.
    """

    #: Readings the parser understood: the denominator of the count and the mean.
    parsed: int
    #: Rows it could not read, or ``None`` when the record does not say.
    skipped: int | None

    @property
    def recorded(self) -> bool:
        """True when the record states a skipped-row count that can be believed."""
        return self.skipped is not None

    @property
    def lossy(self) -> bool:
        """True only when the record says, in a number, that rows were dropped."""
        return self.skipped is not None and self.skipped > 0

    @property
    def source_rows(self) -> int | None:
        """Data rows the source file held, or ``None`` when that cannot be known."""
        if self.skipped is None:
            return None
        return self.parsed + self.skipped

    def reading_count_phrase(self) -> str:
        """How the figcaption names its count: readings parsed, out of what."""
        if not self.lossy:
            return f"{self.parsed} reading(s)"
        return f"{self.parsed} reading(s) parsed from {self.source_rows} row(s) in the source file"

    def mean_scope_phrase(self) -> str:
        """What the average averaged over. Empty when nothing was left out of it."""
        if not self.lossy:
            return ""
        return f" over the {self.parsed} reading(s) parsed"

    def notice(self) -> str:
        """Said where a reader meets the chart, not only behind a collapsed control.

        Empty when there is nothing to disclose -- either the record says no row was
        dropped, or it does not say at all.
        """
        if not self.lossy:
            return ""
        return (
            f"{self.skipped} of the {self.source_rows} row(s) in the source file could not "
            "be read, so they are counted in neither the reading total nor the average. "
            "They remain in the sealed original."
        )


def series_loss(parsed: int, skipped: object) -> SensorLoss:
    """Read a series' ``skipped_rows`` field distrustfully.

    ``skipped`` is the raw JSON value as it arrives from ``bundle.json``, which may be
    absent, null, a string, a float, a bool, or negative. Anything that is not a
    non-negative integer is reported as *not recorded* rather than coerced, because
    every coercion available here (``int(...)``, ``or 0``, ``max(0, ...)``) turns a
    producer's silence or a producer's error into the claim that no row was lost.
    """
    if isinstance(skipped, bool) or not isinstance(skipped, int) or skipped < 0:
        return SensorLoss(parsed=parsed, skipped=None)
    return SensorLoss(parsed=parsed, skipped=skipped)


def series_summary(
    *,
    value_header: str,
    unit: str | None,
    minimum: float,
    maximum: float,
    mean: float,
    loss: SensorLoss,
) -> str:
    """The one measurement sentence both renderers print, built in one place.

    The HTML figcaption and the PDF summary paragraph used to hold two copies of this
    f-string. They agreed by coincidence, and issue #311 is partly a report that the
    two renderings of one bundle disagreed about what a reader is told; a single
    source is the only structural guarantee that they cannot drift again.
    """
    unit_suffix = f" {unit}" if unit else ""
    return (
        f"Instrument data ({value_header}): {loss.reading_count_phrase()}, "
        f"ranging {minimum:g}{unit_suffix} to {maximum:g}{unit_suffix}, "
        f"averaging {mean:g}{unit_suffix}{loss.mean_scope_phrase()}."
    )


def series_extent(total_rows: int, truncated: bool, kept: int) -> SensorExtent:
    """Read the three fields a bundle carries about a series' size, distrustfully.

    ``truncated`` alone is not enough (a producer may omit it) and ``total_rows`` alone
    is not enough (it may be missing, and a missing integer field arrives here as 0).
    A series is a prefix when either the flag says so or the arithmetic does, and the
    total is only reported when it is a number that can actually be true.
    """
    is_prefix = truncated or total_rows > kept
    if not is_prefix:
        return SensorExtent(kept=kept, total=max(total_rows, kept))
    return SensorExtent(kept=kept, total=total_rows if total_rows > kept else None)


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
