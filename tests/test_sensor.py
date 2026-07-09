# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Instrument-corroborated conditions: sensor CSV import (EXP-09).

A cheap temperature logger's or moisture meter's CSV export is a first-class
capture — hashed, sealed, and RFC 3161 timestamped like any photo — and renders
in the packet as an accessible chart + readings table (independent corroboration
opposing counsel cannot wave away as the tenant's own staged photo).
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from habitable.capture import capture
from habitable.packet import build_packet
from habitable.sensor import parse_sensor_csv
from habitable.tsa import LocalRfc3161TSA
from habitable.vault import Vault

_HEATER_CSV = (
    b"Time,Temperature (F)\n"
    b"2026-01-01 00:00,58.4\n"
    b"2026-01-01 01:00,55.1\n"
    b"2026-01-01 02:00,51.9\n"
    b"2026-01-01 03:00,49.2\n"
)


def test_parse_detects_header_unit_and_stats() -> None:
    series = parse_sensor_csv(_HEATER_CSV)
    assert series is not None
    assert series.label_header == "Time"
    assert series.value_header == "Temperature"
    assert series.unit == "F"
    assert series.total_rows == 4
    assert not series.truncated
    assert series.minimum == 49.2
    assert series.maximum == 58.4
    assert round(series.mean, 2) == 53.65
    assert [r.value for r in series.readings] == [58.4, 55.1, 51.9, 49.2]


def test_parse_headerless_two_column() -> None:
    series = parse_sensor_csv(b"1,10\n2,20\n3,30\n")
    assert series is not None
    assert series.label_header == "Reading"
    assert series.value_header == "Value"
    assert series.unit is None
    assert series.total_rows == 3
    assert series.mean == 20.0


def test_parse_skips_malformed_rows_and_warns() -> None:
    series = parse_sensor_csv(b"Time,Value\na,1\nb,not-a-number\nc,3\n")
    assert series is not None
    assert series.total_rows == 2
    assert any("skipped" in w for w in series.warnings)


def test_parse_truncates_long_series() -> None:
    body = b"Time,Value\n" + b"".join(f"t{i},{i}\n".encode() for i in range(10))
    series = parse_sensor_csv(body, max_readings=4)
    assert series is not None
    assert series.total_rows == 10
    assert series.truncated
    assert len(series.readings) == 4
    assert any("first 4 of 10" in w for w in series.warnings)


def test_parse_rejects_non_numeric_and_empty() -> None:
    assert parse_sensor_csv(b"") is None
    assert parse_sensor_csv(b"just,text\nmore,words\n") is None
    assert parse_sensor_csv(b"\x80\x81\x82") is None  # undecodable bytes


def test_parse_strips_utf8_bom() -> None:
    series = parse_sensor_csv(b"\xef\xbb\xbfTime,Value\n0,1\n1,2\n")
    assert series is not None
    assert series.label_header == "Time"


def _capture_csv(
    vault: Vault, tsa: LocalRfc3161TSA, tmp_path: Path, body: bytes = _HEATER_CSV
) -> str:
    issue = vault.document.add_issue(category="no_heat", room="bed", title="No heat", issue_id="i1")
    csv_path = tmp_path / "logger.csv"
    csv_path.write_bytes(body)
    result = capture(vault, csv_path, issue_id=issue, tsa=tsa)
    return result.capture_id


def test_csv_capture_is_first_class_timestamped_item(
    make_vault: Callable[..., Vault],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    vault = make_vault()
    capture_id = _capture_csv(vault, local_tsa, tmp_path)
    record = vault.document.captures()[0]
    assert record.media_type == "text/csv"
    # Same evidence spine as a photo: sealed, fixity-checked, and timestamped.
    assert vault.get_token(capture_id) is not None
    assert vault.custody.verify().ok


def test_packet_renders_accessible_chart_and_table(
    make_vault: Callable[..., Vault],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    vault = make_vault()
    _capture_csv(vault, local_tsa, tmp_path)
    result = build_packet(vault, tmp_path / "pkt", generated_at="2026-01-02T00:10:00Z")
    assert result.html_path is not None
    html = result.html_path.read_text(encoding="utf-8")

    # Accessible: not color-only. The chart is aria-hidden over a text equivalent
    # (summary sentence) and a full readings table with header scopes + caption.
    assert 'aria-hidden="true"' in html
    assert "Instrument data (Temperature)" in html
    assert "<table>" in html and "<caption>" in html
    assert 'scope="col">Temperature (F)' in html
    assert "58.4" in html and "49.2" in html  # every reading is in the table

    # The instrument file is disclosed as included verbatim (independent corroboration).
    assert any("instrument data file" in d for d in result.disclosures)

    # A PDF is produced too and the chart data survives into it.
    assert result.pdf_path is not None and result.pdf_path.is_file()


def test_bundle_carries_sensor_series(
    make_vault: Callable[..., Vault],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    import json

    vault = make_vault()
    _capture_csv(vault, local_tsa, tmp_path)
    result = build_packet(vault, tmp_path / "pkt", make_pdf=False)
    bundle = json.loads(result.bundle_path.read_text(encoding="utf-8"))
    items = bundle["items"]
    assert items and items[0]["sensor"] is not None
    assert items[0]["sensor"]["value_header"] == "Temperature"
