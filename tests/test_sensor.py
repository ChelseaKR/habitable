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
from habitable.htmlpacket import _sensor_figure
from habitable.packet import build_packet
from habitable.pdf import _MAX_PDF_SENSOR_ROWS
from habitable.sensor import parse_sensor_csv, series_extent
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


# --- a prefix must never be rendered as the whole series -----------------------
#
# `parse_sensor_csv` keeps at most 500 readings and the PDF table shows at most forty
# of those, so a long logger export is reduced twice before a recipient sees it. Both
# renderers reported one of those reductions as though it were the other. The parser
# was right the whole time -- `total_rows`, `truncated` and the warning were all
# correct in the bundle -- and nothing read them.


def _long_series(rows: int = 600) -> dict[str, object]:
    body = b"Time,Value\n" + b"".join(f"t{i},{i}\n".encode() for i in range(rows))
    series = parse_sensor_csv(body)
    assert series is not None
    return series.to_dict()


def _sensor_item(sensor: dict[str, object]) -> dict[str, object]:
    return {
        "sensor": sensor,
        "captured_at": "2026-01-01T00:00:00Z",
        "content_hash": "a" * 64,
        "timestamp": None,
    }


def test_the_html_table_control_does_not_say_all_of_a_prefix() -> None:
    """It said "Show all 500 reading(s)" beside a caption reading 600."""
    html = _sensor_figure(_sensor_item(_long_series()))
    assert "Show all" not in html
    assert "Show the first 500 of 600 reading(s)" in html


def test_the_html_says_the_chart_is_a_prefix_without_being_expanded() -> None:
    """The reconciling sentence used to sit inside the collapsed <details>.

    A reader who never clicks saw a caption saying 600 and a chart of 500, with
    nothing on the page connecting them.
    """
    html = _sensor_figure(_sensor_item(_long_series()))
    before_details = html.split("<details", 1)[0]
    assert "the first 500 of 600 readings" in before_details
    assert "sealed original" in before_details


def test_a_complete_series_is_still_described_as_complete() -> None:
    """The fix must not make every series read as truncated."""
    html = _sensor_figure(_sensor_item(_long_series(rows=10)))
    assert "Show all 10 reading(s)" in html
    assert "sealed original" not in html


def test_the_pdf_note_counts_against_the_series_not_against_the_prefix() -> None:
    """It read "showing 40 of 500 rows; full data in bundle.json".

    Both halves were wrong for a truncated series: 500 is what survived the first
    reduction rather than what the instrument recorded, and bundle.json holds that
    same prefix rather than the full data.
    """
    sensor = _long_series()
    extent = series_extent(
        int(sensor["total_rows"]),  # type: ignore[call-overload]
        bool(sensor["truncated"]),
        len(sensor["readings"]),  # type: ignore[arg-type]
    )
    note = extent.table_note(_MAX_PDF_SENSOR_ROWS)
    assert "600 readings" in note
    assert "of 500 rows" not in note
    assert "full data in bundle.json" not in note
    assert "bundle.json carries the first 500" in note
    assert "sealed original" in note


def test_a_series_flagged_truncated_without_a_total_reports_the_total_as_unknown() -> None:
    """A bundle can say it is a prefix and not say of what.

    `_i` returns 0 for a missing integer, so trusting `total_rows` alone would render
    "the first 500 of 0 readings". The unknown is said in words instead of resolved
    into a number a reader would take at face value.
    """
    extent = series_extent(0, True, 500)
    assert extent.complete is False
    assert extent.total is None
    assert extent.table_label() == "Show the first 500 reading(s) of a longer series"
    assert "of 0" not in extent.notice()
    assert "a longer series" in extent.table_note(_MAX_PDF_SENSOR_ROWS)


def test_a_bundle_that_understates_its_total_is_still_read_as_a_prefix() -> None:
    """Arithmetic overrides a missing or false `truncated` flag."""
    extent = series_extent(600, False, 500)
    assert extent.complete is False
    assert extent.total == 600
