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
from html import unescape
from pathlib import Path
from typing import Any, cast

from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet

from habitable.canonical import JSONValue
from habitable.capture import capture
from habitable.htmlpacket import _sensor_figure
from habitable.packet import build_packet
from habitable.pdf import _MAX_PDF_SENSOR_ROWS, _render_sensor_item
from habitable.sensor import (
    SensorExtent,
    SensorSeries,
    parse_sensor_csv,
    series_extent,
    series_loss,
)
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


def _long_series(rows: int = 600) -> SensorSeries:
    body = b"Time,Value\n" + b"".join(f"t{i},{i}\n".encode() for i in range(rows))
    series = parse_sensor_csv(body)
    assert series is not None
    return series


def _sensor_item(series: SensorSeries) -> dict[str, JSONValue]:
    """The shape a renderer receives: the series as it survives into `bundle.json`."""
    return {
        "sensor": cast("JSONValue", series.to_dict()),
        "captured_at": "2026-01-01T00:00:00Z",
        "content_hash": "a" * 64,
        "timestamp": None,
    }


def _extent_of(series: SensorSeries) -> SensorExtent:
    """Built from the serialized bundle fields, not from the dataclass.

    The renderers only ever see the three JSON fields, so a test that reads the
    in-memory series would not exercise the path the defect was on.
    """
    return series_extent(series.total_rows, series.truncated, len(series.readings))


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
    note = _extent_of(_long_series()).table_note(_MAX_PDF_SENSOR_ROWS)
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


# --- rows that could not be read at all ---------------------------------------
#
# The truncation half of this (above) was about readings that were parsed and then
# reduced twice. This half is about rows that were never parsed: `_read_rows` drops
# a row with no second column or a non-numeric value, `total_rows` then counts the
# survivors, and `mean` divides by them. So a 600-row export with 90 unreadable rows
# reported "510 reading(s) ... averaging X" with the 90 named only inside a `warnings`
# sentence -- which the HTML put behind a collapsed <details> and the PDF put in the
# normal flow. One bundle, two renderings, one of them silent (issue #311).

_PARTLY_UNREADABLE_CSV = (
    b"Time,Temperature (F)\n"
    b"2026-01-01 00:00,58.4\n"
    b"2026-01-01 01:00,\n"  # no value at all
    b"2026-01-01 02:00,ERR\n"  # the logger's own error marker
    b"2026-01-01 03:00,49.2\n"
    b"2026-01-01 04:00\n"  # a truncated line: no second column
)


def _pdf_styles() -> Any:
    """The stylesheet `render_packet_pdf` builds, so the renderer runs unchanged."""
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="Small", parent=styles["Normal"], fontSize=8, leading=10))
    return styles


def _series_with_unreadable_rows() -> SensorSeries:
    series = parse_sensor_csv(_PARTLY_UNREADABLE_CSV)
    assert series is not None
    return series


def test_the_series_records_how_many_rows_it_could_not_read() -> None:
    """Structurally, in the bundle -- not only inside an English sentence.

    The count existed before this, but only formatted into `warnings`, so a renderer
    had to string-match a sentence to learn it and a verifier could not reconcile it
    the way `SensorExtent` reconciles the truncation counts.
    """
    series = _series_with_unreadable_rows()
    assert series.total_rows == 2, "readings parsed"
    assert series.skipped_rows == 3, "rows that could not be read"
    assert series.to_dict()["skipped_rows"] == 3, "and it survives into bundle.json"


def test_the_figcaption_separates_source_rows_from_readings_parsed() -> None:
    """A count and an average whose denominator silently excluded rows.

    Both numbers are literals here on purpose: a property ("the caption mentions two
    numbers") holds for the wrong pair just as well as the right one.
    """
    html = _sensor_figure(_sensor_item(_series_with_unreadable_rows()))
    assert "2 reading(s) parsed from 5 row(s) in the source file" in html
    assert "averaging 53.8 F over the 2 reading(s) parsed" in html


def test_a_reader_who_never_expands_the_details_is_told_rows_were_dropped() -> None:
    """The notice has to be above the collapsed control, like the truncation one."""
    html = _sensor_figure(_sensor_item(_series_with_unreadable_rows()))
    before_details = html.split("<details", 1)[0]
    assert "3 of the 5 row(s) in the source file could not be read" in before_details
    assert "neither the reading total nor the average" in before_details


def test_both_renderers_tell_a_recipient_the_same_thing_about_the_unread_rows() -> None:
    """The disagreement is the defect, so the agreement is what gets asserted.

    The PDF paragraphs are read out of the story rather than out of a rendered file:
    the point is what the renderer emits, and `Paragraph.text` is the string a reader
    sees on the page.
    """
    item = _sensor_item(_series_with_unreadable_rows())
    html = _sensor_figure(item)

    story: list[Any] = []
    _render_sensor_item(story, item, _pdf_styles())
    pdf_text = " ".join(
        getattr(flowable, "text", "") for flowable in story if hasattr(flowable, "text")
    )

    sentence = series_loss(2, 3).notice()
    assert sentence, "the fixture must actually have unreadable rows"
    assert sentence in unescape(html)
    assert sentence in unescape(pdf_text)
    # And the measurement sentence itself, which used to be two f-strings.
    assert "2 reading(s) parsed from 5 row(s) in the source file" in unescape(pdf_text)


def test_a_clean_csv_reads_exactly_as_it_did_before() -> None:
    """The complement: the fix must not make every series read as damaged."""
    series = parse_sensor_csv(_HEATER_CSV)
    assert series is not None
    assert series.skipped_rows == 0
    html = _sensor_figure(_sensor_item(series))
    assert "Instrument data (Temperature): 4 reading(s), ranging" in html
    assert "source file" not in html
    assert "could not be read" not in html
    assert "reading(s) parsed" not in html


def test_a_record_that_does_not_say_how_many_rows_were_unread_does_not_say_zero() -> None:
    """A bundle written before `skipped_rows` existed is silent, not clean.

    `_i` returns 0 for an absent integer field, and 0 here is the sentence "no row was
    unreadable" -- a claim the packet never made, published as a measurement. The old
    packet's own `warnings` prose still carries the count, so silence is the honest
    rendering and it is byte-for-byte the rendering that bundle already got.
    """
    series = _series_with_unreadable_rows()
    old_shape = cast("dict[str, JSONValue]", series.to_dict())
    del old_shape["skipped_rows"]
    item: dict[str, JSONValue] = {
        "sensor": cast("JSONValue", old_shape),
        "captured_at": "2026-01-01T00:00:00Z",
        "content_hash": "a" * 64,
        "timestamp": None,
    }

    loss = series_loss(2, old_shape.get("skipped_rows"))
    assert loss.skipped is None, "unknown, not zero"
    assert loss.recorded is False
    assert loss.source_rows is None
    assert loss.notice() == ""

    html = _sensor_figure(item)
    assert "Instrument data (Temperature): 2 reading(s), ranging" in html
    assert "could not be read" not in html
    # The count it does carry is still reachable, where it always was.
    assert "3 row(s) skipped" in html


def test_a_skipped_row_count_that_cannot_be_believed_is_not_rendered_as_one() -> None:
    """Every coercion available here turns a producer's error into a measurement."""
    for bogus in (-1, "3", 3.0, True, None, [3]):
        loss = series_loss(2, bogus)
        assert loss.skipped is None, f"{bogus!r} was accepted as a count"
        assert loss.source_rows is None
        assert loss.notice() == ""
    believable = series_loss(2, 0)
    assert believable.recorded is True
    assert believable.lossy is False
    assert believable.source_rows == 2
