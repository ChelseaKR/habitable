# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Backward-compatibility guard: every packet version we have emitted must verify.

`tests/golden/packet-vN/` holds a committed, self-contained packet for each format
version. These must keep verifying forever — a change that breaks them is the
definition of a backward-incompatible regression and is caught here, not in prose.

`tests/golden/scoped-packet-v3/` sits beside them and is not one of them: it is a
second packet of a version that already has a fixture, reconstructed from the ~30-hour
window in which issue-scoped export existed (issue #279, item 3). It is verified here
because "old scoped packets keep verifying" is the compatibility claim the scoped-export
work leans on hardest and nothing else in the tree pins it. Its own README states the
provenance, which is not the same as the other fixtures'.

`tests/golden/correspondence-packet-v4/` sits beside them for the same reason as the
sensor fixture and a different gap: until it was committed, **no bundle in this corpus
carried a `correspondence` record**, so the sealed-message surface (issue #304) -- the
header summary, the attachment decomposition, the four body states -- was pinned by
nothing on the day it shipped.

`tests/golden/sensor-packet-v4/` sits beside them for the same kind of reason and a
different gap: until it was committed, **no bundle in this corpus carried a `sensor`
record at all**, so the instrument-data format was pinned by nothing while two defects
in it were being fixed from a code read (issue #314). It is the current format version
rather than a historical one, because it exists to pin a live surface.
"""

from __future__ import annotations

import json
import shutil
from collections.abc import Mapping
from html import unescape
from pathlib import Path
from typing import Any

from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet

from habitable.canonical import JSONValue
from habitable.htmlpacket import render_packet_html
from habitable.pdf import _render_document_item, _render_sensor_item
from habitable.verify import SUPPORTED_PACKET_VERSION, _check_packet_version, verify_packet


def _pdf_sensor_text(bundle: Mapping[str, JSONValue]) -> str:
    """What the PDF renderer emits for this bundle's instrument items, as text.

    The document is built flowable by flowable rather than written and read back:
    nothing in this repository extracts text from a PDF, and `pypdf` would be a new
    runtime dependency for a project whose minimal-dependency principle is load-bearing.
    `Paragraph.text` is the string that reaches the page, so this reads what a recipient
    is shown; what it does not exercise is pagination, which is not what #311 was about.
    """
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="Small", parent=styles["Normal"], fontSize=8, leading=10))
    story: list[Any] = []
    items = bundle["items"]
    assert isinstance(items, list)
    for item in items:
        if isinstance(item, dict) and item.get("sensor") is not None:
            _render_sensor_item(story, item, styles)
    return unescape(
        " ".join(getattr(flowable, "text", "") for flowable in story if hasattr(flowable, "text"))
    )


def _pdf_document_text(bundle: Mapping[str, JSONValue]) -> str:
    """What the PDF renderer emits for this bundle's document artifacts, as text.

    Built flowable by flowable for the same reason `_pdf_sensor_text` is: nothing in
    this repository extracts text from a PDF, and `pypdf` would be a new runtime
    dependency for a project whose minimal-dependency principle is load-bearing.
    """
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="Small", parent=styles["Normal"], fontSize=8, leading=10))
    story: list[Any] = []
    items = bundle["items"]
    assert isinstance(items, list)
    for item in items:
        # The same condition `_render_evidence_item` dispatches on: an image artifact
        # is rendered as an image, not as a document.
        if (
            isinstance(item, dict)
            and item.get("record_kind") == "artifact"
            and not str(item.get("media_type", "")).startswith("image/")
        ):
            _render_document_item(story, item, styles, "caption", "en")
    return unescape(" ".join(_flowable_text(flowable) for flowable in story))


def _flowable_text(flowable: Any) -> str:
    """Every string a flowable puts on the page, table cells included.

    A `Table`'s rows are themselves flowables, so reading only `.text` off the story
    misses the header summary entirely -- and a rendering assertion that silently
    examines nothing is this campaign's most common way to be wrong.
    """
    text = getattr(flowable, "text", None)
    if isinstance(text, str):
        return text
    cells = getattr(flowable, "_cellvalues", None)
    if cells is None:
        return ""
    return " ".join(_flowable_text(cell) for row in cells for cell in row)


_GOLDEN = Path(__file__).resolve().parent / "golden"
_SCOPED = _GOLDEN / "scoped-packet-v3"
_SENSOR = _GOLDEN / f"sensor-packet-v{SUPPORTED_PACKET_VERSION}"
_CORRESPONDENCE = _GOLDEN / f"correspondence-packet-v{SUPPORTED_PACKET_VERSION}"


def _corpus() -> list[Path]:
    """Every committed packet this file verifies: the per-version corpus, plus the two siblings.

    The scoped and sensor fixtures are deliberately outside the `packet-v*` glob. That
    glob is the one-fixture-per-version corpus enumerated by `test_verify_fuzz.py` and
    `test_contrib_importer.py` as well, and pulling a second packet of an already
    covered version into those harnesses is a decision for whoever owns them, not a
    side effect of committing evidence here.
    """
    return [
        *sorted(path for path in _GOLDEN.glob("packet-v*") if path.is_dir()),
        _SCOPED,
        _SENSOR,
        _CORRESPONDENCE,
    ]


def test_a_fixture_exists_for_every_version_we_have_ever_emitted() -> None:
    """Turn "we forgot" into a red build (issue #160).

    ``test_every_golden_packet_verifies`` asserted only that *something* was on
    disk, so when packet v4 shipped without a fixture the corpus stayed green —
    for two weeks the format tenants were actually exporting, and the format of
    the packet on the public site, was pinned by nothing, while two documents
    said "every version ever emitted keeps verifying, guarded by the committed
    golden-packet corpus". This is the assertion that stops it recurring: the
    next version bump fails here until its fixture is committed.
    """
    committed = {path.name for path in _corpus()}
    expected = {f"packet-v{version}" for version in range(1, SUPPORTED_PACKET_VERSION + 1)}
    assert expected <= committed, f"missing golden fixture(s): {sorted(expected - committed)}"


def test_the_current_version_fixture_exercises_its_own_format() -> None:
    """A fixture that is only the shape every version shares pins nothing new.

    ``_verify_v3_timeline`` and ``_verify_v4_workflows`` are gated on
    ``packet_version``; a v4 fixture carrying no artifact, relationship,
    profile, or handoff view would leave those paths as unguarded as no fixture
    at all. (The published site sample is `packet_version: 4` and has exactly
    none of them — which is why it is not a substitute for this.)
    """
    bundle = json.loads(
        (_GOLDEN / f"packet-v{SUPPORTED_PACKET_VERSION}" / "bundle.json").read_text("utf-8")
    )

    assert bundle["packet_version"] == SUPPORTED_PACKET_VERSION
    assert any(item.get("record_kind") == "artifact" for item in bundle["items"])
    assert bundle["relationships"], "no relationship in the current-version fixture"
    assert bundle["use_case_profile"], "no use-case profile in the current-version fixture"
    assert bundle["handoff_views"], "no handoff view in the current-version fixture"
    assert bundle["timeline"], "no timeline entry in the current-version fixture"


def test_the_scoped_fixture_is_a_scoped_packet_and_names_what_it_excluded() -> None:
    """Pin both halves of what this fixture is for (issue #279, item 3).

    First: it is actually scoped. Every other committed packet is
    ``scope.type == "unit"``, so a fixture that quietly drifted back to a whole-unit
    export would leave the corpus exactly as it was before — with no scoped packet in
    it — while looking like it had one.

    Second: it still contains the contradiction it was kept for. Its signed scope
    statement says custody records from other issues "are not included", and its
    ``custody_proof.items`` names the capture and timeline entry of the excluded issue
    anyway. That is ADR 0018's fact 3 as bytes rather than prose, and it is the reason
    ``share.export_share`` and ``packet.build_packet`` refuse a scope today. If a future
    change makes this assertion fail, the fixture has stopped being evidence of the
    format that shipped and the test is right to say so.
    """
    bundle = json.loads((_SCOPED / "bundle.json").read_text("utf-8"))

    assert bundle["packet_version"] == 3
    assert bundle["scope"]["type"] == "issue"
    scoped_issue = bundle["scope"]["issue_id"]
    assert scoped_issue and [issue["issue_id"] for issue in bundle["issues"]] == [scoped_issue]

    disclosed = (
        {item["capture_id"] for item in bundle["items"]}
        | {entry["entry_id"] for entry in bundle["timeline"]}
        | {scoped_issue}
    )
    named_by_custody = set(bundle["custody_proof"]["items"])
    assert named_by_custody - disclosed == {"cap-3cbf05d983c31784", "tl-839fd8292269d9fb"}
    assert bundle["custody_proof"]["length"] > len(disclosed)


def _sensor_records() -> list[dict[str, object]]:
    """Every `sensor` record in the instrument-data fixture, in item order."""
    bundle = json.loads((_SENSOR / "bundle.json").read_text("utf-8"))
    return [item["sensor"] for item in bundle["items"] if item.get("sensor") is not None]


def test_the_corpus_carries_an_instrument_data_packet(tmp_path: Path) -> None:
    """Issue #314: measured across all six committed bundles, none held a sensor record.

    So the instrument-data path was outside the compatibility guarantee entirely, while
    two defects in it (#307, #311) were being found by reading the code because no
    fixture would have shown them. The counts are asserted as literals: a property
    ("the fixture has a sensor record with some numbers in it") is satisfied by the
    wrong numbers as comfortably as by the right ones.
    """
    clean, lossy = _sensor_records()

    assert clean["total_rows"] == 6
    assert clean["skipped_rows"] == 0
    assert clean["truncated"] is False
    assert len(clean["readings"]) == 6  # type: ignore[arg-type]

    # The record where all three counts differ: 620 rows in the file, 600 of them
    # readable, 500 of those carried in the bundle.
    assert lossy["skipped_rows"] == 20
    assert lossy["total_rows"] == 600
    assert lossy["truncated"] is True
    assert len(lossy["readings"]) == 500  # type: ignore[arg-type]
    assert lossy["mean"] == 56.54, "an average over the 600 that parsed, not the 620 written"


def test_the_sensor_fixture_tracks_the_current_format() -> None:
    """A fixture pinning a live surface has to be at the version people export.

    `scoped-packet-v3` is frozen because it is evidence of a format that no longer
    exists. This one is not: if it lags a version bump it stops pinning the format
    anyone is producing, which is the failure `test_a_fixture_exists_for_every_version`
    exists to prevent one directory over. Regenerate with
    `uv run python scripts/make_golden_sensor_packet.py`.
    """
    bundle = json.loads((_SENSOR / "bundle.json").read_text("utf-8"))
    assert bundle["packet_version"] == SUPPORTED_PACKET_VERSION, (
        "sensor fixture is behind the current packet version; regenerate it with "
        "scripts/make_golden_sensor_packet.py"
    )


def test_both_renderings_of_the_fixture_disclose_what_was_left_out(tmp_path: Path) -> None:
    """The renderers' instrument output over the fixture, in HTML and in PDF.

    #311 was a disagreement between two renderings of one bundle, so what is asserted
    is that both say the same things about the lossy series: how many source rows could
    not be read, and what the average averaged over.

    The prefix disclosure is deliberately *not* asserted as one shared sentence. The two
    renderings reduce the series by different amounts -- the HTML table carries all 500
    readings the bundle holds, the PDF table shows forty of them -- so a single sentence
    would have to be wrong in one of them. Each is checked against its own accurate
    wording instead, which is the distinction `SensorExtent.notice` and
    `SensorExtent.table_note` exist to keep.
    """
    bundle = json.loads((_SENSOR / "bundle.json").read_text("utf-8"))

    html_path = tmp_path / "packet.html"
    render_packet_html(bundle, _SENSOR / "media", html_path)
    html = unescape(html_path.read_text("utf-8"))

    pdf_text = _pdf_sensor_text(bundle)

    for rendering, text in (("html", html), ("pdf", pdf_text)):
        assert "600 reading(s) parsed from 620 row(s) in the source file" in text, rendering
        assert "averaging 56.54 F over the 600 reading(s) parsed" in text, rendering
        assert "20 of the 620 row(s) in the source file could not be read" in text, rendering
        # And the clean capture still reads as complete in the same document.
        assert "Instrument data (Temperature): 6 reading(s), ranging" in text, rendering
        assert "6 reading(s) parsed from" not in text, rendering

    # Each rendering's own prefix disclosure, measured against what it actually shows.
    assert "This chart and table show the first 500 of 600 readings" in html
    assert "showing 40 rows of 600 readings" in pdf_text
    assert "bundle.json carries the first 500" in pdf_text

    # The skipped-row notice reaches a reader who never expands the disclosure.
    # Scoped to the lossy figure: splitting the whole page at its first <details> would
    # land inside the *clean* capture, which correctly has nothing to disclose, and the
    # assertion would then be measuring the wrong figure.
    lossy_figure = html.split('<figure class="sensor-evidence">')[2]
    assert "could not be read" in lossy_figure.split("<details", 1)[0]


def _correspondence_records() -> tuple[dict[str, Any], dict[str, Any]]:
    """The fixture's two message summaries, in the order the messages were sealed."""
    bundle: Any = json.loads((_CORRESPONDENCE / "bundle.json").read_text("utf-8"))
    blocks = [
        item["correspondence"]
        for item in bundle["items"]
        if isinstance(item, dict) and item.get("correspondence")
    ]
    assert len(blocks) == 2, "the fixture carries exactly two sealed messages"
    complete = next(b for b in blocks if b["attachments_readable"] == b["attachment_count"])
    partial = next(b for b in blocks if b["attachments_readable"] != b["attachment_count"])
    return complete, partial


def test_the_corpus_carries_a_sealed_correspondence_packet() -> None:
    """Issue #304: measured across all seven committed bundles, none held one.

    So the sealed-message surface was outside the compatibility guarantee on the day
    it shipped -- the state issue #314 found the instrument-data surface in, one
    directory over, after two defects in it had been found by reading the code. The
    counts are asserted as literals: a property ("there is a message summary with
    some fields in it") is satisfied by the wrong values as comfortably as the right
    ones.
    """
    bundle: Any = json.loads((_CORRESPONDENCE / "bundle.json").read_text("utf-8"))
    # Two messages and three sealed attachments, of four attachments declared.
    assert bundle["appendix"]["item_count"] == 5
    assert bundle["appendix"]["relationship_count"] == 3
    assert {r["relationship_type"] for r in bundle["relationships"]} == {"supports"}

    complete, partial = _correspondence_records()

    assert complete["attachment_count"] == 2
    assert complete["attachments_readable"] == 2
    assert complete["body"]["state"] == "present"
    assert [h["state"] for h in _header_states(complete)] == ["present"] * 4
    assert complete["warnings"] == []

    # The record where every state that is not "present" occurs at once.
    assert partial["date_header"]["state"] == "absent"
    assert partial["subject"]["state"] == "unreadable"
    assert partial["subject"]["value"] == "", "a damaged header value is never published"
    assert partial["body"]["state"] == "not_plain_text"
    assert partial["body"]["media_type"] == "text/html"
    assert partial["attachment_count"] == 2
    assert partial["attachments_readable"] == 1
    assert len(partial["attachments"]) == 2, "the part that could not be read is still listed"
    assert any("notes.txt" in warning for warning in partial["warnings"])

    for block in (complete, partial):
        assert block["header_dates_are_claims"] is True


def _header_states(block: dict[str, Any]) -> list[dict[str, Any]]:
    return [block[key] for key in ("from_header", "date_header", "subject", "message_id")]


def test_the_correspondence_fixture_tracks_the_current_format() -> None:
    """Same discipline as the sensor fixture: a fixture pinning a live surface has to
    be at the version people export. Regenerate with
    `uv run python scripts/make_golden_correspondence_packet.py`."""
    bundle = json.loads((_CORRESPONDENCE / "bundle.json").read_text("utf-8"))
    assert bundle["packet_version"] == SUPPORTED_PACKET_VERSION, (
        "correspondence fixture is behind the current packet version; regenerate it with "
        "scripts/make_golden_correspondence_packet.py"
    )


def test_no_header_date_in_the_fixture_is_rendered_as_a_time_bound(tmp_path: Path) -> None:
    """The fixture's own version of issue #304's third acceptance criterion.

    Its `Date:` header is a well-formed RFC 5322 date beside a real RFC 3161 token,
    which is precisely the packet where the two could be confused. Both renderings
    are checked, because #311 was one bundle whose two renderings disagreed.
    """
    bundle: Any = json.loads((_CORRESPONDENCE / "bundle.json").read_text("utf-8"))
    complete, _ = _correspondence_records()
    header_date = complete["date_header"]["value"]
    assert header_date == "Fri, 02 Jan 2026 08:41:13 +0000"

    for item in bundle["items"]:
        assert item["captured_at"] != header_date
        for token in [item.get("timestamp"), *item.get("archive_timestamps", [])]:
            assert header_date not in json.dumps(token)

    html_path = tmp_path / "packet.html"
    render_packet_html(bundle, _CORRESPONDENCE / "media", html_path)
    html = unescape(html_path.read_text("utf-8"))
    pdf_text = _pdf_document_text(bundle)
    for rendering, text in (("html", html), ("pdf", pdf_text)):
        assert header_date in text, rendering
        assert "Date header (claimed by the sender, not a timestamp)" in text, rendering
        assert "habitable does not check DKIM" in text, rendering
        # And the two numbers that keep an inventory honest.
        assert "declares 2 attachment(s), of which 1 could be read" in text, rendering


def test_every_golden_packet_verifies() -> None:
    corpus = _corpus()
    assert corpus, "no golden packets committed"
    for packet in corpus:
        report = verify_packet(packet)
        # Golden packets prove format compatibility and mechanical verification.
        # They intentionally do not bundle an external trust policy/root.
        assert report.structurally_intact, f"{packet.name}: {report.summary()} {report.problems}"
        assert report.signature_ok and report.custody_ok
        assert report.cryptographically_verified_items >= 1
        assert not report.evidence_ready and not report.ok


def test_unknown_newer_version_is_rejected_not_crashed(tmp_path: Path) -> None:
    src = _GOLDEN / "packet-v1"
    dst = tmp_path / "future"
    shutil.copytree(src, dst)
    bundle = json.loads((dst / "bundle.json").read_text())
    bundle["packet_version"] = SUPPORTED_PACKET_VERSION + 999  # a format from the future
    (dst / "bundle.json").write_text(json.dumps(bundle))
    report = verify_packet(dst)  # must not raise
    assert not report.ok
    assert any("newer than supported" in p for p in report.problems)


def test_version_check_unit() -> None:
    assert _check_packet_version({"packet_version": SUPPORTED_PACKET_VERSION}) is None
    assert _check_packet_version({}) is not None  # missing
    assert _check_packet_version({"packet_version": True}) is not None  # bool is not a version
    assert _check_packet_version({"packet_version": SUPPORTED_PACKET_VERSION + 1}) is not None
