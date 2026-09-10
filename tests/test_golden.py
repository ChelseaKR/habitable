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
from habitable.evidence import CustodyAction
from habitable.htmlpacket import render_packet_html
from habitable.pdf import _render_sensor_item
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


_GOLDEN = Path(__file__).resolve().parent / "golden"
_SCOPED = _GOLDEN / "scoped-packet-v3"
_SENSOR = _GOLDEN / f"sensor-packet-v{SUPPORTED_PACKET_VERSION}"


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


# --- the published JSON Schema ------------------------------------------------
#
# `docs/packet-bundle.schema.json` is the machine-readable contract this project
# hands to strangers: `docs/embedding-the-verifier.md` points a court, a clerk or an
# opposing party at it, and its `$id` is a public URL. Nothing in the tree validated
# anything against it, so it drifted from the code it claims to describe -- the same
# shape as the gap `test_a_fixture_exists_for_every_version_we_have_ever_emitted`
# above was written to end, one layer further out: the corpus proved old packets keep
# *verifying*, and two documents said so, while whether they still matched the
# published *schema* was pinned by nothing.
#
# These two guards are deliberately not a JSON Schema implementation. They assert
# exact set relationships read out of the schema file itself, so they cannot pass by
# quietly failing to understand a keyword -- which is what a hand-rolled validator
# would risk, and it is the reason a full conformance run is left as a dependency
# decision rather than approximated here.

_SCHEMA_PATH = Path(__file__).resolve().parents[1] / "docs" / "packet-bundle.schema.json"
_SITE_SAMPLE = Path(__file__).resolve().parents[1] / "site" / "sample-packet" / "bundle.json"


def _schema() -> dict[str, Any]:
    loaded: object = json.loads(_SCHEMA_PATH.read_text("utf-8"))
    assert isinstance(loaded, dict), "the published schema must be a JSON object"
    return loaded


def test_the_published_schema_lists_every_custody_action_the_code_can_emit() -> None:
    """The custody enum must equal `CustodyAction`, not merely overlap it.

    Packet v4 added `artifact_added` and `relationship_added` to the chain of custody
    and the schema's enum was not extended with them, so the committed `packet-v4`
    fixture -- a valid packet, produced by this code -- failed the project's own
    published contract on three of its custody entries. A relying party who did what
    `embedding-the-verifier.md` tells them to do would have concluded that the custody
    proof, the most trust-critical part of the artifact, was malformed.

    Set equality rather than containment, in both directions on purpose: a value in
    the code and not the schema rejects real packets, and a value in the schema and
    not the code advertises a custody event this software cannot produce.
    """
    declared = set(_schema()["$defs"]["custodyEntry"]["properties"]["action"]["enum"])
    emitted = {action.value for action in CustodyAction}
    assert declared == emitted, (
        f"schema enum and CustodyAction disagree; "
        f"in the code only: {sorted(emitted - declared)}; "
        f"in the schema only: {sorted(declared - emitted)}"
    )


def test_every_published_bundle_meets_the_schemas_own_required_and_closed_declarations() -> None:
    """Every packet this repository publishes must satisfy the schema it ships beside.

    Scoped to what can be checked exactly: the `required` key lists and the
    `additionalProperties: false` property sets, read from the schema file rather than
    restated here, plus the custody action enum at the data layer. That is enough to
    have caught both drifts this test was written for, and it stays correct when the
    schema changes because it derives its expectations from the schema.

    The site sample is included deliberately. It is the packet a stranger downloads
    from the public site, so it is the one whose disagreement with the contract would
    be found by someone the project cannot talk to.
    """
    schema = _schema()
    defs = schema["$defs"]
    item_required = set(defs["item"]["required"])
    entry_required = set(defs["custodyEntry"]["required"])
    entry_allowed = set(defs["custodyEntry"]["properties"])
    actions = set(defs["custodyEntry"]["properties"]["action"]["enum"])

    bundles = [(path.name, path / "bundle.json") for path in _corpus()]
    bundles.append(("site/sample-packet", _SITE_SAMPLE))

    items_checked = 0
    entries_checked = 0
    for name, path in bundles:
        bundle = json.loads(path.read_text("utf-8"))
        for index, item in enumerate(bundle["items"]):
            missing = item_required - set(item)
            assert not missing, f"{name} items[{index}] missing required {sorted(missing)}"
            items_checked += 1
        for entry in bundle["custody_proof"]["entries"]:
            seq = entry.get("seq")
            missing = entry_required - set(entry)
            assert not missing, f"{name} custody entry {seq} missing required {sorted(missing)}"
            unexpected = set(entry) - entry_allowed
            assert not unexpected, (
                f"{name} custody entry {seq} carries {sorted(unexpected)}, and custodyEntry is a "
                "closed object: adding a field to it is a schema change, not an additive one"
            )
            assert entry["action"] in actions, (
                f"{name} custody entry {seq} has action {entry['action']!r}, "
                "which the published schema does not list"
            )
            entries_checked += 1

    # A loop that checked nothing would otherwise pass. These are the counts the
    # committed corpus holds today; they only ever grow.
    assert items_checked >= 6, f"only {items_checked} items checked -- the corpus did not load"
    assert entries_checked >= 20, f"only {entries_checked} custody entries checked"
