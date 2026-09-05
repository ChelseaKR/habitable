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
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from habitable.verify import SUPPORTED_PACKET_VERSION, _check_packet_version, verify_packet

_GOLDEN = Path(__file__).resolve().parent / "golden"
_SCOPED = _GOLDEN / "scoped-packet-v3"


def _corpus() -> list[Path]:
    """Every committed packet this file verifies: the per-version corpus, plus the scoped one.

    The scoped fixture is deliberately outside the `packet-v*` glob. That glob is the
    one-fixture-per-version corpus enumerated by `test_verify_fuzz.py` and
    `test_contrib_importer.py` as well, and pulling a second v3 packet into those
    harnesses is a decision for whoever owns them, not a side effect of committing
    evidence here.
    """
    return [*sorted(path for path in _GOLDEN.glob("packet-v*") if path.is_dir()), _SCOPED]


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
