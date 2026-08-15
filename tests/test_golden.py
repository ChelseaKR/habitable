# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Backward-compatibility guard: every packet version we have emitted must verify.

`tests/golden/packet-vN/` holds a committed, self-contained packet for each format
version. These must keep verifying forever — a change that breaks them is the
definition of a backward-incompatible regression and is caught here, not in prose.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from habitable.verify import SUPPORTED_PACKET_VERSION, _check_packet_version, verify_packet

_GOLDEN = Path(__file__).resolve().parent / "golden"


def _corpus() -> list[Path]:
    return sorted(path for path in _GOLDEN.glob("packet-v*") if path.is_dir())


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
