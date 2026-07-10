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


def test_every_golden_packet_verifies() -> None:
    corpus = sorted(_GOLDEN.glob("packet-v*"))
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
