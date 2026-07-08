# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""EXP-02: bundle.json is deterministic; generated_at lives in manifest.json only."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

from habitable.packet import build_packet
from habitable.tsa import LocalRfc3161TSA
from habitable.vault import Vault
from habitable.verify import verify_packet


def _case_with_captures(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    tsa: LocalRfc3161TSA,
) -> Vault:
    vault = make_vault()
    issue = vault.document.add_issue(category="mold", room="bathroom", title="Mold", issue_id="i1")
    vault.document.add_timeline_entry(issue, "observed", "spreading")
    from habitable.capture import capture

    capture(vault, make_jpeg("a.jpg"), issue_id=issue, tsa=tsa)
    return vault


def test_two_exports_of_unchanged_case_are_byte_identical(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    vault = _case_with_captures(make_vault, make_jpeg, local_tsa)

    out_1 = tmp_path / "packet-1"
    build_packet(vault, out_1, generated_at="2026-01-02T00:10:00Z")
    out_2 = tmp_path / "packet-2"
    build_packet(vault, out_2, generated_at="2026-06-06T18:00:00Z")

    bundle_1 = (out_1 / "bundle.json").read_bytes()
    bundle_2 = (out_2 / "bundle.json").read_bytes()
    assert bundle_1 == bundle_2

    sig_1 = (out_1 / "bundle.sig.json").read_text(encoding="utf-8")
    sig_2 = (out_2 / "bundle.sig.json").read_text(encoding="utf-8")
    assert json.loads(sig_1)["bundle_sha256"] == json.loads(sig_2)["bundle_sha256"]
    assert json.loads(sig_1)["signature"] == json.loads(sig_2)["signature"]


def test_generated_at_is_not_in_bundle_json_but_is_in_manifest(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    vault = _case_with_captures(make_vault, make_jpeg, local_tsa)
    out = tmp_path / "packet"
    result = build_packet(vault, out, generated_at="2026-03-04T05:06:07Z")

    bundle = json.loads((out / "bundle.json").read_text(encoding="utf-8"))
    assert "generated_at" not in bundle

    manifest_path = out / "manifest.json"
    assert manifest_path.exists()
    assert result.manifest_path == manifest_path
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["generated_at"] == "2026-03-04T05:06:07Z"
    assert manifest["packet_version"] == bundle["packet_version"]
    assert result.generated_at == "2026-03-04T05:06:07Z"


def test_manifest_absence_does_not_break_verification(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    """A verifier that never reads manifest.json still fully verifies the packet."""
    vault = _case_with_captures(make_vault, make_jpeg, local_tsa)
    out = tmp_path / "packet"
    build_packet(vault, out, generated_at="2026-03-04T05:06:07Z")
    (out / "manifest.json").unlink()

    report = verify_packet(out)
    assert report.ok


def test_html_and_pdf_still_show_generated_at(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    vault = _case_with_captures(make_vault, make_jpeg, local_tsa)
    out = tmp_path / "packet"
    build_packet(vault, out, generated_at="2026-03-04T05:06:07Z")
    html = (out / "packet.html").read_text(encoding="utf-8")
    assert "2026-03-04T05:06:07Z" in html
