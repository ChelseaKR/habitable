# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Packet assembly and the standalone verifier, including tamper detection."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

from habitable.capture import capture
from habitable.exif import read_metadata
from habitable.packet import build_packet
from habitable.tsa import LocalRfc3161TSA
from habitable.vault import Vault
from habitable.verify import verify_packet


def _case_with_two_captures(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    tsa: LocalRfc3161TSA,
) -> Vault:
    vault = make_vault()
    issue = vault.document.add_issue(category="mold", room="bathroom", title="Mold", issue_id="i1")
    vault.document.add_timeline_entry(issue, "observed", "spreading")
    capture(vault, make_jpeg("a.jpg", with_location=True), issue_id=issue, tsa=tsa)
    capture(vault, make_jpeg("b.jpg", with_location=True), issue_id=issue, tsa=tsa)
    return vault


def test_export_and_verify_intact(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    vault = _case_with_two_captures(make_vault, make_jpeg, local_tsa)
    out = tmp_path / "packet"
    result = build_packet(vault, out, generated_at="2026-01-02T00:10:00Z")
    assert result.item_count == 2 and result.timestamped_count == 2
    assert result.pdf_path is not None and result.pdf_path.stat().st_size > 1000

    report = verify_packet(out)
    assert report.ok and report.signature_ok and report.custody_ok
    assert report.verified_items == 2
    assert "packet intact" in report.summary()

    # Shared copies must not leak location.
    for media in (out / "media").glob("*.jpg"):
        assert not read_metadata(media).has_location


def test_bundle_records_disclosures(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    vault = _case_with_two_captures(make_vault, make_jpeg, local_tsa)
    out = tmp_path / "packet"
    build_packet(vault, out, generated_at="2026-01-02T00:10:00Z")
    bundle = json.loads((out / "bundle.json").read_text())
    disclosures = bundle["disclosures"]
    assert any("location" in note for note in disclosures)


def test_packet_html_has_proof_and_disclosure(
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    from habitable.disclosure import proof_statement

    for lang, include_originals in (("en", False), ("es", True)):
        vault = Vault.create(
            tmp_path / f"vault-{lang}", "pw", case_id="c", unit="4B", language=lang
        )
        issue = vault.document.add_issue(category="mold", title="Mold", issue_id="i1")
        capture(vault, make_jpeg(f"{lang}.jpg", with_location=True), issue_id=issue, tsa=local_tsa)
        out = tmp_path / f"packet-{lang}"
        build_packet(
            vault, out, generated_at="2026-01-02T00:10:00Z", include_originals=include_originals
        )
        html = (out / "packet.html").read_text(encoding="utf-8")
        stmt = proof_statement(lang)
        assert stmt.heading in html  # "what this proves — and does not"
        assert stmt.privacy_heading in html  # "what this discloses"
        # The embedded-originals residual-PII warning appears only when originals ship.
        assert (stmt.privacy_originals_warning in html) is include_originals


def test_media_tamper_detected(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    vault = _case_with_two_captures(make_vault, make_jpeg, local_tsa)
    out = tmp_path / "packet"
    build_packet(vault, out, generated_at="2026-01-02T00:10:00Z")
    media = next((out / "media").glob("*.jpg"))
    data = bytearray(media.read_bytes())
    data[len(data) // 2] ^= 0xFF
    media.write_bytes(bytes(data))
    report = verify_packet(out)
    assert not report.ok and report.verified_items < 2


def test_bundle_tamper_breaks_signature(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    vault = _case_with_two_captures(make_vault, make_jpeg, local_tsa)
    out = tmp_path / "packet"
    build_packet(vault, out, generated_at="2026-01-02T00:10:00Z")
    bundle = json.loads((out / "bundle.json").read_text())
    bundle["unit"] = "999-FAKE"
    (out / "bundle.json").write_text(json.dumps(bundle))
    report = verify_packet(out)
    assert not report.signature_ok and not report.ok


def test_include_originals_enables_fixity(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    vault = _case_with_two_captures(make_vault, make_jpeg, local_tsa)
    out = tmp_path / "packet"
    build_packet(vault, out, include_originals=True, generated_at="2026-01-02T00:10:00Z")
    report = verify_packet(out)
    assert report.ok
    assert all(item.original_fixity_ok is True for item in report.items)

    # Corrupting an embedded original is caught by fixity.
    original = next((out / "originals").iterdir())
    original.write_bytes(b"not the original bytes")
    assert not verify_packet(out).ok


def test_since_filter_and_issue_scope(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    vault = _case_with_two_captures(make_vault, make_jpeg, local_tsa)
    # A second issue with no captures -> exporting it yields zero items.
    other = vault.document.add_issue(category="heat", issue_id="i2")
    out = tmp_path / "packet"
    result = build_packet(vault, out, issue_id=other, generated_at="2026-01-02T00:10:00Z")
    assert result.item_count == 0
    assert verify_packet(out).ok  # an empty-but-signed packet is still intact
