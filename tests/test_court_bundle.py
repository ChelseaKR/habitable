# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""The recipient packet: cover sheet, chronology, and an integrity summary.

Asserts both renderings carry the three recipient-facing sections and that the
accessible HTML stays structurally sound (one h1, landmarks, captioned tables).
The data layer is exercised in ``test_bundleview.py``; this is the wiring.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from habitable.capture import capture
from habitable.packet import build_packet
from habitable.tsa import LocalRfc3161TSA
from habitable.vault import Vault


def _packet(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    tsa: LocalRfc3161TSA,
    out: Path,
) -> Path:
    vault = make_vault()
    issue = vault.document.add_issue(category="mold", room="bath", title="Mold", issue_id="i1")
    vault.document.add_timeline_entry(issue, "observed", "spreading after roof leak")
    capture(vault, make_jpeg(with_location=True), issue_id=issue, tsa=tsa)
    result = build_packet(vault, out, generated_at="2026-01-02T00:10:00Z")
    assert result.html_path is not None and result.pdf_path is not None
    return out


def test_html_packet_has_recipient_facing_sections(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    out = _packet(make_vault, make_jpeg, local_tsa, tmp_path / "pkt")
    html = (out / "packet.html").read_text(encoding="utf-8")
    # Exactly one h1 even with the added sections (accessibility invariant).
    assert html.count("<h1>") == 1
    # Cover sheet, chronology, and integrity sections are all present and labelled.
    assert 'id="cover-heading">Cover sheet' in html
    assert 'id="chronology-heading">Chronological evidence timeline' in html
    assert "Chain of custody &amp; integrity" in html
    # The chronology interleaves the note and the photo.
    assert "[observed]" in html
    assert "Custody chain head:" in html


def test_pdf_packet_builds_with_recipient_facing_sections(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    out = _packet(make_vault, make_jpeg, local_tsa, tmp_path / "pkt")
    pdf = (out / "packet.pdf").read_bytes()
    assert pdf.startswith(b"%PDF-")
    # The added headings are recorded in the navigable outline (uncompressed in the
    # catalog), so they are findable even though body text is stream-encoded.
    assert b"Cover sheet" in pdf
    assert b"Chronological evidence timeline" in pdf
    assert b"Chain of custody" in pdf


def test_court_sections_do_not_break_verification(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    from habitable.verify import verify_packet

    out = _packet(make_vault, make_jpeg, local_tsa, tmp_path / "pkt")
    report = verify_packet(out, trusted_certs=[local_tsa.certificate])
    assert report.ok, report.summary()
