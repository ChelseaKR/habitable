# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""The packet PDF carries basic accessibility hints (toward PDF/UA)."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from habitable.capture import capture
from habitable.packet import build_packet
from habitable.tsa import LocalRfc3161TSA
from habitable.vault import Vault


def test_packet_pdf_has_accessibility_markers(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    vault = make_vault()
    issue = vault.document.add_issue(category="mold", title="Mold", issue_id="i1")
    capture(vault, make_jpeg(), issue_id=issue, tsa=local_tsa)
    out = tmp_path / "packet"
    build_packet(vault, out, generated_at="2026-01-02T00:10:00Z")

    pdf = (out / "packet.pdf").read_bytes()
    assert pdf.startswith(b"%PDF-")
    # Declares the document language and asks viewers to show the title, not the
    # file name — basic PDF/UA hygiene (full tagging is tracked in the ACR).
    assert b"/Lang" in pdf
    assert b"/ViewerPreferences" in pdf
    assert b"/DisplayDocTitle" in pdf


def _with_config(vault: Vault, **kwargs: object) -> None:
    from habitable.config import Config

    base = {
        "node_id": vault.config.node_id,
        "language": vault.config.language,
        "timestamp_authorities": vault.config.timestamp_authorities,
        "packet_template": vault.config.packet_template,
    }
    base.update(kwargs)
    vault.config = Config(**base)  # type: ignore[arg-type]


def test_packet_bundle_includes_template_wording(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    from habitable.config import PacketTemplate

    vault = make_vault()
    # Jurisdiction wording is presentation only; it lives in the (signed) bundle.
    # (PDF text is encoded in streams and not byte-findable, so we assert the data
    # layer here; PDF rendering is covered by the build succeeding.)
    _with_config(
        vault,
        packet_template=PacketTemplate(
            header="Filed under STATE habitability law", footer="By the union"
        ),
    )
    issue = vault.document.add_issue(category="mold", issue_id="i1")
    capture(vault, make_jpeg(), issue_id=issue, tsa=local_tsa)
    out = tmp_path / "packet"
    result = build_packet(vault, out, generated_at="2026-01-02T00:10:00Z")
    bundle = result.bundle_path.read_bytes()
    assert b"Filed under STATE habitability law" in bundle
    assert b"By the union" in bundle
    assert result.pdf_path is not None and result.pdf_path.stat().st_size > 1000


def test_pdf_escapes_active_markup_in_template(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    """A hostile <img> in a packet template must NOT be parsed as markup.

    ReportLab would otherwise open a local path or fetch a URL at build time. A
    reference to a nonexistent file would raise during rendering if it were parsed
    as an image; escaped, it is inert text and the build succeeds.
    """
    from habitable.config import PacketTemplate

    vault = make_vault()
    poison = '<img src="/no/such/file/should-not-be-opened.png"/>'
    _with_config(vault, packet_template=PacketTemplate(header=poison, footer=poison))
    issue = vault.document.add_issue(category="mold", issue_id="i1")
    capture(vault, make_jpeg(), issue_id=issue, tsa=local_tsa)
    out = tmp_path / "packet"
    result = build_packet(vault, out, generated_at="2026-01-02T00:10:00Z")  # must not raise
    assert result.pdf_path is not None and result.pdf_path.exists()
    # It is stored as inert data (a quote-free fragment survives canonical JSON).
    assert b"should-not-be-opened.png" in result.bundle_path.read_bytes()


def test_pdf_declares_configured_language(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    vault = make_vault()
    _with_config(vault, language="es")
    issue = vault.document.add_issue(category="moho", issue_id="i1")
    capture(vault, make_jpeg(), issue_id=issue, tsa=local_tsa)
    out = tmp_path / "packet"
    result = build_packet(vault, out, generated_at="2026-01-02T00:10:00Z")
    assert b'"language":"es"' in result.bundle_path.read_bytes()
    assert b"/Lang" in (out / "packet.pdf").read_bytes()
