# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Timeline 2.0 / packet-v3 semantics, custody binding, and rendering."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from habitable.canonical import canonical_json
from habitable.capture import capture
from habitable.clock import HybridLogicalClock
from habitable.errors import HabitableError
from habitable.model import CaseDocument
from habitable.packet import PACKET_VERSION, _write_signature, build_packet
from habitable.tsa import LocalRfc3161TSA
from habitable.vault import Vault
from habitable.verify import verify_packet


def test_timeline_event_separates_occurrence_recording_source_and_recurrence(
    make_vault: Callable[..., Vault],
) -> None:
    vault = make_vault()
    issue_id = vault.document.add_issue(category="mold", status="resolved", issue_id="i1")
    entry_id = vault.add_timeline_event(
        issue_id,
        event_type="recurrence",
        text="Mold returned after the ceiling dried.",
        occurred_at="2026-01-03T08:15:00-08:00",
        source="firsthand",
    )

    entry = next(item for item in vault.document.timeline() if item.entry_id == entry_id)
    assert entry.occurred_at == "2026-01-03T16:15:00Z"
    assert entry.recorded_at.endswith("Z") and entry.recorded_at != entry.occurred_at
    assert entry.source == "firsthand"
    assert (
        next(item for item in vault.document.issues() if item.issue_id == issue_id).status == "open"
    )

    binding = next(item for item in vault.custody.entries if item.item_id == entry_id)
    assert binding.action == "note_added"
    assert binding.details["timeline_sha256"] == entry.commitment()
    assert binding.details["stage"] == "recorded"
    assert binding.signature  # signed in the encrypted vault


def test_reviewed_choices_other_and_link_validation(make_vault: Callable[..., Vault]) -> None:
    vault = make_vault()
    issue_id = vault.document.add_issue(category="mold", issue_id="i1")

    with pytest.raises(HabitableError, match="Other timeline event"):
        vault.add_timeline_event(
            issue_id,
            event_type="other",
            text="A factual note.",
            occurred_at="2026-01-03",
            source="firsthand",
        )


def test_case_schema_v1_reads_forward_but_future_state_fails_closed(
    make_vault: Callable[..., Vault],
) -> None:
    vault = make_vault()
    issue_id = vault.document.add_issue(category="mold", issue_id="i1")
    vault.document.add_timeline_entry(issue_id, "observed", "Legacy note")
    state = vault.document.to_state()
    state["schema_version"] = 1

    migrated = CaseDocument.from_state(state, HybridLogicalClock("migration-test"))
    entry = migrated.timeline()[0]
    assert entry.schema_version == 1 and entry.source == "unspecified"
    assert migrated.to_state()["schema_version"] == 2

    state["schema_version"] = 999
    with pytest.raises(HabitableError, match="newer than supported"):
        CaseDocument.from_state(state, HybridLogicalClock("future-test"))
    with pytest.raises(HabitableError, match="unknown timeline event type"):
        vault.add_timeline_event(
            issue_id,
            event_type="free text",
            text="A factual note.",
            occurred_at="2026-01-03",
            source="firsthand",
        )

    notice = vault.add_timeline_event(
        issue_id,
        event_type="notice_sent",
        text="Sent a written repair request.",
        occurred_at="2026-01-03",
        source="message",
    )
    with pytest.raises(HabitableError, match="response_received"):
        vault.add_timeline_event(
            issue_id,
            event_type="condition_observed",
            text="Still leaking.",
            occurred_at="2026-01-04",
            source="firsthand",
            response_entry_id=notice,
        )


def _linked_case(
    vault: Vault, photo: Path, tsa: LocalRfc3161TSA
) -> tuple[str, tuple[str, str, str, str]]:
    issue_id = vault.document.add_issue(category="mold", title="Mold", issue_id="i1")
    captured = capture(vault, photo, issue_id=issue_id, tsa=tsa)
    notice = vault.add_timeline_event(
        issue_id,
        event_type="notice_sent",
        text="Sent repair request by email.",
        occurred_at="2026-01-03",
        source="message",
    )
    receipt = vault.add_timeline_event(
        issue_id,
        event_type="delivery_confirmed",
        text="Email system recorded delivery.",
        occurred_at="2026-01-03",
        source="document",
        notice_entry_id=notice,
    )
    response = vault.add_timeline_event(
        issue_id,
        event_type="response_received",
        text="Manager said someone would inspect next week.",
        occurred_at="2026-01-04",
        source="message",
        notice_entry_id=notice,
        receipt_entry_id=receipt,
    )
    summary = vault.add_timeline_event(
        issue_id,
        event_type="condition_observed",
        text="Leak continued after the response.",
        occurred_at="2026-01-05",
        source="firsthand",
        capture_ids=(captured.capture_id,),
        notice_entry_id=notice,
        receipt_entry_id=receipt,
        response_entry_id=response,
    )
    return captured.capture_id, (notice, receipt, response, summary)


def test_packet_v3_links_and_custody_verify_and_render_deterministically(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    vault = make_vault()
    capture_id, (notice, receipt, response, summary) = _linked_case(vault, make_jpeg(), local_tsa)
    out = tmp_path / "packet"
    result = build_packet(vault, out, generated_at="2026-01-06T00:00:00Z")
    bundle = json.loads(result.bundle_path.read_text(encoding="utf-8"))

    assert bundle["packet_version"] == PACKET_VERSION == 3
    by_id = {entry["entry_id"]: entry for entry in bundle["timeline"]}
    event = by_id[summary]
    assert "kind" not in event and "hlc" not in event  # do not reuse packet-v2 meanings
    assert event["occurred_at"] == "2026-01-05"
    assert event["recorded_at"].endswith("Z")
    assert event["source"] == "firsthand"
    assert event["links"] == {
        "capture_ids": [capture_id],
        "notice_entry_id": notice,
        "receipt_entry_id": receipt,
        "response_entry_id": response,
    }
    assert event["integrity"]["binding_stage"] == "recorded"
    assert verify_packet(out).ok

    html_once = (out / "packet.html").read_text(encoding="utf-8")
    assert "Occurred: 2026-01-05" in html_once
    assert "Source: Firsthand observation" in html_once
    assert "custody-bound when recorded" in html_once
    assert f"notice {notice}" in html_once and f"response {response}" in html_once
    # Rendering the same signed mapping twice is byte-for-byte stable.
    from habitable.htmlpacket import render_packet_html

    second = tmp_path / "packet-again.html"
    render_packet_html(bundle, out / "media", second)
    assert second.read_text(encoding="utf-8") == html_once
    assert result.pdf_path is not None and result.pdf_path.stat().st_size > 1000


def test_legacy_case_entry_migrates_without_inventing_occurrence_or_source(
    make_vault: Callable[..., Vault], tmp_path: Path
) -> None:
    vault = make_vault()
    issue_id = vault.document.add_issue(category="mold", issue_id="i1")
    legacy_id = vault.document.add_timeline_entry(issue_id, "sent_request", "Asked for repair")
    vault.save()

    out = tmp_path / "packet"
    build_packet(vault, out, generated_at="2026-01-06T00:00:00Z", make_pdf=False)
    bundle = json.loads((out / "bundle.json").read_text(encoding="utf-8"))
    event = next(item for item in bundle["timeline"] if item["entry_id"] == legacy_id)
    assert event["event_type"] == "other"
    assert event["other_label"] == "sent_request"
    assert event["occurred_at"] == ""
    assert event["source"] == "unspecified"
    assert event["migration"]["occurred_at_unknown"] is True
    assert event["integrity"]["binding_stage"] == "migration"
    assert verify_packet(out).ok


def test_resigned_timeline_tamper_fails_v3_commitment_check(
    make_vault: Callable[..., Vault], tmp_path: Path
) -> None:
    vault = make_vault()
    issue_id = vault.document.add_issue(category="mold", issue_id="i1")
    vault.add_timeline_event(
        issue_id,
        event_type="condition_observed",
        text="Original factual note.",
        occurred_at="2026-01-03",
        source="firsthand",
    )
    out = tmp_path / "packet"
    build_packet(vault, out, generated_at="2026-01-06T00:00:00Z", make_pdf=False)

    bundle = json.loads((out / "bundle.json").read_text(encoding="utf-8"))
    bundle["timeline"][0]["text"] = "Changed after the custody commitment."
    bundle_bytes = canonical_json(bundle)
    (out / "bundle.json").write_bytes(bundle_bytes)
    _write_signature(vault, out, bundle_bytes)  # isolate the timeline/custody check

    report = verify_packet(out)
    assert report.signature_ok and report.custody_ok
    assert not report.ok
    assert any("timeline commitment does not match" in problem for problem in report.problems)


def test_spanish_timeline_rendering_uses_same_signed_fields(
    make_jpeg: Callable[..., Path], local_tsa: LocalRfc3161TSA, tmp_path: Path
) -> None:
    vault = Vault.create(tmp_path / "vault-es", "pw", case_id="caso", unit="4B", language="es")
    issue_id = vault.document.add_issue(category="moho", title="Moho", issue_id="i1")
    captured = capture(vault, make_jpeg("es.jpg"), issue_id=issue_id, tsa=local_tsa)
    vault.add_timeline_event(
        issue_id,
        event_type="other",
        other_label="Visita de mantenimiento",
        text="La persona de mantenimiento tomó notas.",
        occurred_at="2026-01-03",
        source="other",
        source_detail="testigo presencial",
        capture_ids=(captured.capture_id,),
    )
    out = tmp_path / "packet-es"
    result = build_packet(vault, out, generated_at="2026-01-06T00:00:00Z")
    html = (out / "packet.html").read_text(encoding="utf-8")
    assert "Cronología de la evidencia" in html
    assert "Ocurrió: 2026-01-03" in html
    assert "Fuente: Otra fuente: testigo presencial" in html
    assert "protegido por custodia al registrarse" in html
    assert verify_packet(out).ok
    assert result.pdf_path is not None and result.pdf_path.stat().st_size > 1000
