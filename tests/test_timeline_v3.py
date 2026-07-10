# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Timeline 2.0 / packet-v3 semantics, custody binding, and rendering."""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from pathlib import Path

import pytest

from habitable.canonical import canonical_json
from habitable.capture import capture
from habitable.clock import HybridLogicalClock
from habitable.errors import HabitableError
from habitable.evidence import CustodyLog
from habitable.model import CaseDocument
from habitable.packet import PACKET_VERSION, _write_signature, build_packet
from habitable.tsa import LocalRfc3161TSA
from habitable.vault import Vault
from habitable.verify import _verify_v3_timeline, verify_packet


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


def test_export_repairs_incomplete_or_version_inappropriate_timeline_bindings(
    make_vault: Callable[..., Vault], tmp_path: Path
) -> None:
    """A stale note must not poison export by masquerading as a v3 binding."""
    vault = make_vault()
    issue_id = vault.document.add_issue(category="mold", issue_id="i1")
    current_id = vault.document.add_timeline_event(
        issue_id,
        event_type="condition_observed",
        text="A current-schema entry recorded outside the service wrapper.",
        occurred_at="2026-01-03",
        source="firsthand",
    )
    legacy_id = vault.document.add_timeline_entry(issue_id, "observed", "A legacy note.")
    entries = {entry.entry_id: entry for entry in vault.document.timeline()}
    actor = vault.identity.public().fingerprint

    # Missing timeline_schema: it has the right digest and a plausible stage, but
    # is not a valid packet-v3 declaration.
    vault.custody.append(
        "note_added",
        current_id,
        actor=actor,
        hlc=vault.document.clock.now().encode(),
        details={
            "timeline_sha256": entries[current_id].commitment(),
            "stage": "recorded",
        },
        identity=vault.identity,
    )
    # A legacy entry cannot truthfully claim it was bound when first recorded.
    vault.custody.append(
        "note_added",
        legacy_id,
        actor=actor,
        hlc=vault.document.clock.now().encode(),
        details={
            "timeline_schema": "2",
            "timeline_sha256": entries[legacy_id].commitment(),
            "stage": "recorded",
        },
        identity=vault.identity,
    )
    vault.save()

    out = tmp_path / "repaired-bindings"
    build_packet(vault, out, generated_at="2026-01-06T00:00:00Z", make_pdf=False)
    bundle = json.loads((out / "bundle.json").read_text(encoding="utf-8"))
    by_id = {entry["entry_id"]: entry for entry in bundle["timeline"]}
    assert by_id[current_id]["integrity"]["binding_stage"] == "backfill"
    assert by_id[legacy_id]["integrity"]["binding_stage"] == "migration"
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


def test_v3_verifier_fails_closed_on_malformed_semantics_and_links(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    """Exercise each v3 fail-closed boundary without hiding behind the outer signature."""
    vault = make_vault()
    _, (_, _, _, summary_id) = _linked_case(vault, make_jpeg(), local_tsa)
    out = tmp_path / "malformed-source"
    build_packet(vault, out, generated_at="2026-01-06T00:00:00Z", make_pdf=False)
    base = json.loads((out / "bundle.json").read_text(encoding="utf-8"))
    custody = CustodyLog.from_records(base["custody_proof"]["entries"])
    index = next(i for i, entry in enumerate(base["timeline"]) if entry["entry_id"] == summary_id)

    def event_problem(expected: str, **updates: object) -> None:
        bundle = copy.deepcopy(base)
        bundle["timeline"][index].update(updates)
        assert expected in "\n".join(_verify_v3_timeline(bundle, custody))

    event_problem("timeline_schema must be 2", timeline_schema=9)
    event_problem("entry_id must be a string", entry_id=7)
    event_problem("entry_id must not be empty", entry_id=" ")
    event_problem("order_token must not be empty", order_token="")
    event_problem("must not reuse legacy field", kind="observed", hlc="opaque")
    event_problem("unknown event_type", event_type="free_text")
    event_problem("Other event is missing", event_type="other", other_label="")
    event_problem("other_label is only valid", other_label="custom")
    event_problem("unknown source", source="rumor")
    event_problem("source unspecified", source="unspecified")
    event_problem("Other source is missing", source="other", source_detail="")
    event_problem("source_detail is only valid", source_detail="extra")
    event_problem("occurred_at may be empty", occurred_at="")
    event_problem("occurred_at is not normalized", occurred_at="2026-01-03T00:00:00-08:00")
    event_problem("occurred_at is not a valid", occurred_at="not-a-date")
    event_problem("recorded_at must be", recorded_at="not-utc")
    event_problem("recorded_at must be", recorded_at="not-a-dateZ")
    event_problem("text must not be empty", text=" ")
    event_problem("integrity.algorithm", integrity={})
    event_problem("migration must be an object", migration="legacy")
    event_problem(
        "legacy migration must carry",
        migration={"from_case_timeline_schema": 4},
    )
    event_problem("migration.from_case_timeline_schema", migration={"from_case_timeline_schema": 4})

    def links_problem(expected: str, links: object) -> None:
        event_problem(expected, links=links)

    links_problem("capture_ids must be an array", {"capture_ids": "bad"})
    links_problem(
        "capture_ids must not contain duplicates",
        {
            "capture_ids": ["same", "same"],
            "notice_entry_id": "",
            "receipt_entry_id": "",
            "response_entry_id": "",
        },
    )
    links_problem(
        "notice_entry_id must be a string",
        {
            "capture_ids": [7],
            "notice_entry_id": 7,
            "receipt_entry_id": 7,
            "response_entry_id": 7,
        },
    )

    malformed = copy.deepcopy(base)
    malformed["timeline"].append("bad")
    assert "malformed packet-v3 timeline entry" in _verify_v3_timeline(malformed, custody)

    duplicate = copy.deepcopy(base)
    duplicate["timeline"].append(copy.deepcopy(duplicate["timeline"][index]))
    duplicate["appendix"]["timeline_count"] += 1
    duplicate["appendix"]["custody_bound_timeline_count"] += 1
    assert "packet-v3 timeline contains duplicate" in "\n".join(
        _verify_v3_timeline(duplicate, custody)
    )

    counts = copy.deepcopy(base)
    counts["appendix"]["timeline_count"] = 0
    counts["appendix"]["custody_bound_timeline_count"] = 0
    assert "appendix.timeline_count" in "\n".join(_verify_v3_timeline(counts, custody))

    malformed_top_level: dict[str, tuple[str, object]] = {
        "timeline": ("packet-v3 timeline must be an array", {}),
        "issues": ("packet-v3 issues must be an array", {}),
        "items": ("packet-v3 items must be an array", {}),
        "appendix": ("packet-v3 appendix must be an object", []),
    }
    for key, (expected, bad_value) in malformed_top_level.items():
        malformed_bundle = copy.deepcopy(base)
        malformed_bundle[key] = bad_value
        assert expected in "\n".join(_verify_v3_timeline(malformed_bundle, custody))

    nonlegacy_migration_stage = copy.deepcopy(base)
    nonlegacy_migration_stage["timeline"][index]["integrity"]["binding_stage"] = "migration"
    assert "requires an explicit legacy migration" in "\n".join(
        _verify_v3_timeline(nonlegacy_migration_stage, custody)
    )

    missing_issue = copy.deepcopy(base)
    missing_issue["timeline"][index]["issue_id"] = "not-in-packet"
    issue_problems = "\n".join(_verify_v3_timeline(missing_issue, custody))
    assert "issue_id is not present" in issue_problems
    assert "linked capture" in issue_problems

    missing_link = copy.deepcopy(base)
    missing_link["timeline"][index]["links"]["notice_entry_id"] = "missing"
    assert "points to a missing timeline event" in "\n".join(
        _verify_v3_timeline(missing_link, custody)
    )

    wrong_issue = copy.deepcopy(base)
    notice_id = wrong_issue["timeline"][index]["links"]["notice_entry_id"]
    notice = next(entry for entry in wrong_issue["timeline"] if entry["entry_id"] == notice_id)
    notice["issue_id"] = "i2"
    wrong_issue["issues"].append({"issue_id": "i2"})
    assert "points to another issue" in "\n".join(_verify_v3_timeline(wrong_issue, custody))

    wrong_type = copy.deepcopy(base)
    notice_id = wrong_type["timeline"][index]["links"]["notice_entry_id"]
    notice = next(entry for entry in wrong_type["timeline"] if entry["entry_id"] == notice_id)
    notice["event_type"] = "repair"
    assert "does not point to a notice_sent" in "\n".join(_verify_v3_timeline(wrong_type, custody))


def test_renderer_marks_a_linked_capture_omitted_by_packet_scope(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    vault = make_vault()
    capture_id, (_, _, _, summary_id) = _linked_case(vault, make_jpeg(), local_tsa)
    out = tmp_path / "source-packet"
    build_packet(vault, out, generated_at="2026-01-06T00:00:00Z", make_pdf=False)
    bundle = json.loads((out / "bundle.json").read_text(encoding="utf-8"))
    assert any(entry["entry_id"] == summary_id for entry in bundle["timeline"])

    bundle["items"] = []
    bundle["appendix"]["item_count"] = 0
    bundle["appendix"]["timestamped_count"] = 0
    from habitable.htmlpacket import render_packet_html

    rendered = tmp_path / "omitted-capture.html"
    render_packet_html(bundle, out / "media", rendered)
    html = rendered.read_text(encoding="utf-8")
    assert f"capture {capture_id} (not included in this packet)" in html


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
