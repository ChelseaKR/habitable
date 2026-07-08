# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Packet assembly and the standalone verifier, including tamper detection."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest
from cryptography.hazmat.primitives.serialization import Encoding

from habitable.canonical import JSONValue, sha256_bytes
from habitable.capture import capture, resolve_deferred
from habitable.exif import read_metadata
from habitable.packet import build_packet
from habitable.tsa import LocalRfc3161TSA
from habitable.vault import Vault
from habitable.verify import _verify_item, verify_packet


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


def test_bundle_threads_captures_to_timeline_entries(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    """EXP-04: a capture linked to a timeline event carries that link into the packet."""
    vault = make_vault()
    issue = vault.document.add_issue(category="mold", room="bathroom", title="Mold", issue_id="i1")
    vault.document.add_timeline_entry(issue, "sent_request", "emailed landlord requesting repair")
    worsened = vault.document.add_timeline_entry(
        issue, "worsened", "14 days of silence; mold has spread"
    )
    result = capture(
        vault,
        make_jpeg("wall.jpg", with_location=True),
        issue_id=issue,
        tsa=local_tsa,
        timeline_entry_id=worsened,
    )
    out = tmp_path / "packet"
    build_packet(vault, out, generated_at="2026-01-02T00:10:00Z")
    bundle = json.loads((out / "bundle.json").read_text())

    [item] = bundle["items"]
    assert item["capture_id"] == result.capture_id
    assert item["timeline_entry_id"] == worsened
    worsened_entry = next(e for e in bundle["timeline"] if e["entry_id"] == worsened)
    assert worsened_entry["kind"] == "worsened"

    # Verification still checks each linked item independently (no new coupling).
    report = verify_packet(out)
    assert report.ok


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
    from habitable.disclosure import proof_statement, scope_statement

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
        # The minimal-disclosure scope statement renders, localized (R-35).
        scope = scope_statement(lang, scope_type="unit")
        assert scope.heading in html
        assert scope.statement in html


def test_awaiting_timestamp_disclosed_at_export(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    """A packet with an un-timestamped item discloses that honestly — never silently.

    FIX-09: one capture is stamped, one is queued offline (``tsa=None``), so the
    export is 1-of-2 awaiting. The awaiting state must surface in the ExportResult,
    in bundle.json, and in the packet's own EN disclosure section — without failing
    the export or implying the awaiting item is worthless.
    """
    from habitable.disclosure import proof_statement

    vault = make_vault()
    issue = vault.document.add_issue(category="mold", title="Mold", issue_id="i1")
    capture(vault, make_jpeg("a.jpg", with_location=True), issue_id=issue, tsa=local_tsa)
    # No TSA -> the item is queued (deferred) and ships awaiting a trusted timestamp.
    capture(vault, make_jpeg("b.jpg", with_location=True), issue_id=issue, tsa=None)

    out = tmp_path / "packet"
    result = build_packet(vault, out, generated_at="2026-01-02T00:10:00Z")
    assert result.item_count == 2 and result.timestamped_count == 1

    expected = proof_statement("en").awaiting_timestamp_note.format(awaiting=1, total=2)

    # (a) The in-process ExportResult carries the honest disclosure.
    assert expected in result.disclosures

    # (b) bundle.json records the same disclosure (drives CLI, app, and recipients).
    bundle = json.loads((out / "bundle.json").read_text())
    assert expected in bundle["disclosures"]

    # (c) The packet's own (localized) HTML disclosure section states it.
    html = (out / "packet.html").read_text(encoding="utf-8")
    assert expected in html
    assert "awaiting a trusted timestamp" in html


def test_no_awaiting_note_when_all_timestamped(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    """When every item is trusted-timestamped, no awaiting disclosure is emitted."""
    vault = _case_with_two_captures(make_vault, make_jpeg, local_tsa)
    out = tmp_path / "packet"
    result = build_packet(vault, out, generated_at="2026-01-02T00:10:00Z")
    assert result.timestamped_count == result.item_count == 2

    assert not any("awaiting a trusted timestamp" in note for note in result.disclosures)
    bundle = json.loads((out / "bundle.json").read_text())
    assert not any("awaiting a trusted timestamp" in note for note in bundle["disclosures"])
    html = (out / "packet.html").read_text(encoding="utf-8")
    assert "awaiting a trusted timestamp" not in html


def test_cli_verify_trusted_cert_anchors_chain(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from habitable.cli import main

    vault = _case_with_two_captures(make_vault, make_jpeg, local_tsa)
    out = tmp_path / "packet"
    build_packet(vault, out, generated_at="2026-01-02T00:10:00Z")

    def all_notes(argv: list[str]) -> str:
        assert main(argv) == 0
        report = json.loads(capsys.readouterr().out)
        return " ".join(note for item in report["items"] for note in item["notes"])

    # Without a trusted root, a valid token is flagged as not chained to one.
    assert "not chained to a trusted root" in all_notes(["verify", str(out), "--json"])

    # With the issuer's own cert as a trusted root, that note is gone.
    pem = tmp_path / "root.pem"
    pem.write_bytes(local_tsa.certificate.public_bytes(Encoding.PEM))
    anchored = all_notes(["verify", str(out), "--json", "--trusted-cert", str(pem)])
    assert "not chained to a trusted root" not in anchored

    # A bad cert path is a clean error, never a crash.
    assert main(["verify", str(out), "--trusted-cert", str(tmp_path / "nope.pem")]) == 1


def test_multi_authority_capture_and_verify(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    second = LocalRfc3161TSA("second-tsa")
    vault = make_vault()
    issue = vault.document.add_issue(category="mold", title="Mold", issue_id="i1")
    result = capture(
        vault,
        make_jpeg("a.jpg", with_location=True),
        issue_id=issue,
        tsa=local_tsa,
        extra_tsas=[second],
    )
    assert result.extra_authorities == ("second-tsa",)

    out = tmp_path / "packet"
    build_packet(vault, out, generated_at="2026-01-02T00:10:00Z")
    item = json.loads((out / "bundle.json").read_text())["items"][0]
    assert len(item["additional_timestamps"]) == 1

    report = verify_packet(out)
    assert report.ok
    authorities = set(report.items[0].verified_authorities)
    assert {"test-rfc3161", "second-tsa"} <= authorities  # both authorities verified


def test_deferred_then_resolved_reports_both_authorities(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    second = LocalRfc3161TSA("second-tsa")
    vault = make_vault()
    issue = vault.document.add_issue(category="mold", title="Mold", issue_id="i1")
    # Capture offline: the item is queued rather than stamped.
    capture(vault, make_jpeg("a.jpg", with_location=True), issue_id=issue, tsa=None)
    assert len(vault.deferred()) == 1

    resolved = resolve_deferred(vault, local_tsa, extra_tsas=[second])
    assert resolved[0].extra_authorities == ("second-tsa",)

    out = tmp_path / "packet"
    build_packet(vault, out, generated_at="2026-01-02T00:10:00Z")
    report = verify_packet(out)
    assert report.ok
    authorities = set(report.items[0].verified_authorities)
    assert {"test-rfc3161", "second-tsa"} <= authorities  # both authorities verified


def test_redundant_authority_satisfies_when_primary_absent(
    local_tsa: LocalRfc3161TSA, tmp_path: Path
) -> None:
    token = local_tsa.stamp(sha256_bytes(b"some sealed bytes"))

    def item_for(content_hash: str) -> dict[str, JSONValue]:
        return cast(
            "dict[str, JSONValue]",
            {
                "capture_id": "cap-x",
                "shared_name": "",
                "shared_hash": "",
                "timestamp": None,
                "content_hash": content_hash,
                "additional_timestamps": [token.to_dict()],
            },
        )

    # No primary token, but a valid independent authority over the same hash → verified.
    verdict = _verify_item(item_for(sha256_bytes(b"some sealed bytes")), tmp_path, {}, {}, None)
    assert verdict.timestamp_verified and verdict.ok
    assert verdict.verified_authorities == ("test-rfc3161",)

    # An additional token over a *different* hash does not satisfy the item.
    other = _verify_item(item_for(sha256_bytes(b"other")), tmp_path, {}, {}, None)
    assert not other.timestamp_verified and not other.ok


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


def test_issue_scope_excludes_other_issues_and_states_scope(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    vault = make_vault()
    i1 = vault.document.add_issue(category="mold", room="bath", title="Mold", issue_id="i1")
    vault.document.add_timeline_entry(i1, "observed", "mold spreading")
    capture(vault, make_jpeg("a.jpg", with_location=True), issue_id=i1, tsa=local_tsa)
    i2 = vault.document.add_issue(category="heat", title="No heat", issue_id="i2")
    vault.document.add_timeline_entry(i2, "observed", "freezing")
    capture(vault, make_jpeg("b.jpg", with_location=True), issue_id=i2, tsa=local_tsa)

    out = tmp_path / "packet"
    result = build_packet(vault, out, issue_id="i1", generated_at="2026-01-02T00:10:00Z")
    assert result.item_count == 1

    bundle = json.loads((out / "bundle.json").read_text())
    # The other issue's captures and timeline are absent, not merely down-ranked.
    assert {item["issue_id"] for item in bundle["items"]} == {"i1"}
    assert [e["issue_id"] for e in bundle["timeline"]] == ["i1"]
    assert {issue["issue_id"] for issue in bundle["issues"]} == {"i1"}

    # The machine-readable scope object states the minimal-disclosure boundary (R-35).
    scope = bundle["scope"]
    assert scope["type"] == "issue"
    assert "issue i1 only" in scope["statement"]
    assert scope["exclusions"] and any("not exported" in x for x in scope["exclusions"])

    # The scope statement also rides in the human-readable disclosures and in packet.html.
    assert any("issue i1 only" in note for note in bundle["disclosures"])
    html = (out / "packet.html").read_text(encoding="utf-8")
    assert "issue i1 only" in html
    assert "Scope of this export" in html

    assert verify_packet(out).ok  # a freshly scoped packet still verifies end-to-end


def test_since_excludes_earlier_items_and_states_exclusion(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    vault = make_vault()
    issue = vault.document.add_issue(category="mold", title="Mold", issue_id="i1")
    capture(
        vault,
        make_jpeg("old.jpg", capture_time="2026:01:01 00:00:00"),
        issue_id=issue,
        tsa=local_tsa,
    )
    capture(
        vault,
        make_jpeg("new.jpg", capture_time="2026:01:03 00:00:00"),
        issue_id=issue,
        tsa=local_tsa,
    )

    out = tmp_path / "packet"
    since = "2026-01-02T00:00:00Z"
    result = build_packet(vault, out, since=since, generated_at="2026-01-04T00:10:00Z")
    assert result.item_count == 1  # only the post-cutoff capture

    bundle = json.loads((out / "bundle.json").read_text())
    assert all(item["captured_at"] >= since for item in bundle["items"])
    assert any(since in x for x in bundle["scope"]["exclusions"])
    assert any(since in note for note in bundle["disclosures"])
    assert verify_packet(out).ok
