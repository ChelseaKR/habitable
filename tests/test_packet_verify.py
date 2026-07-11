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
from habitable.config import SharingPolicy
from habitable.errors import PacketError
from habitable.exif import read_metadata
from habitable.packet import build_packet
from habitable.tsa import LocalRfc3161TSA
from habitable.vault import Vault
from habitable.verify import VerificationReport, _verify_item, verify_packet


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

    report = verify_packet(out, trusted_certs=[local_tsa.certificate])
    assert report.ok and report.signature_ok and report.custody_ok
    assert report.structurally_intact
    assert report.timestamp_authority_trusted
    assert report.evidence_ready
    assert report.verified_items == 2
    assert "evidence readiness: READY" in report.summary()

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
    assert "all embedded metadata stripped from supported shared media" in disclosures
    assert "custody identities not exported" in disclosures
    assert not any("custody identities EXPORTED" in note for note in disclosures)


def test_retained_metadata_policy_is_disclosed_in_bundle_and_human_view(
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    from habitable.disclosure import proof_statement

    vault = Vault.create(tmp_path / "vault-retained", "pw", case_id="c", unit="4B", language="es")
    issue = vault.document.add_issue(category="mold", title="Mold", issue_id="i1")
    capture(vault, make_jpeg("retained.jpg", with_location=True), issue_id=issue, tsa=local_tsa)
    out = tmp_path / "packet-retained"
    build_packet(
        vault,
        out,
        generated_at="2026-01-02T00:10:00Z",
        make_pdf=False,
        policy=SharingPolicy(strip_location=False, strip_all_metadata=False),
    )

    bundle = json.loads((out / "bundle.json").read_text(encoding="utf-8"))
    disclosures = bundle["disclosures"]
    assert any("permits embedded metadata, including location" in note for note in disclosures)
    assert "custody identities not exported" in disclosures
    shared = next((out / "media").glob("*.jpg"))
    assert read_metadata(shared).has_location
    html = (out / "packet.html").read_text(encoding="utf-8")
    statement = proof_statement("es")
    assert statement.privacy_metadata_warning in html
    assert statement.privacy_stripped not in html


def test_packet_html_has_proof_and_disclosure(
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    from habitable.disclosure import packet_trust_text, proof_statement, scope_statement

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
        trust = packet_trust_text(lang)
        assert stmt.heading in html  # "what this proves — and does not"
        assert stmt.privacy_heading in html  # "what this discloses"
        assert trust.view_notice in html
        assert trust.attached_unassessed in html
        assert "trusted-timestamped" not in html
        # The embedded-originals residual-PII warning appears only when originals ship.
        assert (stmt.privacy_originals_warning in html) is include_originals
        assert stmt.privacy_stripped in html
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
    # No TSA -> the item is queued (deferred) and ships awaiting a timestamp token.
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
    assert "awaiting a timestamp token" in html


def test_no_awaiting_note_when_all_timestamped(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    """When every item has a token attached, no awaiting disclosure is emitted."""
    vault = _case_with_two_captures(make_vault, make_jpeg, local_tsa)
    out = tmp_path / "packet"
    result = build_packet(vault, out, generated_at="2026-01-02T00:10:00Z")
    assert result.timestamped_count == result.item_count == 2

    assert not any("awaiting a timestamp token" in note for note in result.disclosures)
    bundle = json.loads((out / "bundle.json").read_text())
    assert not any("awaiting a timestamp token" in note for note in bundle["disclosures"])
    html = (out / "packet.html").read_text(encoding="utf-8")
    assert "awaiting a timestamp token" not in html


def test_packet_html_marks_dev_timestamp_untrusted(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    from habitable.disclosure import packet_trust_text
    from habitable.tsa import DevTSA

    vault = make_vault()
    issue = vault.document.add_issue(category="mold", issue_id="i1")
    capture(vault, make_jpeg(), issue_id=issue, tsa=DevTSA())
    out = tmp_path / "dev-packet"
    build_packet(vault, out, generated_at="2026-01-02T00:10:00Z")
    html = (out / "packet.html").read_text(encoding="utf-8")
    trust = packet_trust_text("en")
    assert trust.dev_untrusted in html
    assert "evidence readiness: READY" not in html

    # Even supplying an unrelated trusted certificate cannot upgrade DevTSA.
    report = verify_packet(out, trusted_certs=[local_tsa.certificate])
    assert report.structurally_intact and report.items[0].timestamp_verified
    assert not report.timestamp_authority_trusted and not report.evidence_ready


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

    def result(argv: list[str], expected_exit: int) -> dict[str, object]:
        assert main(argv) == expected_exit
        report = json.loads(capsys.readouterr().out)
        return cast("dict[str, object]", report)

    # Without a trusted root, signatures verify and integrity is intact, but the
    # fail-closed readiness verdict and process exit remain false/non-zero.
    untrusted = result(["verify", str(out), "--json"], 1)
    assert untrusted["structurally_intact"] is True
    assert untrusted["cryptographically_verified_items"] == 2
    assert untrusted["timestamp_authority_trusted"] is False
    assert untrusted["evidence_ready"] is False and untrusted["ok"] is False
    notes = " ".join(
        note
        for item in cast("list[dict[str, object]]", untrusted["items"])
        for note in cast("list[str]", item["notes"])
    )
    assert "not chained to a trusted root" in notes

    # With the issuer's own cert as a trusted root, that note is gone.
    pem = tmp_path / "root.pem"
    pem.write_bytes(local_tsa.certificate.public_bytes(Encoding.PEM))
    anchored = result(["verify", str(out), "--json", "--trusted-cert", str(pem)], 0)
    assert anchored["structurally_intact"] is True
    assert anchored["timestamp_authority_trusted"] is True
    assert anchored["evidence_ready"] is True and anchored["ok"] is True
    anchored_notes = " ".join(
        note
        for item in cast("list[dict[str, object]]", anchored["items"])
        for note in cast("list[str]", item["notes"])
    )
    assert "not chained to a trusted root" not in anchored_notes

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

    report = verify_packet(out, trusted_certs=[local_tsa.certificate, second.certificate])
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
    report = verify_packet(out, trusted_certs=[local_tsa.certificate, second.certificate])
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

    # No primary token, but a valid independent authority over the same hash: the
    # token verifies mechanically, while readiness still requires a trusted root.
    verdict = _verify_item(item_for(sha256_bytes(b"some sealed bytes")), tmp_path, {}, {}, None)
    assert verdict.timestamp_verified and verdict.cryptographically_verified
    assert not verdict.timestamp_authority_trusted and not verdict.ok
    assert verdict.verified_authorities == ("test-rfc3161",)

    trusted = _verify_item(
        item_for(sha256_bytes(b"some sealed bytes")),
        tmp_path,
        {},
        {},
        [local_tsa.certificate],
    )
    assert trusted.timestamp_authority_trusted and trusted.evidence_ready and trusted.ok

    # An additional token over a *different* hash does not satisfy the item.
    other = _verify_item(item_for(sha256_bytes(b"other")), tmp_path, {}, {}, None)
    assert not other.timestamp_verified and not other.ok


def test_invalid_attached_timestamp_is_not_mislabeled_awaiting(
    local_tsa: LocalRfc3161TSA, tmp_path: Path
) -> None:
    token = local_tsa.stamp(sha256_bytes(b"different content"))
    item: dict[str, JSONValue] = {
        "capture_id": "cap-invalid",
        "content_hash": sha256_bytes(b"expected content"),
        "shared_name": "",
        "shared_hash": "",
        "timestamp": cast("JSONValue", token.to_dict()),
    }
    verdict = _verify_item(item, tmp_path, {}, {}, [local_tsa.certificate])
    assert verdict.timestamp_present
    assert not verdict.timestamp_verified
    assert verdict.structurally_intact  # the packet bytes can still be intact as produced

    report = VerificationReport(
        packet_dir=tmp_path,
        signature_ok=True,
        custody_ok=True,
        custody_length=1,
        items=(verdict,),
        problems=(),
    )
    assert report.structurally_intact
    assert report.status == "timestamp_invalid"
    assert not report.timestamp_authority_trusted and not report.evidence_ready


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
    report = verify_packet(out, trusted_certs=[local_tsa.certificate])
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
    report = verify_packet(out, trusted_certs=[local_tsa.certificate])
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
    report = verify_packet(out, trusted_certs=[local_tsa.certificate])
    assert report.ok
    assert all(item.original_fixity_ok is True for item in report.items)

    # Corrupting an embedded original is caught by fixity.
    original = next((out / "originals").iterdir())
    original.write_bytes(b"not the original bytes")
    broken = verify_packet(out, trusted_certs=[local_tsa.certificate])
    assert not broken.structurally_intact and not broken.ok


def test_issue_selector_fails_even_when_selected_issue_has_no_captures(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    vault = _case_with_two_captures(make_vault, make_jpeg, local_tsa)
    # Even an apparently empty scope is blocked conservatively: the v3 custody
    # proof is whole-chain and would otherwise expose records outside the scope.
    other = vault.document.add_issue(category="heat", issue_id="i2")
    out = tmp_path / "packet"
    with pytest.raises(PacketError, match="scoped packet exports are temporarily blocked"):
        build_packet(vault, out, issue_id=other, generated_at="2026-01-02T00:10:00Z")
    assert not out.exists()


def test_issue_scope_fails_before_excluded_identifiers_can_be_published(
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
    excluded_timeline = vault.document.add_timeline_entry(i2, "observed", "freezing")
    excluded_capture = capture(
        vault, make_jpeg("b.jpg", with_location=True), issue_id=i2, tsa=local_tsa
    ).capture_id

    out = tmp_path / "packet"
    before_custody = vault.custody.to_vault_records()
    with pytest.raises(PacketError) as caught:
        build_packet(vault, out, issue_id="i1", generated_at="2026-01-02T00:10:00Z")

    error = str(caught.value)
    assert "scoped packet exports are temporarily blocked" in error
    assert "i2" not in error
    assert excluded_capture not in error
    assert excluded_timeline not in error
    assert not out.exists()  # no bundle, media, HTML, PDF, or partial staging output
    assert vault.custody.to_vault_records() == before_custody


def test_since_scope_fails_closed_before_any_output(
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
    before_custody = vault.custody.to_vault_records()
    with pytest.raises(PacketError, match="scoped packet exports are temporarily blocked"):
        build_packet(vault, out, since=since, generated_at="2026-01-04T00:10:00Z")
    assert not out.exists()
    assert vault.custody.to_vault_records() == before_custody
