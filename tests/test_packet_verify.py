# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Packet assembly and the standalone verifier, including tamper detection."""

from __future__ import annotations

import json
import shutil
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
from habitable.verify import (
    VerificationReport,
    _verify_appendix_redundancy,
    _verify_correspondence,
    _verify_item,
    verify_packet,
)


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
    """Every human rendering of one bundle makes the same metadata claim.

    ``inspector.html`` is asserted here, beside ``packet.html``, because until
    this test it was not asserted anywhere. #104 added the retained-metadata
    branch and threaded it through ``render_packet_html`` and the PDF; the third
    caller of the same helper, ``render_inspector_html``, kept the default and so
    printed "embedded location metadata removed from its shared media copies"
    over a packet whose own signed ``disclosures`` said the opposite -- in the
    view written specifically to be handed to an inspector.
    """
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
        inspector_view=True,
        policy=SharingPolicy(strip_location=False, strip_all_metadata=False),
    )

    bundle = json.loads((out / "bundle.json").read_text(encoding="utf-8"))
    disclosures = bundle["disclosures"]
    assert any("permits embedded metadata, including location" in note for note in disclosures)
    assert "custody identities not exported" in disclosures
    shared = next((out / "media").glob("*.jpg"))
    assert read_metadata(shared).has_location
    statement = proof_statement("es")
    for name in ("packet.html", "inspector.html"):
        html = (out / name).read_text(encoding="utf-8")
        assert statement.privacy_metadata_warning in html, name
        assert statement.privacy_stripped not in html, name


def test_stripping_policy_is_disclosed_in_every_human_view(
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    """The negative half: the reassuring sentence is still printed when it is true.

    Without this, the assertion above could be satisfied by a renderer that had
    simply lost the ability to say "removed" at all.
    """
    from habitable.disclosure import proof_statement

    vault = Vault.create(tmp_path / "vault-stripped", "pw", case_id="c", unit="4B", language="es")
    issue = vault.document.add_issue(category="mold", title="Mold", issue_id="i1")
    capture(vault, make_jpeg("stripped.jpg", with_location=True), issue_id=issue, tsa=local_tsa)
    out = tmp_path / "packet-stripped"
    build_packet(
        vault,
        out,
        generated_at="2026-01-02T00:10:00Z",
        make_pdf=False,
        inspector_view=True,
        policy=SharingPolicy(strip_location=True, strip_all_metadata=True),
    )

    statement = proof_statement("es")
    for name in ("packet.html", "inspector.html"):
        html = (out / name).read_text(encoding="utf-8")
        assert statement.privacy_stripped in html, name
        assert statement.privacy_metadata_warning not in html, name


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
    # No anchor was supplied, so the note says that, rather than implying the
    # token failed a check it was never given the material to pass (issue #159).
    assert "no certificate anchor was supplied" in notes
    assert untrusted["anchors_supplied"] == 0
    assert "no certificate anchor was supplied" in cast("str", untrusted["guidance"])

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
    assert anchored_notes.strip() == ""
    assert anchored["anchors_supplied"] == 1

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
    # A real embedded original, matching the primary fixture's content hash --
    # this test is about multi-authority timestamp logic, not evidence-byte
    # presence (issue #158 decision 3), so give the item real bytes rather
    # than relying on the now-forbidden shared_name="" + no-original state.
    (tmp_path / "originals").mkdir()
    (tmp_path / "originals" / "cap-x").write_bytes(b"some sealed bytes")

    def item_for(content_hash: str) -> dict[str, JSONValue]:
        return cast(
            "dict[str, JSONValue]",
            {
                "capture_id": "cap-x",
                "shared_name": "",
                "shared_hash": "",
                "has_original": True,
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
    # A real embedded original: this test isolates timestamp validity from byte
    # presence (issue #158 decision 3 requires the latter for structural
    # intactness on its own), so give the item real evidence bytes.
    (tmp_path / "originals").mkdir()
    (tmp_path / "originals" / "cap-invalid").write_bytes(b"expected content")
    item: dict[str, JSONValue] = {
        "capture_id": "cap-invalid",
        "content_hash": sha256_bytes(b"expected content"),
        "shared_name": "",
        "shared_hash": "",
        "has_original": True,
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


def test_byteless_item_is_never_structurally_intact_or_evidence_ready(
    local_tsa: LocalRfc3161TSA, tmp_path: Path
) -> None:
    """issue #158 decision 3: an item with no shared media and no embedded
    original must never be ``evidence_ready``, even with an otherwise perfect,
    authority-trusted timestamp over its content hash.

    Decision 1 (``packet._require_shareable_bytes``) makes this state
    unreachable through ``build_packet``, so this test constructs the item by
    hand -- the defense-in-depth scenario this check exists for: a hand-
    crafted bundle, a future code path that bypasses ``build_packet``, or a
    packet produced by a different tool entirely.
    """
    content_hash = sha256_bytes(b"a photograph that was never actually included")
    token = local_tsa.stamp(content_hash)
    item: dict[str, JSONValue] = {
        "capture_id": "cap-byteless",
        "content_hash": content_hash,
        "media_type": "image/heic",
        "shared_name": "",
        "shared_hash": "",
        "timestamp": cast("JSONValue", token.to_dict()),
    }
    verdict = _verify_item(item, tmp_path, {}, {}, [local_tsa.certificate])

    # The timestamp itself is perfectly valid and trusted...
    assert verdict.timestamp_verified
    assert verdict.timestamp_authority_trusted
    # ...but there is nothing behind it: no shared copy, no embedded original.
    assert not verdict.evidence_present
    assert not verdict.structurally_intact
    assert not verdict.cryptographically_verified
    assert not verdict.evidence_ready
    assert not verdict.ok
    assert "no checkable evidence bytes" in " ".join(verdict.notes)
    assert "no photo, recording, or file was included" in verdict.human_detail("en")
    assert "no se incluyó ninguna foto" in verdict.human_detail("es")

    report = VerificationReport(
        packet_dir=tmp_path,
        signature_ok=True,
        custody_ok=True,
        custody_length=1,
        items=(verdict,),
        problems=(),
    )
    assert not report.structurally_intact
    assert not report.evidence_ready
    assert not report.ok
    assert report.status == "integrity_failed"
    assert "evidence readiness: READY" not in report.summary()
    assert "evidence readiness: NOT READY" in report.summary()


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


def test_every_disclosure_lookup_resolves_a_regional_tag_the_same_way() -> None:
    """Issue #210: three sibling lookups in `disclosure.py` disagreed on `es-MX`.

    `proof_statement` and `packet_trust_text` normalized (lowercase, strip the
    region subtag); `scope_statement` did an exact-match `lang in _SCOPE`. So a
    union running `habitable init --lang es-MX` — which `cli.py` accepts as free
    text, and which `i18n.normalize_locale` documents as expected input — got a
    Spanish packet with one English section wedged in the middle of it: "Scope of
    this export", the section stating whether the packet covers the whole unit or
    a single issue. That is a distinction a court or inspector reads.

    Pinned across all three functions, not just the one that was wrong, because
    the defect was drift between siblings and a fix to one of them does not stop
    the next one drifting.
    """
    from habitable.disclosure import packet_trust_text, proof_statement, scope_statement

    spanish_spellings = ("es", "es-MX", "es-ES", "ES", "es_MX", "ES-mx", "es-419")
    for tag in spanish_spellings:
        assert proof_statement(tag) == proof_statement("es"), tag
        assert packet_trust_text(tag) == packet_trust_text("es"), tag
        assert scope_statement(tag, scope_type="unit") == scope_statement(
            "es", scope_type="unit"
        ), f"{tag} resolved to a different scope statement than plain 'es'"

    # An unsupported language still falls back to English in all three, rather
    # than raising on a packet that has already been signed and handed over.
    for tag in ("fr", "de-CH", "", "not-a-language"):
        assert proof_statement(tag) == proof_statement("en"), tag
        assert packet_trust_text(tag) == packet_trust_text("en"), tag
        assert scope_statement(tag, scope_type="unit") == scope_statement(
            "en", scope_type="unit"
        ), tag

    # And the two languages are genuinely different text, so the assertions above
    # are not all trivially comparing English to English.
    assert scope_statement("es", scope_type="unit") != scope_statement("en", scope_type="unit")


# ----------------------------------------------------------------------------------
# appendix.redundancy — the one appendix figure the verifier cannot re-derive
# ----------------------------------------------------------------------------------


def test_a_packet_that_omits_the_device_count_still_verifies() -> None:
    """Absence is accepted, and it has to be.

    Every packet exported before issue #297 shipped omits ``redundancy``,
    including all six committed golden fixtures. Requiring the field would turn
    "every packet version we have emitted keeps verifying" -- the compatibility
    guarantee `tests/test_golden.py` exists for -- into a promise this repository
    broke the day it added an optional field.
    """
    assert _verify_appendix_redundancy({"item_count": 0}) == []


def test_a_well_formed_device_count_raises_no_problem() -> None:
    assert (
        _verify_appendix_redundancy(
            {
                "redundancy": {
                    "state": "acknowledged",
                    "device_count": 3,
                    "acknowledged_by": 2,
                    "identities_included": False,
                    "as_of": "2026-01-02T00:05:00Z",
                }
            }
        )
        == []
    )
    assert (
        _verify_appendix_redundancy(
            {
                "redundancy": {
                    "state": "this_device_only",
                    "device_count": 1,
                    "acknowledged_by": 0,
                    "identities_included": False,
                }
            }
        )
        == []
    )


@pytest.mark.parametrize(
    ("redundancy", "expected"),
    [
        pytest.param("not an object", "not an object", id="scalar"),
        pytest.param(
            {
                "state": "everyone",
                "device_count": 2,
                "acknowledged_by": 1,
                "identities_included": False,
            },
            "state is not one of",
            id="state-outside-the-vocabulary",
        ),
        pytest.param(
            {
                "state": "acknowledged",
                "device_count": "2",
                "acknowledged_by": 1,
                "identities_included": False,
            },
            "are not counts",
            id="count-as-a-string",
        ),
        pytest.param(
            {
                "state": "acknowledged",
                "device_count": 4,
                "acknowledged_by": 1,
                "identities_included": False,
            },
            "does not count the producing device plus",
            id="arithmetic-a-hand-edit-would-carry",
        ),
        pytest.param(
            {
                "state": "this_device_only",
                "device_count": 3,
                "acknowledged_by": 2,
                "identities_included": False,
            },
            "contradicts acknowledged_by",
            id="word-and-number-disagree",
        ),
        pytest.param(
            {
                "state": "acknowledged",
                "device_count": 2,
                "acknowledged_by": 1,
                "identities_included": True,
            },
            "counts devices and never names them",
            id="identities-claimed",
        ),
        pytest.param(
            {
                "state": "acknowledged",
                "device_count": 2,
                "acknowledged_by": 1,
                "identities_included": False,
                "as_of": 1767312000,
            },
            "as_of is not a string",
            id="epoch-instead-of-a-date",
        ),
    ],
)
def test_a_stated_device_count_must_agree_with_its_own_arithmetic(
    redundancy: JSONValue, expected: str
) -> None:
    """Nothing in a packet says how many devices exist, so nothing re-derives this.

    What is checkable is that the producer's three numbers and the word beside
    them agree -- which is what refuses a hand-edited packet claiming four
    devices over one acknowledgement.
    """
    problems = _verify_appendix_redundancy({"redundancy": redundancy})
    assert any(expected in problem for problem in problems), problems


# ----------------------------------------------------------------------------------
# item.correspondence — a summary the verifier cannot re-derive either (issue #304)
# ----------------------------------------------------------------------------------


def _summary(**overrides: JSONValue) -> dict[str, JSONValue]:
    """A well-formed correspondence block, with one field replaced per test.

    Written out rather than parsed from a message on purpose: these tests are about
    what a *packet* may say, including packets nothing in this repository produced.
    """
    block: dict[str, JSONValue] = {
        "correspondence_schema": 1,
        "from_header": {"name": "From", "state": "present", "value": "a@example.test"},
        "date_header": {"name": "Date", "state": "absent", "value": ""},
        "subject": {"name": "Subject", "state": "unreadable", "value": ""},
        "message_id": {"name": "Message-ID", "state": "present", "value": "<x@y.test>"},
        "attachment_count": 2,
        "attachments_readable": 1,
        "attachments": [
            {"index": 1, "filename": "a.png", "media_type": "image/png"},
            {"index": 2, "filename": "b.txt", "media_type": "text/plain"},
        ],
        "body": {
            "state": "not_plain_text",
            "media_type": "text/html",
            "text": "",
            "characters": 0,
            "truncated": False,
        },
        "header_dates_are_claims": True,
        "warnings": ["attachment 2 of 2 (b.txt, text/plain) could not be decoded"],
    }
    block.update(overrides)
    return block


def test_an_item_that_is_not_a_message_raises_no_correspondence_problem() -> None:
    """Absence and an explicit null are both accepted, and both have to be.

    Every packet exported before issue #304 omits the field, including all seven
    fixtures committed before this one, and every photo item in every packet since
    carries it as ``null``. Requiring it would break the compatibility guarantee
    ``tests/test_golden.py`` exists for on the day an optional field shipped.
    """
    assert _verify_correspondence({"capture_id": "cap-1"}) == []
    assert _verify_correspondence({"capture_id": "cap-1", "correspondence": None}) == []


def test_a_well_formed_message_summary_raises_no_problem() -> None:
    assert _verify_correspondence({"correspondence": _summary()}) == []


@pytest.mark.parametrize(
    ("block", "expected"),
    [
        pytest.param("not an object", "correspondence is not an object", id="scalar"),
        pytest.param(
            _summary(header_dates_are_claims=False),
            "header_dates_are_claims must be true",
            id="a-header-date-promoted-to-a-proved-time",
        ),
        pytest.param(
            _summary(correspondence_schema=2),
            "correspondence_schema must be 1",
            id="a-schema-this-verifier-does-not-know",
        ),
        pytest.param(
            _summary(subject={"name": "Subject", "state": "withheld", "value": ""}),
            "subject.state is not one of",
            id="state-outside-the-vocabulary",
        ),
        pytest.param(
            _summary(subject={"name": "Subject", "state": "absent", "value": "leak"}),
            "carries a value while stating it is not present",
            id="a-value-under-a-state-that-says-there-is-none",
        ),
        pytest.param(
            _summary(attachment_count="two"),
            "are not counts",
            id="a-count-as-a-string",
        ),
        pytest.param(
            _summary(attachments_readable=3),
            "exceeds the attachment_count the message itself declares",
            id="more-read-than-the-message-declares",
        ),
        pytest.param(
            _summary(attachments=[{"index": 1, "filename": "a.png", "media_type": "image/png"}]),
            "does not list every attachment the message declares",
            id="an-inventory-shorter-than-its-own-count",
        ),
        pytest.param(
            _summary(body={"state": "rendered", "media_type": "", "text": ""}),
            "body.state is not one of",
            id="body-state-outside-the-vocabulary",
        ),
        pytest.param(
            _summary(from_header="Manager <m@example.test>"),
            "from_header is not an object",
            id="a-header-flattened-into-a-bare-string",
        ),
        pytest.param(
            _summary(subject={"name": "Subject", "state": "present", "value": 7}),
            "subject.value is not a string",
            id="a-header-value-that-is-not-text",
        ),
        pytest.param(
            _summary(body="the whole message, as a string"),
            "body is not an object",
            id="a-body-flattened-into-a-bare-string",
        ),
        pytest.param(
            _summary(attachments={"1": "a.png"}),
            "attachments is not an array",
            id="an-inventory-that-is-not-a-list",
        ),
    ],
)
def test_a_stated_message_summary_must_agree_with_itself(block: JSONValue, expected: str) -> None:
    """The verifier cannot re-parse the message: a packet exported without
    ``--include-originals`` does not carry the bytes. What it can refuse is a block
    that contradicts itself or has been edited into a stronger claim than the format
    allows -- above all one asserting that its ``Date:`` header is a verified time.
    """
    problems = _verify_correspondence({"correspondence": block})
    assert any(expected in problem for problem in problems), problems


def test_the_whole_packet_reports_a_hand_edited_message_summary(tmp_path: Path) -> None:
    """End to end, because `_verify_correspondence` being right is not the claim.

    The claim is that a packet carrying an edited summary comes back with a problem
    naming the item, which needs the call site as well as the function.
    """
    source = Path(__file__).resolve().parent / "golden" / "correspondence-packet-v4"
    packet = tmp_path / "packet"
    shutil.copytree(source, packet)
    bundle = json.loads((packet / "bundle.json").read_text("utf-8"))
    edited = next(item for item in bundle["items"] if item.get("correspondence"))
    edited["correspondence"]["header_dates_are_claims"] = False
    (packet / "bundle.json").write_text(json.dumps(bundle), encoding="utf-8")

    report = verify_packet(packet)
    assert not report.structurally_intact
    assert any(
        edited["capture_id"] in problem and "header_dates_are_claims" in problem
        for problem in report.problems
    ), report.problems
