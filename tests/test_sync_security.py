# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Adversarial tests for authenticated, case-bound sync protocol v2."""

from __future__ import annotations

import base64
import hmac
import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import cast

import pytest

from habitable.canonical import JSONValue, canonical_json, sha256_bytes
from habitable.capture import capture
from habitable.clock import HybridLogicalClock
from habitable.crypto import Identity, PublicIdentity, open_sealed, seal_to
from habitable.errors import SyncError, VaultError
from habitable.evidence import CustodyLog
from habitable.model import CaseDocument, verify_state_provenance
from habitable.packet import build_packet
from habitable.pairing import (
    PAIRING_PREFIX,
    accept_pairing_material,
    create_pairing_material,
)
from habitable.sync import export_message, import_messages
from habitable.tsa import LocalRfc3161TSA, retimestamp
from habitable.vault import Vault
from habitable.verify import verify_packet


def test_pairing_material_is_sealed_signed_case_bound_and_persistent(tmp_path: Path) -> None:
    a = Vault.create(tmp_path / "a", "pw-a", case_id="case-4B")
    b = Vault.create(tmp_path / "b", "pw-b", case_id="case-4B")
    wrong_case = Vault.create(tmp_path / "wrong", "pw-w", case_id="case-9C")

    material = create_pairing_material(a, b.identity.public())
    assert material.startswith(PAIRING_PREFIX)
    assert a.document.case_id not in material
    assert a.identity.public().encode() not in material

    accepted = accept_pairing_material(b, material)
    assert accepted == a.identity.public()
    assert Vault.open(a.path, "pw-a").sync_peer(b.identity.public()) is not None
    assert Vault.open(b.path, "pw-b").sync_peer(a.identity.public()) is not None

    wrong_material = create_pairing_material(a, wrong_case.identity.public())
    with pytest.raises(SyncError, match="for case"):
        accept_pairing_material(wrong_case, wrong_material)

    tampered = material[:-1] + ("A" if material[-1] != "A" else "B")
    with pytest.raises(SyncError, match="malformed, tampered, or not for this device"):
        accept_pairing_material(b, tampered)


def test_encrypted_sync_policy_fails_closed_for_unauthorized_mutation(
    make_vault: Callable[..., Vault],
) -> None:
    a = make_vault("a")
    b = make_vault("b")
    peer = a.sync_peer(b.identity.public())
    assert peer is not None

    # Re-accepting the exact record is idempotent, but implicit replacement and
    # malformed key material are rejected.
    a.authorize_sync_peer(b.identity.public(), peer.pairing_id, peer.key)
    with pytest.raises(VaultError, match="invalid sync pairing"):
        a.authorize_sync_peer(b.identity.public(), "", b"short")
    with pytest.raises(VaultError, match="already paired"):
        a.authorize_sync_peer(b.identity.public(), "different", b"x" * 32)

    stranger = Identity.generate().public()
    assert a.pending_sync_receipts(stranger) == ()
    assert a.source_custody(stranger, "capture") is None
    assert a.verified_sync_receipt(stranger, "message") is None
    assert a.sent_sync_message_digest(stranger, "message") is None
    with pytest.raises(VaultError, match="unauthorized peer"):
        a.record_sync_message_sent(stranger, "message", "digest")
    with pytest.raises(VaultError, match="unauthorized peer"):
        a.mark_sync_message_seen(stranger, "message")
    with pytest.raises(VaultError, match="unauthorized peer"):
        a.queue_sync_receipt(stranger, "message", {})
    with pytest.raises(VaultError, match="unauthorized peer"):
        a.record_verified_sync_receipt(stranger, "message", {})
    with pytest.raises(VaultError, match="unauthorized peer"):
        a.record_source_custody(stranger, "capture", {})


def test_legacy_fields_are_signed_as_attestations_before_v2_transfer() -> None:
    clock = HybridLogicalClock("legacy", time_source=lambda: 1_000)
    document = CaseDocument("case-legacy", clock)
    document.set_meta("unit", "4B")
    document.add_issue(category="mold", title="Legacy value", issue_id="i1")
    identity = Identity.generate()
    document.set_identity(identity)

    assert document.attest_unsigned_fields() == 7
    assert document.attest_unsigned_fields() == 0
    state = document.to_state()
    provenance = document.field_provenance("i1", "title")
    assert provenance is not None
    assert provenance.kind == "attested_legacy"
    assert provenance.actor == identity.public().fingerprint
    assert (
        verify_state_provenance(
            document.case_id,
            state,
            identity.public().fingerprint,
            identity.public().sign_public,
        )
        == []
    )


def test_concurrent_legacy_attestations_keep_crdt_merge_commutative() -> None:
    original = CaseDocument("case-legacy", HybridLogicalClock("legacy", time_source=lambda: 1_000))
    original.set_meta("unit", "4B")
    unsigned_state = original.to_state()

    left = CaseDocument.from_state(
        unsigned_state, HybridLogicalClock("left", time_source=lambda: 2_000)
    )
    right = CaseDocument.from_state(
        unsigned_state, HybridLogicalClock("right", time_source=lambda: 3_000)
    )
    left.set_identity(Identity.generate())
    right.set_identity(Identity.generate())
    left.attest_unsigned_fields()
    right.attest_unsigned_fields()

    left_then_right = CaseDocument.from_state(
        left.to_state(), HybridLogicalClock("merge-a", time_source=lambda: 4_000)
    )
    right_then_left = CaseDocument.from_state(
        right.to_state(), HybridLogicalClock("merge-b", time_source=lambda: 5_000)
    )
    left_then_right.merge(right.to_state())
    right_then_left.merge(left.to_state())
    assert left_then_right.to_state() == right_then_left.to_state()


def test_unpaired_sender_is_rejected_before_state_merge(
    make_vault: Callable[..., Vault],
) -> None:
    recipient = make_vault("recipient")
    attacker = Identity.generate()
    inner: dict[str, JSONValue] = {
        "protocol": "habitable-sync-v2",
        "message_id": "a" * 64,
        "case_id": recipient.document.case_id,
        "recipient": recipient.identity.public().encode(),
        "state": recipient.document.to_state(),
        "state_sha256": sha256_bytes(canonical_json(recipient.document.to_state())),
        "have": [],
        "captures": [],
        "custody_proof": CustodyLog().integrity_proof(),
        "receipts": [],
    }
    inner_bytes = canonical_json(inner)
    envelope: dict[str, JSONValue] = {
        "sender": attacker.public().encode(),
        "pairing_id": "not-authorized",
        "inner_b64": base64.b64encode(inner_bytes).decode("ascii"),
        "sig": base64.b64encode(attacker.sign(inner_bytes)).decode("ascii"),
        "mac": base64.b64encode(b"x" * 32).decode("ascii"),
    }
    blob = seal_to(recipient.identity.public(), canonical_json(envelope))

    before = recipient.document.to_state()
    with pytest.raises(SyncError, match="not an authorized peer"):
        import_messages(recipient, [blob])
    assert recipient.document.to_state() == before


def test_wrong_case_and_pairing_mac_tamper_fail_closed(
    make_vault: Callable[..., Vault],
) -> None:
    a = make_vault("a")
    b = make_vault("b")
    original = export_message(a, b.identity.public())
    envelope, inner = _open_message(b, original)

    wrong_state = dict(cast(Mapping[str, JSONValue], inner["state"]))
    wrong_state["case_id"] = "case-other"
    wrong_inner = dict(inner)
    wrong_inner["case_id"] = "case-other"
    wrong_inner["state"] = wrong_state
    wrong_inner["state_sha256"] = sha256_bytes(canonical_json(wrong_state))
    wrong_blob = _seal_authenticated(a, b.identity.public(), wrong_inner)
    with pytest.raises(SyncError, match="message is for case"):
        import_messages(b, [wrong_blob])

    envelope["mac"] = base64.b64encode(b"0" * 32).decode("ascii")
    tampered_blob = seal_to(b.identity.public(), canonical_json(envelope))
    with pytest.raises(SyncError, match="pairing authentication"):
        import_messages(b, [tampered_blob])
    assert b.document.issues() == []


def test_replay_is_detected_without_reapplying_custody(
    make_vault: Callable[..., Vault],
) -> None:
    a = make_vault("a")
    b = make_vault("b")
    blob = export_message(a, b.identity.public())

    first = import_messages(b, [blob])
    custody_length = len(b.custody)
    second = import_messages(b, [blob])
    assert first.messages_merged == 1
    assert second.messages_merged == 0
    assert second.replays_skipped == 1
    assert len(b.custody) == custody_length


def test_per_field_provenance_survives_merge_and_rejects_forged_overwrite(
    make_vault: Callable[..., Vault],
) -> None:
    a = make_vault("a")
    b = make_vault("b")
    a.document.add_issue(category="mold", title="Original", issue_id="i1")
    a.save()
    valid_blob = export_message(a, b.identity.public())
    assert import_messages(b, [valid_blob]).messages_merged == 1
    provenance = b.document.field_provenance("i1", "title")
    assert provenance is not None
    assert provenance.actor == a.identity.public().fingerprint
    assert provenance.signed

    _envelope, inner = _open_message(b, export_message(a, b.identity.public()))
    state = cast(dict[str, JSONValue], inner["state"])
    issue_fields = cast(dict[str, JSONValue], state["issue_fields"])
    registers = cast(dict[str, JSONValue], issue_fields["i1"])
    title = cast(dict[str, JSONValue], registers["title"])
    title["value"] = "Forged after signing"
    inner["state_sha256"] = sha256_bytes(canonical_json(state))
    forged = _seal_authenticated(a, b.identity.public(), inner)

    with pytest.raises(SyncError, match="field provenance signature is invalid"):
        import_messages(b, [forged])
    assert b.document.issues()[0].title == "Original"

    # Removing every provenance field is not a legacy escape hatch: an
    # authenticated peer still cannot downgrade attribution to unsigned.
    _envelope, downgraded_inner = _open_message(b, export_message(a, b.identity.public()))
    downgraded_state = cast(dict[str, JSONValue], downgraded_inner["state"])
    downgraded_issue_fields = cast(dict[str, JSONValue], downgraded_state["issue_fields"])
    downgraded_registers = cast(dict[str, JSONValue], downgraded_issue_fields["i1"])
    downgraded_title = cast(dict[str, JSONValue], downgraded_registers["title"])
    downgraded_title.pop("actor")
    downgraded_title.pop("sig")
    downgraded_title.pop("provenance_kind")
    downgraded_inner["state_sha256"] = sha256_bytes(canonical_json(downgraded_state))
    downgraded = _seal_authenticated(a, b.identity.public(), downgraded_inner)
    with pytest.raises(SyncError, match="unsigned mutable field"):
        import_messages(b, [downgraded])
    assert b.document.issues()[0].title == "Original"


def test_signed_receipt_round_trip_is_bound_to_the_exact_message(
    make_vault: Callable[..., Vault],
) -> None:
    a = make_vault("a")
    b = make_vault("b")
    outbound = export_message(a, b.identity.public())
    _envelope, inner = _open_message(b, outbound)
    message_id = cast(str, inner["message_id"])
    assert import_messages(b, [outbound]).receipts_created == 1

    reply = export_message(b, a.identity.public())
    result = import_messages(a, [reply])
    assert result.receipts_received == 1
    receipt = a.verified_sync_receipt(b.identity.public(), message_id)
    assert receipt is not None
    payload = cast(Mapping[str, JSONValue], receipt["payload"])
    assert payload["message_sha256"] == a.sent_sync_message_digest(b.identity.public(), message_id)
    assert payload["importer"] == b.identity.public().encode()


def test_sync_preserves_complete_timestamp_and_custody_material_for_packet(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    a = make_vault("a")
    b = make_vault("b")
    issue_id = a.document.add_issue(category="mold", title="Mold", issue_id="i1")
    captured = capture(a, make_jpeg(), issue_id=issue_id, tsa=local_tsa)
    extra_tsa = LocalRfc3161TSA("extra", time_source=lambda: 1_767_312_100)
    archive_tsa = LocalRfc3161TSA("archive", time_source=lambda: 1_767_312_200)
    extra = extra_tsa.stamp(captured.content_hash)
    primary = a.get_token(captured.capture_id)
    assert primary is not None
    archive = retimestamp(primary, archive_tsa)
    a.add_additional_token(captured.capture_id, extra)
    a.add_archive_token(captured.capture_id, archive)
    a.save()

    blob = export_message(a, b.identity.public())
    result = import_messages(b, [blob])
    assert result.captures_imported == 1
    assert b.get_token(captured.capture_id) is not None
    assert [token.tsa_name for token in b.get_additional_tokens(captured.capture_id)] == ["extra"]
    assert [token.tsa_name for token in b.get_archive_tokens(captured.capture_id)] == ["archive"]

    source_proof = b.source_custody(a.identity.public(), captured.capture_id)
    assert source_proof is not None
    proof = source_proof
    entries = cast(list[Mapping[str, JSONValue]], proof["entries"])
    assert CustodyLog.from_records(entries).verify().ok

    packet = tmp_path / "packet"
    build_packet(b, packet, make_pdf=False, generated_at="2026-07-10T00:00:00Z")
    report = verify_packet(packet)
    assert report.ok
    bundle = json.loads((packet / "bundle.json").read_text(encoding="utf-8"))
    item = bundle["items"][0]
    assert len(item["additional_timestamps"]) == 1
    assert len(item["archive_timestamps"]) == 1


def _open_message(
    recipient: Vault, blob: bytes
) -> tuple[dict[str, JSONValue], dict[str, JSONValue]]:
    envelope_raw: JSONValue = json.loads(open_sealed(recipient.identity, blob))
    assert isinstance(envelope_raw, dict)
    inner_raw: JSONValue = json.loads(
        base64.b64decode(cast(str, envelope_raw["inner_b64"]), validate=True)
    )
    assert isinstance(inner_raw, dict)
    return envelope_raw, inner_raw


def _seal_authenticated(
    sender: Vault, recipient: PublicIdentity, inner: Mapping[str, JSONValue]
) -> bytes:
    peer = sender.sync_peer(recipient)
    assert peer is not None
    inner_bytes = canonical_json(dict(inner))
    envelope: dict[str, JSONValue] = {
        "sender": sender.identity.public().encode(),
        "pairing_id": peer.pairing_id,
        "inner_b64": base64.b64encode(inner_bytes).decode("ascii"),
        "sig": base64.b64encode(sender.identity.sign(inner_bytes)).decode("ascii"),
        "mac": base64.b64encode(hmac.digest(peer.key, inner_bytes, "sha256")).decode("ascii"),
    }
    return seal_to(recipient, canonical_json(envelope))
