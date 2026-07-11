# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Chelsea Kelly-Reif
"""Cross-tests for the contrib legal-aid reference importer + signed evidence receipt.

These exercise EXP-10's excellence bar: a downstream (third-party) system ingests and
independently re-verifies a habitable packet using only the published verifier subset plus
this reference importer, validated against the committed golden-packet corpus in CI.
"""

from __future__ import annotations

import copy
import json
import sys
from collections.abc import Callable
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.serialization import Encoding

# The importer lives in contrib/ (not the shipped wheel); put it on the path like an
# integrator vendoring it would.
_CONTRIB = Path(__file__).resolve().parent.parent / "contrib"
sys.path.insert(0, str(_CONTRIB))

import legal_aid_importer as imp  # noqa: E402  (after sys.path insert, by design)

from habitable.canonical import canonical_json, sha256_bytes  # noqa: E402
from habitable.capture import capture  # noqa: E402
from habitable.errors import VerificationError  # noqa: E402
from habitable.packet import build_packet  # noqa: E402
from habitable.tsa import LocalRfc3161TSA  # noqa: E402
from habitable.vault import Vault  # noqa: E402

_GOLDEN = Path(__file__).resolve().parent / "golden" / "packet-v1"


def test_import_golden_packet_verifies_and_builds_receipt() -> None:
    result = imp.import_packet(_GOLDEN, now="2026-01-02T00:10:00Z")

    # The golden corpus has no independently supplied trust root: format and token
    # mechanics pass, while authority trust/readiness fail closed.
    assert result.structurally_intact
    assert not result.evidence_ready and not result.ok
    receipt = result.receipt
    assert receipt["receipt_type"] == imp.RECEIPT_TYPE
    assert receipt["receipt_version"] == imp.RECEIPT_VERSION
    assert receipt["packet_schema"] == imp.PACKET_SCHEMA_ID
    assert receipt["verified_at"] == "2026-01-02T00:10:00Z"

    verdict = receipt["verdict"]
    assert verdict["ok"] is False
    assert verdict["structurally_intact"] is True
    assert verdict["timestamp_authority_trusted"] is False
    assert verdict["evidence_ready"] is False
    assert verdict["status"] == "timestamp_authority_untrusted"
    assert verdict["signature_ok"] is True
    assert verdict["custody_ok"] is True
    assert verdict["items_total"] == verdict["items_cryptographically_verified"] == 1
    assert verdict["items_verified"] == verdict["items_trusted_timestamp"] == 0

    # The receipt is pinned to the exact bundle bytes (the packet's identity).
    expected = sha256_bytes((_GOLDEN / "bundle.json").read_bytes())
    assert receipt["packet"]["bundle_sha256"] == expected == result.bundle_sha256
    assert receipt["packet"]["case_id"] == "golden-4B"
    assert receipt["packet"]["packet_version"] == 1

    # Per-item verdict is carried through with its timestamp authority.
    (item,) = receipt["items"]
    assert item["ok"] is False
    assert item["structurally_intact"] is True
    assert item["cryptographically_verified"] is True
    assert item["timestamp_verified"] is True
    assert item["timestamp_authority_trusted"] is False
    assert item["evidence_ready"] is False
    assert item["tsa_name"] == "golden-tsa"
    assert item["verified_authorities"] == ["golden-tsa"]
    assert item["trusted_authorities"] == []


def test_import_with_trusted_root_is_evidence_ready(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    vault: Vault = make_vault()
    issue = vault.document.add_issue(category="mold", issue_id="i1")
    capture(vault, make_jpeg(), issue_id=issue, tsa=local_tsa)
    packet = tmp_path / "packet"
    build_packet(vault, packet, generated_at="2026-01-02T00:10:00Z")

    result = imp.import_packet(packet, trusted_certs=[local_tsa.certificate])
    assert result.ok and result.evidence_ready and result.structurally_intact
    verdict = result.receipt["verdict"]
    assert verdict["ok"] is True
    assert verdict["timestamp_authority_trusted"] is True
    assert verdict["evidence_ready"] is True

    pem = tmp_path / "tsa.pem"
    pem.write_bytes(local_tsa.certificate.public_bytes(Encoding.PEM))
    assert imp._main([str(packet), "--trusted-cert", str(pem)]) == 0
    cli_receipt = json.loads(capsys.readouterr().out)
    assert cli_receipt["verdict"]["evidence_ready"] is True


def test_importer_cli_rejects_bad_trust_certificate(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad = tmp_path / "not-a-cert.pem"
    bad.write_text("not a certificate", encoding="utf-8")
    assert imp._main([str(_GOLDEN), "--trusted-cert", str(bad)]) == 2
    assert "could not load trusted certificate" in json.loads(capsys.readouterr().out)["error"]


def test_receipt_is_canonical_serializable() -> None:
    result = imp.import_packet(_GOLDEN, now="2026-01-02T00:10:00Z")
    # Must round-trip through the same canonical encoder the signature relies on.
    encoded = canonical_json(result.receipt)
    assert json.loads(encoded) == result.receipt


def test_verified_at_omitted_when_no_clock_supplied() -> None:
    receipt = imp.import_packet(_GOLDEN).receipt
    assert "verified_at" not in receipt  # do not invent a time


def test_sign_and_verify_receipt_roundtrip() -> None:
    private, public = imp.generate_signing_key()
    receipt = imp.import_packet(_GOLDEN, now="2026-01-02T00:10:00Z").receipt

    envelope = imp.sign_receipt(receipt, private)
    assert envelope["algorithm"] == "ed25519"
    assert envelope["receipt"] == receipt

    # Re-verify with the signer's key pinned: fully trusted.
    result = imp.verify_receipt(envelope, expected_public=public)
    assert result.ok
    assert result.digest_ok
    assert result.signature_ok
    assert result.key_trusted is True

    # Without pinning a key, signature still checks; trust is simply not asserted.
    unpinned = imp.verify_receipt(envelope)
    assert unpinned.ok
    assert unpinned.key_trusted is None


def test_tampered_receipt_fails_digest() -> None:
    private, public = imp.generate_signing_key()
    receipt = imp.import_packet(_GOLDEN, now="2026-01-02T00:10:00Z").receipt
    envelope = imp.sign_receipt(receipt, private)

    # Flip the stored verdict after signing — a downstream store must catch it.
    tampered = copy.deepcopy(envelope)
    tampered["receipt"]["verdict"]["ok"] = True
    result = imp.verify_receipt(tampered, expected_public=public)
    assert not result.ok
    assert not result.digest_ok


def test_wrong_key_is_untrusted() -> None:
    private, _ = imp.generate_signing_key()
    _, other_public = imp.generate_signing_key()
    receipt = imp.import_packet(_GOLDEN).receipt
    envelope = imp.sign_receipt(receipt, private)

    result = imp.verify_receipt(envelope, expected_public=other_public)
    assert result.digest_ok
    assert result.signature_ok  # signature is valid ...
    assert result.key_trusted is False  # ... but not from a key we pinned
    assert not result.ok


def test_malformed_envelope_fails_closed() -> None:
    assert not imp.verify_receipt({}).ok
    assert not imp.verify_receipt({"receipt": "not-a-dict"}).ok
    assert not imp.verify_receipt(
        {"receipt": {}, "receipt_sha256": "x", "sign_public": "!!", "signature": "!!"}
    ).ok


def test_missing_bundle_raises_verification_error(tmp_path: Path) -> None:
    with pytest.raises(VerificationError):
        imp.import_packet(tmp_path)


def test_tampered_packet_yields_failed_receipt(tmp_path: Path) -> None:
    # Copy the golden packet, corrupt the shared media, and confirm the receipt reports failure
    # rather than a false "intact" — the fail-closed contract the importer inherits.
    packet = tmp_path / "packet"
    packet.mkdir()
    (packet / "media").mkdir()
    (packet / "bundle.json").write_bytes((_GOLDEN / "bundle.json").read_bytes())
    (packet / "bundle.sig.json").write_bytes((_GOLDEN / "bundle.sig.json").read_bytes())
    for media in (_GOLDEN / "media").iterdir():
        (packet / "media" / media.name).write_bytes(b"corrupted-not-the-real-photo")

    result = imp.import_packet(packet, now="2026-01-02T00:10:00Z")
    assert not result.ok
    assert result.receipt["verdict"]["ok"] is False
    (item,) = result.receipt["items"]
    assert item["shared_media_ok"] is False
