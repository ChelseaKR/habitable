# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Chelsea Kelly-Reif
"""Reference importer + signed evidence receipt for legal-aid case-management tools.

A legal-aid case-management system (persona P-23 in the roadmap; Alejandra / P-12 as the
organizer who hands over a packet) needs two things to treat a habitable evidence packet as
a first-class record: (1) a *small, dependency-light* way to ingest and independently
re-verify the packet, and (2) a *machine-readable, signed* summary it can store next to the
case file and re-check later without re-running the whole verifier.

This module provides both. :func:`import_packet` runs the standalone verifier over a packet
directory and distills the result into an ``evidence receipt`` — a plain JSON object that
records the packet's identity (the SHA-256 of its exact ``bundle.json`` bytes), the overall
verdict, and the per-item verdicts. :func:`sign_receipt` seals a receipt with an Ed25519 key
so the receipt itself is tamper-evident, and :func:`verify_receipt` re-checks that seal.

Licensing — no AGPL reaches you. This file is offered under **Apache-2.0** and imports only
the habitable *verification subset* (``habitable.verify`` and the pure helpers it depends on,
plus the ``verify`` signature-check granted permissively in ``NOTICE``). Receipt signing uses
the ``cryptography`` library directly, not habitable's AGPL signing code, so an integrator who
vendors this importer inherits no copyleft obligation. See ``docs/embedding-the-verifier.md``.

Stability — the receipt is pinned to the packet schema's semver contract. ``RECEIPT_VERSION``
and ``PACKET_SCHEMA_ID`` name exactly which contract a receipt was produced against, so a
downstream store can refuse a receipt whose schema major it does not understand rather than
silently mis-read a future format (roadmap EXP-10 risk note).

Portability — like the verifier subset, this module uses only standard, parenthesized
exception syntax and no 3.14-only features, so it runs on any maintained Python 3 an embedder
vendors it onto.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from habitable.canonical import canonical_json, sha256_bytes
from habitable.crypto import verify as _verify_ed25519  # NOTICE: Apache-granted verify()
from habitable.errors import VerificationError
from habitable.verify import (
    SUPPORTED_PACKET_VERSION,
    VerificationReport,
    verify_packet,
)

__all__ = [
    "PACKET_SCHEMA_ID",
    "RECEIPT_TYPE",
    "RECEIPT_VERSION",
    "SUPPORTED_PACKET_VERSION",
    "ImportResult",
    "ReceiptVerification",
    "VerificationError",
    "build_receipt",
    "generate_signing_key",
    "import_packet",
    "public_key_b64",
    "sign_receipt",
    "verify_receipt",
]

# --- contract identity --------------------------------------------------------

#: Format version of the receipt object this module emits. A downstream store keys its
#: compatibility off this: it accepts receipts it understands and rejects a newer major.
RECEIPT_VERSION = 2

#: A stable discriminator so a receipt is self-identifying in a mixed document store.
RECEIPT_TYPE = "habitable.evidence-receipt"

#: The packet ``bundle.json`` schema this importer is pinned to (its ``$id``). A receipt
#: names the exact schema it was verified against, honouring the packet's semver contract.
PACKET_SCHEMA_ID = "https://chelseakr.github.io/habitable/schema/packet-bundle-v1.schema.json"

#: Human/machine label for the tool that produced a receipt, recorded in every receipt.
_IMPORTER = "habitable-contrib-importer/2"

#: Ed25519 signature algorithm label recorded in a signed receipt envelope.
_SIG_ALG = "ed25519"

_BUNDLE = "bundle.json"


# --- data types ---------------------------------------------------------------


@dataclass(frozen=True)
class ImportResult:
    """The outcome of importing a packet: the full verifier report plus a receipt."""

    #: The structured verification report from :func:`habitable.verify.verify_packet`.
    report: VerificationReport
    #: The machine-readable receipt (a canonical-JSON-serializable ``dict``).
    receipt: dict[str, Any]
    #: SHA-256 (hex) of the packet's exact ``bundle.json`` bytes — the packet's identity.
    bundle_sha256: str

    @property
    def ok(self) -> bool:
        """Fail-closed compatibility alias for :attr:`evidence_ready`."""
        return self.report.evidence_ready

    @property
    def structurally_intact(self) -> bool:
        return self.report.structurally_intact

    @property
    def evidence_ready(self) -> bool:
        return self.report.evidence_ready


@dataclass(frozen=True)
class ReceiptVerification:
    """The outcome of re-checking a signed receipt envelope."""

    #: The receipt canonicalises to the ``receipt_sha256`` recorded in the envelope.
    digest_ok: bool
    #: The Ed25519 signature over that digest verified against the embedded public key.
    signature_ok: bool
    #: The signing key matched the caller's ``expected_public`` (None when not asserted).
    key_trusted: bool | None

    @property
    def ok(self) -> bool:
        """Digest and signature both check, and the key is trusted if a key was asserted."""
        return self.digest_ok and self.signature_ok and self.key_trusted is not False


# --- importing ----------------------------------------------------------------


def import_packet(
    packet_dir: Path | str,
    *,
    trusted_certs: list[x509.Certificate] | None = None,
    now: str | None = None,
) -> ImportResult:
    """Verify a packet directory and distil the result into an evidence receipt.

    ``packet_dir`` is a habitable packet directory (contains ``bundle.json``). ``trusted_certs``
    is forwarded to the verifier to anchor RFC 3161 timestamp roots you trust. ``now`` is an
    optional ISO-8601 UTC string recorded as ``verified_at`` — pass your own clock so the
    receipt is reproducible; leave it ``None`` to omit the field rather than invent a time.

    Fails closed exactly like the verifier: a malformed or newer-than-supported packet yields a
    receipt whose ``verdict.ok`` is ``False``. ``ok`` is the verifier's fail-closed
    evidence-readiness alias, not structural integrity. Pre-structural read/parse failures
    raise :class:`VerificationError`.
    """
    packet_dir = Path(packet_dir)
    report = verify_packet(packet_dir, trusted_certs=trusted_certs)

    bundle_path = packet_dir / _BUNDLE
    if not bundle_path.exists():
        raise VerificationError(f"no {_BUNDLE} in {packet_dir}")
    bundle_bytes = bundle_path.read_bytes()
    bundle_sha256 = sha256_bytes(bundle_bytes)
    meta = _packet_meta(bundle_bytes)

    receipt = build_receipt(report, bundle_sha256=bundle_sha256, meta=meta, now=now)
    return ImportResult(report=report, receipt=receipt, bundle_sha256=bundle_sha256)


def build_receipt(
    report: VerificationReport,
    *,
    bundle_sha256: str,
    meta: dict[str, Any],
    now: str | None = None,
) -> dict[str, Any]:
    """Build the machine-readable receipt ``dict`` from a verifier report.

    The receipt binds the verdict to ``bundle_sha256`` (the packet's identity), so a downstream
    system re-checking a *signed* receipt is transitively asserting "the receipt's signer
    verified the packet whose bundle.json hashes to this value, with this itemized result." The
    system can independently re-hash the packet's ``bundle.json`` and compare.
    """
    items = [
        {
            "capture_id": item.capture_id,
            "content_hash": item.content_hash,
            "structurally_intact": item.structurally_intact,
            "cryptographically_verified": item.cryptographically_verified,
            "timestamp_present": item.timestamp_present,
            "timestamp_kind": item.timestamp_kind,
            "timestamp_verified": item.timestamp_verified,
            "timestamp_authority_trusted": item.timestamp_authority_trusted,
            "evidence_ready": item.evidence_ready,
            "gen_time": item.gen_time,
            "tsa_name": item.tsa_name,
            "verified_authorities": list(item.verified_authorities),
            "trusted_authorities": list(item.trusted_authorities),
            "shared_media_ok": item.shared_media_ok,
            "custody_binding_ok": item.custody_binding_ok,
            "original_fixity_ok": item.original_fixity_ok,
            "ok": item.ok,
            "notes": list(item.notes),
        }
        for item in report.items
    ]

    receipt: dict[str, Any] = {
        "receipt_type": RECEIPT_TYPE,
        "receipt_version": RECEIPT_VERSION,
        "importer": _IMPORTER,
        "packet_schema": PACKET_SCHEMA_ID,
        "supported_packet_version": SUPPORTED_PACKET_VERSION,
        "packet": {
            "bundle_sha256": bundle_sha256,
            "packet_version": meta.get("packet_version"),
            "case_id": meta.get("case_id", ""),
            "unit": meta.get("unit", ""),
            "producer_fingerprint": meta.get("producer_fingerprint", ""),
        },
        "verdict": {
            "ok": report.ok,
            "status": report.status,
            "structurally_intact": report.structurally_intact,
            "timestamp_authority_trusted": report.timestamp_authority_trusted,
            "evidence_ready": report.evidence_ready,
            "signature_ok": report.signature_ok,
            "custody_ok": report.custody_ok,
            "custody_length": report.custody_length,
            "items_total": len(report.items),
            "items_verified": report.verified_items,
            "items_cryptographically_verified": report.cryptographically_verified_items,
            "items_trusted_timestamp": report.trusted_timestamp_items,
            "problems": list(report.problems),
            "summary": report.summary(),
            "guidance": report.guidance(),
        },
        "items": items,
    }
    if now is not None:
        receipt["verified_at"] = now
    return receipt


def _packet_meta(bundle_bytes: bytes) -> dict[str, Any]:
    """Best-effort extraction of packet identity fields; never raises on odd shapes."""
    try:
        parsed = json.loads(bundle_bytes)
    except json.JSONDecodeError, UnicodeDecodeError:
        return {}
    if not isinstance(parsed, dict):
        return {}
    keep = ("packet_version", "case_id", "unit", "producer_fingerprint")
    return {k: parsed[k] for k in keep if k in parsed}


# --- signing & re-verification ------------------------------------------------


def generate_signing_key() -> tuple[bytes, bytes]:
    """Mint a fresh Ed25519 receipt-signing key: ``(private_seed, public_raw)`` (32 bytes each).

    Provided so a downstream tool can create a receipt-signing identity without pulling in
    habitable's (AGPL) key management. Store the private seed securely; publish the public key
    so relying parties can pin it via ``verify_receipt(..., expected_public=...)``.
    """
    private = Ed25519PrivateKey.generate()
    public = private.public_key()
    return (
        private.private_bytes_raw(),
        public.public_bytes(Encoding.Raw, PublicFormat.Raw),
    )


def public_key_b64(public_raw: bytes) -> str:
    """Base64 the raw 32-byte Ed25519 public key for publishing / pinning."""
    return base64.b64encode(public_raw).decode("ascii")


def sign_receipt(receipt: dict[str, Any], private_seed: bytes) -> dict[str, Any]:
    """Seal a receipt with an Ed25519 key, returning a signed envelope.

    The envelope carries the receipt, the SHA-256 of its canonical bytes, the signer's public
    key, and an Ed25519 signature over that digest (mirroring how a packet signs the SHA-256 of
    its bundle). The digest binds the *exact* receipt content, so any later edit to a stored
    receipt fails :func:`verify_receipt`.
    """
    receipt_sha256 = sha256_bytes(canonical_json(receipt))
    signer = Ed25519PrivateKey.from_private_bytes(private_seed)
    signature = signer.sign(receipt_sha256.encode("ascii"))
    public_raw = signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {
        "receipt": receipt,
        "receipt_sha256": receipt_sha256,
        "algorithm": _SIG_ALG,
        "sign_public": base64.b64encode(public_raw).decode("ascii"),
        "signature": base64.b64encode(signature).decode("ascii"),
    }


def verify_receipt(
    envelope: dict[str, Any],
    *,
    expected_public: bytes | Sequence[bytes] | None = None,
) -> ReceiptVerification:
    """Re-check a signed receipt envelope. Fails closed — never raises on a malformed envelope.

    Recomputes the canonical digest of the embedded receipt, compares it to the recorded
    ``receipt_sha256``, and verifies the Ed25519 signature over that digest. If ``expected_public``
    is given (a raw 32-byte key or a set of them), also asserts the signer is one you trust.
    """
    receipt = envelope.get("receipt")
    recorded_digest = envelope.get("receipt_sha256")
    public_b64 = envelope.get("sign_public")
    signature_b64 = envelope.get("signature")

    if not isinstance(receipt, dict) or not isinstance(recorded_digest, str):
        return ReceiptVerification(digest_ok=False, signature_ok=False, key_trusted=None)

    recomputed = sha256_bytes(canonical_json(receipt))
    digest_ok = recomputed == recorded_digest

    signature_ok = False
    key_trusted: bool | None = None
    public_raw: bytes | None = None
    if isinstance(public_b64, str) and isinstance(signature_b64, str):
        try:
            public_raw = base64.b64decode(public_b64, validate=True)
            signature = base64.b64decode(signature_b64, validate=True)
        except ValueError, TypeError:
            public_raw = None
        else:
            signature_ok = _verify_ed25519(public_raw, recorded_digest.encode("ascii"), signature)

    if expected_public is not None:
        trusted = (
            [expected_public]
            if isinstance(expected_public, (bytes, bytearray))
            else list(expected_public)
        )
        key_trusted = public_raw is not None and any(
            _constant_eq(public_raw, bytes(k)) for k in trusted
        )

    return ReceiptVerification(
        digest_ok=digest_ok, signature_ok=signature_ok, key_trusted=key_trusted
    )


def _constant_eq(a: bytes, b: bytes) -> bool:
    """Length-safe equality for key comparison (avoids leaking via early return)."""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b, strict=True):
        result |= x ^ y
    return result == 0


# --- tiny CLI: import a packet dir, print the (optionally signed) receipt -----


def _main(argv: Sequence[str]) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="legal_aid_importer",
        description="Verify a habitable packet and emit a machine-readable evidence receipt.",
    )
    parser.add_argument("packet_dir", type=Path, help="a habitable packet directory")
    parser.add_argument("--now", default=None, help="ISO-8601 UTC time to record as verified_at")
    parser.add_argument(
        "--trusted-cert",
        action="append",
        type=Path,
        metavar="PEM",
        help="trusted RFC 3161 authority certificate; repeatable",
    )
    parser.add_argument(
        "--sign-key",
        type=Path,
        default=None,
        help="path to a 32-byte raw Ed25519 seed to sign the receipt",
    )
    args = parser.parse_args(argv)

    try:
        trusted_certs = _load_trusted_certs(args.trusted_cert)
        result = import_packet(args.packet_dir, trusted_certs=trusted_certs, now=args.now)
    except VerificationError as exc:
        print(json.dumps({"error": str(exc)}))
        return 2

    payload: dict[str, Any] = result.receipt
    if args.sign_key is not None:
        payload = sign_receipt(result.receipt, args.sign_key.read_bytes())

    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if result.ok else 1


def _load_trusted_certs(paths: list[Path] | None) -> list[x509.Certificate] | None:
    """Load explicitly supplied trust roots; malformed paths are clean importer errors."""
    if not paths:
        return None
    certs: list[x509.Certificate] = []
    for path in paths:
        try:
            certs.append(x509.load_pem_x509_certificate(path.read_bytes()))
        except (OSError, ValueError) as exc:
            raise VerificationError(f"could not load trusted certificate {path}: {exc}") from exc
    return certs


if __name__ == "__main__":  # pragma: no cover
    import sys

    raise SystemExit(_main(sys.argv[1:]))
