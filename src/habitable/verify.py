# SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0
# Copyright 2026 Chelsea Kelly-Reif
"""Independent verification of an evidence packet.

This is the module a skeptic runs. Given only a packet directory (and, optionally,
trusted TSA root certificates), it re-derives every hash, validates each trusted
timestamp against its authority, checks the producer's signature over the whole
bundle, and walks the chain of custody — confirming the packet has not been
altered after the fact, without access to the union's other data.

Licensing: this verifier, together with the pure modules it imports
(:mod:`habitable.canonical`, :mod:`habitable.crypto`, :mod:`habitable.evidence`,
:mod:`habitable.tsa`), is the "verification subset" offered under Apache-2.0 as an
additional permission (see NOTICE), so a court or legal-aid group can embed and
redistribute verification without the AGPL reaching their code.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from .canonical import JSONValue, sha256_bytes, sha256_file
from .crypto import verify as verify_signature
from .errors import VerificationError
from .evidence import CustodyLog
from .tsa import TimestampToken, verify_token

if TYPE_CHECKING:
    from cryptography import x509

__all__ = ["ItemVerdict", "VerificationReport", "verify_packet"]

_BUNDLE = "bundle.json"
_SIGNATURE = "bundle.sig.json"
_MEDIA = "media"
_ORIGINALS = "originals"


@dataclass(frozen=True, slots=True)
class ItemVerdict:
    """The verification outcome for one media item."""

    capture_id: str
    content_hash: str
    timestamp_verified: bool
    gen_time: str
    tsa_name: str
    shared_media_ok: bool
    custody_binding_ok: bool
    original_fixity_ok: bool | None  # None when the sealed original is not included
    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def ok(self) -> bool:
        return (
            self.timestamp_verified
            and self.shared_media_ok
            and self.custody_binding_ok
            and self.original_fixity_ok is not False
        )


@dataclass(frozen=True, slots=True)
class VerificationReport:
    """The overall verdict on a packet."""

    packet_dir: Path
    signature_ok: bool
    custody_ok: bool
    custody_length: int
    items: tuple[ItemVerdict, ...]
    problems: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return self.signature_ok and self.custody_ok and not self.problems and all(
            item.ok for item in self.items
        )

    @property
    def verified_items(self) -> int:
        return sum(1 for item in self.items if item.ok)

    def summary(self) -> str:
        total = len(self.items)
        if self.ok:
            return (
                f"{self.verified_items}/{total} items verify against their sealed originals "
                f"and timestamp tokens — packet intact"
            )
        return (
            f"{self.verified_items}/{total} items verified; "
            f"signature={'ok' if self.signature_ok else 'FAILED'}, "
            f"custody={'ok' if self.custody_ok else 'BROKEN'} — packet NOT intact"
        )


def verify_packet(
    packet_dir: Path, *, trusted_certs: list[x509.Certificate] | None = None
) -> VerificationReport:
    """Verify a packet directory end to end and return a structured report."""
    packet_dir = Path(packet_dir)
    bundle_bytes = _read_bundle_bytes(packet_dir)
    bundle = _parse_bundle(bundle_bytes)

    signature_ok = _verify_signature(packet_dir, bundle_bytes)
    custody_ok, custody_length, custody = _verify_custody(bundle)
    bindings = _sharing_bindings(custody)

    problems: list[str] = []
    items: list[ItemVerdict] = []
    for raw_item in _list(bundle, "items"):
        if not isinstance(raw_item, dict):
            problems.append("malformed item in bundle")
            continue
        items.append(_verify_item(raw_item, packet_dir, bindings, trusted_certs))

    return VerificationReport(
        packet_dir=packet_dir,
        signature_ok=signature_ok,
        custody_ok=custody_ok,
        custody_length=custody_length,
        items=tuple(items),
        problems=tuple(problems),
    )


def _verify_item(
    item: Mapping[str, JSONValue],
    packet_dir: Path,
    bindings: dict[str, set[tuple[str, str]]],
    trusted_certs: list[x509.Certificate] | None,
) -> ItemVerdict:
    capture_id = _s(item, "capture_id")
    content_hash = _s(item, "content_hash")
    shared_name = _s(item, "shared_name")
    shared_hash = _s(item, "shared_hash")
    notes: list[str] = []

    # 1. Trusted timestamp over the original content hash.
    timestamp_verified = False
    gen_time = ""
    tsa_name = ""
    token_raw = item.get("timestamp")
    if isinstance(token_raw, dict):
        try:
            token = TimestampToken.from_dict(token_raw)
            info = verify_token(token, content_hash, trusted_certs=trusted_certs)
            timestamp_verified = True
            gen_time = info.gen_time
            tsa_name = info.tsa_name
            if not info.trusted_chain:
                notes.append("timestamp valid but authority not chained to a trusted root")
        except VerificationError as exc:  # pragma: no cover - defensive
            notes.append(f"timestamp invalid: {exc}")
        except Exception as exc:
            notes.append(f"timestamp check failed: {exc}")
    else:
        notes.append("awaiting timestamp")

    # 2. Shared media hashes to its recorded shared_hash.
    shared_media_ok = True
    if shared_name:
        media_path = packet_dir / _MEDIA / shared_name
        if not media_path.exists():
            shared_media_ok = False
            notes.append("shared media file missing")
        elif sha256_file(media_path) != shared_hash:
            shared_media_ok = False
            notes.append("shared media does not match its recorded hash")
    else:
        notes.append("no shared media included for this item")

    # 3. Custody binds the shared copy to the sealed original's content hash.
    custody_binding_ok = True
    if shared_name:
        custody_binding_ok = (content_hash, shared_hash) in bindings.get(capture_id, set())
        if not custody_binding_ok:
            notes.append("no signed custody entry binds the shared copy to the original")

    # 4. If the sealed original is embedded, re-derive its content hash.
    original_fixity_ok: bool | None = None
    original_path = packet_dir / _ORIGINALS / capture_id
    if original_path.exists():
        original_fixity_ok = sha256_file(original_path) == content_hash
        if not original_fixity_ok:
            notes.append("embedded original failed fixity")

    return ItemVerdict(
        capture_id=capture_id,
        content_hash=content_hash,
        timestamp_verified=timestamp_verified,
        gen_time=gen_time,
        tsa_name=tsa_name,
        shared_media_ok=shared_media_ok,
        custody_binding_ok=custody_binding_ok,
        original_fixity_ok=original_fixity_ok,
        notes=tuple(notes),
    )


def _verify_signature(packet_dir: Path, bundle_bytes: bytes) -> bool:
    sig_path = packet_dir / _SIGNATURE
    if not sig_path.exists():
        return False
    try:
        doc = json.loads(sig_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return False
    if not isinstance(doc, dict):
        return False
    bundle_hash = sha256_bytes(bundle_bytes)
    if doc.get("bundle_sha256") != bundle_hash:
        return False
    public = doc.get("sign_public")
    signature = doc.get("signature")
    if not isinstance(public, str) or not isinstance(signature, str):
        return False
    return verify_signature(
        base64.b64decode(public), bundle_hash.encode("ascii"), base64.b64decode(signature)
    )


def _verify_custody(bundle: Mapping[str, JSONValue]) -> tuple[bool, int, CustodyLog]:
    proof = _map(bundle, "custody_proof")
    raw_entries = _list(proof, "entries")
    records: list[Mapping[str, JSONValue]] = [e for e in raw_entries if isinstance(e, dict)]
    custody = CustodyLog.from_records(records)
    try:
        result = custody.verify()
    except Exception:
        return False, len(records), custody
    declared_head = proof.get("head_hash")
    head_ok = declared_head == result.head_hash
    return (result.ok and head_ok), result.length, custody


def _sharing_bindings(custody: CustodyLog) -> dict[str, set[tuple[str, str]]]:
    """Map capture_id -> {(content_hash, shared_hash)} attested in custody."""
    bindings: dict[str, set[tuple[str, str]]] = {}
    for entry in custody.entries:
        if entry.action == "copied_for_sharing":
            content_hash = entry.details.get("content_hash", "")
            shared_hash = entry.details.get("shared_hash", "")
            bindings.setdefault(entry.item_id, set()).add((content_hash, shared_hash))
    return bindings


# --- parsing helpers ----------------------------------------------------------


def _read_bundle_bytes(packet_dir: Path) -> bytes:
    bundle_path = packet_dir / _BUNDLE
    if not bundle_path.exists():
        raise VerificationError(f"no {_BUNDLE} in {packet_dir}")
    return bundle_path.read_bytes()


def _parse_bundle(bundle_bytes: bytes) -> Mapping[str, JSONValue]:
    try:
        parsed = json.loads(bundle_bytes)
    except json.JSONDecodeError as exc:
        raise VerificationError(f"bundle is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise VerificationError("bundle must be a JSON object")
    return parsed


def _s(mapping: Mapping[str, JSONValue], key: str) -> str:
    value = mapping.get(key)
    return value if isinstance(value, str) else ""


def _list(mapping: Mapping[str, JSONValue], key: str) -> list[JSONValue]:
    value = mapping.get(key)
    return value if isinstance(value, list) else []


def _map(mapping: Mapping[str, JSONValue], key: str) -> Mapping[str, JSONValue]:
    value = mapping.get(key)
    return value if isinstance(value, dict) else {}
