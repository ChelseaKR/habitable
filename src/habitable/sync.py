# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""End-to-end-encrypted, peer-to-peer case sync.

Two devices on a case keep in step by exchanging their CRDT state — small, and
always sent in full — plus only the sealed originals and timestamp tokens the
recipient does not already have. Peers first exchange signed, recipient-sealed,
case-bound pairing material. Each message is *sealed* to the recipient's public
key, *signed* by the sender, and authenticated by that pairing key. A relay only moves
ciphertext and sees room metadata — never contents, and never which captures a
peer holds (the "have" manifest below travels inside the sealed envelope).
Because the case model is a CRDT and import persists random message ids, replay
is detected explicitly: re-delivering a message changes neither state nor custody.

Every message also carries a compact "have" manifest — the sender's own
``capture_id -> content_hash`` inventory, no bytes attached — so that the next
time the recipient exports *back* to this sender, it can skip re-embedding any
original the sender already confirmed holding (FIX-02: incremental sync
deltas, see docs/ideation/02-large-scale-fixes.md). The first exchange between
two peers still carries every original, since neither has yet declared an
inventory to the other; steady-state re-syncs and small deltas thereafter cost
close to nothing beyond the CRDT state.

Transports decide how the sealed bytes travel — a shared directory
(:class:`LocalDirTransport`, also good for USB/AirDrop-style transfer) or a relay
(:class:`RelayClient`).

:class:`PaddingTransport` wraps any of those to reduce the *metadata* a relay
operator can infer about a sync — see its docstring and
``docs/relay-observability-matrix.md`` for exactly what it does and does not hide.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import urllib.error
import urllib.request
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast

from .canonical import JSONValue, canonical_json, sha256_bytes
from .crypto import Identity, PublicIdentity, open_sealed, seal_to, verify
from .errors import SyncError
from .evidence import CustodyAction, CustodyLog
from .model import verify_state_provenance
from .obslog import log_event
from .tsa import TimestampToken, verify_archive_chain, verify_token
from .vault import Vault

__all__ = [
    "LocalDirTransport",
    "PaddingTransport",
    "RelayClient",
    "SyncResult",
    "Transport",
    "export_message",
    "import_messages",
    "suggested_delta_filename",
    "sync",
]


@dataclass(frozen=True, slots=True)
class SyncResult:
    """What a sync exchange did, including the data it moved (item R-18).

    ``bytes_sent``/``bytes_received`` count the sealed message payloads posted and
    fetched, so a tenant on a metered link can see what a sync cost.
    """

    sent: bool
    messages_merged: int
    captures_imported: int
    bytes_sent: int = 0
    bytes_received: int = 0
    replays_skipped: int = 0
    receipts_created: int = 0
    receipts_received: int = 0


class Transport(Protocol):
    """Moves opaque (already-encrypted) bytes between peers on a channel."""

    def post(self, channel: str, blob: bytes) -> None: ...

    def fetch(self, channel: str) -> list[bytes]: ...


# --- authenticated message construction --------------------------------------

_SYNC_PROTOCOL = "habitable-sync-v2"
_RECEIPT_PROTOCOL = "habitable-sync-receipt-v1"


@dataclass(frozen=True, slots=True)
class _ValidatedCapture:
    capture_id: str
    content_hash: str
    original: bytes | None
    primary: TimestampToken | None
    additional: tuple[TimestampToken, ...]
    archives: tuple[TimestampToken, ...]


@dataclass(frozen=True, slots=True)
class _ValidatedMessage:
    message_id: str
    message_digest: str
    state: Mapping[str, JSONValue]
    captures: tuple[_ValidatedCapture, ...]
    custody_proof: dict[str, JSONValue]
    receipt_records: tuple[tuple[str, dict[str, JSONValue]], ...]


def export_message(
    vault: Vault,
    recipient: PublicIdentity,
    *,
    state: Mapping[str, JSONValue] | None = None,
    capture_ids: set[str] | None = None,
) -> bytes:
    """Build a v2 delta for one explicitly paired peer.

    The complete inner payload is case- and recipient-bound, Ed25519-signed,
    authenticated with the pairing key, replay-identified, and then sealed to
    the recipient. Originals retain FIX-02's incremental transfer behavior;
    timestamp and custody material remains present even when the peer already
    confirmed holding the original bytes.

    ``capture_ids`` is retained for compatibility with the former share-subset
    caller but fails closed. Protocol v2 has no honest representation for a
    selected capture set plus its complete source custody proof.
    """
    peer = vault.sync_peer(recipient)
    if peer is None:
        raise SyncError(
            f"peer {recipient.fingerprint} is not authorized; exchange pairing material first"
        )
    if capture_ids is not None:
        raise SyncError(
            "scoped sync payloads are temporarily blocked: sync v2 carries the complete "
            "custody chain; use a full-case message until a versioned scoped custody-view "
            "protocol is available"
        )
    vault.document.attest_unsigned_fields()
    selected_state = dict(state) if state is not None else vault.document.to_state()
    if selected_state.get("case_id") != vault.document.case_id:
        raise SyncError("outgoing state is not bound to this vault's case")
    known = vault.known_peer_captures(recipient.fingerprint)
    have: list[JSONValue] = []
    captures: list[JSONValue] = []
    carries_original = False
    for capture in vault.document.captures():
        have.append({"capture_id": capture.capture_id, "content_hash": capture.content_hash})
        primary = vault.get_token(capture.capture_id)
        additional = vault.get_additional_tokens(capture.capture_id)
        archives = vault.get_archive_tokens(capture.capture_id)
        raw = None
        if capture.capture_id not in known:
            raw = vault.read_original(capture.capture_id, capture.content_hash)
            carries_original = True
        captures.append(
            {
                "capture_id": capture.capture_id,
                "content_hash": capture.content_hash,
                "media_type": capture.media_type,
                "original_b64": (
                    base64.b64encode(raw).decode("ascii") if raw is not None else None
                ),
                "timestamp": cast(JSONValue, primary.to_dict()) if primary else None,
                "additional_timestamps": cast(JSONValue, [token.to_dict() for token in additional]),
                "archive_timestamps": cast(JSONValue, [token.to_dict() for token in archives]),
            }
        )
    message_id = secrets.token_hex(32)
    inner: dict[str, JSONValue] = {
        "protocol": _SYNC_PROTOCOL,
        "message_id": message_id,
        "case_id": vault.document.case_id,
        "recipient": recipient.encode(),
        "state": selected_state,
        "state_sha256": sha256_bytes(canonical_json(selected_state)),
        "have": have,
        "captures": captures,
        "custody_proof": (
            vault.custody.integrity_proof() if carries_original else CustodyLog().integrity_proof()
        ),
        "receipts": cast(JSONValue, list(vault.pending_sync_receipts(recipient))),
    }
    inner_bytes = canonical_json(inner)
    message_digest = sha256_bytes(inner_bytes)
    envelope: dict[str, JSONValue] = {
        "sender": vault.identity.public().encode(),
        "pairing_id": peer.pairing_id,
        "inner_b64": base64.b64encode(inner_bytes).decode("ascii"),
        "sig": base64.b64encode(vault.identity.sign(inner_bytes)).decode("ascii"),
        "mac": base64.b64encode(hmac.digest(peer.key, inner_bytes, "sha256")).decode("ascii"),
    }
    vault.record_sync_message_sent(recipient, message_id, message_digest)
    vault.save()
    return seal_to(recipient, canonical_json(envelope))


def suggested_delta_filename(recipient: PublicIdentity) -> str:
    """A stable, filesystem-safe name for a sneakernet delta sealed to *recipient*.

    ``habitable-delta-<peerfp8>.hsync`` — ``peerfp8`` is the first eight hex digits
    of the peer's fingerprint, enough to tell two sticks apart at a glance. The name
    leaks nothing: the file is end-to-end encrypted and sealed to the peer's key
    regardless of what it is called.
    """
    peerfp8 = recipient.fingerprint.replace("-", "")[:8]
    return f"habitable-delta-{peerfp8}.hsync"


def import_messages(
    vault: Vault, blobs: list[bytes], *, require_case_id: str | None = None
) -> SyncResult:
    """Verify and merge messages addressed to this vault, failing closed.

    ``require_case_id`` is retained for API compatibility, but can only equal
    the opened vault's case.  Case binding is unconditional in protocol v2.
    """
    if require_case_id is not None and require_case_id != vault.document.case_id:
        raise SyncError("required case id does not match the opened vault")
    merged = 0
    imported = 0
    replays = 0
    receipts_created = 0
    receipts_received = 0
    received = sum(len(blob) for blob in blobs)
    for blob in blobs:
        envelope_bytes = _try_open(vault.identity, blob)
        if envelope_bytes is None:
            continue
        inner, sender = _verify_envelope(vault, envelope_bytes)
        message_id = _required_string(inner, "message_id")
        if vault.has_seen_sync_message(sender, message_id):
            replays += 1
            continue
        validated = _validate_message(vault, inner, sender)
        vault.document.merge(validated.state)
        vault.record_peer_captures(sender.fingerprint, _confirmed_have(vault, inner))
        imported += _apply_captures(vault, validated, sender)
        for receipt_message_id, receipt in validated.receipt_records:
            vault.record_verified_sync_receipt(sender, receipt_message_id, receipt)
            receipts_received += 1
        receipt = _create_receipt(vault, sender, validated)
        vault.queue_sync_receipt(sender, validated.message_id, receipt)
        vault.mark_sync_message_seen(sender, validated.message_id)
        receipts_created += 1
        merged += 1
    if merged:
        vault.save()
    return SyncResult(
        sent=False,
        messages_merged=merged,
        captures_imported=imported,
        bytes_received=received,
        replays_skipped=replays,
        receipts_created=receipts_created,
        receipts_received=receipts_received,
    )


def sync(vault: Vault, peer: PublicIdentity, transport: Transport, *, channel: str) -> SyncResult:
    """Post our state to ``peer`` and merge anything waiting for us."""
    posted = export_message(vault, peer)
    transport.post(channel, posted)
    blobs = transport.fetch(channel)
    result = import_messages(vault, blobs)
    # Metadata-only round summary (no-op unless logging is opted in): ciphertext
    # sizes and counts only — never the channel id, peer id, or any message content.
    log_event(
        "sync",
        sent=True,
        bytes_sent=len(posted),
        fetched=len(blobs),
        messages_merged=result.messages_merged,
        captures_imported=result.captures_imported,
    )
    return SyncResult(
        sent=True,
        messages_merged=result.messages_merged,
        captures_imported=result.captures_imported,
        bytes_sent=len(posted),
        bytes_received=result.bytes_received,
        replays_skipped=result.replays_skipped,
        receipts_created=result.receipts_created,
        receipts_received=result.receipts_received,
    )


def _try_open(identity: Identity, blob: bytes) -> bytes | None:
    """Open a sealed message, or return None if it is not addressed to us."""
    try:
        return open_sealed(identity, blob)
    except Exception:
        return None


def _verify_envelope(
    vault: Vault, envelope_bytes: bytes
) -> tuple[Mapping[str, JSONValue], PublicIdentity]:
    envelope = _as_map(_loads(envelope_bytes))
    sender_raw = envelope.get("sender")
    pairing_id = envelope.get("pairing_id")
    sig_raw = envelope.get("sig")
    mac_raw = envelope.get("mac")
    inner_b64 = envelope.get("inner_b64")
    if (
        not isinstance(sender_raw, str)
        or not isinstance(pairing_id, str)
        or not isinstance(sig_raw, str)
        or not isinstance(mac_raw, str)
        or not isinstance(inner_b64, str)
    ):
        raise SyncError("malformed sync envelope")
    try:
        sender = PublicIdentity.decode(sender_raw)
        inner_bytes = base64.b64decode(inner_b64, validate=True)
        signature = base64.b64decode(sig_raw, validate=True)
        supplied_mac = base64.b64decode(mac_raw, validate=True)
    except Exception as exc:
        raise SyncError("malformed sync envelope key or encoding") from exc
    peer = vault.sync_peer(sender)
    if peer is None:
        raise SyncError(f"message sender {sender.fingerprint} is not an authorized peer")
    if pairing_id != peer.pairing_id:
        raise SyncError("sync message uses stale or unexpected pairing material")
    if not verify(sender.sign_public, inner_bytes, signature):
        raise SyncError("sync message signature is invalid")
    expected_mac = hmac.digest(peer.key, inner_bytes, "sha256")
    if not hmac.compare_digest(supplied_mac, expected_mac):
        raise SyncError("sync message pairing authentication is invalid")
    return _as_map(_loads(inner_bytes)), sender


def _validate_message(
    vault: Vault, inner: Mapping[str, JSONValue], sender: PublicIdentity
) -> _ValidatedMessage:
    if inner.get("protocol") != _SYNC_PROTOCOL:
        raise SyncError("unsupported sync protocol; authenticated v2 pairing is required")
    if inner.get("recipient") != vault.identity.public().encode():
        raise SyncError("sync message recipient binding is invalid")
    case_id = inner.get("case_id")
    if case_id != vault.document.case_id:
        raise SyncError(f"message is for case {case_id!r}, not {vault.document.case_id!r}")
    state = _as_map(inner.get("state"))
    if state.get("case_id") != case_id:
        raise SyncError("sync state case_id does not match the signed message case_id")
    state_hash = _required_string(inner, "state_sha256")
    if sha256_bytes(canonical_json(dict(state))) != state_hash:
        raise SyncError("sync state digest is invalid")
    _check_field_provenance(vault, state)
    message_id = _required_string(inner, "message_id")
    if len(message_id) != 64 or any(ch not in "0123456789abcdef" for ch in message_id):
        raise SyncError("sync message id is malformed")
    proof = _validate_custody_proof(inner.get("custody_proof"))
    captures = _validate_captures(vault, inner, proof)
    receipts = _validate_receipts(vault, sender, inner.get("receipts"))
    return _ValidatedMessage(
        message_id=message_id,
        message_digest=sha256_bytes(canonical_json(dict(inner))),
        state=state,
        captures=tuple(captures),
        custody_proof=proof,
        receipt_records=tuple(receipts),
    )


def _check_field_provenance(vault: Vault, state: Mapping[str, JSONValue]) -> None:
    """Verify every signed field author against an exact locally known identity."""
    case_id = _required_string(state, "case_id")
    unsigned = _unsigned_register_targets(state)
    if unsigned:
        raise SyncError(
            "sync state contains unsigned mutable field(s): " + ", ".join(sorted(unsigned))
        )
    actors = _state_actors(state)
    own = vault.identity.public()
    for actor in actors:
        if actor == own.fingerprint:
            identity = own
        else:
            peer = vault.sync_peer_by_fingerprint(actor)
            if peer is None:
                raise SyncError(f"state contains a field authored by unknown device {actor}")
            try:
                identity = PublicIdentity.decode(peer.identity)
            except Exception as exc:
                raise SyncError("authorized field-author identity is malformed") from exc
        failed = verify_state_provenance(case_id, state, actor, identity.sign_public)
        if failed:
            raise SyncError(
                "field provenance signature is invalid for " + ", ".join(sorted(failed))
            )


def _unsigned_register_targets(state: Mapping[str, JSONValue]) -> list[str]:
    unsigned: list[str] = []
    raw_meta = state.get("meta")
    if isinstance(raw_meta, dict):
        for key, raw in raw_meta.items():
            if isinstance(raw, dict) and not _complete_register_provenance(raw):
                unsigned.append(f"meta:{key}")
    raw_issue_fields = state.get("issue_fields")
    if isinstance(raw_issue_fields, dict):
        for issue_id, registers in raw_issue_fields.items():
            if not isinstance(registers, dict):
                continue
            for name, raw in registers.items():
                if isinstance(raw, dict) and not _complete_register_provenance(raw):
                    unsigned.append(f"issue:{issue_id}:{name}")
    return unsigned


def _complete_register_provenance(raw: Mapping[str, JSONValue]) -> bool:
    return all(
        isinstance(raw.get(key), str) and bool(raw.get(key))
        for key in ("actor", "sig", "provenance_kind")
    )


def _state_actors(state: Mapping[str, JSONValue]) -> set[str]:
    actors: set[str] = set()
    raw_meta = state.get("meta")
    raw_issue_fields = state.get("issue_fields")
    if isinstance(raw_meta, dict):
        _collect_register_actors(raw_meta.values(), actors)
    if isinstance(raw_issue_fields, dict):
        for registers in raw_issue_fields.values():
            if isinstance(registers, dict):
                _collect_register_actors(registers.values(), actors)
    return actors


def _collect_register_actors(values: Iterable[JSONValue], actors: set[str]) -> None:
    for raw in values:
        if isinstance(raw, dict):
            actor = raw.get("actor")
            if isinstance(actor, str) and actor:
                actors.add(actor)


def _validate_captures(
    vault: Vault, inner: Mapping[str, JSONValue], proof: Mapping[str, JSONValue]
) -> list[_ValidatedCapture]:
    raw_captures = inner.get("captures")
    if not isinstance(raw_captures, list):
        raise SyncError("sync captures must be an array")
    custody = _custody_from_proof(proof)
    captures: list[_ValidatedCapture] = []
    for raw in raw_captures:
        if not isinstance(raw, dict):
            raise SyncError("sync capture must be an object")
        captures.append(_validate_capture(vault, raw, custody))
    return captures


def _validate_capture(
    vault: Vault, raw: Mapping[str, JSONValue], custody: CustodyLog
) -> _ValidatedCapture:
    capture_id = _required_string(raw, "capture_id")
    content_hash = _required_string(raw, "content_hash")
    original = _decode_original(raw.get("original_b64"), capture_id, content_hash)
    if original is None and not vault.has_original(capture_id):
        raise SyncError(f"sync omitted original bytes the recipient does not hold: {capture_id}")
    primary = _token_or_none(raw.get("timestamp"), content_hash)
    additional = _token_list(raw.get("additional_timestamps"), content_hash)
    archives = _token_list(raw.get("archive_timestamps"), None)
    if archives:
        if primary is None:
            raise SyncError(f"archive timestamps for {capture_id} have no primary token")
        verify_archive_chain(content_hash, primary, list(archives))
    custody_bound = any(
        entry.item_id == capture_id and entry.details.get("content_hash") == content_hash
        for entry in custody.entries
    )
    if original is not None and not custody_bound:
        raise SyncError(f"custody proof does not bind capture {capture_id} to its content hash")
    return _ValidatedCapture(
        capture_id, content_hash, original, primary, tuple(additional), tuple(archives)
    )


def _decode_original(raw: JSONValue, capture_id: str, content_hash: str) -> bytes | None:
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise SyncError(f"received original marker for {capture_id} is malformed")
    try:
        original = base64.b64decode(raw, validate=True)
    except ValueError as exc:
        raise SyncError(f"received original for {capture_id} is malformed") from exc
    if sha256_bytes(original) != content_hash:
        raise SyncError(f"received original for {capture_id} failed fixity")
    return original


def _apply_captures(vault: Vault, message: _ValidatedMessage, sender: PublicIdentity) -> int:
    imported = 0
    proof_has_entries = message.custody_proof.get("length") != 0
    proof_hash = sha256_bytes(canonical_json(message.custody_proof))
    proof_head = _required_string(message.custody_proof, "head_hash")
    for capture in message.captures:
        imported_original = False
        if not vault.has_original(capture.capture_id):
            if capture.original is None:
                continue
            vault.store_original_bytes(capture.capture_id, capture.original, capture.content_hash)
            imported += 1
            imported_original = True
        _store_timestamp_material(vault, capture)
        if proof_has_entries:
            vault.record_source_custody(sender, capture.capture_id, message.custody_proof)
        if imported_original:
            vault.custody.append(
                CustodyAction.IMPORTED,
                capture.capture_id,
                actor=vault.identity.public().fingerprint,
                hlc=vault.document.clock.now().encode(),
                details={
                    "content_hash": capture.content_hash,
                    "source_custody_head": proof_head,
                    "source_custody_sha256": proof_hash,
                },
                private_details={"from": sender.fingerprint},
                identity=vault.identity,
            )
    return imported


def _store_timestamp_material(vault: Vault, capture: _ValidatedCapture) -> None:
    if capture.primary is not None:
        vault.store_token(capture.capture_id, capture.primary)
    existing_additional = {
        canonical_json(cast(JSONValue, token.to_dict()))
        for token in vault.get_additional_tokens(capture.capture_id)
    }
    for token in capture.additional:
        encoded = canonical_json(cast(JSONValue, token.to_dict()))
        if encoded not in existing_additional:
            vault.add_additional_token(capture.capture_id, token)
            existing_additional.add(encoded)
    existing_archives = {
        canonical_json(cast(JSONValue, token.to_dict()))
        for token in vault.get_archive_tokens(capture.capture_id)
    }
    for token in capture.archives:
        encoded = canonical_json(cast(JSONValue, token.to_dict()))
        if encoded not in existing_archives:
            vault.add_archive_token(capture.capture_id, token)
            existing_archives.add(encoded)


def _validate_custody_proof(raw: JSONValue) -> dict[str, JSONValue]:
    if not isinstance(raw, dict):
        raise SyncError("sync message is missing its source custody proof")
    _custody_from_proof(raw)
    return raw


def _custody_from_proof(proof: Mapping[str, JSONValue]) -> CustodyLog:
    entries = proof.get("entries")
    if not isinstance(entries, list):
        raise SyncError("source custody proof entries must be an array")
    records: list[Mapping[str, JSONValue]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise SyncError("source custody proof contains a malformed entry")
        records.append(entry)
    try:
        custody = CustodyLog.from_records(records)
        result = custody.verify()
    except Exception as exc:
        raise SyncError("source custody proof is broken or tampered") from exc
    if proof.get("head_hash") != result.head_hash or proof.get("length") != result.length:
        raise SyncError("source custody proof summary does not match its entries")
    return custody


def _token_or_none(raw: JSONValue, content_hash: str) -> TimestampToken | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise SyncError("timestamp material must be an object")
    token = TimestampToken.from_dict(raw)
    verify_token(token, content_hash)
    return token


def _token_list(raw: JSONValue, content_hash: str | None) -> list[TimestampToken]:
    if not isinstance(raw, list):
        raise SyncError("timestamp collection must be an array")
    tokens: list[TimestampToken] = []
    for item in raw:
        if not isinstance(item, dict):
            raise SyncError("timestamp collection contains a malformed token")
        token = TimestampToken.from_dict(item)
        if content_hash is not None:
            verify_token(token, content_hash)
        tokens.append(token)
    return tokens


def _create_receipt(
    vault: Vault, sender: PublicIdentity, message: _ValidatedMessage
) -> dict[str, JSONValue]:
    payload: dict[str, JSONValue] = {
        "protocol": _RECEIPT_PROTOCOL,
        "case_id": vault.document.case_id,
        "message_id": message.message_id,
        "message_sha256": message.message_digest,
        "original_sender": sender.encode(),
        "importer": vault.identity.public().encode(),
        "capture_hashes": {
            capture.capture_id: capture.content_hash for capture in message.captures
        },
        "custody_head_after_import": vault.custody.head_hash,
    }
    payload_bytes = canonical_json(payload)
    return {
        "payload": payload,
        "signature_b64": base64.b64encode(vault.identity.sign(payload_bytes)).decode("ascii"),
    }


def _validate_receipts(
    vault: Vault, sender: PublicIdentity, raw: JSONValue
) -> list[tuple[str, dict[str, JSONValue]]]:
    if not isinstance(raw, list):
        raise SyncError("sync receipts must be an array")
    validated: list[tuple[str, dict[str, JSONValue]]] = []
    for receipt in raw:
        if not isinstance(receipt, dict):
            raise SyncError("sync receipt must be an object")
        message_id = _validate_receipt(vault, sender, receipt)
        validated.append((message_id, receipt))
    return validated


def _validate_receipt(
    vault: Vault, sender: PublicIdentity, receipt: Mapping[str, JSONValue]
) -> str:
    payload = receipt.get("payload")
    signature_raw = receipt.get("signature_b64")
    if not isinstance(payload, dict) or not isinstance(signature_raw, str):
        raise SyncError("sync receipt is malformed")
    if payload.get("protocol") != _RECEIPT_PROTOCOL:
        raise SyncError("sync receipt uses an unsupported protocol")
    message_id = _required_string(payload, "message_id")
    message_digest = _required_string(payload, "message_sha256")
    if payload.get("case_id") != vault.document.case_id:
        raise SyncError("sync receipt is bound to the wrong case")
    if payload.get("original_sender") != vault.identity.public().encode():
        raise SyncError("sync receipt does not acknowledge this device")
    if payload.get("importer") != sender.encode():
        raise SyncError("sync receipt importer does not match the sending peer")
    expected = vault.sent_sync_message_digest(sender, message_id)
    if expected is None or expected != message_digest:
        raise SyncError("sync receipt does not match a message sent to this peer")
    try:
        signature = base64.b64decode(signature_raw, validate=True)
    except ValueError as exc:
        raise SyncError("sync receipt signature is malformed") from exc
    if not verify(sender.sign_public, canonical_json(payload), signature):
        raise SyncError("sync receipt signature is invalid")
    return message_id


def _confirmed_have(vault: Vault, inner: Mapping[str, JSONValue]) -> list[str]:
    local = {capture.capture_id: capture.content_hash for capture in vault.document.captures()}
    raw = inner.get("have")
    if not isinstance(raw, list):
        raise SyncError("sync have manifest must be an array")
    confirmed: list[str] = []
    for item in raw:
        if not isinstance(item, dict):
            raise SyncError("sync have manifest contains a malformed entry")
        capture_id = _required_string(item, "capture_id")
        content_hash = _required_string(item, "content_hash")
        if local.get(capture_id) == content_hash:
            confirmed.append(capture_id)
    return confirmed


# --- transports ---------------------------------------------------------------


class LocalDirTransport:
    """A shared-directory mailbox: one append-only file of messages per channel."""

    def __init__(self, root: Path) -> None:
        self._root = Path(root)
        self._root.mkdir(parents=True, exist_ok=True)

    def post(self, channel: str, blob: bytes) -> None:
        line = base64.b64encode(blob).decode("ascii")
        with (self._root / f"{channel}.mbox").open("a", encoding="ascii") as handle:
            handle.write(line + "\n")

    def fetch(self, channel: str) -> list[bytes]:
        path = self._root / f"{channel}.mbox"
        if not path.exists():
            return []
        return [base64.b64decode(line) for line in path.read_text("ascii").splitlines() if line]


def _room_token(channel: str) -> str:
    """Derive a room write-capability token both peers can compute from the channel.

    Peers already agree on the ``channel`` string, so a keyed digest of it gives a
    deterministic per-room token without any extra key exchange. The relay binds
    the first token it sees for a room (trust-on-first-use) and rejects mismatched
    writes; it never sees this value in the clear beyond an opaque header it only
    ``hmac.compare_digest``-checks and never logs.
    """
    return hashlib.sha256(b"habitable room token v1:" + channel.encode("utf-8")).hexdigest()


class RelayClient:
    """Posts/fetches ciphertext to a habitable relay room over HTTP."""

    _TOKEN_HEADER = "X-Habitable-Room-Token"  # noqa: S105 - header name, not a secret

    def __init__(self, base_url: str, *, timeout: float = 15.0) -> None:
        if not base_url.lower().startswith(("http://", "https://")):
            raise SyncError(f"relay URL must be http(s): {base_url!r}")
        self._base = base_url.rstrip("/")
        self._timeout = timeout

    def post(self, channel: str, blob: bytes) -> None:
        url = f"{self._base}/rooms/{channel}"
        headers = {
            "Content-Type": "application/octet-stream",
            self._TOKEN_HEADER: _room_token(channel),
        }
        request = urllib.request.Request(  # noqa: S310 - scheme validated in __init__
            url, data=blob, headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:  # noqa: S310
                response.read()
        except urllib.error.HTTPError as exc:
            raise self._post_error(exc) from exc
        except OSError as exc:
            raise SyncError(f"relay post failed: {exc}") from exc

    @staticmethod
    def _post_error(exc: urllib.error.HTTPError) -> SyncError:
        exc.close()
        if exc.code == 413:
            return SyncError(
                "relay room is full — peers must fetch and clear it, or the operator "
                "must raise the room cap"
            )
        if exc.code == 403:
            return SyncError(
                "relay rejected the room write token — the room was claimed by a "
                "different channel/key (trust-on-first-use)"
            )
        return SyncError(f"relay post failed: HTTP {exc.code}")

    def fetch(self, channel: str) -> list[bytes]:
        url = f"{self._base}/rooms/{channel}"
        headers = {self._TOKEN_HEADER: _room_token(channel)}
        request = urllib.request.Request(  # noqa: S310 - scheme validated in __init__
            url, headers=headers, method="GET"
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:  # noqa: S310
                payload = json.loads(response.read())
        except urllib.error.HTTPError as exc:
            exc.close()
            raise SyncError(f"relay fetch failed: HTTP {exc.code}") from exc
        except OSError as exc:
            raise SyncError(f"relay fetch failed: {exc}") from exc
        if not isinstance(payload, dict) or not isinstance(payload.get("messages"), list):
            raise SyncError("malformed relay response")
        return [base64.b64decode(item) for item in payload["messages"] if isinstance(item, str)]


# --- metadata-resistant transport (EXP-12) ------------------------------------

# Frame layout for a padded blob:
#   MAGIC (4) | VERSION (1) | payload length (4, big-endian) | payload | random pad
# The whole frame is padded with random bytes to the next multiple of ``block_size``,
# so what leaves the sender reveals the payload size only to block granularity. A frame
# that carries a *decoy* is byte-for-byte indistinguishable from a real one to the relay
# (same magic, same size distribution, random-looking body) but its payload does not open
# to any recipient, so ``import_messages`` drops it as "not addressed to us".
_PAD_MAGIC = b"HbP1"
_PAD_VERSION = 1
_PAD_HEADER = struct.Struct(">4sBI")  # magic, version, length
_PAD_HEADER_LEN = _PAD_HEADER.size
_DEFAULT_BLOCK_SIZE = 64 * 1024


def _round_up(value: int, block: int) -> int:
    return ((value + block - 1) // block) * block


class PaddingTransport:
    """Wrap a transport to shrink the *metadata* a relay can infer from a sync.

    This is the opt-in, honest core of **EXP-12** (see
    ``docs/relay-observability-matrix.md`` §5 and ``docs/threat-model.md`` §5). It does
    **two** concrete, testable things and nothing more:

    1. **Size padding.** Every posted blob is framed and padded with random bytes to the
       next multiple of ``block_size``. The relay therefore learns each message's size
       only to block granularity (default 64 KiB), not its exact byte length, so blob
       size no longer tracks real payload size.
    2. **Cover traffic.** Each *flush* posts a fixed ``batch_size`` of blobs that are all
       padded to the **same** size — the largest real frame in that batch, rounded to a
       block. Short real messages and **decoys** (correctly-framed random blobs that no
       recipient can open and that :func:`import_messages` silently discards) are padded up
       to match. The relay thus sees a constant number of indistinguishable-size posts per
       flush and can tell neither how many were real (up to ``batch_size``) nor which ones.

    With ``auto_flush=True`` (the default) each :meth:`post` immediately emits one full
    padded, cover-filled batch, so it is a drop-in wrapper for :func:`sync` with no API
    change. With ``auto_flush=False`` you may :meth:`post` several messages and then
    :meth:`flush` once, batching real events together to also blunt per-message timing and
    count.

    **What this does NOT hide (honest residual — do not overclaim).** The relay still
    sees the **room id** (``channel``), the **peer IP addresses** (at the network/proxy
    layer), and **that a room is active and roughly when**. Cover traffic hides the real
    message count only up to ``batch_size``; the uniform batch size still reveals the size
    of the *largest* real message (rounded to a block), and padding costs real bandwidth (a
    tension with tight data caps). This wrapper is **not** an anonymity network — it does
    not mix across senders or defeat IP-level correlation — and has **not** had the
    external traffic-analysis review the project's own principle requires before such a
    property is relied upon. To remove relay metadata entirely, use no relay: sync
    peer-to-peer with :class:`LocalDirTransport`.
    """

    def __init__(
        self,
        inner: Transport,
        *,
        block_size: int = _DEFAULT_BLOCK_SIZE,
        batch_size: int = 4,
        auto_flush: bool = True,
    ) -> None:
        if block_size <= _PAD_HEADER_LEN:
            raise SyncError(f"block_size must exceed {_PAD_HEADER_LEN}")
        if batch_size < 1:
            raise SyncError("batch_size must be at least 1")
        self._inner = inner
        self._block_size = block_size
        self._batch_size = batch_size
        self._auto_flush = auto_flush
        self._pending: dict[str, list[bytes]] = {}

    def post(self, channel: str, blob: bytes) -> None:
        """Frame + pad ``blob`` and queue it; emit a batch now if ``auto_flush``."""
        self._pending.setdefault(channel, []).append(self._frame(blob))
        if self._auto_flush:
            self.flush(channel)

    def flush(self, channel: str) -> None:
        """Post ``channel``'s queued frames + cover, all padded to one uniform size."""
        frames = self._pending.pop(channel, [])
        # Round the batch count up so a full multiple of ``batch_size`` leaves the sender;
        # a partial final batch is filled with decoys rather than revealing the remainder.
        count = max(self._batch_size, _round_up(len(frames), self._batch_size))
        # Every blob in this flush is padded to the same size — the largest real frame,
        # rounded to a block — so size distinguishes neither real-from-decoy nor one real
        # message from another within the batch.
        target = max((len(f) for f in frames), default=self._block_size)
        blobs = [self._pad_to(frame, target) for frame in frames]
        while len(blobs) < count:
            blobs.append(self._decoy(target))
        secrets.SystemRandom().shuffle(blobs)  # don't leak real-vs-decoy by position
        for blob in blobs:
            self._inner.post(channel, blob)

    def fetch(self, channel: str) -> list[bytes]:
        """Fetch, unframe, and strip padding; decoys pass through as un-openable bytes."""
        return [self._unframe(raw) for raw in self._inner.fetch(channel)]

    def _frame(self, payload: bytes) -> bytes:
        header = _PAD_HEADER.pack(_PAD_MAGIC, _PAD_VERSION, len(payload))
        return self._pad_to(header + payload, self._block_size)

    def _pad_to(self, body: bytes, target: int) -> bytes:
        # Pad ``body`` with random bytes up to at least ``target``, rounded to a block.
        # Trailing bytes past the header's declared length are ignored on unframe.
        padded_len = max(target, _round_up(len(body), self._block_size))
        return body + secrets.token_bytes(padded_len - len(body))

    def _decoy(self, target: int) -> bytes:
        # A decoy is a real frame over random "payload" bytes, padded to the batch size:
        # same magic and size as a genuine message, but it opens for no one.
        size = secrets.randbelow(max(1, self._block_size - _PAD_HEADER_LEN))
        header = _PAD_HEADER.pack(_PAD_MAGIC, _PAD_VERSION, size)
        return self._pad_to(header + os.urandom(size), target)

    def _unframe(self, raw: bytes) -> bytes:
        # Pass through anything not framed by us, so a mixed channel still delivers.
        if len(raw) < _PAD_HEADER_LEN:
            return raw
        magic, version, length = _PAD_HEADER.unpack(raw[:_PAD_HEADER_LEN])
        if magic != _PAD_MAGIC or version != _PAD_VERSION:
            return raw
        end = _PAD_HEADER_LEN + length
        if end > len(raw):
            raise SyncError("padded frame claims more payload than it carries")
        return raw[_PAD_HEADER_LEN:end]


# --- helpers ------------------------------------------------------------------


def _loads(data: bytes) -> JSONValue:
    parsed: JSONValue = json.loads(data)
    return parsed


def _as_map(value: JSONValue) -> Mapping[str, JSONValue]:
    if not isinstance(value, dict):
        raise SyncError("expected a JSON object")
    return value


def _required_string(mapping: Mapping[str, JSONValue], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        raise SyncError(f"sync field {key!r} must be a non-empty string")
    return value
