# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Authenticated, case-bound pairing for sync peers.

The pairing material is a signed invitation sealed to exactly one recipient.
It can be copied as a one-line code, encoded in a QR symbol, or carried in a
small ``.hpair`` file without exposing the shared pairing key to the courier.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
from collections.abc import Mapping

from .canonical import JSONValue, canonical_json
from .crypto import PublicIdentity, open_sealed, seal_to, verify
from .errors import SyncError
from .vault import Vault

__all__ = [
    "PAIRING_PREFIX",
    "accept_pairing_material",
    "create_pairing_material",
]

PAIRING_PREFIX = "habitable-pairing-v1."
_PAIRING_PROTOCOL = "habitable-pairing-v1"


def create_pairing_material(vault: Vault, recipient: PublicIdentity) -> str:
    """Authorize ``recipient`` and return a signed invitation sealed to it."""
    if recipient == vault.identity.public():
        raise SyncError("cannot pair a vault with its own device identity")
    pairing_id = secrets.token_hex(16)
    key = os.urandom(32)
    payload: dict[str, JSONValue] = {
        "protocol": _PAIRING_PROTOCOL,
        "case_id": vault.document.case_id,
        "pairing_id": pairing_id,
        "issuer": vault.identity.public().encode(),
        "recipient": recipient.encode(),
        "key_b64": base64.b64encode(key).decode("ascii"),
    }
    payload_bytes = canonical_json(payload)
    envelope: dict[str, JSONValue] = {
        "issuer": vault.identity.public().encode(),
        "payload_b64": base64.b64encode(payload_bytes).decode("ascii"),
        "signature_b64": base64.b64encode(vault.identity.sign(payload_bytes)).decode("ascii"),
    }
    sealed = seal_to(recipient, canonical_json(envelope))
    vault.authorize_sync_peer(recipient, pairing_id, key, replace=True)
    vault.save()
    code = base64.urlsafe_b64encode(sealed).decode("ascii").rstrip("=")
    return PAIRING_PREFIX + code


def accept_pairing_material(vault: Vault, material: str) -> PublicIdentity:
    """Open and verify a pairing invitation, then allowlist its exact issuer."""
    issuer, payload = _open_pairing_material(vault, material)
    pairing_id, key = _validate_pairing_payload(vault, payload, issuer)
    vault.authorize_sync_peer(issuer, pairing_id, key)
    vault.save()
    return issuer


def _open_pairing_material(
    vault: Vault, material: str
) -> tuple[PublicIdentity, Mapping[str, JSONValue]]:
    if not material.startswith(PAIRING_PREFIX):
        raise SyncError("pairing material has an unsupported format")
    encoded = material.removeprefix(PAIRING_PREFIX).strip()
    try:
        sealed = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        # Unpadded base64url can have non-canonical aliases whose unused final
        # pad bits differ while decoding to exactly the same bytes. Reject those
        # alternate spellings so a character-level change is always detected.
        canonical = base64.urlsafe_b64encode(sealed).decode("ascii").rstrip("=")
        if encoded != canonical:
            raise ValueError("non-canonical base64url pairing material")
        envelope = _mapping(_loads(open_sealed(vault.identity, sealed)), "pairing envelope")
        issuer = PublicIdentity.decode(_string(envelope, "issuer"))
        payload_bytes = base64.b64decode(_string(envelope, "payload_b64"), validate=True)
        signature = base64.b64decode(_string(envelope, "signature_b64"), validate=True)
    except SyncError:
        raise
    except Exception as exc:
        raise SyncError("pairing material is malformed, tampered, or not for this device") from exc
    if not verify(issuer.sign_public, payload_bytes, signature):
        raise SyncError("pairing material signature is invalid")
    payload = _mapping(_loads(payload_bytes), "pairing payload")
    return issuer, payload


def _validate_pairing_payload(
    vault: Vault, payload: Mapping[str, JSONValue], issuer: PublicIdentity
) -> tuple[str, bytes]:
    if payload.get("protocol") != _PAIRING_PROTOCOL:
        raise SyncError("pairing material uses an unsupported protocol")
    if payload.get("issuer") != issuer.encode():
        raise SyncError("pairing material issuer binding is invalid")
    own_identity = vault.identity.public().encode()
    if payload.get("recipient") != own_identity:
        raise SyncError("pairing material is not bound to this device")
    if payload.get("case_id") != vault.document.case_id:
        raise SyncError(
            f"pairing material is for case {payload.get('case_id')!r}, "
            f"not {vault.document.case_id!r}"
        )
    pairing_id = _string(payload, "pairing_id")
    try:
        key = base64.b64decode(_string(payload, "key_b64"), validate=True)
    except ValueError as exc:
        raise SyncError("pairing material contains an invalid shared key") from exc
    if len(key) != 32:
        raise SyncError("pairing material contains an invalid shared key")
    return pairing_id, key


def _loads(raw: bytes) -> JSONValue:
    try:
        value: JSONValue = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise SyncError("pairing material is not valid JSON") from exc
    return value


def _mapping(raw: JSONValue, label: str) -> Mapping[str, JSONValue]:
    if not isinstance(raw, dict):
        raise SyncError(f"{label} must be an object")
    return raw


def _string(raw: Mapping[str, JSONValue], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str):
        raise SyncError(f"pairing field {key!r} must be a string")
    return value
