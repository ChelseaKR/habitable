# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Encrypted, per-peer state for the authenticated sync protocol.

These records live inside ``sync_security.enc``.  Keeping them separate from
the CRDT is deliberate: authorization, replay state, and receipts are local
security decisions and must never be merged merely because a peer says so.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import cast

from .canonical import JSONValue
from .errors import VaultError

__all__ = ["PeerAuthorization"]


@dataclass(slots=True)
class PeerAuthorization:
    """One explicitly paired peer and the local protocol state for that peer."""

    identity: str
    pairing_id: str
    key: bytes
    seen_message_ids: set[str] = field(default_factory=set)
    sent_messages: dict[str, str] = field(default_factory=dict)
    pending_receipts: dict[str, dict[str, JSONValue]] = field(default_factory=dict)
    verified_receipts: dict[str, dict[str, JSONValue]] = field(default_factory=dict)
    source_custody_proofs: dict[str, dict[str, JSONValue]] = field(default_factory=dict)
    capture_custody: dict[str, str] = field(default_factory=dict)

    def to_json(self) -> dict[str, JSONValue]:
        return cast(
            dict[str, JSONValue],
            {
                "identity": self.identity,
                "pairing_id": self.pairing_id,
                "key_b64": base64.b64encode(self.key).decode("ascii"),
                "seen_message_ids": sorted(self.seen_message_ids),
                "sent_messages": dict(sorted(self.sent_messages.items())),
                "pending_receipts": dict(sorted(self.pending_receipts.items())),
                "verified_receipts": dict(sorted(self.verified_receipts.items())),
                "source_custody_proofs": dict(sorted(self.source_custody_proofs.items())),
                "capture_custody": dict(sorted(self.capture_custody.items())),
            },
        )

    @classmethod
    def from_json(cls, raw: object) -> PeerAuthorization:
        if not isinstance(raw, dict):
            raise VaultError("corrupt sync peer record")
        identity = raw.get("identity")
        pairing_id = raw.get("pairing_id")
        key_b64 = raw.get("key_b64")
        if not isinstance(identity, str) or not isinstance(pairing_id, str):
            raise VaultError("corrupt sync peer identity")
        if not isinstance(key_b64, str):
            raise VaultError("corrupt sync peer key")
        try:
            key = base64.b64decode(key_b64, validate=True)
        except ValueError as exc:
            raise VaultError("corrupt sync peer key") from exc
        if len(key) != 32:
            raise VaultError("sync peer key must be 32 bytes")
        seen = _string_set(raw.get("seen_message_ids", []), "seen message ids")
        sent = _string_map(raw.get("sent_messages", {}), "sent messages")
        pending = _receipt_map(raw.get("pending_receipts", {}), "pending receipts")
        verified = _receipt_map(raw.get("verified_receipts", {}), "verified receipts")
        source_proofs = _receipt_map(raw.get("source_custody_proofs", {}), "source custody")
        capture_custody = _string_map(raw.get("capture_custody", {}), "capture custody")
        return cls(
            identity,
            pairing_id,
            key,
            seen,
            sent,
            pending,
            verified,
            source_proofs,
            capture_custody,
        )


def _string_set(raw: object, label: str) -> set[str]:
    if not isinstance(raw, list) or any(not isinstance(item, str) for item in raw):
        raise VaultError(f"corrupt sync {label}")
    return set(raw)


def _string_map(raw: object, label: str) -> dict[str, str]:
    if not isinstance(raw, dict) or any(
        not isinstance(key, str) or not isinstance(value, str) for key, value in raw.items()
    ):
        raise VaultError(f"corrupt sync {label}")
    return dict(raw)


def _receipt_map(raw: object, label: str) -> dict[str, dict[str, JSONValue]]:
    if not isinstance(raw, dict):
        raise VaultError(f"corrupt sync {label}")
    receipts: dict[str, dict[str, JSONValue]] = {}
    for message_id, receipt in raw.items():
        if not isinstance(message_id, str) or not isinstance(receipt, dict):
            raise VaultError(f"corrupt sync {label}")
        receipts[message_id] = receipt
    return receipts
