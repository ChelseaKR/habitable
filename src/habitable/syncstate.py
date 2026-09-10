# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Encrypted, per-peer state for the authenticated sync protocol.

These records live inside ``sync_security.enc``.  Keeping them separate from
the CRDT is deliberate: authorization, replay state, and receipts are local
security decisions and must never be merged merely because a peer says so.
"""

from __future__ import annotations

import base64
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import cast

from .canonical import JSONValue
from .errors import VaultError

__all__ = [
    "CLOCK_SKEW_TOLERANCE_MS",
    "PeerAuthorization",
    "PeerHolding",
    "SyncRedundancy",
    "redundancy_from_peers",
]


# How far a peer's *claimed* clock may run ahead of this device's own clock
# before the claim is treated as unmeasurable rather than as a time. A receipt
# is signed on the peer's device with the peer's own wall clock, so a little
# skew is ordinary; a watermark far in the future is a broken clock or a
# fabricated record, and either way it is not evidence of recency.
CLOCK_SKEW_TOLERANCE_MS = 300_000


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
    # What *this* device observed when it verified a peer's receipt: the local
    # wall clock and, when the caller knew it, the transport the exchange used.
    # Deliberately not part of the signed receipt: both are facts about this
    # device, and a peer must not be able to assert either one about us.
    receipt_observations: dict[str, dict[str, JSONValue]] = field(default_factory=dict)

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
                "receipt_observations": dict(sorted(self.receipt_observations.items())),
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
        observations = _receipt_map(raw.get("receipt_observations", {}), "receipt observations")
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
            observations,
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


# --- "is this case on more than one device?" (RR-07) -------------------------


@dataclass(frozen=True, slots=True)
class PeerHolding:
    """What this device can *prove* about one paired peer's copy of the case.

    ``confirmed`` is the load-bearing field, and it is deliberately not derived
    from pairing. Pairing means "this peer is allowed to send us data"; it says
    nothing about whether the peer ever received ours. Only a verified receipt
    — a signature by that peer's device key over the digest of a message this
    device recorded as sent to it — proves the peer imported the case. Counting
    paired peers instead would answer "your case is on 3 devices" for a vault
    that has never completed a single exchange.
    """

    fingerprint: str
    identity: str
    confirmed: bool
    receipts: int
    observed_at_ms: int | None
    transport: str | None
    custody_head: str | None
    claimed_clock_ms: int | None
    claimed_clock_state: str


@dataclass(frozen=True, slots=True)
class SyncRedundancy:
    """The organizer-facing answer to "is this case safely on more than one device?"."""

    peers: tuple[PeerHolding, ...]

    @property
    def confirmed_peers(self) -> tuple[PeerHolding, ...]:
        return tuple(peer for peer in self.peers if peer.confirmed)

    @property
    def paired_count(self) -> int:
        return len(self.peers)

    @property
    def confirmed_count(self) -> int:
        return len(self.confirmed_peers)

    @property
    def device_count(self) -> int:
        """This device plus every peer that has proved it holds the case."""
        return 1 + self.confirmed_count

    @property
    def single_device(self) -> bool:
        """True when nothing outside this device is known to hold the case."""
        return self.confirmed_count == 0

    @property
    def last_observed_at_ms(self) -> int | None:
        """The most recent *local* observation time, or ``None`` if none was recorded.

        ``None`` is returned rather than ``0`` or "now": a case can be confirmed
        on another device while this device has no recorded time for it (a
        vault written before observations existed), and an epoch date printed
        as a sync time would be absence rendered as a value.
        """
        times = [peer.observed_at_ms for peer in self.confirmed_peers if peer.observed_at_ms]
        return max(times) if times else None

    @property
    def last_peer(self) -> PeerHolding | None:
        """The confirmed peer behind :attr:`last_observed_at_ms`, if any."""
        confirmed = self.confirmed_peers
        if not confirmed:
            return None
        timed = [peer for peer in confirmed if peer.observed_at_ms]
        if not timed:
            return None
        return max(timed, key=lambda peer: (peer.observed_at_ms or 0, peer.fingerprint))


def redundancy_from_peers(
    peers: Mapping[str, PeerAuthorization], *, now_ms: int | None = None
) -> SyncRedundancy:
    """Summarize which paired peers have proved they hold this case.

    ``peers`` is keyed by peer fingerprint, exactly as the vault holds it.
    ``now_ms`` is *this device's* clock, used only to decide whether a peer's
    claimed clock is usable. It is never substituted for a missing observation.
    """
    holdings = [_holding(fingerprint, peer, now_ms=now_ms) for fingerprint, peer in peers.items()]
    holdings.sort(key=lambda holding: holding.fingerprint)
    return SyncRedundancy(peers=tuple(holdings))


def _holding(fingerprint: str, peer: PeerAuthorization, *, now_ms: int | None) -> PeerHolding:
    receipts = peer.verified_receipts
    newest = _newest_receipt_id(peer)
    observed, transport = _observation(peer, newest)
    payload = _payload(receipts.get(newest)) if newest is not None else None
    claimed_ms, claimed_state = _claimed_clock(payload, now_ms=now_ms)
    head = payload.get("custody_head_after_import") if payload is not None else None
    return PeerHolding(
        fingerprint=fingerprint,
        identity=peer.identity,
        confirmed=bool(receipts),
        receipts=len(receipts),
        observed_at_ms=observed,
        transport=transport,
        custody_head=head if isinstance(head, str) else None,
        claimed_clock_ms=claimed_ms,
        claimed_clock_state=claimed_state,
    )


def _newest_receipt_id(peer: PeerAuthorization) -> str | None:
    """The message id of the peer's most recently observed receipt.

    Ordered by this device's own observation time where one exists. Receipts
    with no recorded observation fall back to the message id, which is stable
    and arbitrary rather than a pretended chronology.
    """
    if not peer.verified_receipts:
        return None
    return max(
        peer.verified_receipts,
        key=lambda message_id: (_observed_ms(peer, message_id) or 0, message_id),
    )


def _observed_ms(peer: PeerAuthorization, message_id: str) -> int | None:
    observed, _transport = _observation(peer, message_id)
    return observed


def _observation(peer: PeerAuthorization, message_id: str | None) -> tuple[int | None, str | None]:
    """This device's own record of when and how a receipt arrived.

    Every unusable shape — no record, a missing key, a bool (which ``int``
    would happily accept), a non-positive value, an empty transport — returns
    ``None`` for that field rather than a stand-in value.
    """
    if message_id is None:
        return None, None
    record = peer.receipt_observations.get(message_id)
    if record is None:
        return None, None
    raw_time = record.get("observed_at_ms")
    observed = raw_time if isinstance(raw_time, int) and not isinstance(raw_time, bool) else None
    if observed is not None and observed <= 0:
        observed = None
    raw_transport = record.get("transport")
    transport = raw_transport if isinstance(raw_transport, str) and raw_transport else None
    return observed, transport


def _payload(receipt: Mapping[str, JSONValue] | None) -> Mapping[str, JSONValue] | None:
    if receipt is None:
        return None
    payload = receipt.get("payload")
    return payload if isinstance(payload, dict) else None


def _claimed_clock(
    payload: Mapping[str, JSONValue] | None, *, now_ms: int | None
) -> tuple[int | None, str]:
    """The peer's own signed HLC watermark, and whether it can be believed.

    Four states, not two. A watermark that is absent, unparseable, or *ahead of
    this device's clock* is reported as unusable and never as a time: a future
    timestamp is a broken clock or a fabricated record, and treating it as a
    reading would make a peer look permanently up to date.
    """
    if payload is None:
        return None, "absent"
    raw = payload.get("importer_hlc_watermark")
    if raw is None:
        return None, "absent"
    if not isinstance(raw, str):
        return None, "malformed"
    try:
        wall_str, counter_str, node_id = raw.split(".", 2)
        wall_ms = int(wall_str)
        int(counter_str)
    except ValueError:
        return None, "malformed"
    if not node_id or wall_ms < 0:
        return None, "malformed"
    if now_ms is not None and wall_ms > now_ms + CLOCK_SKEW_TOLERANCE_MS:
        return None, "ahead"
    return wall_ms, "present"
