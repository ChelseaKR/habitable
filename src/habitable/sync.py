# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""End-to-end-encrypted, peer-to-peer case sync.

Two devices on a case keep in step by exchanging their CRDT state plus the sealed
originals and timestamp tokens, each message *sealed* to the recipient's public
key and *signed* by the sender. A relay, if used, only ever moves ciphertext and
sees room metadata — never contents. Because the case model is a CRDT and import
re-checks fixity, sync is idempotent: re-delivering a message changes nothing.

Transports decide how the sealed bytes travel — a shared directory
(:class:`LocalDirTransport`, also good for USB/AirDrop-style transfer) or a relay
(:class:`RelayClient`).
"""

from __future__ import annotations

import base64
import json
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast

from .canonical import JSONValue, canonical_json, sha256_bytes
from .crypto import Identity, PublicIdentity, open_sealed, seal_to, verify
from .errors import SyncError
from .evidence import CustodyAction
from .tsa import TimestampToken, verify_token
from .vault import Vault

__all__ = [
    "LocalDirTransport",
    "RelayClient",
    "SyncResult",
    "Transport",
    "export_message",
    "import_messages",
    "sync",
]


@dataclass(frozen=True, slots=True)
class SyncResult:
    """What a sync exchange did."""

    sent: bool
    messages_merged: int
    captures_imported: int


class Transport(Protocol):
    """Moves opaque (already-encrypted) bytes between peers on a channel."""

    def post(self, channel: str, blob: bytes) -> None: ...

    def fetch(self, channel: str) -> list[bytes]: ...


# --- message construction -----------------------------------------------------


def export_message(vault: Vault, recipient: PublicIdentity) -> bytes:
    """Build a signed, sealed sync message carrying state + sealed originals."""
    captures: list[JSONValue] = []
    for capture in vault.document.captures():
        raw = vault.read_original(capture.capture_id, capture.content_hash)
        token = vault.get_token(capture.capture_id)
        captures.append(
            {
                "capture_id": capture.capture_id,
                "content_hash": capture.content_hash,
                "media_type": capture.media_type,
                "original_b64": base64.b64encode(raw).decode("ascii"),
                "token": cast(JSONValue, token.to_dict()) if token is not None else None,
            }
        )
    inner: dict[str, JSONValue] = {
        "case_id": vault.document.case_id,
        "state": vault.document.to_state(),
        "captures": captures,
    }
    inner_bytes = canonical_json(inner)
    signature = vault.identity.sign(inner_bytes)
    envelope: dict[str, JSONValue] = {
        "sender": vault.identity.public().encode(),
        "inner_b64": base64.b64encode(inner_bytes).decode("ascii"),
        "sig": base64.b64encode(signature).decode("ascii"),
    }
    return seal_to(recipient, canonical_json(envelope))


def import_messages(vault: Vault, blobs: list[bytes]) -> SyncResult:
    """Open, verify, and merge every message addressed to this device."""
    merged = 0
    imported = 0
    for blob in blobs:
        envelope_bytes = _try_open(vault.identity, blob)
        if envelope_bytes is None:
            # Not addressed to us (or not a sealed message): skip.
            continue
        inner, sender = _verify_envelope(envelope_bytes)
        vault.document.merge(_as_map(inner.get("state")))
        imported += _import_captures(vault, inner, sender)
        merged += 1
    if merged:
        vault.save()
    return SyncResult(sent=False, messages_merged=merged, captures_imported=imported)


def sync(vault: Vault, peer: PublicIdentity, transport: Transport, *, channel: str) -> SyncResult:
    """Post our state to ``peer`` and merge anything waiting for us."""
    transport.post(channel, export_message(vault, peer))
    result = import_messages(vault, transport.fetch(channel))
    return SyncResult(
        sent=True,
        messages_merged=result.messages_merged,
        captures_imported=result.captures_imported,
    )


def _try_open(identity: Identity, blob: bytes) -> bytes | None:
    """Open a sealed message, or return None if it is not addressed to us."""
    try:
        return open_sealed(identity, blob)
    except Exception:
        return None


def _verify_envelope(envelope_bytes: bytes) -> tuple[Mapping[str, JSONValue], PublicIdentity]:
    envelope = _as_map(_loads(envelope_bytes))
    sender_raw = envelope.get("sender")
    sig_raw = envelope.get("sig")
    inner_b64 = envelope.get("inner_b64")
    if (
        not isinstance(sender_raw, str)
        or not isinstance(sig_raw, str)
        or not isinstance(inner_b64, str)
    ):
        raise SyncError("malformed sync envelope")
    sender = PublicIdentity.decode(sender_raw)
    inner_bytes = base64.b64decode(inner_b64)
    if not verify(sender.sign_public, inner_bytes, base64.b64decode(sig_raw)):
        raise SyncError("sync message signature is invalid")
    return _as_map(_loads(inner_bytes)), sender


def _import_captures(vault: Vault, inner: Mapping[str, JSONValue], sender: PublicIdentity) -> int:
    imported = 0
    raw_captures = inner.get("captures")
    if not isinstance(raw_captures, list):
        return 0
    for raw in raw_captures:
        if not isinstance(raw, dict):
            continue
        capture_id = _s(raw, "capture_id")
        content_hash = _s(raw, "content_hash")
        original_b64 = _s(raw, "original_b64")
        if not capture_id or not content_hash or not original_b64:
            continue
        if vault.has_original(capture_id):
            continue  # idempotent: already have it
        original = base64.b64decode(original_b64)
        if sha256_bytes(original) != content_hash:
            raise SyncError(f"received original for {capture_id} failed fixity")
        vault.store_original_bytes(capture_id, original, content_hash)
        token_raw = raw.get("token")
        if isinstance(token_raw, dict):
            token = TimestampToken.from_dict(token_raw)
            verify_token(token, content_hash)  # reject a forged/mismatched token on import
            vault.store_token(capture_id, token)
        vault.custody.append(
            CustodyAction.IMPORTED,
            capture_id,
            actor=vault.identity.public().fingerprint,
            hlc=vault.document.clock.now().encode(),
            details={"from": sender.fingerprint, "content_hash": content_hash},
            identity=vault.identity,
        )
        imported += 1
    return imported


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


class RelayClient:
    """Posts/fetches ciphertext to a habitable relay room over HTTP."""

    def __init__(self, base_url: str, *, timeout: float = 15.0) -> None:
        if not base_url.lower().startswith(("http://", "https://")):
            raise SyncError(f"relay URL must be http(s): {base_url!r}")
        self._base = base_url.rstrip("/")
        self._timeout = timeout

    def post(self, channel: str, blob: bytes) -> None:
        url = f"{self._base}/rooms/{channel}"
        request = urllib.request.Request(  # noqa: S310 - scheme validated in __init__
            url, data=blob, headers={"Content-Type": "application/octet-stream"}, method="POST"
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:  # noqa: S310
                response.read()
        except OSError as exc:
            raise SyncError(f"relay post failed: {exc}") from exc

    def fetch(self, channel: str) -> list[bytes]:
        url = f"{self._base}/rooms/{channel}"
        request = urllib.request.Request(url, method="GET")  # noqa: S310 - scheme validated
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:  # noqa: S310
                payload = json.loads(response.read())
        except OSError as exc:
            raise SyncError(f"relay fetch failed: {exc}") from exc
        if not isinstance(payload, dict) or not isinstance(payload.get("messages"), list):
            raise SyncError("malformed relay response")
        return [base64.b64decode(item) for item in payload["messages"] if isinstance(item, str)]


# --- helpers ------------------------------------------------------------------


def _loads(data: bytes) -> JSONValue:
    parsed: JSONValue = json.loads(data)
    return parsed


def _as_map(value: JSONValue) -> Mapping[str, JSONValue]:
    if not isinstance(value, dict):
        raise SyncError("expected a JSON object")
    return value


def _s(mapping: Mapping[str, JSONValue], key: str) -> str:
    value = mapping.get(key)
    return value if isinstance(value, str) else ""
