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

:class:`PaddingTransport` wraps any of those to reduce the *metadata* a relay
operator can infer about a sync — see its docstring and
``docs/relay-observability-matrix.md`` for exactly what it does and does not hide.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import struct
import urllib.error
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
    "PaddingTransport",
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


def export_message(
    vault: Vault,
    recipient: PublicIdentity,
    *,
    state: Mapping[str, JSONValue] | None = None,
    capture_ids: set[str] | None = None,
) -> bytes:
    """Build a signed, sealed sync message carrying CRDT state + sealed originals.

    By default the whole case is sent. ``state`` overrides the CRDT state (e.g. a
    redacted subset from :meth:`CaseDocument.subset_state` for a scoped share), and
    ``capture_ids`` restricts which sealed originals travel — anything outside the
    set is omitted, so a subset share never ships evidence for issues it excludes.
    The message is signed by the sender and sealed to ``recipient`` (an ECIES sealed
    box), so a relay or any third party only ever sees ciphertext.
    """
    captures: list[JSONValue] = []
    for capture in vault.document.captures():
        if capture_ids is not None and capture.capture_id not in capture_ids:
            continue
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
        "state": dict(state) if state is not None else vault.document.to_state(),
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


def import_messages(
    vault: Vault, blobs: list[bytes], *, require_case_id: str | None = None
) -> SyncResult:
    """Open, verify, and merge every message addressed to this device.

    If ``require_case_id`` is set, a message whose ``case_id`` does not match is
    rejected with :class:`SyncError` rather than merged — so a share addressed to one
    case can never be folded into a different case's vault by mistake.
    """
    merged = 0
    imported = 0
    for blob in blobs:
        envelope_bytes = _try_open(vault.identity, blob)
        if envelope_bytes is None:
            # Not addressed to us (or not a sealed message): skip.
            continue
        inner, sender = _verify_envelope(envelope_bytes)
        if require_case_id is not None and inner.get("case_id") != require_case_id:
            raise SyncError(
                f"message is for case {inner.get('case_id')!r}, not {require_case_id!r}"
            )
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
            details={"content_hash": content_hash},
            # sender fingerprint is a custody-actor identity: vault-only, never exported
            private_details={"from": sender.fingerprint},
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


def _s(mapping: Mapping[str, JSONValue], key: str) -> str:
    value = mapping.get(key)
    return value if isinstance(value, str) else ""
