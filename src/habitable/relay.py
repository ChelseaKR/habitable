# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""An optional, zero-trust relay: ciphertext in, ciphertext out.

Unions that cannot sync device-to-device can run this tiny relay to pass sealed
messages between peers. It is deliberately dumb: it stores opaque blobs per room
and hands them back. It cannot read anything — every message is sealed to a peer's
key before it ever arrives — and it keeps no logs beyond passthrough counts. It is
optional and replaceable; pure peer-to-peer sync needs no relay at all.

Observability (per the portfolio OBSERVABILITY-STANDARD, metadata-only):

- Logs are **structured JSON, one object per line**, emitted through the stdlib
  ``logging`` module (the relay stays dependency-free — no structlog/OTel wheels in
  its image). Lifecycle events (startup/shutdown) always log. Per-request access
  logging is **opt-in and off by default**, preserving the threat-model guarantee
  that the relay writes no request lines unless an operator turns them on.
- The privacy gate is absolute: logs carry **only metadata** — never ciphertext,
  never plaintext bodies, never keys, never peer IP addresses, and never a raw room
  id. The logged ``path`` is a **redacted route template** (``/rooms/{room}``), so a
  room id — an identifier that would link sync sessions and break the threat model —
  never reaches the log stream. Room contents remain sealed end-to-end regardless.
- ``/livez`` (liveness) and ``/readyz`` (readiness; fail-closed 503 when a critical
  dependency is down) sit alongside the existing ``/healthz`` aggregate-counts route.
  Health probes are excluded from the access log to avoid probe noise.
"""

from __future__ import annotations

import _thread
import base64
import binascii
import hashlib
import hmac
import json
import logging
import math
import os
import re
import secrets
import stat
import sys
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import BinaryIO, TextIO

__all__ = [
    "RelayStore",
    "RoomAuthError",
    "RoomFullError",
    "configure_logging",
    "make_server",
    "serve",
]

_MAX_BODY = 128 * 1024 * 1024  # 128 MiB ceiling per message
_MAX_MESSAGES_PER_ROOM = 10_000
_MAX_LIVE_ROOMS = 4_096
_MAX_LIVE_MESSAGES = 50_000
_MAX_CIPHERTEXT_BYTES_PER_ROOM = 128 * 1024 * 1024
_MAX_LIVE_CIPHERTEXT_BYTES = 512 * 1024 * 1024
_MAX_ROOM_TOKEN_CHARS = 256
_ROOM_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_ROOM_TOKEN_RE = re.compile(rf"^[A-Za-z0-9_-]{{1,{_MAX_ROOM_TOKEN_CHARS}}}$")
_ROOM_RE = re.compile(r"^/rooms/([A-Za-z0-9_-]{1,128})$")
_JOURNAL_NAME_RE = re.compile(r"^[0-9a-f]{64}\.jsonl$")
_COMPACTION_TEMP_RE = re.compile(r"^\.habitable-relay-[0-9a-f]{32}\.tmp$")
_MAX_CONTENT_LENGTH_DIGITS = len(str(_MAX_BODY))
_CONTENT_LENGTH_RE = re.compile(rf"^[0-9]{{1,{_MAX_CONTENT_LENGTH_DIGITS}}}$")

# Relay-created timestamps may be slightly ahead after a host clock correction, but
# a journal cannot retain a TOFU binding indefinitely by claiming an arbitrary future.
_MAX_FUTURE_CLOCK_SKEW_SECONDS = 5 * 60

# Per-message time-to-live. Undelivered ciphertext older than this is expired
# lazily on the next post/fetch touching its room, plus a bounded all-room sweep
# before a global-cap rejection (a non-positive value disables expiry). The
# default is 30 days; operators tune it with the
# ``HABITABLE_RELAY_TTL_SECONDS`` environment variable.
_DEFAULT_TTL_SECONDS = 30 * 24 * 60 * 60


def _ttl_from_env() -> float:
    raw = os.environ.get("HABITABLE_RELAY_TTL_SECONDS")
    if raw is None:
        return float(_DEFAULT_TTL_SECONDS)
    try:
        value = float(raw)
    except ValueError:
        return float(_DEFAULT_TTL_SECONDS)
    return value if math.isfinite(value) else float(_DEFAULT_TTL_SECONDS)


_MESSAGE_TTL_SECONDS = _ttl_from_env()

# Ceiling on one room's on-disk journal (only used when persistence is enabled).
# Before an append would cross this, the file is compacted from the in-memory,
# TTL-filtered queue so application writes do not intentionally exceed the cap.
_MAX_PERSIST_BYTES_PER_ROOM = 256 * 1024 * 1024
_MAX_JOURNAL_LINE_BYTES = 4 * ((_MAX_BODY + 2) // 3) + 4_096
_MAX_JOURNAL_ENTRIES_SCAN = _MAX_LIVE_ROOMS * 2
_MAX_STARTUP_JOURNAL_BYTES = _MAX_LIVE_CIPHERTEXT_BYTES * 2
_MAX_JOURNAL_LINES_PER_ROOM = _MAX_MESSAGES_PER_ROOM * 2
_MAX_STARTUP_JOURNAL_LINES = _MAX_LIVE_MESSAGES * 4
_MAX_COMPACTION_TEMP_FILES = 128
_MAX_COMPACTION_NON_TEMP_SCAN_ENTRIES = _MAX_JOURNAL_ENTRIES_SCAN
_MAX_COMPACTION_TEMP_CREATE_ATTEMPTS = 16
_BASE64_CHUNK_BYTES = 48 * 1024  # divisible by three; no padding between chunks
_MESSAGES_PREFIX = b'{"messages":['
_MESSAGES_SUFFIX = b"]}"

# Windows does not permit unlinking an open file. Its fallback closes only after
# two generation checks, then rechecks immediately before unlink. The persistence
# directory is single-process owned; concurrent local writers are unsupported.
_CLOSE_BEFORE_UNLINK = os.name == "nt"


def _max_get_json_bytes() -> int:
    """Conservative upper bound for one room's materialized GET response.

    Base64 can add padding per message, so the bound uses both the raw-byte and
    message-count ceilings. The remaining term covers JSON quotes, separators,
    keys, and braces. Empty messages are not accepted.
    """
    messages = min(_MAX_MESSAGES_PER_ROOM, _MAX_CIPHERTEXT_BYTES_PER_ROOM)
    encoded = 4 * ((_MAX_CIPHERTEXT_BYTES_PER_ROOM + 2 * messages) // 3)
    return encoded + 4 * messages + 32


def _messages_response_length(messages: list[bytes]) -> int:
    encoded = sum(4 * ((len(message) + 2) // 3) for message in messages)
    punctuation = 2 * len(messages) + max(0, len(messages) - 1)
    return len(_MESSAGES_PREFIX) + encoded + punctuation + len(_MESSAGES_SUFFIX)


def _finite_timestamp(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        timestamp = float(value)
    except OverflowError, ValueError:
        return None
    return timestamp if math.isfinite(timestamp) else None


def _timestamp_within_future_skew(timestamp: float, now: float) -> bool:
    """Bound persisted timestamps without overflowing at extreme finite values."""
    return timestamp <= now or timestamp - now <= _MAX_FUTURE_CLOCK_SKEW_SECONDS


# Header carrying a room's write-capability token (see RelayStore.post).
# The token is a capability, never a secret to log: it is compared with
# ``hmac.compare_digest`` and never enters the access log or any error body.
_ROOM_TOKEN_HEADER = "X-Habitable-Room-Token"  # noqa: S105 - header name, not a secret

_LOGGER_NAME = "habitable.relay"
_LOG = logging.getLogger(_LOGGER_NAME)

# Health probes are unauthenticated and excluded from the access log (no probe
# noise), per OBSERVABILITY-STANDARD §6.
_HEALTH_ROUTES = frozenset({"/livez", "/readyz", "/healthz"})


class RoomFullError(Exception):
    """A room is at its message cap; the relay rejects the post (HTTP 413).

    This replaces the old silent ``pop(0)`` eviction: a full room now fails
    loudly, so a peer learns its message was not accepted instead of silently
    displacing an earlier, still-undelivered message.
    """


class RoomAuthError(Exception):
    """A room write presented a missing or mismatched capability token (HTTP 403)."""


class _JournalRejectedError(Exception):
    """A bounded startup read cannot safely accept this complete journal."""


@dataclass(frozen=True, slots=True)
class _PostPlan:
    fresh: list[tuple[float, bytes]]
    fresh_bytes: int
    expired_messages: int
    base_messages: int
    base_bytes: int


@dataclass(frozen=True, slots=True)
class _JournalCandidate:
    path: Path
    device: int
    inode: int
    size: int
    modified_ns: int
    changed_ns: int

    @classmethod
    def from_stat(cls, path: Path, info: os.stat_result) -> _JournalCandidate:
        return cls(
            path,
            info.st_dev,
            info.st_ino,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )

    def matches(self, info: os.stat_result) -> bool:
        """Return whether ``info`` is the same observed file generation."""
        return (
            info.st_dev == self.device
            and info.st_ino == self.inode
            and info.st_size == self.size
            and info.st_mtime_ns == self.modified_ns
            and info.st_ctime_ns == self.changed_ns
        )


def _same_journal_generation(left: os.stat_result, right: os.stat_result) -> bool:
    """Compare stable metadata that distinguishes immediate inode reuse."""
    return (
        left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
        and left.st_size == right.st_size
        and left.st_mtime_ns == right.st_mtime_ns
        and left.st_ctime_ns == right.st_ctime_ns
    )


@dataclass(frozen=True, slots=True)
class _JournalStage:
    room: str | None
    token: str | None
    messages: list[tuple[float, bytes]]
    message_bytes: int
    prune_expired: bool
    cleanup_safe: bool


@dataclass(slots=True)
class RelayStore:
    """Resource-bounded ciphertext mailbox with TTL and opt-in persistence.

    The store is a dumb per-room queue of opaque ciphertext blobs (never
    plaintext, never keys). Four properties keep relay rooms authenticated and
    operational without the relay ever seeing plaintext:

    - **Write capability.** The first token presented for a room binds it
      (trust-on-first-use); later posts must present the same token or are
      rejected with :class:`RoomAuthError`. A rejected candidate never claims a
      binding; a global-cap retry may only remove independently TTL-expired state.
    - **TTL, not silent eviction.** Each message carries a store timestamp;
      messages older than ``_MESSAGE_TTL_SECONDS`` expire lazily on post/fetch
      and in a bounded sweep before global-cap rejection. A room at its cap raises
      :class:`RoomFullError`
      (surfaced as HTTP 413) instead of silently dropping the oldest message.
    - **Aggregate bounds.** Live room, message, per-room byte, and global byte
      ceilings are checked atomically under an internal re-entrant lock. This is
      required because :class:`ThreadingHTTPServer` shares one store across threads.
    - **Opt-in persistence.** With ``persist_dir`` set, each accepted message is
      appended to a bounded at-rest ciphertext journal. Startup uses non-following,
      nonblocking, bounded reads and applies the same live-state limits. This is a
      restart aid, not a claim of fsync-backed delivery durability.
    """

    rooms: dict[str, list[tuple[float, bytes]]] = field(default_factory=dict)
    tokens: dict[str, str] = field(default_factory=dict)
    posted: int = 0
    fetched: int = 0
    bytes_relayed: int = 0
    persist_dir: Path | None = None
    clock: Callable[[], float] = time.time
    capacity_rejections: int = 0
    journal_load_rejections: int = 0
    _room_bytes: dict[str, int] = field(default_factory=dict, init=False, repr=False)
    _live_messages: int = field(default=0, init=False, repr=False)
    _live_bytes: int = field(default=0, init=False, repr=False)
    _startup_bytes_remaining: int = field(default=0, init=False, repr=False)
    _startup_lines_remaining: int = field(default=0, init=False, repr=False)
    _lock: _thread.RLock = field(default_factory=_thread.RLock, init=False, repr=False)

    def __post_init__(self) -> None:
        self._index_initial_state()
        if self.persist_dir is not None:
            self.persist_dir = Path(self.persist_dir)
            self.persist_dir.mkdir(parents=True, exist_ok=True)
            self._load()

    def post(self, room: str, blob: bytes, *, token: str | None = None) -> None:
        """Accept a sealed blob for ``room`` after verifying its write capability.

        Raises :class:`RoomAuthError` for an invalid/mismatched token, and
        :class:`RoomFullError` when any message, room, or aggregate live-state
        ceiling would be exceeded. A rejected candidate never creates or changes
        its token/room/message; a prospective global rejection may first commit
        bounded TTL expiry of older rooms, plus the aggregate rejection counter.
        """
        with self._lock:
            self._validate_room(room)
            checked_token = self._validated_token(token)
            if not isinstance(blob, bytes):
                raise TypeError("relay ciphertext must be immutable bytes")
            blob_size = len(blob)
            if blob_size <= 0 or blob_size > _MAX_BODY:
                self._reject_capacity("message too large")

            # Authenticate against existing TOFU state before considering expiry.
            # A rejected token therefore cannot use a lazy-expiry pass to mutate or
            # reclaim a room.
            bound = self.tokens.get(room)
            if bound is not None and not hmac.compare_digest(bound, checked_token):
                raise RoomAuthError("room token mismatch")

            now = self._now()
            plan = self._plan_post(room, blob_size, now)

            # Commit lazy expiry only after every acceptance check has passed. A
            # rejected capacity check leaves the queue and TOFU map byte-for-byte
            # unchanged.
            if plan.expired_messages:
                self._live_messages = plan.base_messages
                self._live_bytes = plan.base_bytes
                if plan.fresh:
                    self.rooms[room] = plan.fresh
                    self._room_bytes[room] = plan.fresh_bytes
                else:
                    self.rooms.pop(room, None)
                    self._room_bytes.pop(room, None)
                    self.tokens.pop(room, None)

            queue = self.rooms.setdefault(room, [])
            self._room_bytes.setdefault(room, 0)
            if room not in self.tokens:
                self.tokens[room] = checked_token
            queue.append((now, blob))
            self._room_bytes[room] += blob_size
            self._live_messages += 1
            self._live_bytes += blob_size
            self.posted += 1
            self.bytes_relayed += blob_size
            if self.persist_dir is not None and plan.expired_messages:
                # Keep a legitimate journal from accumulating tiny stale lines until
                # the much larger byte cap happens to force compaction.
                self._compact(room)
            elif self.persist_dir is not None:
                self._persist(room, checked_token, now, blob)

    def fetch(self, room: str) -> list[bytes]:
        """Return a snapshot without clearing it; GET remains non-destructive."""
        with self._lock:
            expired = self._expire(room, self._now())
            if expired and self.persist_dir is not None:
                self._compact(room)
            messages = [blob for _ts, blob in self.rooms.get(room, [])]
            self.fetched += len(messages)
            return messages

    def metrics(self) -> dict[str, int]:
        with self._lock:
            return {
                "rooms": len(self.rooms),
                "live_messages": self._live_messages,
                "live_ciphertext_bytes": self._live_bytes,
                "posted": self.posted,
                "fetched": self.fetched,
                "bytes_relayed": self.bytes_relayed,
                "capacity_rejections": self.capacity_rejections,
                "journal_load_rejections": self.journal_load_rejections,
            }

    # --- write capability (trust-on-first-use) --------------------------------

    @staticmethod
    def _validate_room(room: str) -> None:
        if not isinstance(room, str) or _ROOM_ID_RE.fullmatch(room) is None:
            raise RoomAuthError("invalid room")

    @staticmethod
    def _validated_token(token: str | None) -> str:
        if token is None or token == "":
            raise RoomAuthError("room write requires a token")
        if not isinstance(token, str) or _ROOM_TOKEN_RE.fullmatch(token) is None:
            raise RoomAuthError("invalid room token")
        return token

    def _reject_capacity(self, reason: str) -> None:
        self.capacity_rejections += 1
        raise RoomFullError(reason)

    def _plan_post(
        self,
        room: str,
        blob_size: int,
        now: float,
        *,
        allow_global_sweep: bool = True,
    ) -> _PostPlan:
        current = self.rooms.get(room, [])
        fresh = self._fresh(current, now)
        expired_messages = len(current) - len(fresh)
        current_bytes = self._room_bytes.get(room, 0)
        fresh_bytes = sum(len(item) for _ts, item in fresh)
        base_rooms = len(self.rooms) - int(room in self.rooms and not fresh)
        base_messages = self._live_messages - expired_messages
        base_bytes = self._live_bytes - (current_bytes - fresh_bytes)

        if len(fresh) + 1 > _MAX_MESSAGES_PER_ROOM:
            self._reject_capacity("room full")
        if fresh_bytes + blob_size > _MAX_CIPHERTEXT_BYTES_PER_ROOM:
            self._reject_capacity("room full")
        global_full = (
            base_rooms + int(not fresh) > _MAX_LIVE_ROOMS
            or base_messages + 1 > _MAX_LIVE_MESSAGES
            or base_bytes + blob_size > _MAX_LIVE_CIPHERTEXT_BYTES
        )
        if global_full and allow_global_sweep:
            # Lazy per-room TTL alone can strand capacity in rooms no caller knows.
            # The sweep is bounded by the live room/message caps and runs only on a
            # prospective global rejection.
            self._expire_all(now)
            return self._plan_post(room, blob_size, now, allow_global_sweep=False)
        if global_full:
            self._reject_capacity("relay full")
        return _PostPlan(fresh, fresh_bytes, expired_messages, base_messages, base_bytes)

    # --- per-message TTL ------------------------------------------------------

    def _now(self) -> float:
        now = float(self.clock())
        if not math.isfinite(now):
            raise RuntimeError("relay clock returned a non-finite timestamp")
        return now

    @staticmethod
    def _fresh(queue: list[tuple[float, bytes]], now: float) -> list[tuple[float, bytes]]:
        ttl = _MESSAGE_TTL_SECONDS
        if ttl <= 0:
            return queue
        cutoff = now - ttl
        fresh = [(ts, blob) for ts, blob in queue if ts >= cutoff]
        return queue if len(fresh) == len(queue) else fresh

    def _expire(self, room: str, now: float) -> bool:
        queue = self.rooms.get(room)
        if not queue:
            return False
        fresh = self._fresh(queue, now)
        if fresh is not queue:
            expired_messages = len(queue) - len(fresh)
            fresh_bytes = sum(len(blob) for _ts, blob in fresh)
            expired_bytes = self._room_bytes[room] - fresh_bytes
            self._live_messages -= expired_messages
            self._live_bytes -= expired_bytes
        if fresh:
            self.rooms[room] = fresh
            self._room_bytes[room] = sum(len(blob) for _ts, blob in fresh)
        elif fresh is not queue:
            self.rooms.pop(room, None)
            self._room_bytes.pop(room, None)
            self.tokens.pop(room, None)
        return fresh is not queue

    def _expire_all(self, now: float) -> None:
        for room in list(self.rooms):
            expired = self._expire(room, now)
            if expired and self.persist_dir is not None:
                self._compact(room)

    def _index_initial_state(self) -> None:
        """Index explicitly supplied state and reject an over-cap constructor."""
        now = self._now()
        if len(self.rooms) > _MAX_LIVE_ROOMS or len(self.tokens) > _MAX_LIVE_ROOMS:
            raise ValueError("initial relay state exceeds its room/token limit")
        self._precheck_initial_message_counts()
        for room in list(self.rooms):
            queue = self.rooms[room]
            room_bytes = self._initial_room_bytes(room, queue, now)
            if room_bytes == 0:
                self.rooms.pop(room)
                self.tokens.pop(room, None)
                continue
            self._room_bytes[room] = room_bytes
            self._live_messages += len(queue)
            self._live_bytes += room_bytes
        if set(self.tokens) != set(self.rooms):
            raise ValueError("initial relay token bindings must exactly match nonempty rooms")
        if len(self.rooms) > _MAX_LIVE_ROOMS:
            raise ValueError("initial relay state exceeds its room limit")
        if self._live_messages > _MAX_LIVE_MESSAGES:
            raise ValueError("initial relay state exceeds its message limit")
        if self._live_bytes > _MAX_LIVE_CIPHERTEXT_BYTES:
            raise ValueError("initial relay state exceeds its byte limit")

    def _precheck_initial_message_counts(self) -> None:
        messages = 0
        for queue in self.rooms.values():
            if not isinstance(queue, list):
                raise ValueError("initial relay room queue must be a list")
            if len(queue) > _MAX_MESSAGES_PER_ROOM:
                raise ValueError("initial relay room exceeds its message limit")
            messages += len(queue)
            if messages > _MAX_LIVE_MESSAGES:
                raise ValueError("initial relay state exceeds its message limit")

    def _initial_room_bytes(
        self,
        room: str,
        queue: object,
        now: float,
    ) -> int:
        if not isinstance(room, str) or _ROOM_ID_RE.fullmatch(room) is None:
            raise ValueError("initial relay state contains an invalid room")
        if not isinstance(queue, list):
            raise ValueError("initial relay room queue must be a list")
        if not queue:
            return 0
        if len(queue) > _MAX_MESSAGES_PER_ROOM:
            raise ValueError("initial relay room exceeds its message limit")
        token = self.tokens.get(room)
        if not isinstance(token, str) or _ROOM_TOKEN_RE.fullmatch(token) is None:
            raise ValueError("initial relay room has an invalid token binding")
        room_bytes = sum(self._initial_record_size(record, now) for record in queue)
        if room_bytes > _MAX_CIPHERTEXT_BYTES_PER_ROOM:
            raise ValueError("initial relay room exceeds its byte limit")
        return room_bytes

    @staticmethod
    def _initial_record_size(record: object, now: float) -> int:
        if not isinstance(record, tuple) or len(record) != 2:
            raise ValueError("initial relay room contains a malformed message record")
        timestamp, blob = record
        parsed_timestamp = _finite_timestamp(timestamp)
        if parsed_timestamp is None or not _timestamp_within_future_skew(parsed_timestamp, now):
            raise ValueError("initial relay room contains an invalid timestamp")
        if not isinstance(blob, bytes) or not blob or len(blob) > _MAX_BODY:
            raise ValueError("initial relay room contains an invalid ciphertext blob")
        return len(blob)

    # --- opt-in on-disk persistence -------------------------------------------

    def _room_file(self, room: str) -> Path:
        # sha256 of the room id, so a raw room id never becomes a filename on disk.
        assert self.persist_dir is not None
        digest = hashlib.sha256(room.encode("utf-8")).hexdigest()
        return self.persist_dir / f"{digest}.jsonl"

    @staticmethod
    def _journal_line(room: str, token: str, ts: float, blob: bytes) -> str:
        return json.dumps(
            {
                "room": room,
                "token": token,
                "ts": ts,
                "blob": base64.b64encode(blob).decode("ascii"),
            },
            separators=(",", ":"),
        )

    def _persist(self, room: str, token: str, ts: float, blob: bytes) -> None:
        path = self._room_file(room)
        line = (self._journal_line(room, token, ts, blob) + "\n").encode("utf-8")
        if len(line) > _MAX_JOURNAL_LINE_BYTES:
            raise OSError("relay persistence record exceeds its line limit")

        descriptor, current_size, complete_tail = self._open_journal_append(path)
        compact = (
            not complete_tail
            or current_size > _MAX_PERSIST_BYTES_PER_ROOM
            or (current_size + len(line) > _MAX_PERSIST_BYTES_PER_ROOM)
        )
        try:
            if not compact:
                remaining = memoryview(line)
                while remaining:
                    written = os.write(descriptor, remaining)
                    if written <= 0:
                        raise OSError("relay journal append made no progress")
                    remaining = remaining[written:]
        finally:
            os.close(descriptor)
        if compact:
            self._compact(room)

    @staticmethod
    def _open_journal_append(path: Path) -> tuple[int, int, bool]:
        try:
            before = path.lstat()
        except FileNotFoundError:
            before = None
        if before is not None and not stat.S_ISREG(before.st_mode):
            raise OSError("relay journal is not a regular file")

        flags = os.O_RDWR | os.O_APPEND | os.O_CREAT
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_NONBLOCK", 0)
        flags |= getattr(os, "O_BINARY", 0)
        descriptor = os.open(path, flags, 0o600)
        try:
            info = os.fstat(descriptor)
            current = path.lstat()
            identity_changed = not _same_journal_generation(info, current) or (
                before is not None and not _same_journal_generation(info, before)
            )
            if (
                identity_changed
                or not stat.S_ISREG(info.st_mode)
                or not stat.S_ISREG(current.st_mode)
            ):
                raise OSError("relay journal is not a regular file")
            complete_tail = True
            if info.st_size:
                os.lseek(descriptor, info.st_size - 1, os.SEEK_SET)
                complete_tail = os.read(descriptor, 1) == b"\n"
            if os.name == "posix":
                os.fchmod(descriptor, 0o600)
            return descriptor, info.st_size, complete_tail
        except BaseException:
            os.close(descriptor)
            raise

    def _compact(self, room: str) -> None:
        """Atomically rewrite one journal from its already TTL-filtered live queue."""
        path = self._room_file(room)
        if not self.rooms.get(room):
            self._unlink_empty_journal(path)
            return
        token = self.tokens.get(room, "")
        assert self.persist_dir is not None
        descriptor, tmp = self._new_compaction_temp()
        total = 0
        try:
            if os.name == "posix":
                os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = -1
                for ts, blob in self.rooms.get(room, []):
                    line = (self._journal_line(room, token, ts, blob) + "\n").encode("utf-8")
                    total += len(line)
                    if len(line) > _MAX_JOURNAL_LINE_BYTES or total > _MAX_PERSIST_BYTES_PER_ROOM:
                        raise OSError("compacted relay journal exceeds its configured cap")
                    handle.write(line)
            tmp.replace(path)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            tmp.unlink(missing_ok=True)

    def _new_compaction_temp(self) -> tuple[int, Path]:
        """Create an owner-only temp whose exact grammar startup may clean."""
        assert self.persist_dir is not None
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_BINARY", 0)
        for _attempt in range(_MAX_COMPACTION_TEMP_CREATE_ATTEMPTS):
            tmp = self.persist_dir / f".habitable-relay-{secrets.token_hex(16)}.tmp"
            try:
                return os.open(tmp, flags, 0o600), tmp
            except FileExistsError:
                continue
        raise OSError("could not allocate relay compaction file")

    @staticmethod
    def _unlink_empty_journal(
        path: Path,
        expected: _JournalCandidate | None = None,
    ) -> None:
        """Remove an empty room journal after non-following identity verification."""
        try:
            before = path.lstat()
        except FileNotFoundError:
            return
        if not stat.S_ISREG(before.st_mode) or (
            expected is not None and not expected.matches(before)
        ):
            raise OSError("relay journal is not a regular file")
        flags = os.O_RDONLY
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_NONBLOCK", 0)
        flags |= getattr(os, "O_BINARY", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            current = path.lstat()
            if (
                not stat.S_ISREG(opened.st_mode)
                or not stat.S_ISREG(current.st_mode)
                or not _same_journal_generation(opened, before)
                or not _same_journal_generation(opened, current)
            ):
                raise OSError("relay journal identity changed before cleanup")
            if _CLOSE_BEFORE_UNLINK:
                # Windows rejects unlink(open_file). Closing creates a narrow final
                # path race, so persistence requires one local relay writer; recheck
                # the complete generation immediately before unlinking.
                os.close(descriptor)
                descriptor = -1
                final = path.lstat()
                if not _same_journal_generation(opened, final):
                    raise OSError("relay journal identity changed before cleanup")
            path.unlink()
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _load(self) -> None:
        """Stream a bounded set of regular journals without following or blocking."""
        assert self.persist_dir is not None
        with self._lock:
            now = self._now()
            ttl = _MESSAGE_TTL_SECONDS
            cutoff = now - ttl if ttl > 0 else None
            self._startup_bytes_remaining = _MAX_STARTUP_JOURNAL_BYTES
            self._startup_lines_remaining = _MAX_STARTUP_JOURNAL_LINES
            if self._cleanup_compaction_temps():
                for candidate in self._journal_candidates():
                    if self._startup_bytes_remaining <= 0 or self._startup_lines_remaining <= 0:
                        self.journal_load_rejections += 1
                        break
                    self._load_journal(candidate, cutoff, now)
            if self.journal_load_rejections:
                _LOG.warning(
                    "relay journal records rejected during bounded startup",
                    extra={
                        "event_fields": {
                            "journal_load_rejections": self.journal_load_rejections,
                        }
                    },
                )

    def _cleanup_compaction_temps(self) -> bool:
        """Remove a strictly bounded set of exact app-owned crash remnants."""
        assert self.persist_dir is not None
        candidates: list[_JournalCandidate] = []
        temp_entries = 0
        non_temp_entries = 0
        try:
            with os.scandir(self.persist_dir) as entries:
                for entry in entries:
                    if _COMPACTION_TEMP_RE.fullmatch(entry.name) is None:
                        non_temp_entries += 1
                        if non_temp_entries > _MAX_COMPACTION_NON_TEMP_SCAN_ENTRIES:
                            self.journal_load_rejections += 1
                            return False
                        continue
                    temp_entries += 1
                    if temp_entries > _MAX_COMPACTION_TEMP_FILES:
                        self.journal_load_rejections += 1
                        return False
                    try:
                        info = entry.stat(follow_symlinks=False)
                    except OSError:
                        self.journal_load_rejections += 1
                        continue
                    if not stat.S_ISREG(info.st_mode):
                        self.journal_load_rejections += 1
                        continue
                    candidates.append(_JournalCandidate.from_stat(Path(entry.path), info))
        except OSError:
            self.journal_load_rejections += 1
            return False

        for candidate in sorted(candidates, key=lambda item: item.path.name):
            try:
                self._unlink_empty_journal(candidate.path, expected=candidate)
            except OSError:
                self.journal_load_rejections += 1
                return False
        return True

    def _journal_candidates(self) -> list[_JournalCandidate]:
        assert self.persist_dir is not None
        candidates: list[_JournalCandidate] = []
        inspected = 0
        try:
            with os.scandir(self.persist_dir) as entries:
                for entry in entries:
                    inspected += 1
                    if inspected > _MAX_JOURNAL_ENTRIES_SCAN:
                        self.journal_load_rejections += 1
                        break
                    if not entry.name.endswith(".jsonl"):
                        continue
                    if _JOURNAL_NAME_RE.fullmatch(entry.name) is None:
                        self.journal_load_rejections += 1
                        continue
                    try:
                        info = entry.stat(follow_symlinks=False)
                    except OSError:
                        self.journal_load_rejections += 1
                        continue
                    if not stat.S_ISREG(info.st_mode):
                        self.journal_load_rejections += 1
                        continue
                    candidates.append(_JournalCandidate.from_stat(Path(entry.path), info))
        except OSError:
            self.journal_load_rejections += 1
        return sorted(candidates, key=lambda candidate: candidate.path.name)

    def _open_journal(self, candidate: _JournalCandidate) -> BinaryIO | None:
        path = candidate.path
        flags = os.O_RDONLY
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_NONBLOCK", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError:
            return None
        try:
            info = os.fstat(descriptor)
            current = path.lstat()
            identity_changed = not candidate.matches(info) or not _same_journal_generation(
                info, current
            )
            if (
                identity_changed
                or not stat.S_ISREG(info.st_mode)
                or not stat.S_ISREG(current.st_mode)
                or info.st_size > _MAX_PERSIST_BYTES_PER_ROOM
            ):
                os.close(descriptor)
                return None
            return os.fdopen(descriptor, "rb")
        except OSError:
            os.close(descriptor)
            return None
        except BaseException:
            os.close(descriptor)
            raise

    def _load_journal(
        self,
        candidate: _JournalCandidate,
        cutoff: float | None,
        now: float,
    ) -> None:
        handle = self._open_journal(candidate)
        if handle is None:
            self.journal_load_rejections += 1
            return
        try:
            with handle:
                staged = self._stage_journal(handle, candidate.path, cutoff, now)
        except _JournalRejectedError:
            self.journal_load_rejections += 1
            return
        accepted = False
        if staged.room is not None and staged.token is not None and staged.messages:
            accepted = self._commit_loaded(
                staged.room,
                staged.token,
                staged.messages,
                staged.message_bytes,
            )
        if staged.cleanup_safe and staged.prune_expired and staged.messages and accepted:
            assert staged.room is not None
            self._compact(staged.room)
        elif (
            staged.cleanup_safe
            and not staged.messages
            and (staged.prune_expired or staged.room is None)
        ):
            # Valid stale-only and physically empty/blank crash remnants carry no
            # binding to preserve and would otherwise grow directory entries forever.
            self._unlink_empty_journal(candidate.path, expected=candidate)

    def _bounded_journal_lines(self, handle: BinaryIO) -> Iterator[bytes]:
        """Stream one file-capped journal as individually line-capped objects."""
        consumed = 0
        inspected_lines = 0
        while True:
            if (
                self._startup_bytes_remaining <= 0
                or self._startup_lines_remaining <= 0
                or inspected_lines >= _MAX_JOURNAL_LINES_PER_ROOM
            ):
                if handle.read(1):  # one-byte bounded probe distinguishes EOF from truncation
                    raise _JournalRejectedError
                return
            read_limit = min(
                _MAX_JOURNAL_LINE_BYTES + 1,
                self._startup_bytes_remaining + 1,
            )
            raw = handle.readline(read_limit)
            if not raw:
                return
            inspected_lines += 1
            self._startup_lines_remaining -= 1
            consumed += len(raw)
            if (
                len(raw) > _MAX_JOURNAL_LINE_BYTES
                or len(raw) > self._startup_bytes_remaining
                or consumed > _MAX_PERSIST_BYTES_PER_ROOM
            ):
                self._startup_bytes_remaining = 0
                raise _JournalRejectedError
            self._startup_bytes_remaining -= len(raw)
            if raw.strip():
                yield raw

    def _record_for_load(
        self,
        raw: bytes,
        path: Path,
        cutoff: float | None,
        now: float,
    ) -> tuple[tuple[str, str, float, bytes] | None, bool, bool]:
        record = self._parse_journal_line(raw)
        if record is None:
            self.journal_load_rejections += 1
            return None, False, False
        room, _token, timestamp, _blob = record
        if self._room_file(room).name != path.name or not _timestamp_within_future_skew(
            timestamp, now
        ):
            self.journal_load_rejections += 1
            return None, False, False
        expired = cutoff is not None and timestamp < cutoff
        return record, expired, True

    def _stage_journal(
        self,
        handle: BinaryIO,
        path: Path,
        cutoff: float | None,
        now: float,
    ) -> _JournalStage:
        staged_room: str | None = None
        staged_token: str | None = None
        staged: list[tuple[float, bytes]] = []
        staged_bytes = 0
        prune_expired = False
        cleanup_safe = True
        for raw in self._bounded_journal_lines(handle):
            record, expired, valid = self._record_for_load(raw, path, cutoff, now)
            cleanup_safe = cleanup_safe and valid
            if record is None:
                continue
            room, token, timestamp, blob = record
            if expired:
                # TTL expiry removes the live TOFU binding. A stale record left by
                # transient cleanup failure therefore cannot conflict with a later,
                # legitimately rebound live token in the same canonical journal.
                prune_expired = True
                continue
            if staged_room is None:
                staged_room = room
                staged_token = token
            elif room != staged_room or token != staged_token:
                # Ambiguous *live* TOFU state must not depend on file or line order.
                raise _JournalRejectedError
            if (
                len(staged) + 1 > _MAX_MESSAGES_PER_ROOM
                or staged_bytes + len(blob) > _MAX_CIPHERTEXT_BYTES_PER_ROOM
            ):
                self.capacity_rejections += 1
                raise _JournalRejectedError
            staged.append((timestamp, blob))
            staged_bytes += len(blob)
        return _JournalStage(
            staged_room,
            staged_token,
            staged,
            staged_bytes,
            prune_expired,
            cleanup_safe,
        )

    @staticmethod
    def _parse_journal_line(raw: bytes) -> tuple[str, str, float, bytes] | None:
        try:
            obj = json.loads(raw)
        except ValueError, RecursionError:
            return None
        if not isinstance(obj, dict):
            return None
        room = obj.get("room")
        token = obj.get("token")
        ts = obj.get("ts")
        blob_b64 = obj.get("blob")
        if (
            not isinstance(room, str)
            or _ROOM_ID_RE.fullmatch(room) is None
            or not isinstance(token, str)
            or _ROOM_TOKEN_RE.fullmatch(token) is None
            or not isinstance(blob_b64, str)
        ):
            return None
        timestamp = _finite_timestamp(ts)
        if timestamp is None:
            return None
        try:
            blob = base64.b64decode(blob_b64, validate=True)
        except ValueError, binascii.Error:
            return None
        if not blob or len(blob) > _MAX_BODY:
            return None
        return room, token, timestamp, blob

    def _commit_loaded(
        self,
        room: str,
        token: str,
        staged: list[tuple[float, bytes]],
        staged_bytes: int,
    ) -> bool:
        bound = self.tokens.get(room)
        if bound is not None and not hmac.compare_digest(bound, token):
            self.journal_load_rejections += 1
            return False
        current = self.rooms.get(room, [])
        current_bytes = self._room_bytes.get(room, 0)
        if (
            len(current) + len(staged) > _MAX_MESSAGES_PER_ROOM
            or current_bytes + staged_bytes > _MAX_CIPHERTEXT_BYTES_PER_ROOM
            or (room not in self.rooms and len(self.rooms) + 1 > _MAX_LIVE_ROOMS)
            or self._live_messages + len(staged) > _MAX_LIVE_MESSAGES
            or self._live_bytes + staged_bytes > _MAX_LIVE_CIPHERTEXT_BYTES
        ):
            self.capacity_rejections += 1
            self.journal_load_rejections += 1
            return False
        self.rooms.setdefault(room, []).extend(staged)
        self.tokens.setdefault(room, token)
        self._room_bytes[room] = current_bytes + staged_bytes
        self._live_messages += len(staged)
        self._live_bytes += staged_bytes
        return True


class _JsonFormatter(logging.Formatter):
    """Render each log record as one compact JSON object per line.

    Only the record message and an explicit, metadata-only ``event_fields`` map are
    serialized. There is deliberately no mechanism to smuggle request bodies, keys,
    or exception payloads into the line — the formatter emits exactly what the relay
    hands it, which by construction is metadata only.
    """

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname.lower(),
            "msg": record.getMessage(),
        }
        fields = getattr(record, "event_fields", None)
        if isinstance(fields, dict):
            for key, value in fields.items():
                if value is not None:
                    payload[key] = value
        # json.dumps escapes control characters, so the line is injection-safe and
        # always a single physical line.
        return json.dumps(payload, separators=(",", ":"))


def configure_logging(
    stream: TextIO | None = None, *, level: int = logging.INFO
) -> logging.Handler:
    """Install the JSON formatter on the relay logger (idempotent).

    Pass a ``stream`` (e.g. an in-memory buffer) to capture output in tests; the
    default is ``sys.stderr``. Returns the installed handler so callers can detach
    it again if they wish.
    """
    handler = logging.StreamHandler(stream if stream is not None else sys.stderr)
    handler.setFormatter(_JsonFormatter())
    _LOG.handlers.clear()
    _LOG.addHandler(handler)
    _LOG.setLevel(level)
    _LOG.propagate = False
    return handler


class _RelayHTTPServer(ThreadingHTTPServer):
    """Threaded server whose error path never serializes peer or exception data."""

    def handle_error(self, _request: object, _client_address: object) -> None:
        # socketserver.BaseServer prints client_address plus a full traceback to
        # stderr. Expected peer disconnects are attacker-triggerable and need no log;
        # unexpected faults get one fixed event without exception/address fields.
        if isinstance(sys.exception(), ConnectionError):
            return
        _LOG.error("relay request handler failed")


def _route_label(path: str) -> str:
    """Map a request path to a **redacted** route template for logging.

    Fixed routes log verbatim; a room request logs the template ``/rooms/{room}`` so
    the peer-chosen room id (a linkable identifier) never enters the log stream; any
    other path collapses to a constant so arbitrary client input is never echoed.
    """
    if path in _HEALTH_ROUTES:
        return path
    if _ROOM_RE.match(path):
        return "/rooms/{room}"
    return "/<other>"


def _log_request(
    *, method: str, path: str, status: int, request_id: str, latency_ms: float
) -> None:
    """Emit one structured, metadata-only access-log line."""
    _LOG.info(
        "request",
        extra={
            "event_fields": {
                "request_id": request_id,
                "method": method,
                "path": path,
                "status": status,
                "latency_ms": latency_ms,
            }
        },
    )


def _store_ready(store: RelayStore) -> bool:
    """Readiness probe for the in-memory store — the relay's one critical dependency.

    Returns ``True`` only when the store answers with a well-formed metrics map.
    Any failure returns ``False`` so ``/readyz`` fails closed (503).
    """
    try:
        metrics = store.metrics()
    except Exception:  # fail closed on any store fault
        return False
    return isinstance(metrics, dict) and "rooms" in metrics


def make_server(  # noqa: C901 -- P1-4 follow-up: split route dispatch out of the closure
    host: str,
    port: int,
    store: RelayStore | None = None,
    *,
    ready_check: Callable[[], bool] | None = None,
    access_log: bool = False,
    persist_dir: Path | None = None,
) -> _RelayHTTPServer:
    """Build (but do not start) a relay HTTP server.

    ``ready_check`` backs ``/readyz``; the default verifies the in-memory store. Pass
    a stub returning ``False`` to exercise the fail-closed 503 path. ``access_log``
    enables the per-request structured JSON line (off by default; call
    :func:`configure_logging` first so the line is actually emitted). ``persist_dir``
    (only used when ``store`` is not supplied) turns on the opt-in at-rest ciphertext
    journal; the default is memory-only.
    """
    shared_store = store or RelayStore(persist_dir=persist_dir)
    readiness: Callable[[], bool] = ready_check or (lambda: _store_ready(shared_store))
    emit_access_log = access_log

    class Handler(BaseHTTPRequestHandler):
        store = shared_store

        # Don't write BaseHTTPRequestHandler's ad-hoc request lines to stderr; the
        # relay does its own structured, metadata-only logging instead.
        def log_message(self, _format: str, *_args: object) -> None:
            return

        def do_GET(self) -> None:
            self._start = time.monotonic()
            self._request_id = secrets.token_hex(8)
            self._status = 200
            try:
                self._route_get()
            finally:
                self._access_log("GET")

        def do_POST(self) -> None:
            self._start = time.monotonic()
            self._request_id = secrets.token_hex(8)
            self._status = 200
            try:
                self._route_post()
            finally:
                self._access_log("POST")

        def _route_get(self) -> None:
            if self.path == "/livez":
                # Liveness: process is up, no dependency calls. < 200 ms by design.
                self._json(200, {"status": "ok"})
                return
            if self.path == "/readyz":
                self._readyz()
                return
            if self.path == "/healthz":
                self._json(200, {"status": "ok", **self.store.metrics()})
                return
            match = _ROOM_RE.match(self.path)
            if not match:
                self._json(404, {"error": "not found"})
                return
            messages = self.store.fetch(match.group(1))
            self._send_messages(messages)

        def _route_post(self) -> None:
            match = _ROOM_RE.match(self.path)
            if not match:
                self._json(404, {"error": "not found"})
                return
            lengths = self.headers.get_all("Content-Length", [])
            if self.headers.get_all("Transfer-Encoding", []) or len(lengths) != 1:
                self._json(400, {"error": "invalid request framing"})
                return
            raw_length = lengths[0]
            if _CONTENT_LENGTH_RE.fullmatch(raw_length) is None:
                self._json(400, {"error": "invalid request framing"})
                return
            length = int(raw_length)
            if length <= 0:
                self._json(400, {"error": "bad body"})
                return
            if length > _MAX_BODY:
                self._json(413, {"error": "oversized body"})
                return
            tokens = self.headers.get_all(_ROOM_TOKEN_HEADER, [])
            token = tokens[0] if len(tokens) == 1 else None
            blob = self.rfile.read(length)
            if len(blob) != length:
                self._json(400, {"error": "incomplete body"})
                return
            try:
                self.store.post(match.group(1), blob, token=token)
            except RoomAuthError as exc:
                # str(exc) is metadata-only ("room token mismatch" / "...requires a
                # token"); the token value itself is never echoed.
                self._json(403, {"error": str(exc)})
                return
            except RoomFullError as exc:
                # Capacity reasons are fixed metadata-only vocabulary; no room,
                # token, or body data is echoed.
                self._json(413, {"error": str(exc)})
                return
            self._json(200, {"status": "stored"})

        def _readyz(self) -> None:
            # Readiness reflects dependency health; fail closed on any fault.
            try:
                ready = readiness()
            except Exception:  # an exploding probe means "not ready"
                ready = False
            if ready:
                self._json(200, {"status": "ok", "checks": {"store": "ok"}})
            else:
                self._json(503, {"status": "unavailable", "checks": {"store": "down"}})

        def _access_log(self, method: str) -> None:
            if not emit_access_log:
                return
            label = _route_label(self.path)
            if label in _HEALTH_ROUTES:  # exclude probe noise
                return
            latency_ms = round((time.monotonic() - self._start) * 1000, 3)
            _log_request(
                method=method,
                path=label,
                status=self._status,
                request_id=self._request_id,
                latency_ms=latency_ms,
            )

        def _send_messages(self, messages: list[bytes]) -> None:
            length = _messages_response_length(messages)
            if length > _max_get_json_bytes():
                self._json(500, {"error": "relay response bound violated"})
                return
            self._status = 200
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(length))
            self.end_headers()
            self.wfile.write(_MESSAGES_PREFIX)
            for index, message in enumerate(messages):
                if index:
                    self.wfile.write(b",")
                self.wfile.write(b'"')
                view = memoryview(message)
                for offset in range(0, len(view), _BASE64_CHUNK_BYTES):
                    chunk = view[offset : offset + _BASE64_CHUNK_BYTES]
                    self.wfile.write(base64.b64encode(chunk))
                self.wfile.write(b'"')
            self.wfile.write(_MESSAGES_SUFFIX)

        def _json(self, code: int, payload: dict[str, object]) -> None:
            body = json.dumps(payload).encode("utf-8")
            self._status = code
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return _RelayHTTPServer((host, port), Handler)


def serve(
    host: str = "127.0.0.1",
    port: int = 8787,
    store: RelayStore | None = None,
    *,
    access_log: bool = False,
    persist_dir: Path | None = None,
) -> None:
    """Run the relay until interrupted.

    ``persist_dir`` (opt-in) enables the at-rest ciphertext journal; the default
    is memory-only. The startup line logs only whether persistence is on, never
    the path itself.
    """
    configure_logging()
    server = make_server(host, port, store, access_log=access_log, persist_dir=persist_dir)
    _LOG.info(
        "relay listening (ciphertext passthrough only)",
        extra={
            "event_fields": {
                "host": host,
                "port": port,
                "access_log": access_log,
                "persist": persist_dir is not None,
            }
        },
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        _LOG.info("relay shutting down")
        server.shutdown()
        server.server_close()


def _main() -> None:
    """Entry point for ``python -m habitable.relay`` (used by the container image).

    Host/port come from the environment so the dependency-free relay can run with
    only the standard library and the source tree on PYTHONPATH. Per-request access
    logging is opt-in via ``HABITABLE_RELAY_LOG`` (``json``/``1``/``true``/``on``),
    keeping the no-request-log default the threat model documents. On-disk
    persistence is opt-in via ``HABITABLE_RELAY_PERSIST_DIR`` (unset = memory-only).
    """
    host = os.environ.get("HABITABLE_RELAY_HOST", "127.0.0.1")
    port = int(os.environ.get("HABITABLE_RELAY_PORT", "8787"))
    access_log = os.environ.get("HABITABLE_RELAY_LOG", "").strip().lower() in {
        "json",
        "1",
        "true",
        "on",
    }
    persist_raw = os.environ.get("HABITABLE_RELAY_PERSIST_DIR", "").strip()
    persist_dir = Path(persist_raw) if persist_raw else None
    serve(host, port, access_log=access_log, persist_dir=persist_dir)


if __name__ == "__main__":
    _main()
