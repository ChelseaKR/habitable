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

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import TextIO

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
_ROOM_RE = re.compile(r"^/rooms/([A-Za-z0-9_-]{1,128})$")

# Per-message time-to-live. Undelivered ciphertext older than this is expired
# lazily on the next post/fetch touching its room (a non-positive value disables
# expiry). The default is 30 days; operators tune it with the
# ``HABITABLE_RELAY_TTL_SECONDS`` environment variable.
_DEFAULT_TTL_SECONDS = 30 * 24 * 60 * 60


def _ttl_from_env() -> float:
    raw = os.environ.get("HABITABLE_RELAY_TTL_SECONDS")
    if raw is None:
        return float(_DEFAULT_TTL_SECONDS)
    try:
        return float(raw)
    except ValueError:
        return float(_DEFAULT_TTL_SECONDS)


_MESSAGE_TTL_SECONDS = _ttl_from_env()

# Ceiling on one room's on-disk journal (only used when persistence is enabled).
# When a journal outgrows this it is compacted from the in-memory, TTL-filtered
# queue so it can never grow without bound.
_MAX_PERSIST_BYTES_PER_ROOM = 256 * 1024 * 1024

# Header carrying a room's write-capability token (see RelayStore._check_write).
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


@dataclass(slots=True)
class RelayStore:
    """Ciphertext mailbox with a write-capability token, TTL, and opt-in persistence.

    The store is a dumb per-room queue of opaque ciphertext blobs (never
    plaintext, never keys). Three properties make relay rooms authenticated and
    durable without the relay ever seeing plaintext:

    - **Write capability.** The first token presented for a room binds it
      (trust-on-first-use); later posts must present the same token or are
      rejected with :class:`RoomAuthError`. Tokens are compared with
      :func:`hmac.compare_digest` and never logged.
    - **TTL, not silent eviction.** Each message carries a store timestamp;
      messages older than ``_MESSAGE_TTL_SECONDS`` expire lazily on the next
      post/fetch. A room at its message cap raises :class:`RoomFullError`
      (surfaced as HTTP 413) instead of silently dropping the oldest message.
    - **Opt-in persistence.** With ``persist_dir`` set, each accepted message is
      appended to an at-rest ciphertext journal and reloaded (honoring TTL) on
      the next startup. The default is memory-only: no ``persist_dir``, nothing
      touches disk.
    """

    rooms: dict[str, list[tuple[float, bytes]]] = field(default_factory=dict)
    tokens: dict[str, str] = field(default_factory=dict)
    posted: int = 0
    fetched: int = 0
    bytes_relayed: int = 0
    persist_dir: Path | None = None
    clock: Callable[[], float] = time.time

    def __post_init__(self) -> None:
        if self.persist_dir is not None:
            self.persist_dir = Path(self.persist_dir)
            self.persist_dir.mkdir(parents=True, exist_ok=True)
            self._load()

    def post(self, room: str, blob: bytes, *, token: str | None = None) -> None:
        """Accept a sealed blob for ``room`` after verifying its write capability.

        Raises :class:`RoomAuthError` for a missing/mismatched token, and
        :class:`RoomFullError` when the room (after lazy expiry) is at its cap.
        """
        self._check_write(room, token)
        self._expire(room)
        queue = self.rooms.setdefault(room, [])
        if len(queue) >= _MAX_MESSAGES_PER_ROOM:
            raise RoomFullError("room full")
        ts = self.clock()
        queue.append((ts, blob))
        self.posted += 1
        self.bytes_relayed += len(blob)
        if self.persist_dir is not None:
            # token is non-None here: _check_write rejects a missing token first.
            self._persist(room, self.tokens[room], ts, blob)

    def fetch(self, room: str) -> list[bytes]:
        self._expire(room)
        messages = [blob for _ts, blob in self.rooms.get(room, [])]
        self.fetched += len(messages)
        return messages

    def metrics(self) -> dict[str, int]:
        return {
            "rooms": len(self.rooms),
            "posted": self.posted,
            "fetched": self.fetched,
            "bytes_relayed": self.bytes_relayed,
        }

    # --- write capability (trust-on-first-use) --------------------------------

    def _check_write(self, room: str, token: str | None) -> None:
        if not token:
            raise RoomAuthError("room write requires a token")
        bound = self.tokens.get(room)
        if bound is None:
            self.tokens[room] = token  # trust on first use
            return
        if not hmac.compare_digest(bound, token):
            raise RoomAuthError("room token mismatch")

    # --- per-message TTL ------------------------------------------------------

    def _expire(self, room: str) -> None:
        queue = self.rooms.get(room)
        if not queue:
            return
        ttl = _MESSAGE_TTL_SECONDS
        if ttl <= 0:
            return  # expiry disabled
        cutoff = self.clock() - ttl
        fresh = [(ts, blob) for ts, blob in queue if ts >= cutoff]
        if len(fresh) != len(queue):
            self.rooms[room] = fresh

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
        with path.open("a", encoding="utf-8") as handle:
            handle.write(self._journal_line(room, token, ts, blob) + "\n")
        try:
            oversized = path.stat().st_size > _MAX_PERSIST_BYTES_PER_ROOM
        except OSError:
            oversized = False
        if oversized:
            self._compact(room)

    def _compact(self, room: str) -> None:
        # Rewrite the journal from the current TTL-filtered in-memory queue, so it
        # cannot grow without bound; expired/rejected lines are dropped.
        self._expire(room)
        path = self._room_file(room)
        token = self.tokens.get(room, "")
        tmp = path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as handle:
            for ts, blob in self.rooms.get(room, []):
                handle.write(self._journal_line(room, token, ts, blob) + "\n")
        tmp.replace(path)

    def _load(self) -> None:
        assert self.persist_dir is not None
        ttl = _MESSAGE_TTL_SECONDS
        cutoff = self.clock() - ttl if ttl > 0 else None
        for path in sorted(self.persist_dir.glob("*.jsonl")):
            for raw in path.read_text("utf-8").splitlines():
                if raw.strip():
                    self._load_line(raw, cutoff)

    def _load_line(self, raw: str, cutoff: float | None) -> None:
        try:
            obj = json.loads(raw)
        except ValueError:
            return
        if not isinstance(obj, dict):
            return
        room = obj.get("room")
        token = obj.get("token")
        ts = obj.get("ts")
        blob_b64 = obj.get("blob")
        if not isinstance(room, str) or not isinstance(blob_b64, str):
            return
        if not isinstance(ts, (int, float)):
            return
        if cutoff is not None and ts < cutoff:
            return  # already expired; do not resurrect it
        try:
            blob = base64.b64decode(blob_b64)
        except ValueError:
            return
        self.rooms.setdefault(room, []).append((float(ts), blob))
        if isinstance(token, str) and room not in self.tokens:
            self.tokens[room] = token  # TOFU binding survives a restart


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


def make_server(
    host: str,
    port: int,
    store: RelayStore | None = None,
    *,
    ready_check: Callable[[], bool] | None = None,
    access_log: bool = False,
    persist_dir: Path | None = None,
) -> ThreadingHTTPServer:
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
            encoded = [base64.b64encode(m).decode("ascii") for m in messages]
            self._json(200, {"messages": encoded})

        def _route_post(self) -> None:
            match = _ROOM_RE.match(self.path)
            if not match:
                self._json(404, {"error": "not found"})
                return
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > _MAX_BODY:
                self._json(413, {"error": "bad or oversized body"})
                return
            token = self.headers.get(_ROOM_TOKEN_HEADER)
            blob = self.rfile.read(length)
            try:
                self.store.post(match.group(1), blob, token=token)
            except RoomAuthError as exc:
                # str(exc) is metadata-only ("room token mismatch" / "...requires a
                # token"); the token value itself is never echoed.
                self._json(403, {"error": str(exc)})
                return
            except RoomFullError:
                self._json(413, {"error": "room full"})
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

        def _json(self, code: int, payload: dict[str, object]) -> None:
            self._status = code
            body = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return ThreadingHTTPServer((host, port), Handler)


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
