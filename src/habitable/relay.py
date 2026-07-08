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
import json
import logging
import os
import re
import secrets
import sys
import time
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TextIO

__all__ = ["RelayStore", "configure_logging", "make_server", "serve"]

_MAX_BODY = 128 * 1024 * 1024  # 128 MiB ceiling per message
_MAX_MESSAGES_PER_ROOM = 10_000
_ROOM_RE = re.compile(r"^/rooms/([A-Za-z0-9_-]{1,128})$")

_LOGGER_NAME = "habitable.relay"
_LOG = logging.getLogger(_LOGGER_NAME)

# Health probes are unauthenticated and excluded from the access log (no probe
# noise), per OBSERVABILITY-STANDARD §6.
_HEALTH_ROUTES = frozenset({"/livez", "/readyz", "/healthz"})


@dataclass(slots=True)
class RelayStore:
    """In-memory ciphertext mailbox plus passthrough metrics (no contents logged)."""

    rooms: dict[str, list[bytes]] = field(default_factory=lambda: defaultdict(list))
    posted: int = 0
    fetched: int = 0
    bytes_relayed: int = 0

    def post(self, room: str, blob: bytes) -> None:
        queue = self.rooms.setdefault(room, [])
        if len(queue) >= _MAX_MESSAGES_PER_ROOM:
            queue.pop(0)
        queue.append(blob)
        self.posted += 1
        self.bytes_relayed += len(blob)

    def fetch(self, room: str) -> list[bytes]:
        messages = list(self.rooms.get(room, []))
        self.fetched += len(messages)
        return messages

    def metrics(self) -> dict[str, int]:
        return {
            "rooms": len(self.rooms),
            "posted": self.posted,
            "fetched": self.fetched,
            "bytes_relayed": self.bytes_relayed,
        }


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


def make_server(  # noqa: C901 -- P1-4 follow-up: split route dispatch out of the closure
    host: str,
    port: int,
    store: RelayStore | None = None,
    *,
    ready_check: Callable[[], bool] | None = None,
    access_log: bool = False,
) -> ThreadingHTTPServer:
    """Build (but do not start) a relay HTTP server.

    ``ready_check`` backs ``/readyz``; the default verifies the in-memory store. Pass
    a stub returning ``False`` to exercise the fail-closed 503 path. ``access_log``
    enables the per-request structured JSON line (off by default; call
    :func:`configure_logging` first so the line is actually emitted).
    """
    shared_store = store or RelayStore()
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
            blob = self.rfile.read(length)
            self.store.post(match.group(1), blob)
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
) -> None:
    """Run the relay until interrupted."""
    configure_logging()
    server = make_server(host, port, store, access_log=access_log)
    _LOG.info(
        "relay listening (ciphertext passthrough only)",
        extra={"event_fields": {"host": host, "port": port, "access_log": access_log}},
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
    keeping the no-request-log default the threat model documents.
    """
    host = os.environ.get("HABITABLE_RELAY_HOST", "127.0.0.1")
    port = int(os.environ.get("HABITABLE_RELAY_PORT", "8787"))
    access_log = os.environ.get("HABITABLE_RELAY_LOG", "").strip().lower() in {
        "json",
        "1",
        "true",
        "on",
    }
    serve(host, port, access_log=access_log)


if __name__ == "__main__":
    _main()
