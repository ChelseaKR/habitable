# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""An optional, zero-trust relay: ciphertext in, ciphertext out.

Unions that cannot sync device-to-device can run this tiny relay to pass sealed
messages between peers. It is deliberately dumb: it stores opaque blobs per room
and hands them back. It cannot read anything — every message is sealed to a peer's
key before it ever arrives — and it keeps no logs beyond passthrough counts. It is
optional and replaceable; pure peer-to-peer sync needs no relay at all.
"""

from __future__ import annotations

import base64
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

__all__ = ["RelayStore", "make_server", "serve"]

_MAX_BODY = 128 * 1024 * 1024  # 128 MiB ceiling per message
_MAX_MESSAGES_PER_ROOM = 10_000
_ROOM_RE = re.compile(r"^/rooms/([A-Za-z0-9_-]{1,128})$")


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


def make_server(host: str, port: int, store: RelayStore | None = None) -> ThreadingHTTPServer:
    """Build (but do not start) a relay HTTP server."""
    shared_store = store or RelayStore()

    class Handler(BaseHTTPRequestHandler):
        store = shared_store

        # Don't write request lines to stderr; the relay logs only aggregate metrics.
        def log_message(self, _format: str, *_args: object) -> None:
            return

        def do_GET(self) -> None:
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

        def do_POST(self) -> None:
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

        def _json(self, code: int, payload: dict[str, object]) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return ThreadingHTTPServer((host, port), Handler)


def serve(host: str = "127.0.0.1", port: int = 8787, store: RelayStore | None = None) -> None:
    """Run the relay until interrupted."""
    server = make_server(host, port, store)
    print(f"habitable relay listening on http://{host}:{port} (ciphertext passthrough only)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
