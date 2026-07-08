# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""The optional ciphertext-only relay."""

from __future__ import annotations

import io
import json
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Iterator

import pytest

from habitable.relay import RelayStore, _route_label, configure_logging, make_server

# Fields every structured access-log line must carry (OBSERVABILITY-STANDARD §3,
# specialized to the relay's metadata-only contract).
_REQUIRED_LOG_FIELDS = {
    "ts",
    "level",
    "msg",
    "request_id",
    "method",
    "path",
    "status",
    "latency_ms",
}


class TestRelayStore:
    def test_post_fetch_round_trip_and_metrics(self) -> None:
        store = RelayStore()
        store.post("room", b"ciphertext-1")
        store.post("room", b"ciphertext-2")
        assert store.fetch("room") == [b"ciphertext-1", b"ciphertext-2"]
        metrics = store.metrics()
        assert metrics["posted"] == 2 and metrics["rooms"] == 1
        assert metrics["bytes_relayed"] == len(b"ciphertext-1") + len(b"ciphertext-2")

    def test_empty_room(self) -> None:
        assert RelayStore().fetch("nobody") == []


@pytest.fixture
def server_url() -> Iterator[str]:
    server = make_server("127.0.0.1", 0)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _get(url: str) -> tuple[int, bytes]:
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        body = exc.read()
        exc.close()
        return exc.code, body


def test_healthz(server_url: str) -> None:
    status, body = _get(f"{server_url}/healthz")
    assert status == 200
    assert json.loads(body)["status"] == "ok"


def test_unknown_path_is_404(server_url: str) -> None:
    status, _ = _get(f"{server_url}/nope")
    assert status == 404


def test_http_post_then_get(server_url: str) -> None:
    request = urllib.request.Request(f"{server_url}/rooms/abc", data=b"sealed-bytes", method="POST")
    with urllib.request.urlopen(request, timeout=5) as response:
        assert response.status == 200
    status, body = _get(f"{server_url}/rooms/abc")
    assert status == 200
    assert json.loads(body)["messages"]  # one base64 message present


def test_healthz_exposes_only_aggregate_counts(server_url: str) -> None:
    """The relay must leak no room names or message contents — only counts."""
    room = "room-SECRETNAME-123"
    blob = b"SECRET-CIPHERTEXT-PAYLOAD"
    request = urllib.request.Request(f"{server_url}/rooms/{room}", data=blob, method="POST")
    with urllib.request.urlopen(request, timeout=5) as response:
        assert response.status == 200
    status, body = _get(f"{server_url}/healthz")
    assert status == 200
    payload = json.loads(body)
    assert set(payload) <= {"status", "rooms", "posted", "fetched", "bytes_relayed"}
    text = body.decode("utf-8")
    assert "SECRETNAME" not in text  # no room identifiers
    assert "SECRET-CIPHERTEXT" not in text  # no message contents
    assert payload["rooms"] == 1 and payload["posted"] == 1


# --- Health & readiness endpoints (OBSERVABILITY-STANDARD §6) -----------------


def test_livez_is_ok(server_url: str) -> None:
    status, body = _get(f"{server_url}/livez")
    assert status == 200
    assert json.loads(body) == {"status": "ok"}


def test_readyz_ready_when_store_healthy(server_url: str) -> None:
    status, body = _get(f"{server_url}/readyz")
    assert status == 200
    payload = json.loads(body)
    assert payload["status"] == "ok"
    assert payload["checks"]["store"] == "ok"


def test_readyz_fails_closed_when_dependency_down() -> None:
    """A failing critical dependency must yield 503 (fail-closed), not 200."""
    server = make_server("127.0.0.1", 0, ready_check=lambda: False)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, body = _get(f"http://127.0.0.1:{port}/readyz")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    assert status == 503
    payload = json.loads(body)
    assert payload["status"] == "unavailable"
    assert payload["checks"]["store"] == "down"


def test_readyz_fails_closed_when_probe_raises() -> None:
    def boom() -> bool:
        raise RuntimeError("dependency exploded")

    server = make_server("127.0.0.1", 0, ready_check=boom)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, _ = _get(f"http://127.0.0.1:{port}/readyz")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    assert status == 503


# --- Structured JSON access logging (metadata-only) ---------------------------


def test_route_label_redacts() -> None:
    """The route label redacts room ids and never echoes arbitrary client input."""
    assert _route_label("/livez") == "/livez"
    assert _route_label("/readyz") == "/readyz"
    assert _route_label("/healthz") == "/healthz"
    assert _route_label("/rooms/room-SECRETNAME-123") == "/rooms/{room}"
    assert _route_label("/anything/else") == "/<other>"


@pytest.fixture
def logging_relay() -> Iterator[tuple[str, io.StringIO]]:
    """A relay with access logging on, capturing JSON lines to an in-memory buffer."""
    buffer = io.StringIO()
    configure_logging(buffer)
    server = make_server("127.0.0.1", 0, access_log=True)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}", buffer
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        configure_logging()  # reset the module logger back to stderr


def _wait_for_lines(buffer: io.StringIO, count: int, timeout: float = 3.0) -> list[str]:
    """Poll until the buffer holds >= ``count`` non-empty lines (avoids a race with
    the server thread emitting the log line after the client's response returns)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        lines = [ln for ln in buffer.getvalue().splitlines() if ln.strip()]
        if len(lines) >= count:
            return lines
        time.sleep(0.02)
    return [ln for ln in buffer.getvalue().splitlines() if ln.strip()]


def test_access_log_line_is_valid_json_with_expected_fields(
    logging_relay: tuple[str, io.StringIO],
) -> None:
    url, buffer = logging_relay
    request = urllib.request.Request(f"{url}/rooms/abc", data=b"sealed-bytes", method="POST")
    with urllib.request.urlopen(request, timeout=5) as response:
        assert response.status == 200
    _get(f"{url}/rooms/abc")

    lines = _wait_for_lines(buffer, 2)
    assert len(lines) >= 2
    for line in lines:
        record = json.loads(line)  # must be valid JSON (non-JSON raises here)
        assert set(record) >= _REQUIRED_LOG_FIELDS, f"missing fields in {record}"
        assert record["msg"] == "request"
        assert record["method"] in {"GET", "POST"}
        assert record["path"] == "/rooms/{room}"  # redacted route, never the room id
        assert record["status"] == 200
        assert isinstance(record["latency_ms"], (int, float))
        assert len(record["request_id"]) >= 8


def test_access_log_never_leaks_room_id_key_or_payload(
    logging_relay: tuple[str, io.StringIO],
) -> None:
    """Reinforce the threat model: no room id, no ciphertext, no key material in logs."""
    url, buffer = logging_relay
    room = "room-SECRETNAME-123"
    blob = b"SECRET-CIPHERTEXT-PAYLOAD"
    request = urllib.request.Request(f"{url}/rooms/{room}", data=blob, method="POST")
    with urllib.request.urlopen(request, timeout=5) as response:
        assert response.status == 200

    lines = _wait_for_lines(buffer, 1)
    assert lines, "expected an access-log line"
    text = "\n".join(lines)
    assert "SECRETNAME" not in text  # no room identifier
    assert "SECRET-CIPHERTEXT" not in text  # no ciphertext/payload
    assert "sealed-bytes" not in text
    record = json.loads(lines[0])
    assert record["path"] == "/rooms/{room}"


def test_health_probes_excluded_from_access_log(
    logging_relay: tuple[str, io.StringIO],
) -> None:
    url, buffer = logging_relay
    for route in ("/livez", "/readyz", "/healthz"):
        _get(f"{url}{route}")
    # A room request DOES log; use it as a synchronization point, then assert the
    # only logged lines are the room request — health probes emit nothing.
    _get(f"{url}/rooms/xyz")
    lines = _wait_for_lines(buffer, 1)
    assert lines
    for line in lines:
        record = json.loads(line)
        assert record["path"] == "/rooms/{room}"
        assert record["path"] not in {"/livez", "/readyz", "/healthz"}


def test_access_log_is_off_by_default() -> None:
    """Default deployments write no request lines (threat-model default preserved)."""
    buffer = io.StringIO()
    configure_logging(buffer)
    server = make_server("127.0.0.1", 0)  # access_log defaults to False
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{port}"
        for _ in range(3):
            _get(f"{url}/rooms/silent")
        time.sleep(0.2)  # give the server thread time to (not) log
        assert buffer.getvalue().strip() == ""
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        configure_logging()
