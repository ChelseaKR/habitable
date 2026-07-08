# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""The optional ciphertext-only relay."""

from __future__ import annotations

import hashlib
import io
import json
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import pytest

from habitable import relay
from habitable.relay import (
    RelayStore,
    RoomAuthError,
    RoomFullError,
    _route_label,
    configure_logging,
    make_server,
)

# A stand-in room write-capability token for tests that drive the store/HTTP layer
# directly (the real client derives it from the channel; see habitable.sync).
_TOKEN = "test-room-token"
_TOKEN_HEADER = "X-Habitable-Room-Token"

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
        store.post("room", b"ciphertext-1", token=_TOKEN)
        store.post("room", b"ciphertext-2", token=_TOKEN)
        assert store.fetch("room") == [b"ciphertext-1", b"ciphertext-2"]
        metrics = store.metrics()
        assert metrics["posted"] == 2 and metrics["rooms"] == 1
        assert metrics["bytes_relayed"] == len(b"ciphertext-1") + len(b"ciphertext-2")

    def test_empty_room(self) -> None:
        assert RelayStore().fetch("nobody") == []

    def test_post_requires_a_token(self) -> None:
        store = RelayStore()
        with pytest.raises(RoomAuthError):
            store.post("room", b"x", token=None)
        with pytest.raises(RoomAuthError):
            store.post("room", b"x", token="")

    def test_first_token_binds_and_mismatch_is_rejected(self) -> None:
        """Trust-on-first-use: the first token claims the room; others are rejected."""
        store = RelayStore()
        store.post("room", b"one", token=_TOKEN)
        store.post("room", b"two", token=_TOKEN)  # same token: fine
        with pytest.raises(RoomAuthError):
            store.post("room", b"evil", token="a-different-token")
        # The rejected write did not land.
        assert store.fetch("room") == [b"one", b"two"]

    def test_room_full_raises_instead_of_silent_eviction(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(relay, "_MAX_MESSAGES_PER_ROOM", 2)
        store = RelayStore()
        store.post("room", b"1", token=_TOKEN)
        store.post("room", b"2", token=_TOKEN)
        with pytest.raises(RoomFullError):
            store.post("room", b"3", token=_TOKEN)
        # The earlier messages are intact — no silent pop(0) displacement.
        assert store.fetch("room") == [b"1", b"2"]

    def test_ttl_expires_stale_messages_lazily(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(relay, "_MESSAGE_TTL_SECONDS", 10.0)
        now = {"t": 1_000.0}
        store = RelayStore(clock=lambda: now["t"])
        store.post("room", b"fresh", token=_TOKEN)
        assert store.fetch("room") == [b"fresh"]
        now["t"] += 11.0  # advance past the TTL
        assert store.fetch("room") == []  # expired lazily on fetch
        # A subsequent post starts a clean queue (expiry also runs on post).
        store.post("room", b"new", token=_TOKEN)
        assert store.fetch("room") == [b"new"]

    def test_ttl_zero_disables_expiry(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(relay, "_MESSAGE_TTL_SECONDS", 0.0)
        now = {"t": 1_000.0}
        store = RelayStore(clock=lambda: now["t"])
        store.post("room", b"keep", token=_TOKEN)
        now["t"] += 10_000_000.0
        assert store.fetch("room") == [b"keep"]


class TestPersistence:
    def test_round_trip_across_a_new_store_instance(self, tmp_path: Path) -> None:
        store = RelayStore(persist_dir=tmp_path)
        store.post("room", b"cipher-1", token=_TOKEN)
        store.post("room", b"cipher-2", token=_TOKEN)

        # A fresh instance (simulating a relay restart) reloads undelivered messages.
        reborn = RelayStore(persist_dir=tmp_path)
        assert reborn.fetch("room") == [b"cipher-1", b"cipher-2"]
        # The trust-on-first-use token binding also survives the restart.
        with pytest.raises(RoomAuthError):
            reborn.post("room", b"x", token="wrong-token")
        reborn.post("room", b"cipher-3", token=_TOKEN)
        assert reborn.fetch("room") == [b"cipher-1", b"cipher-2", b"cipher-3"]

    def test_expired_messages_are_not_resurrected_on_load(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(relay, "_MESSAGE_TTL_SECONDS", 10.0)
        now = {"t": 1_000.0}
        store = RelayStore(persist_dir=tmp_path, clock=lambda: now["t"])
        store.post("room", b"stale", token=_TOKEN)
        now["t"] += 11.0  # let it age past the TTL
        reborn = RelayStore(persist_dir=tmp_path, clock=lambda: now["t"])
        assert reborn.fetch("room") == []

    def test_raw_room_id_never_becomes_a_filename(self, tmp_path: Path) -> None:
        room = "room-SECRETNAME-123"
        store = RelayStore(persist_dir=tmp_path)
        store.post(room, b"SECRET-CIPHERTEXT-PAYLOAD", token=_TOKEN)
        names = [p.name for p in tmp_path.iterdir()]
        assert names
        for name in names:
            assert "SECRETNAME" not in name  # no raw room id in any filename
        expected = f"{hashlib.sha256(room.encode()).hexdigest()}.jsonl"
        assert expected in names


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


def _post(url: str, data: bytes, *, token: str | None = _TOKEN) -> tuple[int, bytes]:
    headers = {} if token is None else {_TOKEN_HEADER: token}
    request = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
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
    status, _ = _post(f"{server_url}/rooms/abc", b"sealed-bytes")
    assert status == 200
    status, body = _get(f"{server_url}/rooms/abc")
    assert status == 200
    assert json.loads(body)["messages"]  # one base64 message present


def test_http_post_without_token_is_403(server_url: str) -> None:
    status, body = _post(f"{server_url}/rooms/abc", b"sealed-bytes", token=None)
    assert status == 403
    assert "token" in json.loads(body)["error"]


def test_http_post_with_mismatched_token_is_403(server_url: str) -> None:
    assert _post(f"{server_url}/rooms/abc", b"first", token="claimant")[0] == 200
    status, body = _post(f"{server_url}/rooms/abc", b"second", token="impostor")
    assert status == 403
    assert json.loads(body)["error"] == "room token mismatch"


def test_http_room_full_is_413(server_url: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(relay, "_MAX_MESSAGES_PER_ROOM", 1)
    assert _post(f"{server_url}/rooms/full", b"1")[0] == 200
    status, body = _post(f"{server_url}/rooms/full", b"2")
    assert status == 413
    assert json.loads(body)["error"] == "room full"


def test_healthz_exposes_only_aggregate_counts(server_url: str) -> None:
    """The relay must leak no room names or message contents — only counts."""
    room = "room-SECRETNAME-123"
    blob = b"SECRET-CIPHERTEXT-PAYLOAD"
    assert _post(f"{server_url}/rooms/{room}", blob)[0] == 200
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
    assert _post(f"{url}/rooms/abc", b"sealed-bytes")[0] == 200
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
    assert _post(f"{url}/rooms/{room}", blob)[0] == 200

    lines = _wait_for_lines(buffer, 1)
    assert lines, "expected an access-log line"
    text = "\n".join(lines)
    assert "SECRETNAME" not in text  # no room identifier
    assert "SECRET-CIPHERTEXT" not in text  # no ciphertext/payload
    assert "sealed-bytes" not in text
    record = json.loads(lines[0])
    assert record["path"] == "/rooms/{room}"


def test_access_log_never_leaks_the_room_write_token(
    logging_relay: tuple[str, io.StringIO],
) -> None:
    """The write-capability token is a header, compared only via hmac — never logged."""
    url, buffer = logging_relay
    token = "ROOMTOKEN-SENTINEL-must-not-appear-in-logs"
    assert _post(f"{url}/rooms/tokenroom", b"sealed", token=token)[0] == 200

    lines = _wait_for_lines(buffer, 1)
    assert lines, "expected an access-log line"
    text = "\n".join(lines)
    assert token not in text  # the token never reaches the log stream
    assert "tokenroom" not in text  # nor the raw room id
    assert json.loads(lines[0])["path"] == "/rooms/{room}"


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
