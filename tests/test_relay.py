# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""The optional ciphertext-only relay."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator

import pytest

from habitable.relay import RelayStore, make_server


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
