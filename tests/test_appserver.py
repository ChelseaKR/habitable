# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""The local app server's JSON API."""

from __future__ import annotations

import base64
import json
import threading
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import NamedTuple

import pytest

from habitable.appserver import make_app_server
from habitable.tsa import LocalRfc3161TSA
from habitable.vault import Vault


class App(NamedTuple):
    url: str
    token: str


@pytest.fixture
def app(
    make_vault: Callable[..., Vault], local_tsa: LocalRfc3161TSA, tmp_path: Path
) -> Iterator[App]:
    vault = make_vault()
    server = make_app_server("127.0.0.1", 0, vault, tsa=local_tsa, static_root=tmp_path / "noapp")
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield App(url=f"http://127.0.0.1:{port}", token=server.session_token)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _call(
    app: App, method: str, path: str, body: dict[str, object] | None = None
) -> tuple[int, dict[str, object]]:
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(
        f"{app.url}{path}",
        data=data,
        method=method,
        headers={"Content-Type": "application/json", "X-Habitable-Token": app.token},
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        payload = json.loads(exc.read())
        exc.close()
        return exc.code, payload


def _status_code(url: str, headers: dict[str, str]) -> int:
    request = urllib.request.Request(f"{url}/api/status", method="GET", headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return int(response.status)
    except urllib.error.HTTPError as exc:
        exc.close()
        return int(exc.code)


def test_full_api_flow(app: App, make_jpeg: Callable[..., Path]) -> None:
    status, issue = _call(app, "POST", "/api/issues", {"category": "mold", "title": "Mold"})
    assert status == 200
    issue_id = issue["issue_id"]

    photo = make_jpeg(with_location=True)
    media_b64 = base64.b64encode(photo.read_bytes()).decode()
    status, cap = _call(
        app,
        "POST",
        "/api/capture",
        {"issue_id": issue_id, "filename": "p.jpg", "media_b64": media_b64},
    )
    assert status == 200 and cap["timestamped"] is True and cap["had_location"] is True

    status, _ = _call(
        app, "POST", f"/api/issues/{issue_id}/timeline", {"kind": "observed", "text": "spreading"}
    )
    assert status == 200

    status, state = _call(app, "GET", "/api/status")
    assert status == 200 and state["unit"] == "4B"
    assert state["capture_count"] == 1 and state["custody_ok"] is True

    status, export = _call(app, "POST", "/api/export", {})
    assert status == 200 and export["verified"] is True and export["item_count"] == 1


def test_missing_field_is_400(app: App) -> None:
    status, payload = _call(app, "POST", "/api/issues", {"room": "bath"})  # no category
    assert status == 400 and "error" in payload


def test_unknown_route_is_404(app: App) -> None:
    status, _ = _call(app, "POST", "/api/nope", {})
    assert status == 404


def test_bad_json_is_400(app: App) -> None:
    request = urllib.request.Request(
        f"{app.url}/api/issues",
        data=b"{not json",
        method="POST",
        headers={"X-Habitable-Token": app.token},
    )
    try:
        with urllib.request.urlopen(request, timeout=5):
            raise AssertionError("expected an error")
    except urllib.error.HTTPError as exc:
        assert exc.code == 400
        exc.close()


def test_api_requires_session_token(app: App) -> None:
    """FIX-03: without the per-session token, the unlocked-vault API is closed. An
    unauthenticated LAN client can neither read case status nor write to the case."""
    assert _status_code(app.url, {}) == 401  # no token at all
    assert _status_code(app.url, {"X-Habitable-Token": "wrong"}) == 401  # bad token
    assert _status_code(app.url, {"X-Habitable-Token": app.token}) == 200  # correct token

    # Writes are equally closed without the token.
    bad = App(url=app.url, token="wrong")
    status, payload = _call(bad, "POST", "/api/issues", {"category": "m"})
    assert status == 401 and "error" in payload


def test_authorization_bearer_header_is_accepted(app: App) -> None:
    """The standard Authorization: Bearer form works too, for non-browser clients."""
    assert _status_code(app.url, {"Authorization": f"Bearer {app.token}"}) == 200


def test_static_shell_is_served_without_a_token(app: App) -> None:
    """The app shell must load unauthenticated so it can read the token from the URL;
    only the /api surface is gated. (404 here is fine — it proves it is not a 401.)"""
    assert _status_code_path(app.url, "/index.html") != 401


def _status_code_path(url: str, path: str) -> int:
    request = urllib.request.Request(f"{url}{path}", method="GET")
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return int(response.status)
    except urllib.error.HTTPError as exc:
        exc.close()
        return int(exc.code)
