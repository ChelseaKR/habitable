# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""The local app server's JSON API."""

from __future__ import annotations

import base64
import http.client
import json
import os
import re
import shutil
import stat
import threading
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import NamedTuple, NoReturn, cast

import pytest

from habitable import appserver as appserver_module
from habitable.appserver import _STATIC_ROOT, AppServer, _awaiting_only, make_app_server
from habitable.capture import capture
from habitable.errors import CaptureError, HabitableError
from habitable.tsa import LocalRfc3161TSA
from habitable.vault import Vault
from habitable.verify import ItemVerdict, VerificationReport


class App(NamedTuple):
    url: str
    token: str


@pytest.fixture
def app(make_vault: Callable[..., Vault], local_tsa: LocalRfc3161TSA) -> Iterator[App]:
    vault = make_vault()
    server = make_app_server("127.0.0.1", 0, vault, tsa=local_tsa)
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


def _raw_request(
    app: App,
    method: str,
    path: str,
    headers: list[tuple[str, str]],
    body: bytes | None = None,
) -> tuple[int, dict[str, str], dict[str, object]]:
    """Send exact headers, including duplicates that urllib normalizes away."""
    host, port_text = app.url.removeprefix("http://").split(":", 1)
    connection = http.client.HTTPConnection(host, int(port_text), timeout=5)
    try:
        connection.putrequest(method, path, skip_host=True)
        for name, value in headers:
            connection.putheader(name, value)
        connection.endheaders(body)
        response = connection.getresponse()
        raw = response.read()
        payload = (
            json.loads(raw)
            if response.headers.get_content_type() == "application/json"
            else {"body": raw.decode("utf-8")}
        )
        return int(response.status), dict(response.headers.items()), payload
    finally:
        connection.close()


def test_default_static_root_contains_complete_app() -> None:
    """The default server root works in source and installed-wheel layouts."""
    required = {
        "index.html",
        "app.js",
        "styles.css",
        "manifest.webmanifest",
        "service-worker.js",
        "i18n/en.json",
        "i18n/es.json",
        "icons/icon.svg",
    }
    assert {path for path in required if not (_STATIC_ROOT / path).is_file()} == set()


def test_failed_browser_capture_uses_private_ephemeral_staging_outside_vault(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A downstream failure must not leave plaintext, names, or a temp directory behind."""
    vault = make_vault()
    issue_id = vault.document.add_issue(category="mold", issue_id="i1")
    media = make_jpeg("tenant-home.JPG", with_location=True).read_bytes()
    observed: dict[str, object] = {}

    def fail_after_inspection(_vault: Vault, source: str | Path, **_kwargs: object) -> NoReturn:
        staged = Path(source)
        observed["path"] = staged
        observed["bytes"] = staged.read_bytes()
        observed["file_mode"] = stat.S_IMODE(staged.stat().st_mode)
        observed["directory_mode"] = stat.S_IMODE(staged.parent.stat().st_mode)
        raise CaptureError("synthetic downstream failure")

    monkeypatch.setattr(appserver_module, "capture", fail_after_inspection)
    app_server = AppServer(vault, local_tsa, tmp_path, threading.Lock())
    with pytest.raises(CaptureError, match="synthetic downstream failure"):
        app_server.capture(
            {
                "issue_id": issue_id,
                "filename": "tenant-home.JPG",
                "media_b64": base64.b64encode(media).decode("ascii"),
            }
        )

    staged = cast(Path, observed["path"])
    assert observed["bytes"] == media
    assert not staged.resolve().is_relative_to(vault.path.resolve())
    assert staged.name != "tenant-home.JPG"
    assert staged.suffix == ".jpg"  # media-type inference is preserved
    if os.name == "posix":
        assert observed["file_mode"] == 0o600
        assert observed["directory_mode"] == 0o700
    assert not staged.exists()
    assert not staged.parent.exists()
    assert not (vault.path / "_incoming").exists()


def test_browser_capture_preserves_media_type_and_private_source_name(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    vault = make_vault()
    issue_id = vault.document.add_issue(category="mold", issue_id="i1")
    media = make_jpeg("tenant-home.JPG").read_bytes()
    app_server = AppServer(vault, local_tsa, tmp_path, threading.Lock())

    result = app_server.capture(
        {
            "issue_id": issue_id,
            "filename": "tenant-home.JPG",
            "media_b64": base64.b64encode(media).decode("ascii"),
        }
    )

    captured = next(
        item for item in vault.document.captures() if item.capture_id == result["capture_id"]
    )
    assert captured.media_type == "image/jpeg"
    custody = next(
        entry
        for entry in vault.custody.entries
        if entry.action == "captured" and entry.item_id == captured.capture_id
    )
    assert custody.private_details["source"] == "tenant-home.JPG"
    assert not (vault.path / "_incoming").exists()
    for path in vault.path.rglob("*"):
        if path.is_file():
            assert media not in path.read_bytes()


def test_app_start_removes_legacy_incoming_without_following_symlinks(
    make_vault: Callable[..., Vault], tmp_path: Path
) -> None:
    vault = make_vault()
    incoming = vault.path / "_incoming"
    incoming.mkdir()
    (incoming / "stale-upload.jpg").write_bytes(b"legacy plaintext")

    AppServer(vault, None, tmp_path, threading.Lock())
    assert not incoming.exists()

    protected = tmp_path / "must-not-delete.jpg"
    protected.write_bytes(b"outside target")
    incoming.symlink_to(protected)
    AppServer(vault, None, tmp_path, threading.Lock())
    assert not incoming.exists()
    assert protected.read_bytes() == b"outside target"


def test_app_start_fails_closed_when_legacy_staging_cannot_be_removed(
    make_vault: Callable[..., Vault], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = make_vault()
    incoming = vault.path / "_incoming"
    incoming.mkdir()
    (incoming / "stale-upload.jpg").write_bytes(b"legacy plaintext")

    def refuse_cleanup(_path: Path) -> NoReturn:
        raise OSError("synthetic cleanup denial")

    monkeypatch.setattr(shutil, "rmtree", refuse_cleanup)
    with pytest.raises(HabitableError, match="could not remove the legacy plaintext"):
        AppServer(vault, None, tmp_path, threading.Lock())
    assert incoming.exists()


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

    status, timeline = _call(
        app,
        "POST",
        f"/api/issues/{issue_id}/timeline",
        {
            "event_type": "condition_observed",
            "occurred_at": "2026-01-03",
            "source": "firsthand",
            "text": "spreading",
            "capture_ids": [cap["capture_id"]],
        },
    )
    assert status == 200
    assert timeline["status"] == "open"

    status, state = _call(app, "GET", "/api/status")
    assert status == 200 and state["unit"] == "4B"
    assert state["capture_count"] == 1 and state["custody_ok"] is True

    # EXP-03: an on-device record-strength summary rides along on each issue —
    # one capture, one authority, so it reads as "developing", not "strong".
    issues = cast("list[dict[str, object]]", state["issues"])
    strength = cast("dict[str, object]", issues[0]["record_strength"])
    assert strength["item_count"] == 1
    assert strength["level"] == "developing"
    assert strength["timeline_entries"] == 1
    timeline_entries = cast("list[dict[str, object]]", issues[0]["timeline"])
    assert timeline_entries[0]["event_type"] == "condition_observed"
    assert timeline_entries[0]["kind"] == "condition_observed"  # pre-v3 API compatibility
    assert timeline_entries[0]["occurred_at"] == "2026-01-03"

    status, export = _call(app, "POST", "/api/export", {})
    assert status == 200 and export["item_count"] == 1
    assert export["verified"] is False and export["evidence_ready"] is False
    assert export["structurally_intact"] is True
    assert export["timestamp_authority_trusted"] is False
    assert export["verification_status"] == "timestamp_authority_untrusted"
    # A token is attached, but the local app has no recipient trust store and must
    # not present it as evidence-ready. It is not in the awaiting state either.
    assert export["awaiting"] == 0 and export["awaiting_only"] is False

    status, blocked = _call(app, "POST", "/api/export", {"issue_id": issue_id})
    assert status == 400
    assert "scoped packet exports are temporarily blocked" in cast(str, blocked["error"])


def test_export_reports_awaiting_state_honestly(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    """An export whose only defect is awaiting timestamps says so, distinctly.

    FIX-09 / R-01 / R-17: the packet can remain structurally intact while items
    await a timestamp, but the API must let the UI tell that state apart
    from a broken chain or a failed hash — the tenant needs a next step, not an
    integrity alarm.
    """
    vault = make_vault()
    issue = vault.document.add_issue(category="mold", title="Mold", issue_id="i1")
    capture(vault, make_jpeg("a.jpg"), issue_id=issue, tsa=local_tsa)
    capture(vault, make_jpeg("b.jpg"), issue_id=issue, tsa=None)  # queued offline

    server = make_app_server("127.0.0.1", 0, vault, tsa=None, static_root=tmp_path / "noapp")
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, export = _call(
            App(url=f"http://127.0.0.1:{port}", token=server.session_token),
            "POST",
            "/api/export",
            {},
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert status == 200
    assert export["verified"] is False
    assert export["structurally_intact"] is True
    assert export["evidence_ready"] is False
    assert export["verification_status"] == "timestamp_missing"
    assert export["item_count"] == 2 and export["timestamped_count"] == 1
    assert export["awaiting"] == 1
    assert export["awaiting_only"] is True


def _verdict(**overrides: object) -> ItemVerdict:
    base: dict[str, object] = {
        "capture_id": "cap-1",
        "content_hash": "0" * 64,
        "timestamp_verified": True,
        "timestamp_present": True,
        "timestamp_authority_trusted": True,
        "trusted_authorities": ("test",),
        "gen_time": "2026-01-02T00:00:00Z",
        "tsa_name": "test",
        "shared_media_ok": True,
        "custody_binding_ok": True,
        "original_fixity_ok": None,
    }
    base.update(overrides)
    return ItemVerdict(**base)  # type: ignore[arg-type]


def _report(items: tuple[ItemVerdict, ...], **overrides: object) -> VerificationReport:
    base: dict[str, object] = {
        "packet_dir": Path("unused"),
        "signature_ok": True,
        "custody_ok": True,
        "custody_length": 1,
        "items": items,
        "problems": (),
    }
    base.update(overrides)
    return VerificationReport(**base)  # type: ignore[arg-type]


def test_awaiting_only_is_false_for_real_failures() -> None:
    """Only a pure awaiting-timestamp degradation earns the calm state."""
    awaiting = _verdict(
        timestamp_verified=False,
        timestamp_present=False,
        timestamp_authority_trusted=False,
        trusted_authorities=(),
        gen_time="",
        tsa_name="",
    )
    # Purely awaiting -> True.
    assert _awaiting_only(_report((awaiting,))) is True
    # A fully-verified packet is not "awaiting only".
    assert _awaiting_only(_report((_verdict(),))) is False
    # A valid but untrusted token and an attached-but-invalid token are distinct
    # states; neither receives the calm awaiting label.
    untrusted = _verdict(timestamp_authority_trusted=False, trusted_authorities=())
    assert _awaiting_only(_report((untrusted,))) is False
    invalid = _verdict(
        timestamp_verified=False,
        timestamp_present=True,
        timestamp_authority_trusted=False,
        trusted_authorities=(),
    )
    assert _awaiting_only(_report((invalid,))) is False
    # A broken signature, custody chain, or structural problem is an alarm.
    assert _awaiting_only(_report((awaiting,), signature_ok=False)) is False
    assert _awaiting_only(_report((awaiting,), custody_ok=False)) is False
    assert _awaiting_only(_report((awaiting,), problems=("malformed item in bundle",))) is False
    # An item that also fails a hash or binding check is an alarm, not a wait.
    tampered = _verdict(
        timestamp_verified=False,
        timestamp_present=False,
        timestamp_authority_trusted=False,
        shared_media_ok=False,
    )
    assert _awaiting_only(_report((awaiting, tampered))) is False
    bad_original = _verdict(
        timestamp_verified=False,
        timestamp_present=False,
        timestamp_authority_trusted=False,
        original_fixity_ok=False,
    )
    assert _awaiting_only(_report((bad_original,))) is False


def test_export_carries_honest_proof_statement(app: App, make_jpeg: Callable[..., Path]) -> None:
    """RR-02: the export response surfaces the packet's 'what this proves / does not'
    framing, so the upper-bound/limits honesty is unmissable in-app, not only in the
    packet output."""
    _, issue = _call(app, "POST", "/api/issues", {"category": "mold", "title": "Mold"})
    media_b64 = base64.b64encode(make_jpeg().read_bytes()).decode()
    _call(
        app,
        "POST",
        "/api/capture",
        {"issue_id": issue["issue_id"], "filename": "p.jpg", "media_b64": media_b64},
    )
    status, export = _call(app, "POST", "/api/export", {})
    assert status == 200
    proof = export["proof"]
    assert isinstance(proof, dict)
    assert proof["heading"]
    not_proves = proof["not_proves"]
    assert isinstance(not_proves, list) and not_proves
    # The honest limits are present: an upper-bound timestamp and "not legal advice".
    assert any("upper bound" in line for line in not_proves)
    assert any("not legal advice" in line.lower() for line in not_proves)


def test_missing_field_is_400(app: App) -> None:
    status, payload = _call(app, "POST", "/api/issues", {"room": "bath"})  # no category
    assert status == 400 and "error" in payload


def test_unknown_route_is_404(app: App) -> None:
    status, _ = _call(app, "POST", "/api/nope", {})
    assert status == 404


@pytest.mark.parametrize("host", ["0.0.0.0", "127.0.0.2", "192.168.1.10", "example.test", ""])
def test_unlocked_app_rejects_non_loopback_bind(
    host: str, make_vault: Callable[..., Vault]
) -> None:
    with pytest.raises(HabitableError, match="only bind to loopback"):
        make_app_server(host, 0, make_vault())


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost"])
def test_unlocked_app_accepts_loopback_bind(host: str, make_vault: Callable[..., Vault]) -> None:
    server = make_app_server(host, 0, make_vault())
    server.server_close()


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
    assert _status_code(app.url, {"Authorization": f"bearer {app.token}"}) == 200


def test_non_ascii_token_is_rejected_not_crashed(app: App) -> None:
    """Header values are attacker-controlled latin-1 text. ``hmac.compare_digest``
    raises TypeError on non-ASCII *str*, so a naive str comparison would turn this
    request into an unhandled exception in the handler thread; it must be a 401."""
    assert _status_code(app.url, {"X-Habitable-Token": "café-über-token"}) == 401
    assert _status_code(app.url, {"Authorization": "Bearer café"}) == 401


def test_ambiguous_or_duplicate_credentials_are_rejected(app: App) -> None:
    """Duplicate auth fields must not be interpreted differently by intermediaries."""
    authority = app.url.removeprefix("http://")
    base = [("Host", authority)]
    status, _, _ = _raw_request(
        app,
        "GET",
        "/api/status",
        [*base, ("X-Habitable-Token", app.token), ("X-Habitable-Token", app.token)],
    )
    assert status == 401
    status, _, _ = _raw_request(
        app,
        "GET",
        "/api/status",
        [
            *base,
            ("X-Habitable-Token", app.token),
            ("Authorization", f"Bearer {app.token}"),
        ],
    )
    assert status == 401


@pytest.mark.parametrize(
    "host,origin",
    [
        ("evil.example:{port}", ""),
        ("127.0.0.1:1", ""),
        ("127.0.0.1:{port}", "http://evil.example"),
        ("127.0.0.1:{port}", "null"),
        ("127.0.0.1:{port}", "http://localhost:{port}"),
    ],
)
def test_dns_rebinding_and_cross_origin_requests_are_rejected(
    app: App, host: str, origin: str
) -> None:
    """A valid bearer token is not enough when the browser authority is wrong."""
    port = app.url.rsplit(":", 1)[1]
    headers = [
        ("Host", host.format(port=port)),
        ("X-Habitable-Token", app.token),
    ]
    if origin:
        headers.append(("Origin", origin.format(port=port)))
    status, response_headers, _ = _raw_request(app, "GET", "/api/status", headers)
    assert status == 403
    assert "Access-Control-Allow-Origin" not in response_headers


def test_same_origin_browser_request_is_accepted(app: App) -> None:
    authority = app.url.removeprefix("http://")
    status, headers, _ = _raw_request(
        app,
        "GET",
        "/api/status",
        [
            ("Host", authority),
            ("Origin", app.url),
            ("X-Habitable-Token", app.token),
        ],
    )
    assert status == 200
    assert "Access-Control-Allow-Origin" not in headers


def test_cross_origin_preflight_is_explicitly_refused(app: App) -> None:
    authority = app.url.removeprefix("http://")
    status, headers, _ = _raw_request(
        app,
        "OPTIONS",
        "/api/status",
        [
            ("Host", authority),
            ("Origin", "https://attacker.example"),
            ("Access-Control-Request-Method", "GET"),
            ("Access-Control-Request-Headers", "X-Habitable-Token"),
        ],
    )
    assert status == 403
    assert "Access-Control-Allow-Origin" not in headers


def test_api_and_shell_send_defensive_browser_headers(app: App) -> None:
    authority = app.url.removeprefix("http://")
    api_status, api_headers, _ = _raw_request(
        app,
        "GET",
        "/api/status",
        [("Host", authority), ("X-Habitable-Token", app.token)],
    )
    shell_status, shell_headers, _ = _raw_request(app, "GET", "/index.html", [("Host", authority)])
    assert api_status == 200 and shell_status == 200
    assert api_headers["Cache-Control"] == "no-store"
    for headers in (api_headers, shell_headers):
        assert "default-src 'self'" in headers["Content-Security-Policy"]
        assert headers["Cross-Origin-Resource-Policy"] == "same-origin"
        assert headers["Referrer-Policy"] == "no-referrer"
        assert headers["X-Content-Type-Options"] == "nosniff"
        assert headers["X-Frame-Options"] == "DENY"


@pytest.mark.parametrize(
    "framing_headers",
    [
        [("Content-Length", "not-a-number")],
        [("Content-Length", "2"), ("Content-Length", "2")],
        [("Content-Length", "2"), ("Transfer-Encoding", "chunked")],
    ],
)
def test_malformed_or_ambiguous_request_framing_is_rejected(
    app: App, framing_headers: list[tuple[str, str]]
) -> None:
    authority = app.url.removeprefix("http://")
    status, _, payload = _raw_request(
        app,
        "POST",
        "/api/issues",
        [
            ("Host", authority),
            ("X-Habitable-Token", app.token),
            ("Content-Type", "application/json"),
            *framing_headers,
        ],
        b"{}",
    )
    assert status == 400
    assert payload == {"error": "invalid request framing"}


def test_internal_error_response_does_not_leak_exception_details(
    app: App, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail_status(_app: AppServer) -> dict[str, object]:
        raise RuntimeError("SENTINEL-SENSITIVE-INTERNAL-DETAIL")

    monkeypatch.setattr(AppServer, "status", fail_status)
    status, payload = _call(app, "GET", "/api/status")
    assert status == 500
    assert payload == {"error": "internal error"}
    assert "SENTINEL" not in json.dumps(payload)


def test_each_server_gets_a_fresh_strong_token(make_vault: Callable[..., Vault]) -> None:
    first = make_app_server("127.0.0.1", 0, make_vault("first"))
    second = make_app_server("127.0.0.1", 0, make_vault("second"))
    try:
        assert first.session_token != second.session_token
        assert len(first.session_token) == len(second.session_token) == 43
        assert re.fullmatch(r"[A-Za-z0-9_-]+", first.session_token)
        assert re.fullmatch(r"[A-Za-z0-9_-]+", second.session_token)
    finally:
        first.server_close()
        second.server_close()


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
