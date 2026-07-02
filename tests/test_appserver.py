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
from typing import Any, cast

import pytest

from habitable.appserver import _STATIC_ROOT, _awaiting_only, make_app_server
from habitable.capture import capture
from habitable.errors import HabitableError
from habitable.tsa import LocalRfc3161TSA
from habitable.vault import Vault
from habitable.verify import ItemVerdict, VerificationReport


@pytest.fixture
def app(
    make_vault: Callable[..., Vault], local_tsa: LocalRfc3161TSA, tmp_path: Path
) -> Iterator[str]:
    vault = make_vault()
    server = make_app_server("127.0.0.1", 0, vault, tsa=local_tsa, static_root=tmp_path / "noapp")
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _call(
    url: str, method: str, path: str, body: dict[str, object] | None = None
) -> tuple[int, dict[str, object]]:
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(
        f"{url}{path}",
        data=data,
        method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        payload = json.loads(exc.read())
        exc.close()
        return exc.code, payload


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


def test_full_api_flow(app: str, make_jpeg: Callable[..., Path]) -> None:
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

    # EXP-03: an on-device record-strength summary rides along on each issue —
    # one capture, one authority, so it reads as "developing", not "strong".
    issues = cast("list[dict[str, object]]", state["issues"])
    strength = cast("dict[str, object]", issues[0]["record_strength"])
    assert strength["item_count"] == 1
    assert strength["level"] == "developing"
    assert strength["timeline_entries"] == 1

    status, export = _call(app, "POST", "/api/export", {})
    assert status == 200 and export["verified"] is True and export["item_count"] == 1
    # A fully-timestamped packet is not in the degraded awaiting state.
    assert export["awaiting"] == 0 and export["awaiting_only"] is False


def test_export_reports_awaiting_state_honestly(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    """An export whose only defect is awaiting timestamps says so, distinctly.

    FIX-09 / R-01 / R-17: the packet correctly verifies NOT intact while items
    await a trusted timestamp, but the API must let the UI tell that state apart
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
        status, export = _call(f"http://127.0.0.1:{port}", "POST", "/api/export", {})
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert status == 200
    assert export["verified"] is False  # degraded is still honestly NOT intact
    assert export["item_count"] == 2 and export["timestamped_count"] == 1
    assert export["awaiting"] == 1
    assert export["awaiting_only"] is True


def _verdict(**overrides: object) -> ItemVerdict:
    base: dict[str, object] = {
        "capture_id": "cap-1",
        "content_hash": "0" * 64,
        "timestamp_verified": True,
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
    awaiting = _verdict(timestamp_verified=False, gen_time="", tsa_name="")
    # Purely awaiting -> True.
    assert _awaiting_only(_report((awaiting,))) is True
    # A fully-verified packet is not "awaiting only".
    assert _awaiting_only(_report((_verdict(),))) is False
    # A broken signature, custody chain, or structural problem is an alarm.
    assert _awaiting_only(_report((awaiting,), signature_ok=False)) is False
    assert _awaiting_only(_report((awaiting,), custody_ok=False)) is False
    assert _awaiting_only(_report((awaiting,), problems=("malformed item in bundle",))) is False
    # An item that also fails a hash or binding check is an alarm, not a wait.
    tampered = _verdict(timestamp_verified=False, shared_media_ok=False)
    assert _awaiting_only(_report((awaiting, tampered))) is False
    bad_original = _verdict(timestamp_verified=False, original_fixity_ok=False)
    assert _awaiting_only(_report((bad_original,))) is False


def test_export_carries_honest_proof_statement(app: str, make_jpeg: Callable[..., Path]) -> None:
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


def test_recur_reopens_issue_and_logs_on_its_timeline(app: str) -> None:
    status, issue = _call(app, "POST", "/api/issues", {"category": "mold", "title": "Mold"})
    assert status == 200
    issue_id = issue["issue_id"]

    status, recur = _call(app, "POST", f"/api/issues/{issue_id}/recur", {"text": "it came back"})
    assert status == 200
    assert recur["entry_id"] and recur["status"] == "open"

    status, state = _call(app, "GET", "/api/status")
    assert status == 200
    issues = cast("list[dict[str, Any]]", state["issues"])
    issue_state = next(i for i in issues if i["issue_id"] == issue_id)
    assert issue_state["status"] == "open"
    timeline = cast("list[dict[str, Any]]", issue_state["timeline"])
    recurrence = next(e for e in timeline if e["kind"] == "recurrence")
    assert recurrence["text"] == "it came back"


def test_recur_unknown_issue_is_4xx(app: str) -> None:
    status, payload = _call(app, "POST", "/api/issues/does-not-exist/recur", {})
    assert 400 <= status < 500 and "error" in payload


def test_missing_field_is_400(app: str) -> None:
    status, payload = _call(app, "POST", "/api/issues", {"room": "bath"})  # no category
    assert status == 400 and "error" in payload


def test_unknown_route_is_404(app: str) -> None:
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


def test_bad_json_is_400(app: str) -> None:
    request = urllib.request.Request(f"{app}/api/issues", data=b"{not json", method="POST")
    try:
        with urllib.request.urlopen(request, timeout=5):
            raise AssertionError("expected an error")
    except urllib.error.HTTPError as exc:
        assert exc.code == 400
        exc.close()
