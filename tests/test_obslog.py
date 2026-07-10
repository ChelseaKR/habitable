# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Opt-in, on-device, metadata-only structured logging for the CLI and app server.

These tests pin the same contract the relay's logging honours, specialized to the
local surfaces: structured one-object-per-line JSON, off by default, and an absolute
no-plaintext gate — no filenames, passphrases, media bytes, case ids, or key material
ever reach the log stream.
"""

from __future__ import annotations

import base64
import io
import json
import logging
import sys
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator
from pathlib import Path

import piexif
import pytest
from PIL import Image

from habitable.appserver import make_app_server
from habitable.cli import main
from habitable.obslog import (
    _JsonFormatter,
    configure_logging,
    enabled_from_env,
    is_configured,
    log_event,
    reset_logging,
)
from habitable.tsa import LocalRfc3161TSA
from habitable.vault import Vault

# Keys any local log line may legitimately carry. A structural allowlist: it fails
# loudly if instrumentation ever grows a field (e.g. a path or id) that isn't clearly
# metadata, catching a leak before it ships.
_ALLOWED_KEYS = {
    "ts",
    "level",
    "msg",
    "command",
    "ok",
    "duration_ms",
    "media_type",
    "timestamped",
    "had_location",
    "extra_authorities",
    "resolved",
    "archived",
    "sent",
    "bytes_sent",
    "fetched",
    "messages_merged",
    "captures_imported",
    "method",
    "path",
    "status",
    "latency_ms",
}


@pytest.fixture(autouse=True)
def _reset_obslog() -> Iterator[None]:
    """Keep the shared ``habitable`` logger clean between tests (no stale handler)."""
    reset_logging()
    yield
    reset_logging()


def _lines(buffer: io.StringIO) -> list[str]:
    return [ln for ln in buffer.getvalue().splitlines() if ln.strip()]


# --- (a) the formatter emits exactly one metadata-only JSON object per line -------


def test_formatter_emits_one_json_line_with_expected_keys() -> None:
    record = logging.makeLogRecord(
        {"msg": "capture", "levelname": "INFO", "created": 1_767_312_000.0}
    )
    record.event_fields = {"timestamped": True, "extra_authorities": 2, "skipped": None}
    line = _JsonFormatter().format(record)

    assert "\n" not in line  # exactly one physical line
    payload = json.loads(line)  # must be valid JSON
    assert payload["msg"] == "capture"
    assert payload["level"] == "info"
    assert payload["timestamped"] is True
    assert payload["extra_authorities"] == 2
    assert "ts" in payload
    assert "skipped" not in payload  # None values are dropped, never serialized


# --- enabled_from_env: only "json" opts in ----------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [("json", True), ("JSON", True), (" json ", True), ("", False), ("1", False), ("on", False)],
)
def test_enabled_from_env(value: str, expected: bool) -> None:
    assert enabled_from_env({"HABITABLE_LOG": value}) is expected


def test_enabled_from_env_unset_is_false() -> None:
    assert enabled_from_env({}) is False


# --- log_event: the scalar-only guard + off-by-default no-op -----------------------


def test_log_event_is_a_noop_until_configured() -> None:
    # No handler installed: even a non-scalar field must not raise or emit anything.
    assert not is_configured()
    log_event("noop", payload=object(), blob=b"bytes")  # must not raise


def test_log_event_rejects_non_scalar_fields() -> None:
    buffer = io.StringIO()
    configure_logging(buffer)
    for bad in ({"nested": 1}, [1, 2], b"raw-bytes", Path("/secret/path")):
        with pytest.raises(TypeError):
            log_event("evt", field=bad)
    assert _lines(buffer) == []  # nothing leaked before the guard tripped


def test_log_event_accepts_scalar_metadata_and_drops_none() -> None:
    buffer = io.StringIO()
    configure_logging(buffer)
    log_event("evt", count=3, ok=True, dur=1.5, name="init", sha="deadbeef", absent=None)
    lines = _lines(buffer)
    assert len(lines) == 1
    payload = json.loads(lines[0])
    assert payload["count"] == 3 and payload["ok"] is True and payload["dur"] == 1.5
    assert payload["name"] == "init" and payload["sha"] == "deadbeef"
    assert "absent" not in payload


def test_configure_logging_is_idempotent() -> None:
    buffer = io.StringIO()
    configure_logging(buffer)
    configure_logging(buffer)  # a second call must not stack handlers (double lines)
    log_event("evt", n=1)
    assert len(_lines(buffer)) == 1


# --- CLI end-to-end -----------------------------------------------------------------


def _make_jpeg(path: Path, *, trailing: bytes = b"") -> None:
    payload: dict[str, object] = {"0th": {}, "Exif": {}, "GPS": {}, "1st": {}, "thumbnail": None}
    Image.new("RGB", (16, 16), (10, 20, 30)).save(path, "jpeg", exif=piexif.dump(payload))
    if trailing:
        with path.open("ab") as handle:
            handle.write(trailing)


def _run_flow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    log: bool,
    passphrase: str = "test-pass",
    case: str = "case-x",
    title: str = "leak-under-sink",
    media_name: str = "photo.jpg",
    media_trailing: bytes = b"",
) -> tuple[str, str]:
    """Run init -> issue -> timeline -> capture -> export via the CLI, capturing the
    stdout and the structured stderr log stream. ``log`` toggles ``--log-format json``."""
    out, err = io.StringIO(), io.StringIO()
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err)

    vault = tmp_path / "vault"
    media = tmp_path / media_name
    packet = tmp_path / "packet"
    _make_jpeg(media, trailing=media_trailing)
    prefix = ["--log-format", "json"] if log else []

    assert main([*prefix, "init", str(vault), "--case", case, "--passphrase", passphrase]) == 0
    assert (
        main(
            [
                *prefix,
                "issue",
                "--vault",
                str(vault),
                "--passphrase",
                passphrase,
                "--category",
                "plumbing",
                "--title",
                title,
            ]
        )
        == 0
    )
    issue_id = Vault.open(vault, passphrase).document.issues()[0].issue_id
    assert (
        main(
            [
                *prefix,
                "timeline",
                "--vault",
                str(vault),
                "--passphrase",
                passphrase,
                "--issue",
                issue_id,
                "--kind",
                "observed",
                "--text",
                title,
            ]
        )
        == 0
    )
    assert (
        main(
            [
                *prefix,
                "capture",
                str(media),
                "--vault",
                str(vault),
                "--passphrase",
                passphrase,
                "--issue",
                issue_id,
                "--dev-tsa",
            ]
        )
        == 0
    )
    assert (
        main(
            [
                *prefix,
                "export",
                "--vault",
                str(vault),
                "--passphrase",
                passphrase,
                "--out",
                str(packet),
            ]
        )
        == 0
    )
    return out.getvalue(), err.getvalue()


def test_cli_json_logs_are_parseable_and_end_to_end(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stdout, stderr = _run_flow(tmp_path, monkeypatch, log=True)
    lines = [ln for ln in stderr.splitlines() if ln.strip()]
    assert lines, "expected structured log lines on stderr"

    events: dict[str, list[dict[str, object]]] = {}
    for line in lines:
        record = json.loads(line)  # every line must be valid JSON
        assert set(record) <= _ALLOWED_KEYS, f"unexpected (possibly leaky) key in {record}"
        assert {"ts", "level", "msg"} <= set(record)
        events.setdefault(str(record["msg"]), []).append(record)

    # One command-boundary event per subcommand, each successful.
    commands = [e["command"] for e in events["command"]]
    assert commands == ["init", "issue", "timeline", "capture", "export"]
    assert all(e["ok"] is True for e in events["command"])
    assert all(isinstance(e["duration_ms"], (int, float)) for e in events["command"])
    # The capture pipeline emitted its metadata-only trace.
    assert events["capture"] and events["capture"][0]["timestamped"] is True


def test_cli_is_silent_by_default(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HABITABLE_LOG", raising=False)
    _stdout, stderr = _run_flow(tmp_path, monkeypatch, log=False)
    assert stderr.strip() == ""  # no flag, no env => no structured log output
    assert not is_configured()


def test_cli_enabled_by_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HABITABLE_LOG", "json")
    out, err = io.StringIO(), io.StringIO()
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err)
    vault = tmp_path / "vault"
    assert main(["init", str(vault), "--case", "c", "--passphrase", "p"]) == 0
    lines = [ln for ln in err.getvalue().splitlines() if ln.strip()]
    assert lines, "HABITABLE_LOG=json must enable logging without the flag"
    assert json.loads(lines[-1])["command"] == "init"


# --- (d) the no-plaintext guard, paralleling tests/test_relay.py --------------------


def test_logs_never_leak_secrets_or_content(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A representative init/capture/export flow with logging on must emit none of the
    sentinels: not the passphrase, media filename, media bytes, or case/issue text."""
    passphrase = "SENTINEL-PASSPHRASE-8931"
    case = "SENTINEL-CASE-4471"
    text = "SENTINEL-CASE-TEXT-2208"
    media_name = "SENTINEL-FILENAME-6650.jpg"
    media_bytes = b"SENTINEL-MEDIA-BYTES-1174"

    _stdout, stderr = _run_flow(
        tmp_path,
        monkeypatch,
        log=True,
        passphrase=passphrase,
        case=case,
        title=text,
        media_name=media_name,
        media_trailing=media_bytes,
    )

    assert stderr.strip(), "the flow should have produced log lines to assert over"
    for sentinel in (passphrase, case, text, media_name, media_bytes.decode("ascii")):
        assert sentinel not in stderr, f"secret leaked into the log stream: {sentinel!r}"
    # The device fingerprint (key-derived identifier) must not ride along either.
    fingerprint = Vault.open(tmp_path / "vault", passphrase).identity.public().fingerprint
    assert fingerprint not in stderr

    # And every emitted line is metadata-only structured JSON.
    for line in stderr.splitlines():
        if line.strip():
            assert set(json.loads(line)) <= _ALLOWED_KEYS


# --- app server request logging: redacted routes, no bodies -------------------------


def _call(
    url: str, method: str, path: str, body: dict[str, object] | None = None
) -> tuple[int, dict[str, object]]:
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(
        f"{url}{path}", data=data, method=method, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        payload = json.loads(exc.read())
        exc.close()
        return exc.code, payload


def _wait_for_lines(buffer: io.StringIO, count: int, timeout: float = 3.0) -> list[str]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        lines = _lines(buffer)
        if len(lines) >= count:
            return lines
        time.sleep(0.02)
    return _lines(buffer)


def test_appserver_logs_redacted_routes_without_bodies(
    make_vault: Callable[..., Vault],
    local_tsa: LocalRfc3161TSA,
    make_jpeg: Callable[..., Path],
    tmp_path: Path,
) -> None:
    buffer = io.StringIO()
    configure_logging(buffer)
    vault = make_vault()
    server = make_app_server("127.0.0.1", 0, vault, tsa=local_tsa, static_root=tmp_path / "noapp")
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{port}"
    try:
        _status, issue = _call(url, "POST", "/api/issues", {"category": "mold"})
        issue_id = str(issue["issue_id"])
        # The issue id is a sentinel: it must never appear in a log line.
        photo = make_jpeg(name="SENTINEL-APP-FILE.jpg")
        media_b64 = base64.b64encode(photo.read_bytes()).decode()
        _call(
            url,
            "POST",
            f"/api/issues/{issue_id}/timeline",
            {"kind": "observed", "text": "SENTINEL-APP-TIMELINE"},
        )
        _call(
            url,
            "POST",
            "/api/capture",
            {"issue_id": issue_id, "filename": "SENTINEL-APP-FILE.jpg", "media_b64": media_b64},
        )
        _call(url, "GET", "/api/status")
        lines = _wait_for_lines(buffer, 4)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert len(lines) >= 4
    records = [json.loads(line) for line in lines]
    for record in records:
        assert set(record) <= _ALLOWED_KEYS  # every line is metadata-only
    # Per-request access lines carry a redacted route template and timing.
    requests = [r for r in records if r["msg"] == "request"]
    assert len(requests) >= 4
    paths = {r["path"] for r in requests}
    for r in requests:
        assert isinstance(r["latency_ms"], (int, float))
    # Routes are redacted templates; the per-issue route never carries the issue id.
    assert "/api/issues/{issue}/timeline" in paths
    assert {"/api/issues", "/api/capture", "/api/status"} <= paths
    # The capture pipeline's own metadata event rode the same enabled logger.
    assert any(r["msg"] == "capture" for r in records)
    text = "\n".join(lines)
    assert issue_id not in text  # no issue id
    assert "SENTINEL-APP-TIMELINE" not in text  # no request body
    assert "SENTINEL-APP-FILE" not in text  # no filename
    assert media_b64 not in text  # no media bytes
