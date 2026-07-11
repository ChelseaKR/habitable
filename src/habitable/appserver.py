# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""A localhost-only app server: the back end for the installable client.

The local-first client is a small web app served from this machine, talking to a
JSON API that holds the *unlocked* vault in memory. Nothing leaves the device: the
server binds to loopback, the passphrase is entered once when it starts, and the
browser never sees keys. This is the engine behind ``habitable app``.

Endpoints (all under ``/api``) reuse the tested core — capture seals and hashes
the uploaded bytes, export builds and auto-verifies a packet — so the UI is a thin,
accessible shell over the same evidence guarantees as the CLI.
"""

from __future__ import annotations

import base64
import hmac
import json
import re
import secrets
import shutil
import stat
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import cast
from urllib.parse import urlsplit

from .capture import capture, resolve_deferred
from .disclosure import proof_statement
from .errors import HabitableError
from .obslog import configure_logging, enabled_from_env, is_configured, log_event
from .packet import build_packet
from .private_temp import private_temp_workspace
from .strength import assess_issue
from .tsa import DevTSA, TimestampAuthority
from .vault import Vault
from .verify import VerificationReport, verify_packet

__all__ = ["AppHTTPServer", "AppServer", "make_app_server"]

_MAX_BODY = 64 * 1024 * 1024
_CONTENT_SECURITY_POLICY = (
    "default-src 'self'; base-uri 'none'; connect-src 'self'; form-action 'self'; "
    "frame-ancestors 'none'; img-src 'self'; manifest-src 'self'; media-src 'self'; "
    "object-src 'none'; script-src 'self'; style-src 'self'; worker-src 'self'"
)


def _default_static_root() -> Path:
    """Return app assets from an installed wheel or the source checkout.

    Hatch maps the repository's ``app/`` directory to ``habitable/_app`` in a
    wheel. Editable/source installs still use the repository directory so there
    is one canonical copy of every asset.
    """
    package_root = Path(__file__).resolve().parent / "_app"
    if package_root.is_dir():
        return package_root
    return Path(__file__).resolve().parent.parent.parent / "app"


_STATIC_ROOT = _default_static_root()
_SAFE_PATH = re.compile(r"^[A-Za-z0-9_./-]+$")
_TIMELINE_ROUTE = re.compile(r"^/api/issues/([A-Za-z0-9_.-]+)/timeline$")

# Fixed API routes log verbatim; everything else is redacted, mirroring the relay's
# _route_label discipline so no issue id, static path, or query value ever reaches
# the log stream.
_API_ROUTES = frozenset(
    {"/api/status", "/api/issues", "/api/capture", "/api/resolve", "/api/export"}
)


def _route_label(path: str) -> str:
    """Map a request path to a **redacted** route template for logging.

    Fixed API routes log verbatim; the per-issue timeline route collapses to
    ``/api/issues/{issue}/timeline`` so the issue id never enters the log; anything
    else (static assets, arbitrary probes) collapses to ``/<static>``. Any query
    string is dropped first so query *values* are never echoed.
    """
    route = path.split("?", 1)[0]
    if route in _API_ROUTES:
        return route
    if _TIMELINE_ROUTE.match(route):
        return "/api/issues/{issue}/timeline"
    return "/<static>"


_CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".webmanifest": "application/manifest+json",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
}


@dataclass(slots=True)
class AppServer:
    """An unlocked vault plus the policy for serving the app over loopback."""

    vault: Vault
    tsa: TimestampAuthority | None
    static_root: Path
    lock: threading.Lock
    extra_tsas: Sequence[TimestampAuthority] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        """Remove the reserved plaintext staging directory used by older versions."""
        _remove_legacy_incoming(self.vault.path)

    # --- API actions (called under the lock) ---------------------------------

    def status(self) -> dict[str, object]:
        doc = self.vault.document
        captures = doc.captures()
        timestamped = sum(1 for c in captures if self.vault.get_token(c.capture_id) is not None)
        custody = self.vault.custody.verify()
        footprint = self.vault.storage_footprint()
        return {
            "unit": doc.get_meta("unit") or doc.case_id,
            "case_id": doc.case_id,
            "fingerprint": self.vault.identity.public().fingerprint,
            "issues": [self._issue(i.issue_id) for i in doc.issues()],
            "capture_count": len(captures),
            "timestamped": timestamped,
            "deferred": len(self.vault.deferred()),
            "custody_ok": custody.ok,
            "custody_length": custody.length,
            # Storage footprint (R-03): sealed originals are kept twice by design.
            "storage": {
                "sealed_originals_bytes": footprint.sealed_originals_bytes,
                "shared_copies_bytes": footprint.shared_copies_bytes,
                "metadata_bytes": footprint.metadata_bytes,
                "total_bytes": footprint.total_bytes,
            },
            # Network policy (R-19), exposed read-only so the app can show it.
            "allow_metered": self.vault.config.network.allow_metered,
        }

    def _issue(self, issue_id: str) -> dict[str, object]:
        doc = self.vault.document
        issue = next(i for i in doc.issues() if i.issue_id == issue_id)
        strength = assess_issue(self.vault, issue_id)
        return {
            "issue_id": issue.issue_id,
            "category": issue.category,
            "room": issue.room,
            "title": issue.title,
            "status": issue.status,
            "severity": issue.severity,
            "description": issue.description,
            "captures": len(doc.captures(issue_id)),
            "capture_items": [
                {
                    "capture_id": capture.capture_id,
                    "captured_at": capture.captured_at,
                    "media_type": capture.media_type,
                }
                for capture in doc.captures(issue_id)
            ],
            "timeline": [
                {
                    "entry_id": entry.entry_id,
                    # Kept for pre-v3 local clients. Packet v3 itself never emits
                    # or reinterprets the historical ``kind`` field.
                    "kind": entry.kind,
                    "event_type": entry.event_type,
                    "other_label": entry.other_label,
                    "text": entry.text,
                    "occurred_at": entry.occurred_at,
                    "recorded_at": entry.recorded_at,
                    "source": entry.source,
                    "source_detail": entry.source_detail,
                }
                for entry in doc.timeline(issue_id)
            ],
            # EXP-03: an on-device, telemetry-free record-strength summary — never a
            # legal or admissibility claim, see habitable.strength module docstring.
            "record_strength": {
                "level": strength.level.value,
                "item_count": strength.item_count,
                "strong_count": strength.strong_count,
                "developing_count": strength.developing_count,
                "minimal_count": strength.minimal_count,
                "timeline_entries": strength.timeline_entries,
            },
        }

    def add_issue(self, body: dict[str, object]) -> dict[str, object]:
        issue_id = self.vault.document.add_issue(
            category=_req_str(body, "category"),
            room=_opt_str(body, "room"),
            title=_opt_str(body, "title"),
            severity=_opt_str(body, "severity"),
            description=_opt_str(body, "description"),
        )
        self.vault.save()
        return {"issue_id": issue_id}

    def add_timeline(self, issue_id: str, body: dict[str, object]) -> dict[str, object]:
        event_type = _opt_str(body, "event_type")
        if not event_type:
            # Compatibility for pre-v3 clients.  Preserve their free-form kind as
            # a legacy entry; packet export later labels its unknown occurrence/source
            # honestly and creates a migration-stage custody binding.
            entry_id = self.vault.document.add_timeline_entry(
                issue_id, _req_str(body, "kind"), _req_str(body, "text")
            )
            self.vault.save()
            return {"entry_id": entry_id, "status": "legacy-migrated"}
        entry_id = self.vault.add_timeline_event(
            issue_id,
            event_type=event_type,
            text=_req_str(body, "text"),
            occurred_at=_req_str(body, "occurred_at"),
            source=_req_str(body, "source"),
            other_label=_opt_str(body, "other_label"),
            source_detail=_opt_str(body, "source_detail"),
            capture_ids=_opt_str_tuple(body, "capture_ids"),
            notice_entry_id=_opt_str(body, "notice_entry_id"),
            receipt_entry_id=_opt_str(body, "receipt_entry_id"),
            response_entry_id=_opt_str(body, "response_entry_id"),
        )
        issue = next(item for item in self.vault.document.issues() if item.issue_id == issue_id)
        return {"entry_id": entry_id, "status": issue.status}

    def capture(self, body: dict[str, object]) -> dict[str, object]:
        issue_id = _req_str(body, "issue_id")
        filename = _opt_str(body, "filename") or "upload.jpg"
        media = base64.b64decode(_req_str(body, "media_b64"))
        tsa = self.tsa
        if _opt_bool(body, "dev_tsa"):
            tsa = DevTSA("dev-tsa")
        transcript = _opt_str(body, "transcript")
        with private_temp_workspace(forbidden_root=self.vault.path) as workspace:
            staged = workspace.write_bytes(media, suffix=Path(filename).suffix)
            result = capture(
                self.vault,
                staged,
                issue_id=issue_id,
                tsa=tsa,
                transcript=transcript,
                source_name=Path(filename).name,
            )
        return {
            "capture_id": result.capture_id,
            "content_hash": result.content_hash,
            "timestamped": result.timestamped,
            "gen_time": result.timestamp_info.gen_time if result.timestamp_info else "",
            "had_location": result.had_location,
        }

    def resolve(self) -> dict[str, object]:
        if self.tsa is None:
            raise HabitableError("no timestamp authority configured")
        results = resolve_deferred(self.vault, self.tsa, extra_tsas=self.extra_tsas)
        return {"resolved": len(results)}

    def export(self, body: dict[str, object]) -> dict[str, object]:
        issue_id = _opt_str(body, "issue_id") or None
        include_originals = _opt_bool(body, "include_originals")
        exports = self.vault.path.parent / "exports"
        exports.mkdir(exist_ok=True)
        name = f"packet-{len(list(exports.iterdir())) + 1}"
        out = exports / name
        result = build_packet(
            self.vault, out, issue_id=issue_id, include_originals=include_originals
        )
        report = verify_packet(out)
        # The same honest "what this proves / does not" statement the packet carries,
        # surfaced in-app at the moment of export so the upper-bound timestamp semantics
        # and the "not legal advice / no admissibility guarantee" limits are unmissable.
        stmt = proof_statement(self.vault.config.language)
        return {
            "out_dir": str(out),
            "item_count": result.item_count,
            "timestamped_count": result.timestamped_count,
            "awaiting": result.item_count - result.timestamped_count,
            "awaiting_only": _awaiting_only(report),
            "disclosures": list(result.disclosures),
            "proof": {
                "heading": stmt.heading,
                "proves_heading": stmt.proves_heading,
                "proves": list(stmt.proves),
                "not_heading": stmt.not_heading,
                "not_proves": list(stmt.not_proves),
                "verify_line": stmt.verify_line,
            },
            # ``verified`` is retained for older app shells; it now means the
            # fail-closed evidence-ready verdict. The named fields prevent a
            # structurally intact but untrusted packet from being shown as ready.
            "verified": report.evidence_ready,
            "structurally_intact": report.structurally_intact,
            "timestamp_authority_trusted": report.timestamp_authority_trusted,
            "evidence_ready": report.evidence_ready,
            "verification_status": report.status,
            "summary": report.summary(),
        }


def _awaiting_only(report: VerificationReport) -> bool:
    """Whether a missing timestamp is the only active integrity/token-validity gap.

    An un-timestamped item can still be structurally intact, but is not evidence-ready.
    For the person exporting, "awaiting a timestamp" is different from a broken chain,
    a failed hash, or an untrusted timestamp authority, and the UI must not collapse
    those states (FIX-09, R-01/R-17). Authority trust may also remain unassessed because
    the local app has no recipient trust store; the named trust fields disclose that
    separately. This compatibility flag only promises there is no integrity failure or
    attached-but-invalid token.
    """
    if report.evidence_ready or not report.structurally_intact:
        return False
    awaiting = [item for item in report.items if not item.timestamp_present]
    return bool(awaiting) and all(
        item.structurally_intact and (item.timestamp_verified if item.timestamp_present else True)
        for item in report.items
    )


# POST routes: path -> a call against the AppServer with the parsed JSON body.
# Kept at module scope (not built inside the handler) so dispatch is a plain dict
# lookup. The old form defined the whole handler class inside make_app_server, so
# every branch in every handler method counted toward that one function's
# complexity (C901 = 19); moving the handler out drops make_app_server to trivial
# with no behavior change.
_POST_ROUTES: dict[str, Callable[[AppServer, dict[str, object]], dict[str, object]]] = {
    "/api/issues": lambda app, body: app.add_issue(body),
    "/api/capture": lambda app, body: app.capture(body),
    "/api/resolve": lambda app, _body: app.resolve(),
    "/api/export": lambda app, body: app.export(body),
}
_TIMELINE_RE = re.compile(r"^/api/issues/([A-Za-z0-9_.-]+)/timeline$")


class AppHTTPServer(ThreadingHTTPServer):
    """Loopback server that carries the shared AppServer and its per-session token.

    Holding ``app`` on the server (rather than closing over it in a handler class
    defined inside ``make_app_server``) is what lets the handler live at module
    scope. ``session_token`` authenticates every ``/api/*`` request so an unlocked
    vault is not a read/write API open to anyone who can reach the host (FIX-03;
    see docs/mobile.md). Read it back from ``make_app_server``'s return value.
    """

    def __init__(
        self,
        server_address: tuple[str, int],
        handler_class: type[BaseHTTPRequestHandler],
        *,
        app: AppServer,
        session_token: str,
    ) -> None:
        self.app = app
        self.session_token = session_token
        super().__init__(server_address, handler_class)


class _AppRequestHandler(BaseHTTPRequestHandler):
    """JSON API plus the static app shell. Behavior mirrors the CLI core."""

    server_version = "habitable"
    sys_version = ""

    @property
    def _server(self) -> AppHTTPServer:
        # socketserver sets ``self.server`` to the server instance that owns this
        # handler; for this server that is always an AppHTTPServer.
        return cast(AppHTTPServer, self.server)

    @property
    def _app(self) -> AppServer:
        return self._server.app

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def do_GET(self) -> None:
        self._status = 200
        start = time.monotonic()
        try:
            if not self._request_allowed():
                return
            if self.path.startswith("/api/"):
                if not self._authorized():
                    return
                if self.path == "/api/status":
                    app = self._app
                    self._guarded(lambda: app.status())
                    return
                self._json(404, {"error": "not found"})
                return
            self._serve_static(self.path)
        finally:
            self._access_log("GET", start)

    def do_POST(self) -> None:
        self._status = 200
        start = time.monotonic()
        try:
            if not self._request_allowed():
                return
            if not self._authorized():
                return
            body = self._read_json()
            if body is None:
                return
            app = self._app
            timeline = _TIMELINE_RE.match(self.path)
            if timeline is not None:
                self._guarded(lambda: app.add_timeline(timeline.group(1), body))
                return
            route = _POST_ROUTES.get(self.path)
            if route is None:
                self._json(404, {"error": "not found"})
                return
            self._guarded(lambda: route(app, body))
        finally:
            self._access_log("POST", start)

    def do_OPTIONS(self) -> None:
        """Refuse CORS preflights; the unlocked API is same-origin only."""
        self._status = 200
        start = time.monotonic()
        try:
            if not self._request_allowed():
                return
            self._json(405, {"error": "method not allowed"})
        finally:
            self._access_log("OPTIONS", start)

    # --- auth -------------------------------------------------------------

    def _request_allowed(self) -> bool:
        """Reject DNS-rebinding hosts and browser requests from another origin.

        Non-browser API clients may omit ``Origin``, but every request must carry
        exactly one loopback ``Host`` header for this server's bound port. When a
        browser supplies ``Origin``, it must exactly match that authority. No CORS
        response headers are emitted, so cross-origin script access stays closed.
        """
        hosts = self.headers.get_all("Host", [])
        if len(hosts) != 1:
            self._json(403, {"error": "forbidden request origin"})
            return False
        authority = _host_authority(hosts[0])
        bound_port = int(self._server.server_address[1])
        if authority is None or not _is_loopback_host(authority[0]) or authority[1] != bound_port:
            self._json(403, {"error": "forbidden request origin"})
            return False

        origins = self.headers.get_all("Origin", [])
        if not origins:
            return True
        if len(origins) != 1 or _origin_authority(origins[0]) != authority:
            self._json(403, {"error": "forbidden request origin"})
            return False
        return True

    def _authorized(self) -> bool:
        """Require the per-session token on API calls; 401 (constant-time) otherwise.

        Accepts ``X-Habitable-Token: <token>`` or ``Authorization: Bearer <token>``.
        The token travels in a header (never a query string) so it is not leaked via
        request logs or the ``Referer`` header. The static shell is served without a
        token so the app can load and read the token from the opaque URL fragment.
        """
        token_headers = self.headers.get_all("X-Habitable-Token", [])
        auth_headers = self.headers.get_all("Authorization", [])
        presented = ""
        if len(token_headers) == 1 and not auth_headers:
            presented = token_headers[0]
        elif len(auth_headers) == 1 and not token_headers:
            scheme, separator, candidate = auth_headers[0].partition(" ")
            if separator and scheme.casefold() == "bearer":
                presented = candidate
        # Compare as bytes: ``hmac.compare_digest`` raises TypeError on non-ASCII
        # *str* input, and header values are attacker-controlled (latin-1 decoded),
        # so a str comparison would turn a garbage token into an unhandled
        # exception in the handler thread instead of this clean 401.
        expected = self._server.session_token.encode("utf-8")
        if presented and hmac.compare_digest(presented.encode("utf-8"), expected):
            return True
        self._json(401, {"error": "unauthorized: missing or invalid session token"})
        return False

    # --- helpers ----------------------------------------------------------

    def _access_log(self, method: str, start: float) -> None:
        # Metadata-only, redacted request line (no-op unless logging is opted in):
        # method, redacted route, status, latency — never a body or query value.
        log_event(
            "request",
            method=method,
            path=_route_label(self.path),
            status=self._status,
            latency_ms=round((time.monotonic() - start) * 1000, 3),
        )

    def _guarded(self, action: Callable[[], dict[str, object]]) -> None:
        try:
            with self._app.lock:
                payload = action()
        except HabitableError as exc:
            self._json(400, {"error": str(exc)})
            return
        except Exception:  # defensive: never leak exception details to the UI
            self._json(500, {"error": "internal error"})
            return
        self._json(200, payload)

    def _read_json(self) -> dict[str, object] | None:
        lengths = self.headers.get_all("Content-Length", [])
        if self.headers.get_all("Transfer-Encoding", []) or len(lengths) != 1:
            self._json(400, {"error": "invalid request framing"})
            return None
        try:
            length = int(lengths[0])
        except ValueError:
            self._json(400, {"error": "invalid request framing"})
            return None
        if length <= 0 or length > _MAX_BODY:
            self._json(413, {"error": "bad or oversized body"})
            return None
        try:
            parsed = json.loads(self.rfile.read(length))
        except json.JSONDecodeError:
            self._json(400, {"error": "invalid JSON"})
            return None
        if not isinstance(parsed, dict):
            self._json(400, {"error": "expected a JSON object"})
            return None
        return parsed

    def _serve_static(self, path: str) -> None:
        static_root = self._app.static_root
        rel = "index.html" if path in ("/", "") else path.lstrip("/")
        if not _SAFE_PATH.match(rel) or ".." in rel:
            self._json(404, {"error": "not found"})
            return
        target = (static_root / rel).resolve()
        if not str(target).startswith(str(static_root.resolve())) or not target.is_file():
            self._json(404, {"error": "not found"})
            return
        body = target.read_bytes()
        content_type = _CONTENT_TYPES.get(target.suffix, "application/octet-stream")
        self._status = 200
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self._send_security_headers()
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, payload: dict[str, object]) -> None:
        self._status = code
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self._send_security_headers()
        self.end_headers()
        self.wfile.write(body)

    def _send_security_headers(self) -> None:
        self.send_header("Content-Security-Policy", _CONTENT_SECURITY_POLICY)
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")


def make_app_server(
    host: str,
    port: int,
    vault: Vault,
    *,
    tsa: TimestampAuthority | None = None,
    extra_tsas: Sequence[TimestampAuthority] = (),
    static_root: Path | None = None,
) -> AppHTTPServer:
    """Build (but do not start) the loopback app server.

    A fresh per-session bearer token is generated and required on every ``/api/*``
    request. The static shell (HTML/CSS/JS) is served without
    it so the app can load, then read the token from the opaque URL fragment and
    present it as a header. Read it back from the returned server's
    ``session_token``.

    ``extra_tsas`` are the case's redundant timestamp authorities (every
    authority beyond the primary, as ``cli._extra_tsas_for`` derives them from
    ``config.timestamp_authorities[1:]``); the ``/api/resolve`` endpoint stamps
    each queued capture against them so deferred captures get the same
    multiple-authority proof as online ones (item R-16).
    """
    if not _is_loopback_host(host):
        raise HabitableError(
            "the unlocked app may only bind to loopback (localhost or 127.0.0.1); "
            "LAN access is not a supported phone-install path"
        )

    # Honor HABITABLE_LOG=json even when not launched via the CLI flag (e.g. a direct
    # embedder). If the CLI already configured logging, this is a no-op.
    if enabled_from_env() and not is_configured():
        configure_logging()

    session_token = secrets.token_urlsafe(32)
    app = AppServer(
        vault=vault,
        tsa=tsa,
        static_root=static_root or _STATIC_ROOT,
        lock=threading.Lock(),
        extra_tsas=tuple(extra_tsas),
    )
    return AppHTTPServer((host, port), _AppRequestHandler, app=app, session_token=session_token)


def _remove_legacy_incoming(vault_path: Path) -> None:
    """Delete the reserved pre-fix upload workspace without following a symlink."""
    legacy = vault_path / "_incoming"
    try:
        try:
            mode = legacy.lstat().st_mode
        except FileNotFoundError:
            return
        if stat.S_ISDIR(mode):
            shutil.rmtree(legacy)
        else:
            legacy.unlink()
    except OSError as exc:
        raise HabitableError(
            "could not remove the legacy plaintext upload staging directory; "
            "close other processes and remove the vault's _incoming path before opening the app"
        ) from exc


def _is_loopback_host(host: str) -> bool:
    """Accept only the loopback forms this IPv4 HTTP server supports."""
    return host.casefold() in {"localhost", "127.0.0.1"}


def _host_authority(value: str) -> tuple[str, int] | None:
    """Parse an HTTP Host header into a normalized ``(host, port)`` pair."""
    try:
        parsed = urlsplit(f"//{value}")
        port = parsed.port
    except ValueError:
        return None
    if (
        parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        return None
    return parsed.hostname.casefold(), 80 if port is None else port


def _origin_authority(value: str) -> tuple[str, int] | None:
    """Parse a serialized browser Origin, accepting plain HTTP loopback only."""
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme.casefold() != "http"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        return None
    return parsed.hostname.casefold(), 80 if port is None else port


# --- request helpers ----------------------------------------------------------


def _req_str(body: dict[str, object], key: str) -> str:
    value = body.get(key)
    if not isinstance(value, str) or not value:
        raise HabitableError(f"missing required field: {key}")
    return value


def _opt_str(body: dict[str, object], key: str) -> str:
    value = body.get(key, "")
    return value if isinstance(value, str) else ""


def _opt_bool(body: dict[str, object], key: str) -> bool:
    return bool(body.get(key, False))


def _opt_str_tuple(body: dict[str, object], key: str) -> tuple[str, ...]:
    value = body.get(key, [])
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise HabitableError(f"field {key} must be an array of strings")
    return tuple(value)
