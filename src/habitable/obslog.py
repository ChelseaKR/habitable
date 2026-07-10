# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Opt-in, on-device, metadata-only structured logging for the CLI and app server.

This mirrors the optional relay's logging discipline (see :mod:`habitable.relay`)
for the *local* surfaces — the ``habitable`` CLI and the loopback app server. It
exists so an operator debugging their own device can turn on a structured trace of
*what happened* (which command ran, how long it took, how many items were touched)
**without ever emitting the things that must never leave the device**: file
contents, filenames, passphrases, key material, case/room ids, or media bytes.

The guarantees, restated for this module:

- Logs are **structured JSON, one object per line**, through the stdlib ``logging``
  module (no structlog/OTel dependency — habitable stays dependency-light).
- Logging is **opt-in and off by default.** Nothing is written unless the operator
  passes ``--log-format json`` or sets ``HABITABLE_LOG=json``; :func:`log_event` is
  a silent no-op until :func:`configure_logging` installs a handler.
- The privacy gate is **absolute and metadata-only.** :func:`log_event` accepts
  only scalar metadata (counts, durations, booleans, event names, sha256 prefixes)
  and rejects anything else, so a dict, list, ``bytes`` blob, or dataclass carrying
  a payload can never be smuggled into the log stream. Callers are additionally
  disciplined to pass presence/counts rather than identifiers or paths.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import TextIO

__all__ = [
    "configure_logging",
    "enabled_from_env",
    "is_configured",
    "log_event",
    "reset_logging",
]

_LOGGER_NAME = "habitable"
_LOG = logging.getLogger(_LOGGER_NAME)

# The only value types allowed onto a log line. Bytes, dicts, lists, Paths and
# arbitrary objects are refused so a payload can never ride into the stream; strings
# are permitted for event names and sha256 prefixes, and callers keep the no-secrets
# discipline (never a filename, passphrase, case id, or key).
_SCALARS = (str, int, float, bool)


class _JsonFormatter(logging.Formatter):
    """Render each log record as one compact JSON object per line.

    Only the record message and an explicit, metadata-only ``event_fields`` map are
    serialized. There is deliberately no mechanism to smuggle file contents, keys, or
    exception payloads into the line — the formatter emits exactly what the caller
    hands it, which :func:`log_event` has already constrained to scalar metadata.
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
    """Install the JSON formatter on the ``habitable`` logger (idempotent).

    Pass a ``stream`` (e.g. an in-memory buffer) to capture output in tests; the
    default is ``sys.stderr`` so structured lines never contaminate command stdout.
    Returns the installed handler so callers can detach it again if they wish.
    """
    handler = logging.StreamHandler(stream if stream is not None else sys.stderr)
    handler.setFormatter(_JsonFormatter())
    _LOG.handlers.clear()
    _LOG.addHandler(handler)
    _LOG.setLevel(level)
    _LOG.propagate = False
    return handler


def reset_logging() -> None:
    """Detach any handler and restore the default (silent, unconfigured) state.

    Mainly for tests: after this, :func:`log_event` is a no-op again and no stale
    handler points at a closed capture buffer.
    """
    _LOG.handlers.clear()
    _LOG.propagate = True


def is_configured() -> bool:
    """True once :func:`configure_logging` has installed a handler (logging is on)."""
    return bool(_LOG.handlers)


def enabled_from_env(env: Mapping[str, str] | None = None) -> bool:
    """Whether ``HABITABLE_LOG`` opts logging in.

    Only the value ``json`` (case-insensitive, surrounding whitespace ignored)
    enables logging; unset or empty disables it, preserving the off-by-default
    contract that the local surfaces write nothing unless explicitly asked.
    """
    source = env if env is not None else os.environ
    return source.get("HABITABLE_LOG", "").strip().lower() == "json"


def log_event(msg: str, **fields: object) -> None:
    """Emit one structured, metadata-only event line — or nothing if logging is off.

    ``msg`` is a fixed event name (never interpolated user data). ``fields`` are
    scalar metadata only: counts, durations, booleans, event names, sha256 prefixes.
    A non-scalar value (``bytes``, ``dict``, ``list``, ``Path``, any object) raises
    :class:`TypeError` — the guard that stops a payload from ever reaching a log line.
    ``None`` values are dropped. When logging has not been configured this returns
    immediately, so instrumentation is free to call it unconditionally.
    """
    if not _LOG.handlers:  # not configured → silent no-op (off by default)
        return
    safe: dict[str, object] = {}
    for key, value in fields.items():
        if value is None:
            continue
        if not isinstance(value, _SCALARS):
            raise TypeError(
                f"log_event field {key!r} must be scalar metadata "
                f"(str/int/float/bool), not {type(value).__name__}"
            )
        safe[key] = value
    _LOG.info(msg, extra={"event_fields": safe})
