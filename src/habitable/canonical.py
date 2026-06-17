# SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0
# Copyright 2026 Chelsea Kelly-Reif
"""Canonical serialization and hashing primitives.

Tamper-evidence and independent verification both require that the *same* logical
content always produces the *same* bytes, on any machine, forever. Every hash in
habitable is taken over :func:`canonical_json` output (UTF-8, sorted keys, no
insignificant whitespace), and content fixity uses streaming SHA-256.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

__all__ = [
    "HASH_ALGORITHM",
    "JSONValue",
    "canonical_json",
    "sha256_bytes",
    "sha256_file",
]

HASH_ALGORITHM = "sha256"
_CHUNK = 1024 * 1024

# A JSON-compatible value. Recursive alias (PEP 695) so nested structures are typed.
type JSONValue = str | int | float | bool | None | list[JSONValue] | dict[str, JSONValue]


def canonical_json(value: JSONValue) -> bytes:
    """Deterministically serialize ``value`` to bytes for hashing/signing.

    Keys are sorted and separators are tight, so the encoding is stable across
    Python versions and platforms — a prerequisite for reproducible verification.
    """
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    """Hex SHA-256 of ``data``."""
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    """Streaming hex SHA-256 of a file, without loading it all into memory."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()
