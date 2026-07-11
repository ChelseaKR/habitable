# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Restrictive, short-lived plaintext workspaces for path-based media tools.

Capture, Pillow, and ffmpeg consume filesystem paths. This module keeps the required
plaintext bridge out of the encrypted vault, uses random names and restrictive POSIX
modes, and removes the workspace on success or failure. Unlinking is not secure erasure:
filesystem snapshots, swap, crash remnants, and storage forensics remain endpoint risks.
"""

from __future__ import annotations

import os
import re
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path

__all__ = ["PrivateTempWorkspace", "private_temp_workspace"]

_SAFE_SUFFIX = re.compile(r"^\.[a-z0-9]{1,12}$")


@dataclass(frozen=True, slots=True)
class PrivateTempWorkspace:
    """A context-owned directory for random, owner-readable temporary files."""

    root: Path

    def write_bytes(self, payload: bytes, *, suffix: str = ".bin") -> Path:
        """Write ``payload`` to a random 0600 file, deleting partial writes on error."""
        normalized_suffix = suffix.casefold()
        if _SAFE_SUFFIX.fullmatch(normalized_suffix) is None:
            normalized_suffix = ".bin"

        descriptor, raw_path = tempfile.mkstemp(
            dir=self.root,
            prefix="item-",
            suffix=normalized_suffix,
        )
        path = Path(raw_path)
        try:
            if os.name == "posix":
                os.fchmod(descriptor, 0o600)
            remaining = memoryview(payload)
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    raise OSError("temporary plaintext write made no progress")
                remaining = remaining[written:]
            os.close(descriptor)
            descriptor = -1
        except BaseException:
            if descriptor >= 0:
                with suppress(OSError):
                    os.close(descriptor)
            path.unlink(missing_ok=True)
            raise
        return path


@contextmanager
def private_temp_workspace(
    *,
    forbidden_root: Path,
    base_dir: Path | None = None,
) -> Iterator[PrivateTempWorkspace]:
    """Yield a private temporary directory that is provably outside ``forbidden_root``.

    ``base_dir`` exists for embedders and deterministic fault-injection tests. The
    default is the operating system's temporary directory. If configuration would put
    the workspace inside the encrypted vault, fail before writing plaintext.
    """
    selected_base = base_dir if base_dir is not None else Path(tempfile.gettempdir())
    with tempfile.TemporaryDirectory(prefix="habitable-private-", dir=selected_base) as raw_root:
        root = Path(raw_root)
        if root.resolve().is_relative_to(forbidden_root.resolve()):
            raise OSError("private temporary workspace must be outside the vault")
        if os.name == "posix":
            root.chmod(0o700)
        yield PrivateTempWorkspace(root)
