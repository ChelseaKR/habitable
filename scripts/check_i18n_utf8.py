#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""G1 — UTF-8 encoding gate (INTERNATIONALIZATION-STANDARD §4).

Every tracked *text* file must be UTF-8 (US-ASCII is a UTF-8 subset, so it
passes). A file that is not valid UTF-8 silently corrupts non-English strings —
accented Spanish characters, Haitian-Creole diacritics — so this is wired into
``make verify`` as a blocking merge gate.

The standard's reference measurement is
``git ls-files -z | xargs -0 file --mime-encoding`` asserting ``utf-8``/
``us-ascii``. We implement the same assertion in pure Python for three reasons:
it stays dependency-light and offline like the sibling parity gate, it needs no
``file(1)`` binary on the runner, and it avoids ``file``'s well-known
``unknown-8bit`` false positive on PDFs (which are binary but begin with ASCII).

Binary blobs (images, the sample PDF, wheels) are not text and are skipped by
two signals: a known binary file extension, or — git's own heuristic — a NUL
byte in the blob. (The sample PDF happens to carry no NUL byte yet is plainly
binary, which is also why the standard's raw ``file`` command misreports it as
``unknown-8bit``; the extension skip handles it.) Everything else is asserted to
decode as UTF-8 — which is exactly "utf-8 or us-ascii".

Exit codes:
    0  every tracked text file is valid UTF-8.
    1  one or more tracked text files are not valid UTF-8.
    2  operator error (not a git work tree / cannot list files).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
# A NUL byte marks a blob as binary (git's own text/binary heuristic).
_NUL = b"\x00"
# Known-binary file extensions: skipped outright. Some binaries (e.g. this repo's
# sample PDF) carry no NUL byte, so extension is the reliable signal for them.
_BINARY_SUFFIXES = frozenset(
    {
        ".pdf", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".icns",
        ".woff", ".woff2", ".ttf", ".otf", ".eot", ".wasm", ".mp3", ".mp4", ".mov",
        ".avi", ".webm", ".ogg", ".whl", ".tar", ".gz", ".tgz", ".zip", ".bz2",
        ".xz", ".7z", ".pyc", ".pyo", ".so", ".dylib", ".dll", ".exe", ".bin",
    }
)


def _tracked_files() -> list[Path]:
    """Return every git-tracked path, NUL-delimited so odd names are safe."""
    try:
        out = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=_REPO_ROOT,
            capture_output=True,
            check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"error: could not list tracked files via git: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
    return [_REPO_ROOT / name for name in out.decode("utf-8").split("\0") if name]


def check_utf8() -> int:
    """Return 0 if every tracked text file is valid UTF-8, else 1."""
    bad: list[str] = []
    checked = 0
    for path in _tracked_files():
        if path.suffix.lower() in _BINARY_SUFFIXES:
            continue  # known binary asset — not a text file
        try:
            data = path.read_bytes()
        except (OSError, FileNotFoundError):
            # A tracked-but-absent path (e.g. a submodule gitlink) is not text.
            continue
        if _NUL in data:
            continue  # binary blob (image, wheel) — not a text file
        checked += 1
        try:
            data.decode("utf-8")
        except UnicodeDecodeError as exc:
            rel = path.relative_to(_REPO_ROOT)
            bad.append(f"{rel}: {exc}")

    if bad:
        print(f"FAIL: {len(bad)} tracked text file(s) are not valid UTF-8:")
        for line in sorted(bad):
            print(f"  - {line}")
        print("\nG1 UTF-8 gate: FAILED — re-save the file(s) above as UTF-8.")
        return 1

    print(f"G1 UTF-8 gate: OK — {checked} tracked text files, all valid UTF-8.")
    return 0


def main() -> int:
    return check_utf8()


if __name__ == "__main__":
    raise SystemExit(main())
