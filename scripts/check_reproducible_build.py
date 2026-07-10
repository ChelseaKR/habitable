#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Verify a byte-identical rebuild of the wheel (and sdist).

Builds the package twice, from a clean copy of the tracked source tree, into
separate directories with a normalized environment (fixed ``SOURCE_DATE_EPOCH``
derived from the last commit, fixed ``PYTHONHASHSEED``, no build-time caches
carried across the two runs), then compares the resulting artifacts byte for
byte. If they differ, this prints which artifact and which files inside it
differ so the mismatch is debuggable, and exits non-zero.

On success, the artifacts from the first build are copied into ``--out-dir``
(default ``dist/``) so this doubles as the normal build step in CI.

Usage:
    uv run python scripts/check_reproducible_build.py [--out-dir dist]

Rationale: ROADMAP.md workstream A ("Reproducible builds") — the same source
must yield the same artifacts, so a downloader (or this project) can confirm a
release wasn't built from something other than the tagged, public source.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def _git_source_date_epoch() -> str:
    """The last commit's timestamp — deterministic and independent of clock/CI."""
    result = subprocess.run(
        ["git", "log", "-1", "--format=%ct"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _clean_source_copy(dest: Path) -> None:
    """Copy only the git-tracked source tree, so stray local files (dist/,
    caches, editor droppings) can never affect the comparison."""
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
    )
    files = [f for f in result.stdout.split(b"\0") if f]
    for raw in files:
        rel = Path(raw.decode())
        src = REPO_ROOT / rel
        if not src.is_file():
            continue
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, target)


def _build(source_dir: Path, out_dir: Path, epoch: str) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    env = {
        **os.environ,
        "SOURCE_DATE_EPOCH": epoch,
        "PYTHONHASHSEED": "0",
    }
    # Carry through whatever locates `uv`'s own cache/toolchain deterministically;
    # a fresh --no-cache build keeps the two runs from sharing mutable state.
    subprocess.run(
        ["uv", "build", "--no-cache", "--out-dir", str(out_dir)],
        cwd=source_dir,
        check=True,
        env=env,
    )
    # `uv build` also drops a dist/.gitignore; only the built artifacts matter here.
    return sorted(p for p in out_dir.glob("*") if p.suffix in {".whl", ".gz"})


def _wheel_member_hashes(wheel: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    with zipfile.ZipFile(wheel) as zf:
        for info in sorted(zf.infolist(), key=lambda i: i.filename):
            hashes[info.filename] = hashlib.sha256(zf.read(info.filename)).hexdigest()
    return hashes


def _report_mismatch(name: str, a: Path, b: Path) -> None:
    print(f"  MISMATCH: {name}", file=sys.stderr)
    if name.endswith(".whl"):
        hashes_a = _wheel_member_hashes(a)
        hashes_b = _wheel_member_hashes(b)
        only_a = sorted(set(hashes_a) - set(hashes_b))
        only_b = sorted(set(hashes_b) - set(hashes_a))
        differing = sorted(n for n in set(hashes_a) & set(hashes_b) if hashes_a[n] != hashes_b[n])
        for n in only_a:
            print(f"    only in build 1: {n}", file=sys.stderr)
        for n in only_b:
            print(f"    only in build 2: {n}", file=sys.stderr)
        for n in differing:
            print(f"    content differs: {n}", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=REPO_ROOT / "dist",
        help="where to place the verified artifacts on success (default: dist/)",
    )
    args = parser.parse_args()

    epoch = _git_source_date_epoch()
    print(f"habitable: verifying a reproducible build (SOURCE_DATE_EPOCH={epoch})")

    with tempfile.TemporaryDirectory(prefix="habitable-repro-") as tmp:
        tmp_path = Path(tmp)
        source_1 = tmp_path / "src-1"
        source_2 = tmp_path / "src-2"
        out_1 = tmp_path / "out-1"
        out_2 = tmp_path / "out-2"
        _clean_source_copy(source_1)
        _clean_source_copy(source_2)

        print("  building #1...")
        artifacts_1 = _build(source_1, out_1, epoch)
        print("  building #2...")
        artifacts_2 = _build(source_2, out_2, epoch)

        names_1 = {p.name for p in artifacts_1}
        names_2 = {p.name for p in artifacts_2}
        if names_1 != names_2:
            print(
                f"FAIL: build produced different artifact sets: {names_1} vs {names_2}",
                file=sys.stderr,
            )
            return 1

        ok = True
        for name in sorted(names_1):
            a = out_1 / name
            b = out_2 / name
            if _sha256(a) != _sha256(b):
                ok = False
                _report_mismatch(name, a, b)
            else:
                print(f"  OK: {name} is byte-identical ({_sha256(a)[:12]}...)")

        if not ok:
            print("FAIL: build is not reproducible", file=sys.stderr)
            return 1

        args.out_dir.mkdir(parents=True, exist_ok=True)
        for name in sorted(names_1):
            shutil.copy2(out_1 / name, args.out_dir / name)

    print(f"habitable: reproducible build verified; artifacts in {args.out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
