# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Fail when repository Markdown links or capability evidence paths drift.

This checker is intentionally standard-library only so the documentation truth gate
can run before project dependencies are installed and can be reused by downstream
packagers. It validates relative Markdown links against the file containing them,
ignores URLs and in-page anchors, and requires every row in the capability ledger to
name at least one local evidence file.
"""

from __future__ import annotations

import argparse
import re
import urllib.parse
from collections.abc import Iterable
from pathlib import Path

_INLINE_LINK = re.compile(r"!?\[[^\]\n]*\]\(\s*(<[^>\n]+>|[^\s)]+)")
_REFERENCE_LINK = re.compile(r"^\s*\[[^\]\n]+\]:\s*(<[^>\n]+>|\S+)")
_FENCE = re.compile(r"^\s*(`{3,}|~{3,})")
_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
_LEDGER_STATUSES = {"Shipped", "Partial", "Planned", "Externally unvalidated"}
_SKIP_PARTS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "build",
    "dist",
    "htmlcov",
    "node_modules",
}


def _markdown_targets(text: str) -> Iterable[tuple[int, str]]:
    """Yield ``(line number, target)`` outside fenced code blocks."""
    open_fence = ""
    for line_number, line in enumerate(text.splitlines(), 1):
        fence = _FENCE.match(line)
        if fence is not None:
            marker = fence.group(1)
            if not open_fence:
                open_fence = marker
            elif marker[0] == open_fence[0] and len(marker) >= len(open_fence):
                open_fence = ""
            continue
        if open_fence:
            continue

        for match in _INLINE_LINK.finditer(line):
            yield line_number, match.group(1)
        reference = _REFERENCE_LINK.match(line)
        if reference is not None:
            yield line_number, reference.group(1)


def _local_path(target: str) -> str | None:
    cleaned = target.strip()
    if cleaned.startswith("<") and cleaned.endswith(">"):
        cleaned = cleaned[1:-1]
    if not cleaned or cleaned.startswith("#") or cleaned.startswith("//"):
        return None
    if _SCHEME.match(cleaned):
        return None
    path = urllib.parse.unquote(cleaned.split("#", 1)[0].split("?", 1)[0])
    return path or None


def _markdown_files(root: Path) -> list[Path]:
    return sorted(
        path
        for path in root.rglob("*.md")
        if not any(part in _SKIP_PARTS for part in path.relative_to(root).parts)
    )


def _check_relative_links(root: Path, markdown_files: list[Path]) -> list[str]:
    problems: list[str] = []
    for markdown in markdown_files:
        relative = markdown.relative_to(root)
        for line_number, target in _markdown_targets(markdown.read_text(encoding="utf-8")):
            local = _local_path(target)
            if local is None:
                continue
            if local.startswith("/"):
                problems.append(
                    f"{relative}:{line_number}: root-relative link is not a "
                    f"repository file: {target}"
                )
                continue
            destination = (markdown.parent / local).resolve()
            try:
                destination.relative_to(root)
            except ValueError:
                problems.append(f"{relative}:{line_number}: link escapes repository: {target}")
                continue
            if not destination.exists():
                problems.append(f"{relative}:{line_number}: missing relative link target: {target}")
    return problems


def _check_capability_ledger(root: Path) -> tuple[list[str], int]:
    ledger = root / "docs" / "capabilities.md"
    if not ledger.is_file():
        return ["docs/capabilities.md: capability ledger is missing"], 0

    problems: list[str] = []
    statuses: set[str] = set()
    rows = 0
    for line_number, line in enumerate(ledger.read_text(encoding="utf-8").splitlines(), 1):
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) != 5 or cells[1] not in _LEDGER_STATUSES:
            continue
        rows += 1
        statuses.add(cells[1])
        evidence_targets = [
            target
            for _line, target in _markdown_targets(cells[3])
            if _local_path(target) is not None
        ]
        if not evidence_targets:
            problems.append(
                f"docs/capabilities.md:{line_number}: capability row has no local evidence path"
            )

    if rows == 0:
        problems.append("docs/capabilities.md: no capability rows found")
    missing_statuses = sorted(_LEDGER_STATUSES - statuses)
    if missing_statuses:
        problems.append(
            "docs/capabilities.md: ledger does not distinguish status(es): "
            + ", ".join(missing_statuses)
        )
    return problems, rows


def check_repository(root: Path) -> tuple[list[str], int, int]:
    resolved = root.resolve()
    markdown_files = _markdown_files(resolved)
    problems = _check_relative_links(resolved, markdown_files)
    ledger_problems, ledger_rows = _check_capability_ledger(resolved)
    problems.extend(ledger_problems)
    return sorted(problems), len(markdown_files), ledger_rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="repository root (defaults to the parent of scripts/)",
    )
    args = parser.parse_args()
    problems, markdown_count, ledger_rows = check_repository(args.root)
    if problems:
        print("documentation link gate failed:")
        for problem in problems:
            print(f"- {problem}")
        return 1
    print(
        f"documentation links: OK — {markdown_count} Markdown files; "
        f"{ledger_rows} capability rows carry local evidence"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
