# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Check the frozen threat-model baselines, and report drift from the latest one.

``docs/audits/threat-model-baseline.md`` pins a SHA-256 for each baseline (B1, ...) and names
the annotated git tag that marks its freeze commit. Two things follow from "immutable once
tagged", and this script treats them differently:

1. **Fails** when the frozen document, read from a baseline's tag, no longer hashes to the value
   pinned in the audit file. That is the immutability the baseline claims: the tag was moved or
   the pin was edited. It also fails when a pinned tag cannot be found, because a check that
   cannot read the tag has verified nothing (a shallow checkout must fetch tags).
2. **Reports, and does not fail,** when the current ``docs/threat-model.md`` differs from the
   latest baseline, naming the commits and lines changed since the freeze. Drift is expected
   between baselines; the point is that it stays visible until a new baseline is cut and
   re-reviewed by a person. This script never writes the pin or the threat model.

Standard library only, so it runs before project dependencies are installed.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

BASELINE_FILE = Path("docs/audits/threat-model-baseline.md")
_DEFAULT_DOCUMENT = "docs/threat-model.md"

_HEADING = re.compile(r"^## Baseline (B\d+)\s*$", re.MULTILINE)
_NEXT_HEADING = re.compile(r"^## ", re.MULTILINE)
_HASH_ROW = re.compile(r"^\|\s*Document SHA-256\s*\|\s*`([0-9a-f]{64})`\s*\|", re.MULTILINE)
_TAG_ROW = re.compile(r"^\|\s*Git tag\s*\|\s*`([^`\s]+)`", re.MULTILINE)
_DOC_ROW = re.compile(r"^\|\s*Frozen document\s*\|\s*\[`([^`\s]+)`\]", re.MULTILINE)


@dataclass(frozen=True)
class Baseline:
    """One pinned baseline as written in the audit file."""

    baseline_id: str
    document: str
    sha256: str
    tag: str


class BaselineError(Exception):
    """The audit file does not carry a readable pin."""


def parse_baselines(text: str) -> list[Baseline]:
    """Return the baselines in file order. Raises if a section is missing its hash or tag."""
    headings = list(_HEADING.finditer(text))
    if not headings:
        raise BaselineError("no '## Baseline B<n>' section found")
    baselines: list[Baseline] = []
    for heading in headings:
        start = heading.end()
        following = _NEXT_HEADING.search(text, start)
        section = text[start : following.start() if following else len(text)]
        digest = _HASH_ROW.search(section)
        tag = _TAG_ROW.search(section)
        if digest is None or tag is None:
            raise BaselineError(
                f"baseline {heading.group(1)} has no readable 'Document SHA-256' and 'Git tag' rows"
            )
        document = _DOC_ROW.search(section)
        baselines.append(
            Baseline(
                baseline_id=heading.group(1),
                document=document.group(1) if document else _DEFAULT_DOCUMENT,
                sha256=digest.group(1),
                tag=tag.group(1),
            )
        )
    return baselines


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    git = shutil.which("git")
    if git is None:
        raise BaselineError("git is not installed; the baseline tags cannot be read")
    return subprocess.run(  # noqa: S603 - resolved git path and constant arguments
        [git, "-C", str(root), *args], capture_output=True, check=False
    )


def _file_at_tag(root: Path, tag: str, document: str) -> bytes | None:
    result = _git(root, "show", f"refs/tags/{tag}:{document}")
    return result.stdout if result.returncode == 0 else None


def verify_immutable(root: Path, baselines: list[Baseline]) -> list[str]:
    """Return one problem per baseline whose tagged document no longer matches its pin."""
    problems: list[str] = []
    for baseline in baselines:
        frozen = _file_at_tag(root, baseline.tag, baseline.document)
        if frozen is None:
            problems.append(
                f"{baseline.baseline_id}: cannot read {baseline.document} at tag "
                f"{baseline.tag} (is the tag missing? a CI checkout needs "
                "fetch-depth: 0 and fetch-tags: true)"
            )
            continue
        actual = hashlib.sha256(frozen).hexdigest()
        if actual != baseline.sha256:
            problems.append(
                f"{baseline.baseline_id}: {baseline.document} at tag {baseline.tag} hashes to "
                f"{actual}, but the audit file pins {baseline.sha256}. A baseline is immutable "
                "once tagged; do not move the tag or edit the pin. Cut a new baseline instead."
            )
    return problems


def drift_report(root: Path, baseline: Baseline) -> str | None:
    """Describe how the working-tree document differs from ``baseline``, or ``None`` if it does not.

    Reports commits (touching the document, since the tag) and added/removed lines (tag against
    the working tree, so uncommitted edits count too). Report-only: callers must not fail on it.
    """
    path = root / baseline.document
    if not path.is_file():
        return f"{baseline.document} is missing; the latest baseline is {baseline.baseline_id}"
    if hashlib.sha256(path.read_bytes()).hexdigest() == baseline.sha256:
        return None

    commits = "an unknown number of"
    counted = _git(
        root, "rev-list", "--count", f"refs/tags/{baseline.tag}..HEAD", "--", baseline.document
    )
    if counted.returncode == 0:
        commits = counted.stdout.decode().strip()

    lines = "an unknown number of lines changed"
    numstat = _git(root, "diff", "--numstat", f"refs/tags/{baseline.tag}", "--", baseline.document)
    if numstat.returncode == 0 and numstat.stdout.strip():
        added, removed, *_ = numstat.stdout.decode().split()
        lines = f"{added} lines added, {removed} removed"

    return (
        f"{baseline.document} differs from baseline {baseline.baseline_id} "
        f"(tag {baseline.tag}): {commits} commit(s) since the freeze, {lines}. "
        "Report only: a maintainer re-review cuts the next baseline."
    )


def check(root: Path) -> tuple[list[str], str | None]:
    """Return ``(problems, drift)``. Only ``problems`` should fail a build."""
    audit = root / BASELINE_FILE
    try:
        baselines = parse_baselines(audit.read_text(encoding="utf-8"))
    except (OSError, BaselineError) as exc:
        return [f"{BASELINE_FILE}: {exc}"], None
    try:
        problems = verify_immutable(root, baselines)
        return problems, drift_report(root, baselines[-1])
    except BaselineError as exc:
        return [str(exc)], None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="repository root (defaults to the parent of scripts/)",
    )
    args = parser.parse_args()
    problems, drift = check(args.root)

    # GitHub renders ::warning:: as an annotation; on a terminal it reads as a plain line.
    on_actions = os.environ.get("GITHUB_ACTIONS") == "true"
    if drift is not None:
        prefix = "::warning title=Threat model drift::" if on_actions else "DRIFT (report only): "
        print(f"{prefix}{drift}")
    if problems:
        print("threat-model baseline gate failed:")
        for problem in problems:
            print(f"- {problem}")
        return 1
    print("threat-model baselines: every pinned tag matches its pinned hash")
    return 0


if __name__ == "__main__":
    sys.exit(main())
