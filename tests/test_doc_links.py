# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""The documentation truth gate itself is regression-tested."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CHECKER = _ROOT / "scripts" / "check_doc_links.py"


def _run(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(_CHECKER), "--root", str(root)],
        capture_output=True,
        check=False,
        text=True,
    )


def _ledger(*, evidence: str = "[README](../README.md)") -> str:
    rows = "\n".join(
        f"| example {number} | {status} | true | {evidence} | gap |"
        for number, status in enumerate(
            ("Shipped", "Partial", "Planned", "Externally unvalidated"), 1
        )
    )
    return (
        "| Capability | Status | Current claim | Evidence | Explicit gap |\n"
        "| --- | --- | --- | --- | --- |\n"
        f"{rows}\n"
    )


def test_repository_documentation_links_and_ledger_are_current() -> None:
    result = _run(_ROOT)
    assert result.returncode == 0, result.stdout + result.stderr


def test_checker_rejects_a_broken_relative_link(tmp_path: Path) -> None:
    (tmp_path / "docs").mkdir()
    (tmp_path / "README.md").write_text("[missing](docs/not-there.md)\n", encoding="utf-8")
    (tmp_path / "docs" / "capabilities.md").write_text(_ledger(), encoding="utf-8")

    result = _run(tmp_path)
    assert result.returncode == 1
    assert "README.md:1: missing relative link target: docs/not-there.md" in result.stdout


def test_checker_requires_ledger_statuses_and_local_evidence(tmp_path: Path) -> None:
    (tmp_path / "docs").mkdir()
    (tmp_path / "README.md").write_text("# fixture\n", encoding="utf-8")
    (tmp_path / "docs" / "capabilities.md").write_text(
        "| Capability | Status | Current claim | Evidence | Explicit gap |\n"
        "| --- | --- | --- | --- | --- |\n"
        "| example | Shipped | true | none | gap |\n",
        encoding="utf-8",
    )

    result = _run(tmp_path)
    assert result.returncode == 1
    assert "capability row has no local evidence path" in result.stdout
    assert "does not distinguish status(es)" in result.stdout


def test_checker_rejects_a_missing_ledger_evidence_target(tmp_path: Path) -> None:
    (tmp_path / "docs").mkdir()
    (tmp_path / "README.md").write_text("# fixture\n", encoding="utf-8")
    (tmp_path / "docs" / "capabilities.md").write_text(
        _ledger(evidence="[missing evidence](../tests/not-there.py)"), encoding="utf-8"
    )

    result = _run(tmp_path)
    assert result.returncode == 1
    assert "missing relative link target: ../tests/not-there.py" in result.stdout


def test_checker_ignores_urls_anchors_and_fenced_examples(tmp_path: Path) -> None:
    (tmp_path / "docs").mkdir()
    (tmp_path / "README.md").write_text(
        "[web](https://example.com/missing) [section](#missing)\n"
        "```markdown\n[example](docs/not-there.md)\n```\n",
        encoding="utf-8",
    )
    (tmp_path / "docs" / "capabilities.md").write_text(_ledger(), encoding="utf-8")

    result = _run(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
