# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""The documentation truth gate itself is regression-tested."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CHECKER = _ROOT / "scripts" / "check_doc_links.py"


def _current_export_claim_paths() -> list[Path]:
    paths = [_ROOT / "README.md", _ROOT / "CHANGELOG.md"]
    for directory, patterns in (
        (_ROOT / "docs", ("*.md", "*.json")),
        (_ROOT / "site", ("*.html",)),
        (_ROOT / "app" / "i18n", ("*.json",)),
        (_ROOT / "src" / "habitable", ("*.py",)),
    ):
        for pattern in patterns:
            paths.extend(directory.rglob(pattern))
    return sorted(paths)


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


def test_current_export_claims_are_scope_and_disclosure_safe() -> None:
    stale_claims = (
        "selective exports",
        "selective export controls",
        "selected captures",
        "selected images",
        "chosen subset of issues",
        "use the minimum scope",
        "assembled for an issue or a unit",
        "media for the in-scope issue(s)",
        "capture deliberately omitted by export scope",
        "only as **shared copies with location stripped**",
        "without the packet ever disclosing",
        "must never leak through a shared copy",
        "shared copies will strip it",
        "location is stripped from anything shared",
        "a home's gps location is stripped from anything shared",
        "any shared or exported copy strips",
        "shared/exported copies strip",
        "without ever seeing the location",
        "shared copy must have its location and metadata stripped",
        "custody actor stored only as a salted commitment",
        "custody actor exported only as nothing",
        "user is shown what a packet discloses before it is produced",
    )
    offenders: list[str] = []
    for path in _current_export_claim_paths():
        content = path.read_text(encoding="utf-8").casefold()
        relative = path.relative_to(_ROOT)
        offenders.extend(f"{relative}: {claim}" for claim in stale_claims if claim in content)
    assert not offenders, "stale scoped-export claim(s): " + "; ".join(offenders)

    how_it_works = (_ROOT / "site/how-it-works/index.html").read_text(encoding="utf-8")
    assert "Current packets include every issue, timeline entry, and capture" in how_it_works
    assert "Embedding sealed originals is optional" in how_it_works
    boundary = (_ROOT / "docs/legal/minimal-disclosure.md").read_text(encoding="utf-8")
    normalized_boundary = " ".join(boundary.split()).casefold()
    assert "whole unit only" in normalized_boundary
    assert "optional withholding of originals" in normalized_boundary
    capabilities = (_ROOT / "docs/capabilities.md").read_text(encoding="utf-8").casefold()
    assert "custody identities are omitted" in capabilities
    assert "retained compatibility setting is rejected before output" in capabilities
    privacy = " ".join((_ROOT / "docs/privacy.md").read_text(encoding="utf-8").split()).casefold()
    assert "retains the salted actor commitment" in privacy
    assert "sync and organizer sharing transfer sealed originals" in privacy
    mobile = (_ROOT / "docs/mobile.md").read_text(encoding="utf-8").casefold()
    assert "three media-sized copies" in mobile


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
