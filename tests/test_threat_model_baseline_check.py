# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""The threat-model baseline gate: immutability fails, drift only reports (issue #366)."""

from __future__ import annotations

import hashlib
import importlib.util
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_SCRIPT = _ROOT / "scripts" / "check_threat_model_baseline.py"

_TAG = "threat-model-baseline-B1"
_FROZEN = "line one\nline two\nline three\n"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_threat_model_baseline", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gate = _load()


def _git(root: Path, *args: str) -> None:
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "tag.gpgsign=false",
            "-C",
            str(root),
            *args,
        ],
        check=True,
        capture_output=True,
    )


def _audit_text(sha: str, *, tag: str = _TAG) -> str:
    return (
        "# Threat-model baseline\n\n"
        "## Baseline B1\n\n"
        "| Field | Value |\n| --- | --- |\n"
        "| Baseline id | **B1** |\n"
        "| Frozen document | [`docs/threat-model.md`](../threat-model.md) |\n"
        f"| Document SHA-256 | `{sha}` |\n"
        f"| Git tag | `{tag}` (annotated) |\n\n"
        '## What "frozen" means\n\nImmutable.\n'
    )


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A throwaway repository with the model frozen and tagged at ``_FROZEN``."""
    _git(tmp_path, "init", "-q")
    (tmp_path / "docs" / "audits").mkdir(parents=True)
    (tmp_path / "docs" / "threat-model.md").write_text(_FROZEN)
    (tmp_path / "docs" / "audits" / "threat-model-baseline.md").write_text(
        _audit_text(_sha(_FROZEN))
    )
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-q", "-m", "freeze")
    _git(tmp_path, "tag", "-a", _TAG, "-m", "B1")
    return tmp_path


def _run(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(_SCRIPT), "--root", str(root)],
        capture_output=True,
        check=False,
        text=True,
    )


def test_the_real_audit_file_pins_a_hash_and_tag_for_b1() -> None:
    """The parser reads the file this gate guards; the tag itself is checked by the CI job."""
    text = (_ROOT / gate.BASELINE_FILE).read_text(encoding="utf-8")
    baselines = gate.parse_baselines(text)
    assert baselines[0].baseline_id == "B1"
    assert baselines[0].document == "docs/threat-model.md"
    assert baselines[0].tag == _TAG
    assert len(baselines[0].sha256) == 64


def test_a_file_with_no_baseline_section_is_an_error() -> None:
    with pytest.raises(gate.BaselineError):
        gate.parse_baselines("# nothing pinned here\n")


def test_a_section_missing_its_hash_is_an_error() -> None:
    with pytest.raises(gate.BaselineError, match="B1"):
        gate.parse_baselines("## Baseline B1\n\n| Git tag | `t` |\n")


def test_an_untouched_baseline_passes_with_no_drift(repo: Path) -> None:
    problems, drift = gate.check(repo)
    assert problems == []
    assert drift is None
    result = _run(repo)
    assert result.returncode == 0
    assert "DRIFT" not in result.stdout


def test_a_tagged_file_that_no_longer_matches_the_pin_fails(repo: Path) -> None:
    """Someone edited the pin (or moved the tag): the immutability B1 claims is gone."""
    audit = repo / "docs" / "audits" / "threat-model-baseline.md"
    audit.write_text(_audit_text(_sha("a different document\n")))
    problems, _ = gate.check(repo)
    assert len(problems) == 1
    assert "immutable" in problems[0]
    result = _run(repo)
    assert result.returncode == 1
    assert "baseline gate failed" in result.stdout


def test_a_moved_tag_fails(repo: Path) -> None:
    (repo / "docs" / "threat-model.md").write_text(_FROZEN + "added after the freeze\n")
    _git(repo, "commit", "-q", "-am", "edit")
    _git(repo, "tag", "-f", "-a", _TAG, "-m", "moved")
    problems, _ = gate.check(repo)
    assert len(problems) == 1
    assert _sha(_FROZEN + "added after the freeze\n") in problems[0]
    assert _run(repo).returncode == 1


def test_a_missing_tag_fails_rather_than_passing_unchecked(repo: Path) -> None:
    _git(repo, "tag", "-d", _TAG)
    problems, _ = gate.check(repo)
    assert len(problems) == 1
    assert "fetch-tags" in problems[0]
    assert _run(repo).returncode == 1


def test_drift_is_reported_with_commits_and_lines_but_does_not_fail(repo: Path) -> None:
    model = repo / "docs" / "threat-model.md"
    model.write_text(_FROZEN + "four\n")
    _git(repo, "commit", "-q", "-am", "one")
    model.write_text("line one\nline three\nfour\nfive\n")
    _git(repo, "commit", "-q", "-am", "two")

    problems, drift = gate.check(repo)
    assert problems == []
    assert drift is not None
    assert "baseline B1" in drift
    assert "2 commit(s)" in drift
    assert "2 lines added, 1 removed" in drift

    result = _run(repo)
    assert result.returncode == 0
    assert "DRIFT (report only)" in result.stdout
    assert "every pinned tag matches" in result.stdout


def test_uncommitted_edits_count_as_drift(repo: Path) -> None:
    (repo / "docs" / "threat-model.md").write_text(_FROZEN + "unsaved thought\n")
    _, drift = gate.check(repo)
    assert drift is not None
    assert "0 commit(s)" in drift
    assert "1 lines added, 0 removed" in drift


def test_github_actions_gets_a_warning_annotation(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (repo / "docs" / "threat-model.md").write_text(_FROZEN + "more\n")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    result = _run(repo)
    assert result.returncode == 0
    assert "::warning title=Threat model drift::" in result.stdout


def test_the_latest_baseline_is_the_one_drift_is_measured_against(repo: Path) -> None:
    """Appending B2 does not rewrite B1: both are checked, drift is reported against B2."""
    model = repo / "docs" / "threat-model.md"
    second = _FROZEN + "second baseline\n"
    model.write_text(second)
    _git(repo, "commit", "-q", "-am", "b2 text")
    _git(repo, "tag", "-a", "threat-model-baseline-B2", "-m", "B2")
    audit = repo / "docs" / "audits" / "threat-model-baseline.md"
    b2_section = (
        "## Baseline B2\n\n"
        "| Field | Value |\n| --- | --- |\n"
        "| Frozen document | [`docs/threat-model.md`](../threat-model.md) |\n"
        f"| Document SHA-256 | `{_sha(second)}` |\n"
        "| Git tag | `threat-model-baseline-B2` (annotated) |\n\n"
    )
    audit.write_text(
        audit.read_text().replace('## What "frozen" means', b2_section + '## What "frozen" means')
    )
    problems, drift = gate.check(repo)
    assert problems == []
    assert drift is None

    model.write_text(second + "after b2\n")
    problems, drift = gate.check(repo)
    assert problems == []
    assert drift is not None
    assert "baseline B2" in drift
