# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Guards for release identity and exact-artifact promotion."""

from __future__ import annotations

import json
import re
from pathlib import Path

_WORKFLOW = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "release.yml"
_WORKFLOWS = Path(__file__).resolve().parent.parent / ".github" / "workflows"
_TAG_RULESET = Path(__file__).resolve().parent.parent / ".github" / "rulesets" / "release-tags.json"
_UPLOAD_ARTIFACT_V7_SHA = "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
_DOWNLOAD_ARTIFACT_V8_SHA = "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"


def _workflow_sections() -> tuple[str, str]:
    text = _WORKFLOW.read_text(encoding="utf-8")
    release, separator, pypi = text.partition("  pypi-publish:\n")
    assert separator, "release workflow must retain a separate PyPI publish job"
    return release, pypi


def test_release_checks_out_exact_tag_before_version_check_and_build() -> None:
    release, _pypi = _workflow_sections()
    resolve = release.index('git rev-parse --verify --end-of-options "${TAG}^{commit}"')
    ancestry = release.index('git merge-base --is-ancestor "$TAG_COMMIT" "$DEFAULT_REF"')
    checkout = release.index('git checkout --detach "$TAG_COMMIT"')
    head_guard = release.index('"$(git rev-parse HEAD)" != "$TAG_COMMIT"')
    version_guard = release.index('TAG_VERSION="${TAG#v}"')
    build = release.index("run: make repro")
    assert resolve < ancestry < checkout < head_guard < version_guard < build


def test_release_tag_must_belong_to_fetched_default_branch_history() -> None:
    release, _pypi = _workflow_sections()
    assert "fetch-depth: 0" in release
    assert "DEFAULT_BRANCH: ${{ github.event.repository.default_branch }}" in release
    assert 'DEFAULT_REF="refs/remotes/origin/$DEFAULT_BRANCH"' in release
    assert 'git show-ref --verify --quiet "$DEFAULT_REF"' in release
    assert 'git merge-base --is-ancestor "$TAG_COMMIT" "$DEFAULT_REF"' in release


def test_pypi_job_only_publishes_artifacts_from_release_job() -> None:
    release, pypi = _workflow_sections()
    assert "actions/upload-artifact@" in release
    assert "name: pypi-distributions" in release
    assert "actions/download-artifact@" in pypi
    assert "name: pypi-distributions" in pypi
    assert "pypa/gh-action-pypi-publish@" in pypi
    assert "actions/checkout@" not in pypi
    assert "uv build" not in pypi
    assert "setup-uv" not in pypi


def test_release_artifact_actions_are_pinned_to_full_commits() -> None:
    release, pypi = _workflow_sections()
    upload = re.search(r"actions/upload-artifact@([0-9a-f]{40})", release)
    download = re.search(r"actions/download-artifact@([0-9a-f]{40})", pypi)
    assert upload is not None
    assert download is not None


def test_artifact_actions_use_node24_releases() -> None:
    workflow_text = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted(_WORKFLOWS.glob("*.yml"))
    )
    upload_shas = re.findall(r"actions/upload-artifact@([0-9a-f]{40})", workflow_text)
    download_shas = re.findall(r"actions/download-artifact@([0-9a-f]{40})", workflow_text)
    assert upload_shas
    assert download_shas
    assert set(upload_shas) == {_UPLOAD_ARTIFACT_V7_SHA}
    assert set(download_shas) == {_DOWNLOAD_ARTIFACT_V8_SHA}


def test_committed_release_tag_ruleset_protects_v_tags() -> None:
    ruleset = json.loads(_TAG_RULESET.read_text(encoding="utf-8"))
    assert ruleset["name"] == "release tag protection (v*)"
    assert ruleset["target"] == "tag"
    assert ruleset["enforcement"] == "active"
    assert ruleset["conditions"]["ref_name"] == {
        "include": ["refs/tags/v*"],
        "exclude": [],
    }
    assert {rule["type"] for rule in ruleset["rules"]} == {
        "deletion",
        "update",
        "required_signatures",
    }
    assert ruleset["bypass_actors"] == []
