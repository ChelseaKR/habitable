# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Guards for release identity and exact-artifact promotion."""

from __future__ import annotations

import json
import re
from pathlib import Path

_WORKFLOW = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "release.yml"
_WORKFLOWS = Path(__file__).resolve().parent.parent / ".github" / "workflows"
_MAIN_RULESET = Path(__file__).resolve().parent.parent / ".github" / "rulesets" / "main-branch.json"
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
    ancestry = release.index('git merge-base --is-ancestor "$TAG_COMMIT" origin/main')
    checkout = release.index('git checkout --detach "$TAG_COMMIT"')
    head_guard = release.index('"$(git rev-parse HEAD)" != "$TAG_COMMIT"')
    version_guard = release.index('TAG_VERSION="${TAG#v}"')
    build = release.index("run: make repro")
    assert resolve < ancestry < checkout < head_guard < version_guard < build


def test_release_is_dispatched_from_current_trusted_main() -> None:
    release, _pypi = _workflow_sections()
    assert "push:\n    tags:" not in release
    assert "workflow_dispatch:" in release
    assert "ref: main" in release
    assert "fetch-depth: 0" in release
    assert 'test "${GITHUB_REF}" = refs/heads/main' in release
    assert 'test "$(git rev-parse HEAD)" = "${GITHUB_SHA}"' in release
    assert 'test "$(git rev-parse origin/main)" = "${GITHUB_SHA}"' in release
    assert 'git merge-base --is-ancestor "$TAG_COMMIT" origin/main' in release


def test_publication_rechecks_tag_without_checking_out_repository_code() -> None:
    release, pypi = _workflow_sections()
    verify, separator, publish = release.partition("  publish-release:\n")
    assert separator, "release workflow must retain a separate GitHub publish job"
    assert "contents: read" in verify
    assert "git verify-tag" in verify
    assert "tag_object_sha=" in verify
    assert "contents: write" in publish
    assert "git/ref/tags/${TAG}" in publish
    assert "--jq .object.sha" in publish
    assert 'test "${LIVE_TAG_OBJECT}" = "${TAG_OBJECT_SHA}"' in publish
    assert "gh release create" in publish
    assert "actions/checkout@" not in publish
    assert "needs: [verify-build, publish-release]" in pypi


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


def test_committed_main_ruleset_requires_prs_and_current_checks() -> None:
    ruleset = json.loads(_MAIN_RULESET.read_text(encoding="utf-8"))
    rules = {rule["type"]: rule for rule in ruleset["rules"]}
    assert ruleset["name"] == "protect-main"
    assert ruleset["target"] == "branch"
    assert ruleset["enforcement"] == "active"
    assert ruleset["conditions"]["ref_name"] == {
        "include": ["refs/heads/main"],
        "exclude": [],
    }
    required_rule_types = {"deletion", "non_fast_forward", "pull_request", "required_status_checks"}
    assert required_rule_types <= rules.keys()
    pull_request = rules["pull_request"]["parameters"]
    assert pull_request["required_approving_review_count"] == 0
    assert pull_request["require_code_owner_review"] is False
    assert pull_request["required_review_thread_resolution"] is True
    status_checks = rules["required_status_checks"]["parameters"]
    assert status_checks["strict_required_status_checks_policy"] is True
    assert status_checks["required_status_checks"]
    assert ruleset["bypass_actors"] == []
