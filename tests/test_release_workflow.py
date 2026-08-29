# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Guards for release identity and exact-artifact promotion."""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any

_WORKFLOW = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "release.yml"
_WORKFLOWS = Path(__file__).resolve().parent.parent / ".github" / "workflows"
_MAIN_RULESET = Path(__file__).resolve().parent.parent / ".github" / "rulesets" / "main-branch.json"
_TAG_RULESET = Path(__file__).resolve().parent.parent / ".github" / "rulesets" / "release-tags.json"
_UPLOAD_ARTIFACT_V7_SHA = "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
_DOWNLOAD_ARTIFACT_V8_SHA = "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"

# The repository owner's standing bypass on the `main` branch ruleset, exactly as
# GitHub returns it for live ruleset 18752848. It is deliberate and permanent: an
# agent once applied a ruleset with no bypass and locked the owner out of their
# own repository, and restoring access took a sweep across eighteen repositories.
# An empty `bypass_actors` list on the branch ruleset is not a stricter gate — it
# is the lockout, and the checks below have to read it as a failure.
#
# The `v*` tag ruleset (18815834) is the opposite case and equally deliberate: it
# really does carry no bypass actor, so a released tag cannot be moved by anyone,
# owner included. The two are not to be harmonised in either direction.
OWNER_BYPASS = {"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}


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
    # Not `== []`. Until 2026-08-28 this asserted an empty list, and the file, the
    # ADR and the scorecard note that agreed with it were all wrong. Exactly one
    # actor, and it is the owner's own: a second bypass handed to a team, an app
    # or another role fails here, and so does the owner's going missing.
    assert ruleset["bypass_actors"] == [OWNER_BYPASS]


def bypass_findings(live: dict[str, Any], committed: dict[str, Any]) -> list[str]:
    """Every way a branch ruleset's bypass list is wrong, on each side separately.

    Deliberately not `live["bypass_actors"] == committed["bypass_actors"]`. If some
    future edit put an empty list back into the committed file on a day the owner
    had also been locked out of the repository, the two sides would agree and an
    equality check would report conformance on precisely the incident this exists
    to catch. So the owner's bypass is asserted against each side absolutely, and
    only *other* actors are compared between them.
    """
    findings: list[str] = []
    live_actors = list(live.get("bypass_actors") or [])
    committed_actors = list(committed.get("bypass_actors") or [])

    if OWNER_BYPASS not in live_actors:
        findings.append(
            "bypass_actors: the repository owner's standing bypass is NOT enforced on "
            "the live ruleset. An empty or owner-less list is the lockout, not a "
            "stricter gate."
        )
    if OWNER_BYPASS not in committed_actors:
        findings.append(
            ".github/rulesets/main-branch.json no longer records the owner's standing "
            "bypass. Re-applying the file as it stands would lock the owner out; "
            "restore it rather than re-applying."
        )

    other_live = [actor for actor in live_actors if actor != OWNER_BYPASS]
    other_committed = [actor for actor in committed_actors if actor != OWNER_BYPASS]
    for actor in other_live:
        if actor not in other_committed:
            findings.append(f"unreviewed bypass actor enforced and not committed: {actor}")
    for actor in other_committed:
        if actor not in other_live:
            findings.append(f"bypass actor committed and not enforced: {actor}")
    return findings


def _live_main_ruleset(**overrides: Any) -> dict[str, Any]:
    """Live ruleset 18752848 as `gh api` returns it, offline, plus overrides.

    Read 2026-08-28 from `gh api repos/ChelseaKR/habitable/rulesets/18752848`:
    `bypass_actors` is exactly `[OWNER_BYPASS]` and `current_user_can_bypass` is
    `"always"`. Reproduced here rather than fetched so the gate stays offline.
    """
    ruleset: dict[str, Any] = copy.deepcopy(json.loads(_MAIN_RULESET.read_text(encoding="utf-8")))
    ruleset["id"] = 18752848
    ruleset["bypass_actors"] = [dict(OWNER_BYPASS)]
    ruleset.update(overrides)
    return ruleset


def test_the_real_live_main_ruleset_conforms() -> None:
    """The configuration the repository is actually in must read as conformance.

    A check that fails forever against a correct repository is not a stricter
    check, it is a broken one — which is what the previous `== []` assertion was.
    """
    committed = json.loads(_MAIN_RULESET.read_text(encoding="utf-8"))
    assert bypass_findings(_live_main_ruleset(), committed) == []


def test_a_second_bypass_actor_is_reported() -> None:
    """The threat actually worth guarding: someone other than the owner handed
    the ability to skip the merge gate."""
    committed = json.loads(_MAIN_RULESET.read_text(encoding="utf-8"))
    for extra in (
        {"actor_id": 4242, "actor_type": "Team", "bypass_mode": "pull_request"},
        {"actor_id": 99, "actor_type": "Integration", "bypass_mode": "always"},
        {"actor_id": 2, "actor_type": "RepositoryRole", "bypass_mode": "always"},
    ):
        drifted = _live_main_ruleset(bypass_actors=[dict(OWNER_BYPASS), extra])
        found = bypass_findings(drifted, committed)
        assert len(found) == 1, found
        assert "unreviewed bypass actor" in found[0]


def test_the_owner_losing_their_live_bypass_is_reported() -> None:
    """The incident the rule exists for. An empty list coming back from the API
    is the owner locked out of their own repository."""
    committed = json.loads(_MAIN_RULESET.read_text(encoding="utf-8"))
    found = bypass_findings(_live_main_ruleset(bypass_actors=[]), committed)
    assert len(found) == 1, found
    assert "NOT enforced" in found[0]
    assert "lockout" in found[0]


def test_both_sides_emptied_together_is_two_findings_not_zero() -> None:
    """The case a plain equality check would pass with a green tick on it: a tidy
    revert of the committed file on a day the owner had also been locked out."""
    committed = dict(
        json.loads(_MAIN_RULESET.read_text(encoding="utf-8")),
        bypass_actors=[],
    )
    found = bypass_findings(_live_main_ruleset(bypass_actors=[]), committed)
    assert len(found) == 2, found
    assert any("NOT enforced" in line for line in found), found
    assert any("no longer records" in line for line in found), found


def test_the_tag_ruleset_is_not_harmonised_with_the_branch_one() -> None:
    """`release-tags.json` genuinely has no bypass actor and must keep none. The
    branch ruleset and the tag ruleset differ on purpose, and a later reader
    "harmonising" them in either direction is the failure this pins down.
    """
    tag_ruleset = json.loads(_TAG_RULESET.read_text(encoding="utf-8"))
    main_ruleset = json.loads(_MAIN_RULESET.read_text(encoding="utf-8"))
    assert tag_ruleset["bypass_actors"] == []
    assert main_ruleset["bypass_actors"] == [OWNER_BYPASS]
    assert "harmonise" in tag_ruleset["_comment"]
    assert "harmonised" in main_ruleset["_comment"]
