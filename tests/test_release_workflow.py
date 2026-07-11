# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Guards for release identity and exact-artifact promotion."""

from __future__ import annotations

import re
from pathlib import Path

_WORKFLOW = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "release.yml"


def _workflow_sections() -> tuple[str, str]:
    text = _WORKFLOW.read_text(encoding="utf-8")
    release, separator, pypi = text.partition("  pypi-publish:\n")
    assert separator, "release workflow must retain a separate PyPI publish job"
    return release, pypi


def test_release_checks_out_exact_tag_before_version_check_and_build() -> None:
    release, _pypi = _workflow_sections()
    resolve = release.index('git rev-parse --verify --end-of-options "${TAG}^{commit}"')
    checkout = release.index('git checkout --detach "$TAG_COMMIT"')
    head_guard = release.index('"$(git rev-parse HEAD)" != "$TAG_COMMIT"')
    version_guard = release.index('TAG_VERSION="${TAG#v}"')
    build = release.index("run: make repro")
    assert resolve < checkout < head_guard < version_guard < build


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
