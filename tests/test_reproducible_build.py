# SPDX-License-Identifier: AGPL-3.0-or-later
"""Guard the reproducible-build artifact contract."""

from __future__ import annotations

import runpy
from collections.abc import Callable
from pathlib import Path
from typing import cast

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "check_reproducible_build.py"
_RELAY_SCRIPT = (
    Path(__file__).resolve().parent.parent / "scripts" / "check_reproducible_relay_image.sh"
)
_MAKEFILE = Path(__file__).resolve().parent.parent / "Makefile"
_CONTAINER_WORKFLOW = (
    Path(__file__).resolve().parent.parent / ".github" / "workflows" / "container-scan.yml"
)
_RELEASE_WORKFLOW = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "release.yml"
_DOCKERIGNORE = Path(__file__).resolve().parent.parent / ".dockerignore"
_artifact_set_problem = cast(
    Callable[[list[Path]], str | None], runpy.run_path(str(_SCRIPT))["_artifact_set_problem"]
)


def test_artifact_set_requires_one_wheel_and_one_sdist(tmp_path: Path) -> None:
    wheel = tmp_path / "habitable-1-py3-none-any.whl"
    sdist = tmp_path / "habitable-1.tar.gz"

    assert _artifact_set_problem([]) is not None
    assert _artifact_set_problem([wheel]) is not None
    assert _artifact_set_problem([sdist]) is not None
    assert _artifact_set_problem([wheel, sdist]) is None
    assert _artifact_set_problem([wheel, sdist, tmp_path / "extra.whl"]) is not None


def test_relay_reproducibility_gate_is_wired_to_merge_and_release() -> None:
    script = _RELAY_SCRIPT.read_text(encoding="utf-8")
    assert "SOURCE_DATE_EPOCH" in script
    assert "--no-cache" in script
    assert "--platform linux/amd64" in script
    assert "type=docker" in script
    assert "rewrite-timestamp=true" in script
    assert "git archive --format=tar HEAD -- relay/Dockerfile src" in script
    assert 'cmp -s "$tmp/relay-1.tar" "$tmp/relay-2.tar"' in script
    assert "relay-repro:" in _MAKEFILE.read_text(encoding="utf-8")
    assert "make relay-repro" in _CONTAINER_WORKFLOW.read_text(encoding="utf-8")
    assert "make relay-repro" in _RELEASE_WORKFLOW.read_text(encoding="utf-8")
    dockerignore = _DOCKERIGNORE.read_text(encoding="utf-8")
    assert "**/__pycache__" in dockerignore
    assert "**/*.py[cod]" in dockerignore
