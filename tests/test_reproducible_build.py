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
_RELAY_DOCKERFILE = Path(__file__).resolve().parent.parent / "relay" / "Dockerfile"
_SETUP_BUILDX_SHA = "37fe631027851001ddb9b187196cc803df7f5f0e"

# Paths apt and dpkg write that differ between two builds installing the
# identical package set. Each was found by bisecting a failing `make
# relay-repro` archive diff, not assumed; leaving any one of them in the image
# reintroduces the failure. The logs carry wall-clock times; aux-cache stores
# per-library inode numbers and ctimes inside its own bytes, which is why
# BuildKit's rewrite-timestamp does not neutralise it.
_NONDETERMINISTIC_APT_PATHS = (
    "/var/log/apt",
    "/var/log/dpkg.log",
    "/var/log/alternatives.log",
    "/var/cache/ldconfig",
)


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
    assert "type=oci" in script
    assert "rewrite-timestamp=true" in script
    assert "git archive --format=tar HEAD -- relay/Dockerfile src" in script
    assert 'cmp -s "$tmp/relay-1.tar" "$tmp/relay-2.tar"' in script
    assert "relay-repro:" in _MAKEFILE.read_text(encoding="utf-8")
    container_workflow = _CONTAINER_WORKFLOW.read_text(encoding="utf-8")
    release_workflow = _RELEASE_WORKFLOW.read_text(encoding="utf-8")
    setup_buildx = f"docker/setup-buildx-action@{_SETUP_BUILDX_SHA}"
    assert container_workflow.index(setup_buildx) < container_workflow.index("make relay-repro")
    assert "docker build --no-cache -f relay/Dockerfile" in container_workflow, (
        "the scanned image must be built without cache: the Dockerfile applies Debian "
        "security updates at build time, so a cached upgrade layer would let Trivy scan "
        "a package set captured from an earlier archive state and report it as current"
    )
    assert release_workflow.index(setup_buildx) < release_workflow.index("make relay-repro")
    dockerignore = _DOCKERIGNORE.read_text(encoding="utf-8")
    assert "**/__pycache__" in dockerignore
    assert "**/*.py[cod]" in dockerignore


def _instructions(dockerfile: str) -> list[str]:
    """Split a Dockerfile into logical instructions, joining `\\` continuations."""
    joined = dockerfile.replace("\\\n", " ")
    return [
        line.strip()
        for line in joined.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def test_security_upgrade_layer_erases_every_nondeterministic_apt_artifact() -> None:
    """The apt layer and its cleanup must stay in the same instruction.

    The relay image applies Debian security updates over its pinned base digest
    because the upstream `python:*-slim` image is not rebuilt when Debian
    publishes a fix, so the digest pin alone ships known-vulnerable packages.
    That upgrade writes timestamped and inode-derived files, which breaks the
    byte-identical rebuild the release gate requires.

    Both halves are asserted, deliberately. Requiring the upgrade to exist means
    this test cannot be satisfied by deleting the layer: dropping the security
    updates is a decision that has to be made here, in the open, rather than
    quietly by editing the Dockerfile until the suite goes green.
    """
    instructions = _instructions(_RELAY_DOCKERFILE.read_text(encoding="utf-8"))
    upgrades = [
        instruction
        for instruction in instructions
        if instruction.startswith("RUN ") and "apt-get upgrade" in instruction
    ]

    assert len(upgrades) == 1, (
        "relay/Dockerfile must apply Debian security updates over the pinned base "
        f"digest in exactly one RUN instruction; found {len(upgrades)}"
    )
    removed: set[str] = set()
    for command in upgrades[0].split("&&"):
        tokens = command.split()
        if tokens and tokens[0] == "rm":
            removed.update(token for token in tokens[1:] if not token.startswith("-"))

    assert len(_NONDETERMINISTIC_APT_PATHS) == 4, (
        "the measured-path list must not be trimmed without a fresh `make relay-repro` "
        "bisect showing the dropped path is now deterministic; an empty list would make "
        "the check below pass without measuring anything"
    )
    missing = [path for path in _NONDETERMINISTIC_APT_PATHS if path not in removed]
    assert not missing, (
        "the security-update layer leaves apt/dpkg state that differs between two "
        f"builds of the same package set, which fails `make relay-repro`: {missing}"
    )
