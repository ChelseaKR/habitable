# SPDX-License-Identifier: AGPL-3.0-or-later
"""Guard the reproducible-build artifact contract."""

from __future__ import annotations

import runpy
from collections.abc import Callable
from pathlib import Path
from typing import cast

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "check_reproducible_build.py"
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
