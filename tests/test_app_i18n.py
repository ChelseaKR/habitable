# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""The app's English and Spanish bundles must stay at parity."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

_APP = Path(__file__).resolve().parent.parent / "app"
_EN = _APP / "i18n" / "en.json"
_ES = _APP / "i18n" / "es.json"


def _load(path: Path) -> dict[str, str]:
    assert path.is_file(), f"missing translation bundle: {path}"
    data = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return {str(k): str(v) for k, v in data.items()}


def test_en_and_es_have_identical_keys() -> None:
    en, es = _load(_EN), _load(_ES)
    assert set(en) == set(es), (
        f"missing in es: {sorted(set(en) - set(es))}; extra in es: {sorted(set(es) - set(en))}"
    )


def test_no_empty_translations() -> None:
    for path in (_EN, _ES):
        for key, value in _load(path).items():
            assert value.strip(), f"{path.name}: empty translation for {key!r}"


def test_spanish_is_actually_translated() -> None:
    """A sanity check that es is not just a copy of en (most strings differ)."""
    en, es = _load(_EN), _load(_ES)
    shared = set(en) & set(es)
    if not shared:
        pytest.skip("no shared keys")
    differing = sum(1 for k in shared if en[k] != es[k])
    assert differing >= len(shared) // 2
