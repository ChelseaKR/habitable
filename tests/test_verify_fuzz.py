# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Property/fuzz harness for the verifier: it must never accept tampered evidence
and never crash on hostile input.

Two invariants over random mutations of a valid packet:
  1. **Never accept on tamper** — any change to the signed bundle or to a media
     file yields a report with ``ok == False`` (or a handled ``VerificationError``).
  2. **Never crash** — the only exception the verifier may raise is
     ``VerificationError``; anything else (KeyError, TypeError, …) is a bug.

Every committed golden packet, not just the oldest
--------------------------------------------------
This harness used to fuzz ``packet-v1`` alone (issue #160). ``_verify_v3_timeline``
and ``_verify_v4_workflows`` are gated on ``bundle["packet_version"]``, so a v1
bundle never reaches them: roughly 250 lines of hostile-input parsing in the
standalone verifier — artifact commitments, relationship endpoint typing,
relationship-graph cycle detection, profile/review-state consistency, handoff
disclosure suppression — were fuzzed by nothing, in the format packets are
actually being exported in today. The corpus is now drawn from at random, and
the structural mutation reaches *nested* objects rather than only top-level keys.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st

from habitable.errors import VerificationError
from habitable.verify import SUPPORTED_PACKET_VERSION, verify_packet

_GOLDEN_ROOT = Path(__file__).resolve().parent / "golden"


class _Fixture:
    """One committed golden packet, copied once into a private working directory."""

    def __init__(self, source: Path) -> None:
        self.name = source.name
        self.bundle = (source / "bundle.json").read_bytes()
        self.media_name = next((source / "media").glob("*")).name
        self.media = (source / "media" / self.media_name).read_bytes()
        self.work = Path(tempfile.mkdtemp(prefix=f"habitable-fuzz-{self.name}-")) / "pkt"
        shutil.copytree(source, self.work)

    def reset(self) -> None:
        (self.work / "bundle.json").write_bytes(self.bundle)
        (self.work / "media" / self.media_name).write_bytes(self.media)


_FIXTURES = {
    path.name: _Fixture(path) for path in sorted(_GOLDEN_ROOT.glob("packet-v*")) if path.is_dir()
}
_NAMES = sorted(_FIXTURES)
assert _NAMES, "no golden packets committed"


def _verify_must_not_crash_or_accept(fixture: _Fixture) -> None:
    try:
        report = verify_packet(fixture.work)
    except VerificationError:
        return  # a clean, handled rejection is fine
    except Exception as exc:  # any other exception is a verifier bug
        raise AssertionError(
            f"{fixture.name}: verifier crashed with {type(exc).__name__}: {exc}"
        ) from exc
    assert not report.ok, f"{fixture.name}: verifier accepted a tampered packet"


@settings(max_examples=200, deadline=None)
@given(st.data())
def test_bundle_byte_mutation(data: st.DataObject) -> None:
    fixture = _FIXTURES[data.draw(st.sampled_from(_NAMES))]
    fixture.reset()
    raw = bytearray(fixture.bundle)
    pos = data.draw(st.integers(min_value=0, max_value=len(raw) - 1))
    val = data.draw(st.integers(0, 255))
    raw[pos] = val if raw[pos] != val else val ^ 0xFF  # ensure a real change
    (fixture.work / "bundle.json").write_bytes(bytes(raw))
    _verify_must_not_crash_or_accept(fixture)


@settings(max_examples=120, deadline=None)
@given(st.data())
def test_media_byte_mutation(data: st.DataObject) -> None:
    fixture = _FIXTURES[data.draw(st.sampled_from(_NAMES))]
    fixture.reset()
    raw = bytearray(fixture.media)
    pos = data.draw(st.integers(min_value=0, max_value=len(raw) - 1))
    val = data.draw(st.integers(0, 255))
    raw[pos] = val if raw[pos] != val else val ^ 0xFF
    (fixture.work / "media" / fixture.media_name).write_bytes(bytes(raw))
    _verify_must_not_crash_or_accept(fixture)


def _mutable_paths(node: Any, prefix: tuple[str | int, ...] = ()) -> list[tuple[str | int, ...]]:
    """Every addressable position in the bundle, nested objects and arrays included."""
    found: list[tuple[str | int, ...]] = []
    if isinstance(node, dict):
        for key in sorted(node):
            here = (*prefix, key)
            found.append(here)
            found.extend(_mutable_paths(node[key], here))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            here = (*prefix, index)
            found.append(here)
            found.extend(_mutable_paths(value, here))
    return found


def _mutate(bundle: Any, path: tuple[str | int, ...], *, garble: bool) -> None:
    parent = bundle
    for step in path[:-1]:
        parent = parent[step]
    last = path[-1]
    if garble:
        parent[last] = 12345  # wrong type for most fields
    else:
        del parent[last]


@settings(max_examples=250, deadline=None)
@given(st.data())
def test_structural_mutation(data: st.DataObject) -> None:
    """Drop a key/element or replace a value with a wrong-typed one, anywhere.

    Previously this only touched *top-level* keys of a v1 bundle, so the nested
    v3 timeline and v4 artifact/relationship/profile/handoff structures were
    untouched even in principle (issue #160).
    """
    fixture = _FIXTURES[data.draw(st.sampled_from(_NAMES))]
    fixture.reset()
    bundle = json.loads(fixture.bundle)
    paths = _mutable_paths(bundle)
    path = data.draw(st.sampled_from(paths))
    _mutate(bundle, path, garble=data.draw(st.booleans()))
    (fixture.work / "bundle.json").write_text(json.dumps(bundle))
    _verify_must_not_crash_or_accept(fixture)


def test_the_corpus_being_fuzzed_includes_the_current_format() -> None:
    """The gap this harness had: it fuzzed only the oldest committed format.

    A version bump that forgets its fixture, or a harness pinned back to v1,
    fails here rather than passing quietly while the format tenants are actually
    exporting goes unfuzzed.
    """
    assert f"packet-v{SUPPORTED_PACKET_VERSION}" in _NAMES

    current = json.loads(_FIXTURES[f"packet-v{SUPPORTED_PACKET_VERSION}"].bundle)
    # And it must actually reach the version-specific checks.
    assert current["relationships"], "current-version fixture has no relationship to fuzz"
    assert current["use_case_profile"], "current-version fixture has no profile to fuzz"
    assert current["handoff_views"], "current-version fixture has no handoff view to fuzz"
    assert any(item.get("record_kind") == "artifact" for item in current["items"])
