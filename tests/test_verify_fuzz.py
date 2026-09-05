# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Property/fuzz harness for the verifier: it must never accept tampered evidence
and never crash on hostile input.

Two invariants over random mutations of a valid packet:
  1. **Never accept on tamper** — any change to the signed bundle or to a media
     file yields a report that is not ``structurally_intact`` (or a handled
     ``VerificationError``).
  2. **Never crash** — the only exception the verifier may raise is
     ``VerificationError``; anything else (KeyError, TypeError, …) is a bug.

Why invariant 1 is stated against ``structurally_intact``
---------------------------------------------------------
It used to be stated against ``report.ok``, and could therefore never fail.
``ok`` is a fail-closed alias for ``evidence_ready``, which also requires every
item's timestamp authority to chain to a *supplied* trust root — and the golden
corpus deliberately ships no trust root, precisely so the fixtures prove format
compatibility rather than a trust policy (`tests/test_golden.py` asserts
``not report.ok`` for a **pristine** fixture). So "the verifier accepted a
tampered packet" was an assertion about a value that is False before any tamper,
across the whole corpus: the crash invariant was doing all the work and the
accept invariant was decoration. ``structurally_intact`` is the predicate that
actually moves — signature, custody, and per-item media checks — and it is what
`tests/test_golden.py` asserts is True for a pristine fixture.

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

import importlib.util
import json
import shutil
import tempfile
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
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
    assert not report.structurally_intact, (
        f"{fixture.name}: verifier reported a structurally intact packet after a tamper"
    )


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


# --- the out-of-tree fuzz harnesses must keep working ---------------------------

_FUZZ_DIR = Path(__file__).resolve().parent.parent / "fuzz"


def _harness(name: str) -> ModuleType:
    """Import one `fuzz/` harness by path.

    `fuzz/` is not a package and is deliberately not on `sys.path`: the harnesses
    are standalone files OSS-Fuzz compiles one at a time, and making them
    importable as a package would let them quietly grow shared state that only
    exists in this repository and not in the fuzzing image.
    """
    path = _FUZZ_DIR / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None, f"cannot load {path}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("name", ["fuzz_verify_packet", "fuzz_timestamp_token"])
def test_the_oss_fuzz_harnesses_still_run_their_own_seed_corpus(name: str) -> None:
    """An out-of-tree fuzz target that nothing exercises rots (issue #256).

    The harnesses in `fuzz/` are built by OSS-Fuzz, not by this repository, so
    nothing here would otherwise notice when a rename in `habitable.verify`, a
    changed exception type, or a moved golden fixture stops them importing. The
    first anyone would hear of it is a build failure in someone else's
    infrastructure, weeks later, having fuzzed nothing in the meantime.

    So the merge gate runs each harness's own seed corpus through its
    `TestOneInput`. That is not fuzzing -- it is a handful of inputs and it finds
    nothing new -- but it does prove the target imports, that its entry point
    still has the shape libFuzzer calls, and that the properties it asserts still
    hold on the inputs chosen to reach each branch.
    """
    module = _harness(name)
    corpus = list(module.seed_corpus())
    assert len(corpus) >= 8, f"{name} ships a seed corpus too small to reach its branches"
    for payload in corpus:
        module.TestOneInput(payload)


def test_every_harness_in_the_fuzz_directory_is_wired_into_the_build() -> None:
    """A harness OSS-Fuzz never compiles is a file, not a fuzz target.

    `fuzz/oss-fuzz/build.sh` globs `fuzz/fuzz_*.py`, so this pins the naming
    convention that glob depends on, and pins that the two harnesses this
    repository claims to have are the two that are actually there. A harness
    added as `verify_fuzzer.py` would be silently skipped by the build and
    silently missing from the corpus, while the README went on describing it.
    """
    harnesses = sorted(path.name for path in _FUZZ_DIR.glob("*.py"))
    assert harnesses == ["fuzz_timestamp_token.py", "fuzz_verify_packet.py"], (
        f"fuzz/ holds {harnesses}; every harness must be named fuzz_*.py so "
        "fuzz/oss-fuzz/build.sh's glob compiles it, and the set must match what "
        "fuzz/README.md and this test describe"
    )

    build = (_FUZZ_DIR / "oss-fuzz" / "build.sh").read_text(encoding="utf-8")
    assert "fuzz/fuzz_*.py" in build, "the build script no longer globs the harnesses"
    assert "compile_python_fuzzer" in build, "the build script no longer compiles anything"
    assert "seed_corpus" in build, "the build script no longer materialises the seed corpora"
