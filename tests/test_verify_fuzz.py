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

Which mutation asks the *content* checks anything
-------------------------------------------------
That fix was not enough, and this section says so plainly rather than leaving the
next reader to measure it. ``structurally_intact`` requires ``signature_ok``, and
the signature is detached over the bundle bytes: **any** byte changed in
``bundle.json`` makes it False before a single content check has an opinion.
Instrumented over the committed settings, ``test_bundle_byte_mutation`` returned
47 reports with ``signature_ok`` True **zero** times and ``test_structural_mutation``
250 reports with ``signature_ok`` True **zero** times, while
``test_media_byte_mutation`` returned 120 reports with ``signature_ok`` True **120**
times — media lives outside the signed bundle, which is what makes that one the
honest member of the trio. Deleting the entire v3/v4 structural dispatch from
`habitable.verify` — artifact commitments, relationship typing, cycle detection,
profile and handoff consistency, all of it — left this module at 7 passed.

So the two byte-level tests below are **crash** tests, and are described as such.
The content checks are asserted by
``test_rewriting_a_position_the_bundle_commits_to_is_refused``, which does what a
producer rewriting their own export would do: change a field, then **re-sign**.
The signature is valid again, so the verdict comes from the artifact commitments,
the custody bindings, the timeline and relationship structures and the profile
and handoff rules, and from nothing else. With the v3/v4 dispatch deleted, 948 of
the 2054 rewrites in that inventory are accepted in silence; with it present,
none are.

``test_media_byte_mutation`` is the one byte-level test that was always honest:
changing a media file leaves the signature valid, so the per-item digest check is
what has to notice.

Every committed golden packet, not just the oldest
--------------------------------------------------
This harness used to fuzz ``packet-v1`` alone (issue #160). ``_verify_v3_timeline``
and ``_verify_v4_workflows`` are gated on ``bundle["packet_version"]``, so a v1
bundle never reaches them: roughly 250 lines of hostile-input parsing in the
standalone verifier were fuzzed by nothing, in the format packets are actually
being exported in today. The crash tests draw from the whole corpus at random and
mutate *nested* objects rather than only top-level keys; the rewrite test is
scoped to the current format, because that is the only fixture whose structures
the version-gated checks run over at all.
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
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from habitable.canonical import canonical_json
from habitable.errors import VerificationError
from habitable.verify import SUPPORTED_PACKET_VERSION, verify_packet

_GOLDEN_ROOT = Path(__file__).resolve().parent / "golden"
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


#: The long-running fuzz target, imported here for its inventory of the positions
#: a bundle commits to and the helpers that rewrite one. Defined there rather than
#: here, and used from both, so the merge gate and the target that runs for hours
#: cannot come to disagree about what this format promises.
_PACKET_FUZZER = _harness("fuzz_verify_packet")


class _Fixture:
    """One committed golden packet, copied once into a private working directory."""

    def __init__(self, source: Path) -> None:
        self.name = source.name
        self.bundle = (source / "bundle.json").read_bytes()
        self.signature = (source / "bundle.sig.json").read_bytes()
        self.media_name = next((source / "media").glob("*")).name
        self.media = (source / "media" / self.media_name).read_bytes()
        self.work = Path(tempfile.mkdtemp(prefix=f"habitable-fuzz-{self.name}-")) / "pkt"
        shutil.copytree(source, self.work)

    def reset(self) -> None:
        (self.work / "bundle.json").write_bytes(self.bundle)
        # The signature too: the rewrite test below re-signs, and a fixture that
        # kept somebody else's signature would hand the next test a packet whose
        # verdict it did not ask for.
        (self.work / "bundle.sig.json").write_bytes(self.signature)
        (self.work / "media" / self.media_name).write_bytes(self.media)


_FIXTURES = {
    path.name: _Fixture(path) for path in sorted(_GOLDEN_ROOT.glob("packet-v*")) if path.is_dir()
}
_NAMES = sorted(_FIXTURES)
assert _NAMES, "no golden packets committed"

_CURRENT = _FIXTURES[f"packet-v{SUPPORTED_PACKET_VERSION}"]
_COMMITTED_PATHS = _PACKET_FUZZER.committed_paths(json.loads(_CURRENT.bundle))


def _verify_must_not_crash_or_accept(fixture: _Fixture) -> None:
    """The crash invariant, plus the accept invariant as a backstop.

    On a mutated bundle the accept half is carried by the detached signature (see
    the module docstring), so a green result here says the verifier did not
    *crash* — it does not say a content check ran.
    """
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
    """Crash test: one byte of the signed bundle, anywhere in the corpus."""
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
    """Crash test, and a real accept test: the signature stays valid here.

    Media files are outside the signed bundle, so ``signature_ok`` is unaffected
    and the per-item ``content_hash``/``shared_hash`` comparison is the only thing
    standing between a substituted photograph and an intact verdict.
    """
    fixture = _FIXTURES[data.draw(st.sampled_from(_NAMES))]
    fixture.reset()
    raw = bytearray(fixture.media)
    pos = data.draw(st.integers(min_value=0, max_value=len(raw) - 1))
    val = data.draw(st.integers(0, 255))
    raw[pos] = val if raw[pos] != val else val ^ 0xFF
    (fixture.work / "media" / fixture.media_name).write_bytes(bytes(raw))
    _verify_must_not_crash_or_accept(fixture)


def _mutate(bundle: Any, path: tuple[str | int, ...], *, garble: bool) -> None:
    parent = bundle
    for step in path[:-1]:
        parent = parent[step]
    last = path[-1]
    if garble:
        parent[last] = 12345  # wrong type for most fields
    else:
        del parent[last]


@settings(max_examples=150, deadline=None)
@given(st.data())
def test_structural_mutation(data: st.DataObject) -> None:
    """Crash test: drop a key/element or wrong-type a value, anywhere, nested.

    Previously this only touched *top-level* keys of a v1 bundle, so the nested
    v3 timeline and v4 artifact/relationship/profile/handoff structures were
    untouched even in principle (issue #160). It reaches them now — and reaching
    them is all it does, because the mutated bundle no longer matches its
    signature. What the checks it reaches actually *decide* is asserted by
    `test_rewriting_a_position_the_bundle_commits_to_is_refused`.
    """
    fixture = _FIXTURES[data.draw(st.sampled_from(_NAMES))]
    fixture.reset()
    bundle = json.loads(fixture.bundle)
    path = data.draw(st.sampled_from(list(_PACKET_FUZZER.positions(bundle))))
    _mutate(bundle, path, garble=data.draw(st.booleans()))
    (fixture.work / "bundle.json").write_text(json.dumps(bundle))
    _verify_must_not_crash_or_accept(fixture)


# --- what the content checks decide ---------------------------------------------


def test_a_pristine_current_packet_is_accepted_and_has_no_problems() -> None:
    """The control the rewrite test below is worthless without.

    "The verifier refused a rewritten packet" means nothing unless the verifier
    accepts the same packet unrewritten: an assertion of the form ``not
    accepted`` is exactly as vacuous as the ``not report.ok`` this module started
    with, unless something pins that ``accepted`` is reachable at all. It also
    pins that a pristine fixture raises no ``problems``, so a problem observed
    after a rewrite is one the rewrite caused.
    """
    _CURRENT.reset()
    report = verify_packet(_CURRENT.work)
    assert report.problems == (), f"a pristine fixture already has problems: {report.problems}"
    assert _PACKET_FUZZER.is_accepted(report), (
        "a pristine current-format fixture is not accepted under the open trust "
        "policy, so every 'must not be accepted' assertion here proves nothing"
    )


def test_the_committed_position_inventory_still_describes_this_fixture() -> None:
    """A pattern that matches nothing takes a whole family's coverage with it.

    `fuzz/fuzz_verify_packet.py` lists the positions a bundle commits to as
    patterns, not as literal paths, so they survive a fixture regenerating with
    different ids. The failure mode of a pattern language is silence: rename
    ``handoff_views`` and the entry stops matching, the sweep still passes, and
    nothing anywhere says that handoff consistency is no longer being asserted.
    So every pattern must match a real position, and every declared exception
    must fall inside the family it is an exception to.
    """
    positions = list(_PACKET_FUZZER.positions(json.loads(_CURRENT.bundle)))
    for pattern in _PACKET_FUZZER.COMMITTED_POSITIONS:
        matched = [path for path in positions if _PACKET_FUZZER.matches(path, pattern)]
        assert matched, f"committed pattern {pattern} matches nothing in {_CURRENT.name}"
    for pattern in _PACKET_FUZZER.UNCOMMITTED_POSITIONS:
        matched = [path for path in positions if _PACKET_FUZZER.matches(path, pattern)]
        assert matched, f"declared exception {pattern} matches nothing in {_CURRENT.name}"
        assert all(
            any(
                _PACKET_FUZZER.matches(path, committed)
                for committed in _PACKET_FUZZER.COMMITTED_POSITIONS
            )
            for path in matched
        ), f"{pattern} is declared as an exception to a family that does not include it"
    assert len(_COMMITTED_PATHS) > 100, (
        f"only {len(_COMMITTED_PATHS)} committed positions in {_CURRENT.name}; the "
        "inventory has lost a family"
    )


@settings(max_examples=150, deadline=None)
@given(st.data())
def test_rewriting_a_position_the_bundle_commits_to_is_refused(data: st.DataObject) -> None:
    """Rewrite one committed field, re-sign, and the verifier must still refuse.

    This is the test the version-gated checks are actually behind. Re-signing is
    what a producer rewriting their own export can do — a packet's signature
    carries its own verifying key (FIX-05), so the open trust policy cannot tell
    a rewriter from the producer and is not asked to. With ``signature_ok`` True
    again, nothing is left to refuse the packet except the commitments inside it:
    the artifact hashes, the custody bindings, the timeline and relationship
    structures, the appendix counts, the profile snapshot and the handoff
    disclosure floor.

    The inventory of positions and the replacement shapes come from
    `fuzz/fuzz_verify_packet.py`, which sweeps the same space for hours. Swept
    exhaustively here while writing it: 295 positions x 7 replacements = 2054
    rewrites that change something, 0 accepted. With `verify.py`'s two-line v3/v4
    dispatch deleted, 948 of the 2054 are accepted.
    """
    _CURRENT.reset()
    path = data.draw(st.sampled_from(_COMMITTED_PATHS))
    replacement = data.draw(st.sampled_from(_PACKET_FUZZER.REPLACEMENTS))
    bundle = json.loads(_CURRENT.bundle)
    _PACKET_FUZZER.rewrite(bundle, path, replacement)
    rewritten = canonical_json(bundle)
    assume(rewritten != _CURRENT.bundle)  # a replacement equal to the current value

    (_CURRENT.work / "bundle.json").write_bytes(rewritten)
    _PACKET_FUZZER.resign(_CURRENT.work)
    try:
        report = verify_packet(_CURRENT.work)
    except VerificationError:
        return  # a named, handled rejection is a refusal
    except Exception as exc:
        raise AssertionError(f"verifier crashed with {type(exc).__name__}: {exc}") from exc
    assert not _PACKET_FUZZER.is_accepted(report), (
        f"the verifier accepted a re-signed packet after {'.'.join(str(x) for x in path)} "
        f"was rewritten to {replacement!r}"
    )


def test_a_relationship_cycle_is_refused() -> None:
    """The one v4 check no field rewrite reaches: a graph, not a field.

    Cycle detection is a property of the relationship *set*, so deleting or
    wrong-typing one endpoint cannot exercise it — the edge simply stops being an
    edge. This builds the smallest cycle the fixture allows (an assertion whose
    two endpoints are the same) and re-signs, so the refusal has to come from
    `_graph_has_cycle` and its callers rather than from the signature.
    """
    _CURRENT.reset()
    bundle = json.loads(_CURRENT.bundle)
    relationship = bundle["relationships"][0]
    relationship["target_id"] = relationship["source_id"]
    (_CURRENT.work / "bundle.json").write_bytes(canonical_json(bundle))
    _PACKET_FUZZER.resign(_CURRENT.work)

    report = verify_packet(_CURRENT.work)
    assert any("cycle" in problem for problem in report.problems), (
        f"a self-referential relationship raised no cycle problem: {report.problems}"
    )
    assert not _PACKET_FUZZER.is_accepted(report)


def test_the_corpus_being_fuzzed_includes_the_current_format() -> None:
    """The gap this harness had: it fuzzed only the oldest committed format.

    A version bump that forgets its fixture, or a harness pinned back to v1,
    fails here rather than passing quietly while the format tenants are actually
    exporting goes unfuzzed.
    """
    assert f"packet-v{SUPPORTED_PACKET_VERSION}" in _NAMES

    current = json.loads(_CURRENT.bundle)
    # And it must actually reach the version-specific checks.
    assert current["relationships"], "current-version fixture has no relationship to fuzz"
    assert current["use_case_profile"], "current-version fixture has no profile to fuzz"
    assert current["handoff_views"], "current-version fixture has no handoff view to fuzz"
    assert any(item.get("record_kind") == "artifact" for item in current["items"])


# --- the out-of-tree fuzz harnesses must keep working ---------------------------


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


def test_the_timestamp_harness_reaches_the_verdicts_it_asserts_about(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A seed corpus that never gets a token accepted asserts two of its three properties
    against nothing.

    That was the defect: the harness built a token out of raw fuzz bytes, so
    reaching a returned ``TimestampInfo`` needed a valid Ed25519 signature over
    canonical JSON or valid CMS SignedData. ``verify_token`` returned zero times
    over the seed corpus and 200,000 random inputs, and the two properties stated
    about the result — no manufactured trust, no attestation over other content —
    were unreachable code. A dev token patched to report ``trusted_chain=True``
    was reported clean by the entire harness.

    Reachability is therefore a merge-gate assertion in its own right, not
    something to re-measure by hand the next time somebody edits the seeds.
    """
    module = _harness("fuzz_timestamp_token")
    accepts = 0
    real = module.verify_token

    def counting(token: object, digest: str, **kwargs: object) -> object:
        nonlocal accepts
        info = real(token, digest, **kwargs)
        accepts += 1
        return info

    monkeypatch.setattr(module, "verify_token", counting)
    for payload in module.seed_corpus():
        module.TestOneInput(payload)
    assert accepts >= 4, (
        f"the seed corpus produced {accepts} accepted token(s); with fewer than one "
        "per real token kind, the harness's trust and digest properties are dead code"
    )


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


def test_the_compiled_target_is_given_the_fixtures_it_reads() -> None:
    """`--onefile` bundles modules, not data (issue #256).

    Both harnesses seed from `tests/golden`, and `fuzz_verify_packet` copies a
    whole packet at *import* time — before `atheris.Setup`, so a missing fixture
    is not a bad run, it is a target that never starts. `compile_python_fuzzer`
    is `pyinstaller --onefile` and forwards its extra arguments, so the tree has
    to be passed with `--add-data` and read back from `sys._MEIPASS`; nothing
    about that is visible in a working copy, where the clone is right there.
    Verified once against a real `pyinstaller --onefile` build run from outside
    any checkout: without this flag the binary dies on startup, with it the whole
    seed corpus replays.
    """
    build = (_FUZZ_DIR / "oss-fuzz" / "build.sh").read_text(encoding="utf-8")
    assert "--add-data" in build and "tests/golden:habitable-golden" in build, (
        "fuzz/oss-fuzz/build.sh no longer bundles tests/golden into the compiled "
        "target, which will die of FileNotFoundError on startup in the fuzzing image"
    )
    for name in ("fuzz_verify_packet", "fuzz_timestamp_token"):
        source = (_FUZZ_DIR / f"{name}.py").read_text(encoding="utf-8")
        assert "habitable-golden" in source and "_MEIPASS" in source, (
            f"{name} no longer reads its fixtures out of the PyInstaller bundle"
        )
