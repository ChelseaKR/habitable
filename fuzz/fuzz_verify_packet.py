#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0
# Copyright 2026 Chelsea Kelly-Reif
"""Continuous-fuzzing harness for the packet verifier (issue #256).

`habitable.verify.verify_packet` is the one function in this project whose entire
purpose is to be run by a skeptic, on a directory an adversary prepared, with a
result someone may have to defend in a housing dispute. That makes it the natural
target for fuzzing that runs for hours rather than the few seconds a merge gate
can spend.

Each iteration takes a real committed golden packet, replaces one part of it with
the fuzzer's bytes, and verifies. Two properties:

1. **Never a crash.** The only exception `verify_packet` may raise is
   :class:`VerificationError`. Anything else -- a ``KeyError`` on a missing field,
   a ``TypeError`` on a wrong-typed one, a decoder blowing up on a truncated
   structure -- is a bug, because an embedder catches the project's own exception
   type and a traceback is not a verdict.
2. **Never an accept on tamper.** Unless the fuzzer has reproduced the exported
   bytes exactly, the report must not come back structurally intact.

That second property is stated against ``structurally_intact``, deliberately, and
not against ``report.ok``. ``ok`` is an alias for ``evidence_ready``, which also
requires a trusted timestamp anchor; the golden corpus ships no trust root, so
``ok`` is already False for a *pristine* golden packet and an assertion built on
it can never fail. Same reasoning as the stateful machine in
`tests/test_property_invariants.py`.

Running it locally, with or without Atheris::

    python fuzz/fuzz_verify_packet.py                    # replay the seed corpus
    python fuzz/fuzz_verify_packet.py corpus/            # replay a directory
    pip install atheris && python fuzz/fuzz_verify_packet.py -atheris_runs=100000
"""

from __future__ import annotations

import contextlib
import shutil
import sys
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

try:  # Atheris is present under OSS-Fuzz and optional everywhere else.
    import atheris as _atheris
except ModuleNotFoundError:  # pragma: no cover - exercised only off OSS-Fuzz
    _atheris = None  # type: ignore[assignment]

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "src"))

# Coverage instrumentation has to wrap the *import* of the code under test.
with _atheris.instrument_imports() if _atheris else contextlib.nullcontext():
    from habitable.errors import VerificationError
    from habitable.verify import SUPPORTED_PACKET_VERSION, verify_packet

if TYPE_CHECKING:
    from collections.abc import Iterator

#: The seed packet. The newest committed format on purpose: `_verify_v3_timeline`
#: and `_verify_v4_workflows` are gated on `packet_version`, so fuzzing an older
#: fixture leaves several hundred lines of hostile-input parsing untouched --
#: the gap issue #160 found in the in-repo harness, which must not be recreated
#: here in the harness that is supposed to run for hours.
SEED_PACKET = _REPO_ROOT / "tests" / "golden" / f"packet-v{SUPPORTED_PACKET_VERSION}"

#: Where the fuzzer's bytes land. The first input byte chooses; every part of a
#: packet a recipient reads is reachable.
_TARGETS = ("bundle", "signature", "media")

_WORK = Path(tempfile.mkdtemp(prefix="habitable-fuzz-verify-")) / "packet"
shutil.copytree(SEED_PACKET, _WORK)
_PRISTINE = {
    path.relative_to(_WORK): path.read_bytes()
    for path in sorted(_WORK.rglob("*"))
    if path.is_file()
}
_MEDIA_NAMES = sorted(path.name for path in (_WORK / "media").iterdir())


def _restore() -> None:
    for relative, payload in _PRISTINE.items():
        (_WORK / relative).write_bytes(payload)


def _plant(data: bytes) -> Path:
    """Write the fuzzer's bytes over one part of the packet; return that path."""
    target = _TARGETS[data[0] % len(_TARGETS)] if data else "bundle"
    body = data[1:]
    if target == "signature":
        path = _WORK / "bundle.sig.json"
    elif target == "media":
        name = _MEDIA_NAMES[body[0] % len(_MEDIA_NAMES)] if body else _MEDIA_NAMES[0]
        path = _WORK / "media" / name
        body = body[1:]
    else:
        path = _WORK / "bundle.json"
    path.write_bytes(body)
    return path


def TestOneInput(data: bytes) -> None:  # noqa: N802 - the name libFuzzer requires
    """One fuzz iteration. Returning normally means the input found nothing."""
    _restore()
    planted = _plant(data)

    try:
        report = verify_packet(_WORK)
    except VerificationError:
        return  # a named, handled rejection is the contract
    except Exception as exc:
        raise AssertionError(f"verify_packet crashed with {type(exc).__name__}: {exc}") from exc

    if not report.structurally_intact:
        return
    # Intact is only defensible if the bytes really are the exported ones. A
    # fuzzer will not guess a whole signed bundle, so in practice this fires only
    # on an empty-difference input -- and if it ever fires otherwise, it is the
    # finding this target exists for, and belongs in SECURITY.md's private path.
    if planted.read_bytes() != _PRISTINE[planted.relative_to(_WORK)]:
        raise AssertionError(
            f"verify_packet reported a structurally intact packet after {planted.name} "
            "was replaced with fuzzer-chosen bytes"
        )


def seed_corpus() -> Iterator[bytes]:
    """Small, deterministic inputs that reach each target and each early exit.

    Written out by `fuzz/oss-fuzz/build.sh` as the target's seed corpus, and
    replayed by `tests/test_verify_fuzz.py` on every merge so the harness cannot
    quietly stop working between OSS-Fuzz runs.
    """
    yield b""
    for index in range(len(_TARGETS)):
        prefix = bytes([index])
        yield prefix
        yield prefix + b"{}"
        yield prefix + b"["
        yield prefix + b'{"packet_version": 4}'
        yield prefix + b'{"packet_version": 99999, "items": []}'
        yield prefix + b"\x00" * 64
        yield prefix + bytes(range(256))
    # The exported bundle itself, so the "intact" branch is a covered path rather
    # than dead code that only a lucky fuzzer would ever reach.
    yield bytes([_TARGETS.index("bundle")]) + _PRISTINE[Path("bundle.json")]


def main() -> None:  # pragma: no cover - the OSS-Fuzz / CLI entry point
    """Fuzz under Atheris when it is installed; otherwise replay inputs."""
    if _atheris is not None:
        _atheris.Setup(sys.argv, TestOneInput)
        _atheris.Fuzz()
        return

    inputs = list(seed_corpus())
    for argument in sys.argv[1:]:
        path = Path(argument)
        if path.is_dir():
            inputs.extend(
                child.read_bytes() for child in sorted(path.rglob("*")) if child.is_file()
            )
        else:
            inputs.append(path.read_bytes())
    for payload in inputs:
        TestOneInput(payload)
    print(f"{Path(__file__).name}: {len(inputs)} input(s), no finding")


if __name__ == "__main__":  # pragma: no cover
    main()
