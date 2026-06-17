# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Property/fuzz harness for the verifier: it must never accept tampered evidence
and never crash on hostile input.

Two invariants over random mutations of a valid packet:
  1. **Never accept on tamper** — any change to the signed bundle or to a media
     file yields a report with ``ok == False`` (or a handled ``VerificationError``).
  2. **Never crash** — the only exception the verifier may raise is
     ``VerificationError``; anything else (KeyError, TypeError, …) is a bug.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from habitable.errors import VerificationError
from habitable.verify import verify_packet

_GOLDEN = Path(__file__).resolve().parent / "golden" / "packet-v1"
_BUNDLE = (_GOLDEN / "bundle.json").read_bytes()
_MEDIA_NAME = next((_GOLDEN / "media").glob("*")).name
_MEDIA = (_GOLDEN / "media" / _MEDIA_NAME).read_bytes()

# One working copy reused across examples; each example resets the files it mutates.
_WORK = Path(tempfile.mkdtemp(prefix="habitable-fuzz-")) / "pkt"
shutil.copytree(_GOLDEN, _WORK)


def _reset() -> None:
    (_WORK / "bundle.json").write_bytes(_BUNDLE)
    (_WORK / "media" / _MEDIA_NAME).write_bytes(_MEDIA)


def _verify_must_not_crash_or_accept() -> None:
    try:
        report = verify_packet(_WORK)
    except VerificationError:
        return  # a clean, handled rejection is fine
    except Exception as exc:  # any other exception is a verifier bug
        raise AssertionError(f"verifier crashed with {type(exc).__name__}: {exc}") from exc
    assert not report.ok, "verifier accepted a tampered packet"


@settings(max_examples=150, deadline=None)
@given(pos=st.integers(min_value=0, max_value=len(_BUNDLE) - 1), val=st.integers(0, 255))
def test_bundle_byte_mutation(pos: int, val: int) -> None:
    _reset()
    data = bytearray(_BUNDLE)
    data[pos] = val if data[pos] != val else val ^ 0xFF  # ensure a real change
    (_WORK / "bundle.json").write_bytes(bytes(data))
    _verify_must_not_crash_or_accept()


@settings(max_examples=80, deadline=None)
@given(pos=st.integers(min_value=0, max_value=len(_MEDIA) - 1), val=st.integers(0, 255))
def test_media_byte_mutation(pos: int, val: int) -> None:
    _reset()
    data = bytearray(_MEDIA)
    data[pos] = val if data[pos] != val else val ^ 0xFF
    (_WORK / "media" / _MEDIA_NAME).write_bytes(bytes(data))
    _verify_must_not_crash_or_accept()


@settings(max_examples=80, deadline=None)
@given(drop=st.integers(0, 64), garble=st.booleans())
def test_structural_mutation(drop: int, garble: bool) -> None:
    """Drop a key or replace a value with a wrong-typed one; the verifier must cope."""
    _reset()
    bundle = json.loads(_BUNDLE)
    keys = sorted(bundle.keys())
    if keys:
        key = keys[drop % len(keys)]
        if garble:
            bundle[key] = 12345  # wrong type for most fields
        else:
            del bundle[key]
    (_WORK / "bundle.json").write_text(json.dumps(bundle))
    _verify_must_not_crash_or_accept()
