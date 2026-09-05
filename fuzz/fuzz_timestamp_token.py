#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0
# Copyright 2026 Chelsea Kelly-Reif
"""Continuous-fuzzing harness for timestamp-token parse and verify (issue #256).

The entry points here are the two a skeptic reaches when a packet hands them a
proof of time: :func:`habitable.tsa.TimestampToken.from_dict`, which parses a
stored record, and :func:`habitable.tsa.verify_token`, which checks a dev token's
signed canonical document or an RFC 3161 CMS blob. Both take bytes an adversary
chose.

Three properties, and only three, because these are the ones the project states
in prose and has to keep:

1. **One named error.** A hostile record or token yields :class:`TimestampError`
   and nothing else. A ``binascii.Error`` from a bad base64 alphabet, an
   ``asn1crypto`` parse failure, an ``IndexError`` off the end of a truncated
   structure -- any of those escaping is the bug, because a caller embedding the
   verifier catches the project's own exception type and would see a traceback
   instead of a verdict.
2. **No accept without an anchor.** With no ``trusted_certs`` supplied, no input
   may return ``trusted_chain=True``. Trust is something a recipient configures;
   it can never be something a token asserts about itself.
3. **No accept over other content.** ``verify_token`` is asked for a specific
   digest, so a returned :class:`TimestampInfo` must carry exactly that digest.

Why continuously and not just in CI: `tests/test_property_invariants.py` sweeps a
shaped space for a few seconds per merge. OSS-Fuzz keeps a corpus across runs and
spends hours on the inputs that need hours -- and a timestamp token is a
structured binary format where that difference is the whole game.

Running it locally, with or without Atheris::

    python fuzz/fuzz_timestamp_token.py                  # replay the seed corpus
    python fuzz/fuzz_timestamp_token.py corpus/          # replay a directory
    pip install atheris && python fuzz/fuzz_timestamp_token.py -atheris_runs=100000

`tests/test_verify_fuzz.py` also imports this module and runs the seed corpus
through it on every merge, so the harness cannot rot while nobody is looking.
"""

from __future__ import annotations

import contextlib
import sys
from pathlib import Path
from typing import TYPE_CHECKING

try:  # Atheris is present under OSS-Fuzz and optional everywhere else.
    import atheris as _atheris
except ModuleNotFoundError:  # pragma: no cover - exercised only off OSS-Fuzz
    _atheris = None  # type: ignore[assignment]

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "src"))

# Coverage instrumentation has to wrap the *import* of the code under test, which
# is why these imports are here rather than at the top of the file.
with _atheris.instrument_imports() if _atheris else contextlib.nullcontext():
    from habitable.canonical import sha256_bytes
    from habitable.errors import TimestampError
    from habitable.tsa import TimestampToken, verify_token

if TYPE_CHECKING:
    from collections.abc import Iterator

#: The content digest every token is asked about. Fixed, because the interesting
#: variable is the token, and a fuzzer that also moved the digest would spend its
#: budget rediscovering "these do not match".
DIGEST = sha256_bytes(b"habitable fuzz target: content that was never stamped")

#: How the first input byte is spent. Both real token kinds are reachable, and so
#: is the record parser, which is a separate entry point with its own failure
#: modes (base64 alphabet, padding, field types).
_KINDS = ("dev", "rfc3161")


def _record_from(data: bytes) -> dict[str, object]:
    """Build a stored-token record out of raw fuzz bytes.

    Deliberately hand-rolled rather than drawn from `atheris.FuzzedDataProvider`,
    so the harness consumes an input identically with and without Atheris. A
    corpus entry that reproduces a finding under OSS-Fuzz reproduces it here.
    """
    kind = _KINDS[data[0] % len(_KINDS)] if data else "dev"
    body = data[1:]
    return {
        "kind": kind,
        "tsa_name": body[:8].decode("utf-8", "replace"),
        "token_b64": body.decode("latin-1"),
    }


def TestOneInput(data: bytes) -> None:  # noqa: N802 - the name libFuzzer requires
    """One fuzz iteration. Returning normally means the input found nothing."""
    kind = _KINDS[data[0] % len(_KINDS)] if data else "dev"
    token = TimestampToken(kind=kind, tsa_name="fuzz", data=data[1:])

    try:
        info = verify_token(token, DIGEST)
    except TimestampError:
        pass
    except Exception as exc:
        raise AssertionError(f"verify_token leaked {type(exc).__name__}: {exc}") from exc
    else:
        # An accept is not by itself a finding: an RFC 3161 wrapper legitimately
        # carries bytes outside its signature, so a mutated token can still be
        # valid. What it may never do is move the attestation or claim trust.
        if info.digest_hex != DIGEST:
            raise AssertionError(f"verify_token accepted a token over {info.digest_hex}")
        if info.trusted_chain:
            raise AssertionError("verify_token reported a trusted chain with no anchor supplied")

    try:
        TimestampToken.from_dict(_record_from(data))
    except TimestampError:
        return
    except Exception as exc:
        raise AssertionError(f"from_dict leaked {type(exc).__name__}: {exc}") from exc


def seed_corpus() -> Iterator[bytes]:
    """Small, deterministic inputs that reach each branch at least once.

    Written out by `fuzz/oss-fuzz/build.sh` as the target's seed corpus, and
    replayed by `tests/test_verify_fuzz.py` so a harness that stops importing,
    or stops holding, fails the merge gate rather than the next OSS-Fuzz run.
    """
    yield b""
    yield b"\x00"
    yield b"\x01"
    for kind in range(len(_KINDS)):
        prefix = bytes([kind])
        yield prefix
        yield prefix + b"!"  # not base64 at all
        yield prefix + b"AA=A"  # base64 alphabet, impossible padding
        yield prefix + b"\x30\x82\xff\xff"  # a DER header promising more than it has
        yield prefix + b"{}"
        yield prefix + b'{"tsa":"x","gen_time":"","digest":""}'
        yield prefix + bytes(range(256))


def main() -> None:  # pragma: no cover - the OSS-Fuzz / CLI entry point
    """Fuzz under Atheris when it is installed; otherwise replay inputs.

    libFuzzer already treats bare path arguments as a corpus to replay, so under
    Atheris there is nothing to special-case. Without it, this walks the same
    inputs by hand, which is what keeps the harness runnable -- and therefore
    honest -- on a laptop with only the project's own dependencies installed.
    """
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
