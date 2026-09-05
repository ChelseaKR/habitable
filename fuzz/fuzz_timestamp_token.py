#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0
# Copyright 2026 Chelsea Kelly-Reif
"""Continuous-fuzzing harness for timestamp-token parse and verify (issue #256).

The entry points here are the two a skeptic reaches when a packet hands them a
proof of time: :func:`habitable.tsa.TimestampToken.from_dict`, which parses a
stored record, and :func:`habitable.tsa.verify_token`, which checks a dev token's
signed canonical document or an RFC 3161 CMS blob. Both take bytes an adversary
chose.

Mutations start from a token that really verifies
-------------------------------------------------
The first version of this harness built ``TimestampToken(data=data[1:])`` out of
raw fuzz bytes and then asserted three properties about a *returned*
:class:`~habitable.tsa.TimestampInfo`. Reaching a return needs a valid Ed25519
signature over canonical JSON, or valid CMS SignedData; a fuzzer does not guess
either. Measured over the seed corpus plus 200,000 random inputs, ``verify_token``
returned exactly **zero** times, so two of the three properties were executed by
nothing and could not have failed. A dev token patched to manufacture
``trusted_chain=True`` was reported clean by the whole harness.

So every iteration now starts from a token that verifies -- a dev token minted
here from a fixed key, and the RFC 3161 token the committed golden packet ships --
and spends the fuzzer's bytes overwriting a slice of it. An input of one byte
leaves the token untouched, which is what keeps the accept path *reachable on
every run* rather than by luck; longer inputs walk outward from something valid,
which is where a parser's interesting states are. `fuzz_verify_packet.py` seeds
from the pristine golden bundle for the same reason.

The properties, and why each one can fail
-----------------------------------------
1. **One named error.** A hostile record or token yields :class:`TimestampError`
   and nothing else. A ``binascii.Error`` from a bad base64 alphabet, an
   ``asn1crypto`` parse failure, an ``IndexError`` off the end of a truncated
   structure -- any of those escaping is the bug, because a caller embedding the
   verifier catches the project's own exception type and would see a traceback
   instead of a verdict.
2. **No accept without an anchor.** With no ``trusted_certs`` supplied, no input
   may return ``trusted_chain=True``. Trust is something a recipient configures;
   it can never be something a token asserts about itself.
3. **No accept over other content.** Stated as a second verification of the same
   token against a digest nothing ever stamped, which must be refused. It cannot
   be stated as ``info.digest_hex != digest``: both verifiers *echo* the digest
   they were asked about into the result, so that comparison is False by
   construction even when the check that earns it has been deleted. The second
   call is the only form of this property that a broken verifier fails.
4. **A record survives the round trip.** ``to_dict``/``from_dict`` must return
   the same token bytes -- the base64 spelling a packet stores is load-bearing,
   because :func:`habitable.tsa._canonical_b64` rejects alternate spellings of
   the same bytes and a producer that emitted one would export unverifiable
   evidence.

Why continuously and not just in CI: `tests/test_property_invariants.py` sweeps a
shaped space for a few seconds per merge. OSS-Fuzz keeps a corpus across runs and
spends hours on the inputs that need hours -- and a timestamp token is a
structured binary format where that difference is the whole game.

Running it locally, with or without Atheris::

    python fuzz/fuzz_timestamp_token.py                  # replay the seed corpus
    python fuzz/fuzz_timestamp_token.py corpus/          # replay a directory
    pip install atheris && python fuzz/fuzz_timestamp_token.py -atheris_runs=100000

`tests/test_verify_fuzz.py` also imports this module and runs the seed corpus
through it on every merge, so the harness cannot rot while nobody is looking, and
pins that the accept path is still reached.
"""

from __future__ import annotations

import contextlib
import json
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
    from habitable.crypto import Identity
    from habitable.errors import TimestampError
    from habitable.tsa import DevTSA, TimestampToken, verify_token

if TYPE_CHECKING:
    from collections.abc import Iterator


def golden_root() -> Path:
    """The committed golden fixtures, in a checkout *and* in a compiled target.

    `compile_python_fuzzer` is ``pyinstaller --onefile``, which bundles imported
    modules and not data files. A harness that resolves a fixture relative to
    ``__file__`` therefore works in a clone and raises ``FileNotFoundError`` on
    startup in the fuzzing image, where there is no repository -- fuzzing nothing
    until somebody reads the build log. `fuzz/oss-fuzz/build.sh` passes
    ``--add-data <repo>/tests/golden:habitable-golden`` for that reason, and
    PyInstaller unpacks it under ``sys._MEIPASS`` at run time; this looks there
    first and falls back to the checkout.

    Raising here rather than degrading to a synthetic fixture is deliberate: a
    target that quietly fuzzes a stand-in nobody reviewed is the same failure as
    a target that fuzzes nothing, minus the traceback that would have said so.
    """
    bundled = getattr(sys, "_MEIPASS", "")  # set only inside a PyInstaller bundle
    candidates = [Path(str(bundled)) / "habitable-golden"] if bundled else []
    candidates.append(_REPO_ROOT / "tests" / "golden")
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    raise RuntimeError(
        "cannot find tests/golden: this harness needs the committed fixtures, so a "
        "compiled target must be built with --add-data <repo>/tests/golden:habitable-golden "
        f"(looked in: {', '.join(str(path) for path in candidates)})"
    )


#: A dev token that really verifies, from a key fixed in this file. Nothing here
#: is secret -- the "authority" is a local Ed25519 key that `habitable.tsa`
#: reports as an untrusted chain by construction -- and fixing it keeps the
#: harness deterministic, which is what makes a libFuzzer reproducer reproduce.
_DEV_IDENTITY = Identity.deserialize(bytes(range(64)))
_DEV_DIGEST = sha256_bytes(b"habitable fuzz target: content the dev seed token attests to")
_DEV_TOKEN = DevTSA(
    "fuzz-dev-tsa",
    identity=_DEV_IDENTITY,
    # The fixed instant `tests/conftest.py` uses, for the same reason.
    time_source=lambda: 1_767_312_000,
).stamp(_DEV_DIGEST)


def _golden_rfc3161_seed() -> tuple[bytes, str]:
    """The RFC 3161 token the golden packet ships, and the digest it covers.

    Minted by a real (offline, self-signed) authority when the fixture was
    generated, and committed -- so it is both a *real* CMS SignedData structure
    and a fixed one. Minting a fresh one here instead would re-key the seed on
    every process, which is the one thing a fuzz target must not do: an input
    that crashed yesterday has to crash again today.
    """
    packet = json.loads((golden_root() / "packet-v4" / "bundle.json").read_bytes())
    for item in packet["items"]:
        stored = item.get("timestamp")
        if isinstance(stored, dict) and stored.get("kind") == "rfc3161":
            return TimestampToken.from_dict(stored).data, str(item["content_hash"])
    raise RuntimeError("the golden packet no longer ships an RFC 3161 timestamp to seed from")


_RFC3161_TOKEN_DATA, _RFC3161_DIGEST = _golden_rfc3161_seed()

#: How the first input byte is spent: which token the fuzzer's bytes are edited
#: into, and which digest that token is asked about. The two empty bases keep the
#: original behaviour -- fuzzer bytes as the *whole* token -- because the record
#: and CMS parsers have failure modes (base64 alphabet, padding, truncated DER)
#: that are reached from nowhere near a valid token.
_CASES: tuple[tuple[str, bytes, str], ...] = (
    ("dev", _DEV_TOKEN.data, _DEV_DIGEST),
    ("rfc3161", _RFC3161_TOKEN_DATA, _RFC3161_DIGEST),
    ("dev", b"", _DEV_DIGEST),
    ("rfc3161", b"", _RFC3161_DIGEST),
)

#: Both token kinds, for the record parser, which is a separate entry point.
_KINDS = ("dev", "rfc3161")

#: A digest of content no authority in this file ever stamped. Property 3 is
#: stated against it: whatever a token proves, it cannot also prove this.
_NEVER_STAMPED = sha256_bytes(b"habitable fuzz target: content that was never stamped")


def _edit(base: bytes, patch: bytes) -> bytes:
    """Overwrite a slice of ``base`` with ``patch[1:]``, at an offset ``patch[0]`` picks.

    Overwrite rather than insert, so a DER structure keeps its declared lengths
    and a mutation reaches the fields *inside* it rather than stopping at the
    outermost length check. An empty patch leaves the base alone, which is how
    the accept path stays reachable on every run.
    """
    if not base:
        return patch
    if not patch:
        return base
    offset = patch[0] * len(base) // 256
    body = patch[1:]
    return base[:offset] + body + base[offset + len(body) :]


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


def _must_refuse_other_content(token: TimestampToken) -> None:
    """Property 3: a token that verified must not also verify over other content.

    Called only after an accept, so the token is one the verifier just vouched
    for. Whatever it proves, it cannot also prove :data:`_NEVER_STAMPED` -- a
    token commits to one digest, and a verifier that returns for two of them has
    stopped comparing the one it was asked about.
    """
    try:
        verify_token(token, _NEVER_STAMPED)
    except TimestampError:
        return
    except Exception as exc:
        raise AssertionError(f"verify_token leaked {type(exc).__name__}: {exc}") from exc
    raise AssertionError(
        "verify_token accepted one token over two different digests, so the "
        "attestation does not bind the content it was asked about"
    )


def TestOneInput(data: bytes) -> None:  # noqa: N802 - the name libFuzzer requires
    """One fuzz iteration. Returning normally means the input found nothing."""
    kind, base, digest = _CASES[data[0] % len(_CASES)] if data else _CASES[0]
    token = TimestampToken(kind=kind, tsa_name="fuzz", data=_edit(base, data[1:]))

    try:
        info = verify_token(token, digest)
    except TimestampError:
        pass
    except Exception as exc:
        raise AssertionError(f"verify_token leaked {type(exc).__name__}: {exc}") from exc
    else:
        # An accept is not by itself a finding: an RFC 3161 wrapper legitimately
        # carries bytes outside its signature, and an unedited seed token is
        # supposed to verify. What an accept may never do is claim trust nobody
        # anchored, or cover content this token does not attest to.
        if info.trusted_chain:
            raise AssertionError("verify_token reported a trusted chain with no anchor supplied")
        _must_refuse_other_content(token)

    if TimestampToken.from_dict(token.to_dict()).data != token.data:
        raise AssertionError("a token record did not survive to_dict/from_dict unchanged")

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
    stops holding, or stops *reaching* its accept path fails the merge gate
    rather than the next OSS-Fuzz run.
    """
    yield b""
    for index in range(len(_CASES)):
        prefix = bytes([index])
        yield prefix  # the unedited seed: the accept path, on every run
        yield prefix + b"\x00"  # a one-byte patch: still unedited, offset 0
        yield prefix + b"\x00!"  # not base64 at all, and not DER
        yield prefix + b"\x80AA=A"  # base64 alphabet, impossible padding
        yield prefix + b"\x00\x30\x82\xff\xff"  # a DER header promising more than it has
        yield prefix + b"\x00{}"
        yield prefix + b'\x00{"tsa":"x","gen_time":"","digest":""}'
        yield prefix + b"\xff" + bytes(range(256))  # off the end of the seed
        yield prefix + b"\x40" + bytes(range(64))  # into the middle of it


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
