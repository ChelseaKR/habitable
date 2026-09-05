#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0
# Copyright 2026 Chelsea Kelly-Reif
"""Continuous-fuzzing harness for the packet verifier (issue #256).

`habitable.verify.verify_packet` is the one function in this project whose entire
purpose is to be run by a skeptic, on a directory an adversary prepared, with a
result someone may have to defend in a housing dispute. That makes it the natural
target for fuzzing that runs for hours rather than the few seconds a merge gate
can spend.

Each iteration takes a real committed golden packet, changes one part of it, and
verifies. Two properties:

1. **Never a crash.** The only exception `verify_packet` may raise is
   :class:`VerificationError`. Anything else -- a ``KeyError`` on a missing field,
   a ``TypeError`` on a wrong-typed one, a decoder blowing up on a truncated
   structure -- is a bug, because an embedder catches the project's own exception
   type and a traceback is not a verdict.
2. **Never an accept on tamper.** Unless the fuzzer has reproduced the exported
   bytes exactly, the report must not come back structurally intact.

Which check is doing the work, and the mode that exists because of it
---------------------------------------------------------------------
Property 2 has to be read one mode at a time, because the modes are not equally
demanding of the verifier:

* Overwriting ``bundle.json`` or ``bundle.sig.json`` invalidates the detached
  signature, and ``structurally_intact`` is False from that alone. Measured on the
  first version of this harness, over the 297 mutated bundles the merge gate's
  hypothesis tests produced, ``signature_ok`` was True **zero** times. Deleting
  the entire v3/v4 structural dispatch from `verify.py` left the harness
  reporting nothing, because no content check ever got to have an opinion. These
  modes are honest *crash* fuzzing, and property 2 over them is a backstop, not a
  test of the content checks.
* Overwriting a media file leaves the signature valid, so the per-item digest
  check is what has to notice. That mode does test a content check.
* ``rewrite-a-committed-position`` (below) rewrites a field the bundle commits to
  and then **re-signs**, exactly as a producer rewriting their own export would.
  The signature is valid again, so the verdict is decided by the artifact
  commitments, the custody bindings, the relationship and timeline structures and
  the profile/handoff consistency rules -- and nothing else.

``structurally_intact``, not ``report.ok``
------------------------------------------
Property 2 is stated against ``structurally_intact``, deliberately, and not
against ``report.ok``. ``ok`` is an alias for ``evidence_ready``, which also
requires a trusted timestamp anchor; the golden corpus ships no trust root, so
``ok`` is already False for a *pristine* golden packet and an assertion built on
it can never fail. Same reasoning as the stateful machine in
`tests/test_property_invariants.py`, whose acceptance predicate
:func:`is_accepted` reproduces here.

Running it locally, with or without Atheris::

    python fuzz/fuzz_verify_packet.py                    # replay the seed corpus
    python fuzz/fuzz_verify_packet.py corpus/            # replay a directory
    pip install atheris && python fuzz/fuzz_verify_packet.py -atheris_runs=100000
"""

from __future__ import annotations

import base64
import contextlib
import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

try:  # Atheris is present under OSS-Fuzz and optional everywhere else.
    import atheris as _atheris
except ModuleNotFoundError:  # pragma: no cover - exercised only off OSS-Fuzz
    _atheris = None  # type: ignore[assignment]

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "src"))

# Coverage instrumentation has to wrap the *import* of the code under test.
with _atheris.instrument_imports() if _atheris else contextlib.nullcontext():
    from habitable.canonical import JSONValue, canonical_json, sha256_bytes
    from habitable.crypto import Identity
    from habitable.errors import VerificationError
    from habitable.verify import SUPPORTED_PACKET_VERSION, VerificationReport, verify_packet

if TYPE_CHECKING:
    from collections.abc import Iterator


def golden_root() -> Path:
    """The committed golden fixtures, in a checkout *and* in a compiled target.

    `compile_python_fuzzer` is ``pyinstaller --onefile``, which bundles imported
    modules and not data files. This harness needs a whole packet directory, so
    resolving it relative to ``__file__`` worked in a clone and raised
    ``FileNotFoundError`` on startup in the fuzzing image, where there is no
    repository -- before `atheris.Setup`, so the target fuzzed nothing at all
    until somebody read the build log. `fuzz/oss-fuzz/build.sh` passes
    ``--add-data <repo>/tests/golden:habitable-golden`` for that reason, and
    PyInstaller unpacks it under ``sys._MEIPASS`` at run time; this looks there
    first and falls back to the checkout.

    Raising here rather than degrading to a synthetic packet is deliberate: a
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


#: The seed packet. The newest committed format on purpose: `_verify_v3_timeline`
#: and `_verify_v4_workflows` are gated on `packet_version`, so fuzzing an older
#: fixture leaves several hundred lines of hostile-input parsing untouched --
#: the gap issue #160 found in the in-repo harness, which must not be recreated
#: here in the harness that is supposed to run for hours.
SEED_PACKET = golden_root() / f"packet-v{SUPPORTED_PACKET_VERSION}"

#: How the first input byte is spent. Every part of a packet a recipient reads is
#: reachable, and the last two modes exist because the first three cannot reach
#: the content checks (see the module docstring).
_MODES = (
    "replace-bundle",
    "replace-signature",
    "replace-media",
    "splice-bundle",
    "rewrite-a-committed-position",
)

_WORK = Path(tempfile.mkdtemp(prefix="habitable-fuzz-verify-")) / "packet"
shutil.copytree(SEED_PACKET, _WORK)
_PRISTINE = {
    path.relative_to(_WORK): path.read_bytes()
    for path in sorted(_WORK.rglob("*"))
    if path.is_file()
}
_MEDIA_NAMES = sorted(path.name for path in (_WORK / "media").iterdir())
_PRISTINE_BUNDLE_BYTES = _PRISTINE[Path("bundle.json")]

# ---------------------------------------------------------------------------
# What the bundle commits to
# ---------------------------------------------------------------------------

#: Positions in ``bundle.json`` whose value the packet commits to *internally* --
#: through a custody entry, an integrity commitment, an appendix count, a
#: cross-structure identity, or a consistency rule the verifier applies. Rewriting
#: any of them must be detected **even when the rewriter re-signs**, because the
#: contradiction is with something other than the signature.
#:
#: This is the inventory the accept property is stated over, and it is what a
#: deleted check fails. Swept exhaustively against a clean tree -- 295 positions
#: in the v4 fixture x the seven replacements below, 2054 rewrites that change
#: something -- nothing was accepted. With `verify.py`'s two-line v3/v4 dispatch
#: deleted, 948 of the same 2054 were accepted in silence.
#:
#: A trailing ``"..."`` means "this position and everything under it"; ``"*"``
#: matches one array index. The list is deliberately *not* the whole bundle:
#: free text (``scope``, ``template``, ``unit``, ``case_id``), presentational
#: mirrors (``handoff_views[*].sections`` -- ``source_of_truth`` is bundle.json by
#: construction) and counts nothing recomputes are all things a producer can
#: legitimately re-export differently, and asserting they cannot be would be
#: asserting something false. The recipient-side answer to *those* is the pinned
#: producer key, which `tests/test_property_invariants.py` holds to.
#:
#: `tests/test_verify_fuzz.py` imports this tuple, sweeps it, and fails if any
#: entry stops matching a real position in the current fixture -- so a renamed
#: field cannot silently empty a family and take its coverage with it.
COMMITTED_POSITIONS: tuple[tuple[str, ...], ...] = (
    ("packet_version",),
    ("custody_proof", "head_hash"),
    ("custody_proof", "entries", "..."),
    ("timeline", "..."),
    ("use_case_profile", "..."),
    ("appendix", "timeline_count"),
    ("appendix", "custody_bound_timeline_count"),
    ("appendix", "artifact_count"),
    ("appendix", "relationship_count"),
    ("issues", "*", "issue_id"),
    ("items", "*", "capture_id"),
    ("items", "*", "content_hash"),
    ("items", "*", "shared_hash"),
    ("items", "*", "shared_name"),
    ("items", "*", "record_kind"),
    ("items", "*", "timestamp", "..."),
    ("items", "*", "artifact", "..."),
    ("items", "*", "integrity", "..."),
    ("relationships", "*", "relationship_id"),
    ("relationships", "*", "relationship_schema"),
    ("relationships", "*", "relationship_type"),
    ("relationships", "*", "source_id"),
    ("relationships", "*", "target_id"),
    ("relationships", "*", "issue_id"),
    ("relationships", "*", "assertion"),
    ("relationships", "*", "recorded_at"),
    ("relationships", "*", "integrity", "..."),
    ("handoff_views", "*", "presentation_only"),
    ("handoff_views", "*", "source_of_truth"),
    ("handoff_views", "*", "profile_id"),
    ("handoff_views", "*", "profile", "..."),
    ("handoff_views", "*", "disclosures", "..."),
)

#: Positions that fall *inside* a family above and are still not commitments.
#: Two, each for a stated reason, and each subtracted here rather than by
#: narrowing the family above -- so a field added to a committed structure
#: tomorrow is covered by default, and someone has to come here and say why if
#: it is not.
UNCOMMITTED_POSITIONS: tuple[tuple[str, ...], ...] = (
    # An opaque ordering token. `verify._v3_timeline_semantic_payload` names the
    # exact fields `timeline_sha256` covers, and this is deliberately not one of
    # them; the entry's meaning -- who, what, when, and what it links to -- is.
    ("timeline", "*", "order_token"),
    # A display label for the authority. What proves the time is the token, whose
    # issuer identity lives inside its own signed structure, so the label beside
    # it is not what a recipient is asked to trust.
    ("items", "*", "timestamp", "tsa_name"),
)


class _Delete:
    """The sentinel that means "delete this position" rather than "replace it"."""

    def __repr__(self) -> str:
        return "<delete>"


DELETE = _Delete()

#: What a rewrite puts there. A wrong type, an empty value, a null, and a string
#: no producer wrote -- enough shapes that a check which only rejects one of them
#: is not mistaken for a check.
REPLACEMENTS: tuple[object, ...] = (DELETE, 12345, "", None, [], {}, "rewritten-after-export")


def positions(node: Any, prefix: tuple[str | int, ...] = ()) -> Iterator[tuple[str | int, ...]]:
    """Every addressable position in a bundle, nested objects and arrays included."""
    if isinstance(node, dict):
        for key in sorted(node):
            here = (*prefix, key)
            yield here
            yield from positions(node[key], here)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            here = (*prefix, index)
            yield here
            yield from positions(value, here)


def matches(path: tuple[str | int, ...], pattern: tuple[str, ...]) -> bool:
    for index, step in enumerate(pattern):
        if step == "...":  # this position and everything under it
            return True
        if index >= len(path):
            return False
        if step == "*":
            if not isinstance(path[index], int):
                return False
        elif path[index] != step:
            return False
    return len(path) == len(pattern)


def committed_paths(bundle: Any) -> list[tuple[str | int, ...]]:
    """Concrete positions in ``bundle`` matching :data:`COMMITTED_POSITIONS`."""
    return [
        path
        for path in positions(bundle)
        if any(matches(path, pattern) for pattern in COMMITTED_POSITIONS)
        and not any(matches(path, pattern) for pattern in UNCOMMITTED_POSITIONS)
    ]


def rewrite(bundle: Any, path: tuple[str | int, ...], replacement: object) -> None:
    """Delete or replace one position, in place."""
    parent = bundle
    for step in path[:-1]:
        parent = parent[step]
    if replacement is DELETE:
        del parent[path[-1]]
    else:
        parent[path[-1]] = replacement


def resign(packet_dir: Path) -> None:
    """Sign the bundle on disk with a freshly generated producer key.

    A packet's signature carries its own verifying key (FIX-05), so anyone who
    rewrites a bundle can also re-sign it and the open trust policy cannot tell
    them from the producer -- which is why re-signing is the only way to ask the
    content checks what they think. The pinned policy is the answer to the
    rewrite itself and is asserted in `tests/test_property_invariants.py`.
    """
    digest = sha256_bytes((packet_dir / "bundle.json").read_bytes())
    identity = Identity.generate()
    public = identity.public()
    record: dict[str, JSONValue] = {
        "bundle_sha256": digest,
        "producer_fingerprint": public.fingerprint,
        "sign_public": base64.b64encode(public.sign_public).decode("ascii"),
        "signature": base64.b64encode(identity.sign(digest.encode("ascii"))).decode("ascii"),
    }
    (packet_dir / "bundle.sig.json").write_bytes(canonical_json(record))


def is_accepted(report: VerificationReport) -> bool:
    """The predicate `tests/test_golden.py` uses for a packet with no trust root.

    Not ``report.ok``: see the module docstring. Stronger than
    ``structurally_intact`` alone, because stripping an item's timestamp token
    leaves a packet that is structurally intact and cryptographically unanchored,
    and a rewrite must not be able to buy silence that way.
    """
    return (
        report.structurally_intact
        and report.signature_ok
        and report.custody_ok
        and bool(report.items)
        and report.cryptographically_verified_items == len(report.items)
    )


# ---------------------------------------------------------------------------
# The target
# ---------------------------------------------------------------------------


def _restore() -> None:
    for relative, payload in _PRISTINE.items():
        (_WORK / relative).write_bytes(payload)


def _splice(base: bytes, patch: bytes) -> bytes:
    """Overwrite a slice of ``base`` with ``patch[1:]``, at an offset ``patch[0]`` picks.

    Whole-file replacement rarely produces anything the JSON parser gets past, so
    on its own it never reaches the structural checks it is supposed to be
    fuzzing. Splicing keeps the rest of a real bundle around the fuzzer's bytes.
    """
    if not patch:
        return base
    offset = patch[0] * len(base) // 256
    body = patch[1:]
    return base[:offset] + body + base[offset + len(body) :]


#: Walked once: this is a fixed list for a fixed fixture, and an OSS-Fuzz run
#: calls the target millions of times.
_COMMITTED_PATHS = committed_paths(json.loads(_PRISTINE_BUNDLE_BYTES))


def _rewrite_a_committed_position(body: bytes) -> bool:
    """Rewrite one committed position and re-sign. False if the input changed nothing."""
    paths = _COMMITTED_PATHS
    index = int.from_bytes(body[:2], "big") % len(paths) if len(body) >= 2 else 0
    replacement = REPLACEMENTS[body[2] % len(REPLACEMENTS)] if len(body) > 2 else DELETE
    bundle = json.loads(_PRISTINE_BUNDLE_BYTES)
    rewrite(bundle, paths[index], replacement)
    rewritten = canonical_json(bundle)
    if rewritten == _PRISTINE_BUNDLE_BYTES:  # replaced a value with the same value
        return False
    (_WORK / "bundle.json").write_bytes(rewritten)
    resign(_WORK)
    return True


def _plant(data: bytes) -> tuple[str, Path | None]:
    """Change one part of the packet; return the mode and the file it wrote, if any."""
    mode = _MODES[data[0] % len(_MODES)] if data else _MODES[0]
    body = data[1:]
    if mode == "replace-signature":
        path = _WORK / "bundle.sig.json"
    elif mode == "replace-media":
        name = _MEDIA_NAMES[body[0] % len(_MEDIA_NAMES)] if body else _MEDIA_NAMES[0]
        path = _WORK / "media" / name
        body = body[1:]
    elif mode == "splice-bundle":
        path = _WORK / "bundle.json"
        body = _splice(_PRISTINE_BUNDLE_BYTES, body)
    elif mode == "rewrite-a-committed-position":
        return mode, (_WORK / "bundle.json" if _rewrite_a_committed_position(body) else None)
    else:
        path = _WORK / "bundle.json"
    path.write_bytes(body)
    return mode, path


def TestOneInput(data: bytes) -> None:  # noqa: N802 - the name libFuzzer requires
    """One fuzz iteration. Returning normally means the input found nothing."""
    _restore()
    mode, planted = _plant(data)
    if planted is None:  # the input asked for a rewrite that rewrote nothing
        return

    try:
        report = verify_packet(_WORK)
    except VerificationError:
        return  # a named, handled rejection is the contract
    except Exception as exc:
        raise AssertionError(f"verify_packet crashed with {type(exc).__name__}: {exc}") from exc

    if mode == "rewrite-a-committed-position":
        # The signature is valid again, so nothing but the content checks stands
        # between this packet and an accept.
        if is_accepted(report):
            raise AssertionError(
                "verify_packet accepted a packet after a position the bundle commits to "
                "was rewritten and the bundle re-signed"
            )
        return

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
    """Small, deterministic inputs that reach each mode and each early exit.

    Written out by `fuzz/oss-fuzz/build.sh` as the target's seed corpus, and
    replayed by `tests/test_verify_fuzz.py` on every merge so the harness cannot
    quietly stop working between OSS-Fuzz runs.
    """
    yield b""
    for index in range(len(_MODES)):
        prefix = bytes([index])
        yield prefix
        yield prefix + b"{}"
        yield prefix + b"["
        yield prefix + b'{"packet_version": 4}'
        yield prefix + b'{"packet_version": 99999, "items": []}'
        yield prefix + b"\x00" * 64
        yield prefix + bytes(range(256))
    # Every replacement shape, over a spread of committed positions, so the mode
    # that carries the accept property is exercised by the merge gate and not
    # only by a fuzzer that happens to reach it.
    rewrite_mode = bytes([_MODES.index("rewrite-a-committed-position")])
    total = len(_COMMITTED_PATHS)
    for step in range(0, total, max(total // 12, 1)):
        for replacement in range(len(REPLACEMENTS)):
            yield rewrite_mode + step.to_bytes(2, "big") + bytes([replacement])
    # The exported bundle itself, so the "intact" branch is a covered path rather
    # than dead code that only a lucky fuzzer would ever reach.
    yield bytes([_MODES.index("replace-bundle")]) + _PRISTINE_BUNDLE_BYTES


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
