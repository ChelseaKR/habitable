# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""The published schema must accept the custody hashes this project actually writes.

`docs/packet-bundle.schema.json` is served under a public `$id` and
`docs/embedding-the-verifier.md` sends third parties to it. Nothing in this repository
validates a bundle against it, so a defect in the schema is invisible here and visible
only to the relying party — a court clerk, an inspector, an opposing party — who does
what the embedding guide tells them to.

One such defect was live: `custodyEntry.prev_hash` and `custodyProof.head_hash` were
each declared as

    "oneOf": [{"$ref": "#/$defs/hexSha256"}, {"type": "string", "pattern": "^0{64}$"}]

and `hexSha256` is `^[0-9a-f]{64}$`, which matches 64 zeros. `oneOf` requires **exactly
one** matching branch, so the documented genesis/empty-chain sentinel matched both and
was rejected. Every custody chain opens with that sentinel, so every packet this project
has ever produced failed its own published contract on `custody_proof.entries[0]` — the
first line of the custody proof, which is the most trust-critical part of the artifact.

These tests are deliberately **not** a JSON Schema implementation. A hand-rolled
validator risks passing by quietly failing to understand a keyword, which is the same
class of bug it would be checking for. Instead they evaluate one narrow keyword subset
over declared leaves, and **refuse any branch shape they do not recognise** rather than
skipping it.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from habitable.verify import REDUNDANCY_STATES

_ROOT = Path(__file__).resolve().parent.parent
_SCHEMA_PATH = _ROOT / "docs" / "packet-bundle.schema.json"

# Every bundle this repository publishes or commits, including the one served from the
# public site. `tests/test_golden.py` deliberately keeps `site/sample-packet` out of its
# corpus; here it belongs, because the site sample is exactly the artifact a stranger
# downloads and checks against the public `$id`.
_BUNDLE_PATHS = (
    "tests/golden/packet-v1/bundle.json",
    "tests/golden/packet-v2/bundle.json",
    "tests/golden/packet-v3/bundle.json",
    "tests/golden/packet-v4/bundle.json",
    "tests/golden/scoped-packet-v3/bundle.json",
    "tests/golden/sensor-packet-v4/bundle.json",
    "site/sample-packet/bundle.json",
)

# The walker below must keep finding the schema. If a refactor moves the file's shape,
# a scan that found nothing prints exactly the same clean line as one that read all of
# it, so a floor is asserted rather than assumed. Seven `oneOf` blocks remain after the
# two custody-hash ones were collapsed; this is a floor and not an equality, so adding
# or removing an alternative does not jam every other pull request in the repository.
_MIN_ONEOF_BLOCKS = 6


def _schema() -> dict[str, Any]:
    loaded: Any = json.loads(_SCHEMA_PATH.read_text("utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def _resolve(schema: dict[str, Any], node: dict[str, Any]) -> dict[str, Any]:
    """Follow a local `$ref` one level. Only `#/$defs/<name>` is supported."""
    ref = node.get("$ref")
    if ref is None:
        return node
    assert isinstance(ref, str) and ref.startswith("#/$defs/"), (
        f"unsupported $ref {ref!r}: this guard resolves only local #/$defs/ references"
    )
    target = schema["$defs"][ref.removeprefix("#/$defs/")]
    assert isinstance(target, dict)
    merged = {key: value for key, value in node.items() if key != "$ref"}
    return {**target, **merged}


def _accepts_string(schema: dict[str, Any], branch: dict[str, Any], value: str) -> bool:
    """Does this branch accept `value`, a string?

    Recognised keywords: `type`, `pattern`, `maxLength`, `minLength`, `const`, `enum`,
    and a local `$ref` to a def built from them. Anything else raises, so a branch shape
    this guard cannot evaluate fails the test loudly instead of silently reading as a
    non-match — which would make an overlap look like a clean disjoint pair.
    """
    node = _resolve(schema, branch)
    understood = {"type", "pattern", "maxLength", "minLength", "const", "enum", "description"}
    unknown = set(node) - understood
    assert not unknown, f"branch uses keyword(s) this guard cannot evaluate: {sorted(unknown)}"

    declared = node.get("type")
    if declared is not None and declared != "string":
        return False
    if "const" in node and value != node["const"]:
        return False
    if "enum" in node and value not in node["enum"]:
        return False
    maximum = node.get("maxLength")
    if maximum is not None and len(value) > maximum:
        return False
    minimum = node.get("minLength")
    if minimum is not None and len(value) < minimum:
        return False
    # JSON Schema's `pattern` is an unanchored search, not a full match.
    pattern = node.get("pattern")
    return pattern is None or re.search(pattern, value) is not None


def _literal_witnesses(node: dict[str, Any]) -> list[str]:
    """String values a branch documents by construction, for overlap testing.

    Only two shapes yield one, and both are exact rather than inferred: an anchored
    pattern that is a single repeated literal character (`^0{64}$` -> 64 zeros), and
    `maxLength: 0` (the empty string). A branch this cannot read contributes nothing,
    which is why the pairwise check below is not the only assertion in its test.
    """
    witnesses: list[str] = []
    pattern = node.get("pattern")
    if isinstance(pattern, str):
        literal = re.fullmatch(r"\^(.)\{(\d+)\}\$", pattern)
        if literal is not None:
            witnesses.append(literal.group(1) * int(literal.group(2)))
    if node.get("maxLength") == 0:
        witnesses.append("")
    return witnesses


def _oneof_blocks(node: Any, pointer: str = "") -> list[tuple[str, list[dict[str, Any]]]]:
    found: list[tuple[str, list[dict[str, Any]]]] = []
    if isinstance(node, dict):
        branches = node.get("oneOf")
        if isinstance(branches, list):
            found.append((pointer + "/oneOf", [b for b in branches if isinstance(b, dict)]))
        for key, value in node.items():
            found.extend(_oneof_blocks(value, f"{pointer}/{key}"))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            found.extend(_oneof_blocks(value, f"{pointer}/{index}"))
    return found


def test_the_published_schema_accepts_the_genesis_custody_link() -> None:
    """The sentinel every chain opens with must satisfy its own declared subschema.

    This fired on unmodified `origin/main`: 7 of 7 committed bundles were rejected at
    `custody_proof/entries/0/prev_hash`, because the sentinel matched both branches of
    a `oneOf`. It is asserted against the values the corpus really carries rather than
    against the string `"0" * 64`, so a fixture that changed shape is not silently
    exempted.
    """
    schema = _schema()
    declared = schema["$defs"]["custodyEntry"]["properties"]["prev_hash"]
    assert "oneOf" not in declared and "anyOf" not in declared, (
        "prev_hash is declared as a set of alternatives again. The genesis sentinel "
        "is a hexSha256 value, so a second branch for it either overlaps the first "
        "(rejecting every packet under `oneOf`) or is inert (under `anyOf`)."
    )

    checked = 0
    for relative in _BUNDLE_PATHS:
        bundle = json.loads((_ROOT / relative).read_text("utf-8"))
        entries = bundle["custody_proof"]["entries"]
        assert entries, f"{relative}: no custody entries to check"
        genesis = entries[0]["prev_hash"]
        assert _accepts_string(schema, declared, genesis), (
            f"{relative}: the published schema rejects the genesis prev_hash {genesis!r}"
        )
        checked += 1

    assert checked == len(_BUNDLE_PATHS), f"only {checked} bundle(s) reached the assertion"


def test_the_published_schema_accepts_an_empty_chain_head() -> None:
    """`head_hash` carried the identical defect, latent because no fixture is empty.

    The schema's own description names 64 zeros as the empty-chain value, so that value
    is the witness. No committed bundle exercises it — which is precisely why a fixture
    could not have caught this and a declaration-level assertion has to.
    """
    schema = _schema()
    declared = schema["$defs"]["custodyProof"]["properties"]["head_hash"]
    assert "oneOf" not in declared and "anyOf" not in declared, (
        "head_hash is declared as a set of alternatives again; see prev_hash."
    )
    assert "64 zeros" in declared["description"], (
        "the empty-chain sentinel is no longer documented here, so this witness is stale"
    )
    assert _accepts_string(schema, declared, "0" * 64), (
        "the published schema rejects the documented empty-chain head_hash"
    )
    # And it still has teeth: a value that is not a lowercase hex digest is refused.
    assert not _accepts_string(schema, declared, "0" * 63)
    assert not _accepts_string(schema, declared, "F" * 64)


def test_no_oneof_in_the_published_schema_has_overlapping_branches() -> None:
    """The rule, not the two instances of it.

    `oneOf` means *exactly one*, so two branches that both accept a value reject it.
    Where the branches are alternative shapes (an object or `null`) that is fine and
    intended; where one documents a special-case string the other already matches, the
    document becomes unpublishable at exactly the value the description highlights.
    """
    schema = _schema()
    blocks = _oneof_blocks(schema)
    assert len(blocks) >= _MIN_ONEOF_BLOCKS, (
        f"found only {len(blocks)} oneOf block(s); this walker has stopped reading the "
        f"schema, and an empty scan looks exactly like a clean one"
    )

    witnesses_tested = 0
    for pointer, branches in blocks:
        for branch in branches:
            for witness in _literal_witnesses(_resolve(schema, branch)):
                accepting = [b for b in branches if _accepts_string(schema, b, witness)]
                assert len(accepting) == 1, (
                    f"{pointer}: {len(accepting)} of {len(branches)} branches accept the "
                    f"documented value {witness[:8]!r}(len {len(witness)}); `oneOf` needs "
                    f"exactly one, so this value is rejected by the published contract"
                )
                witnesses_tested += 1

    assert witnesses_tested >= 1, (
        "no literal witness was derivable from any oneOf branch, so this test asserted "
        "nothing; either the schema changed shape or _literal_witnesses stopped reading it"
    )


def test_the_schema_declares_the_device_count_this_project_actually_writes() -> None:
    """`appendix.redundancy` (issue #297) — the contract and the producer, compared.

    The published schema is the only description of this field a third party
    reads, and nothing else in this repository holds it to what `packet.py`
    emits. Two directions are checked: every key the producer always writes is
    `required` here, and the vocabulary the schema's prose names is the one the
    code enforces -- so widening `REDUNDANCY_STATES` without saying so in the
    document served under the public `$id` fails here rather than in a stranger's
    validator.
    """
    declared = _schema()["properties"]["appendix"]["properties"]["redundancy"]

    # What `packet._redundancy_json` writes unconditionally. `as_of` is
    # deliberately absent: it is omitted, never defaulted, when the producing
    # device recorded no time for the most recent acknowledgement.
    assert set(declared["required"]) == {
        "state",
        "device_count",
        "acknowledged_by",
        "identities_included",
    }
    assert "as_of" not in declared["required"]
    assert declared["properties"]["as_of"]["type"] == "string"

    # A count of devices always includes the device that wrote the packet.
    assert declared["properties"]["device_count"]["minimum"] == 1
    assert declared["properties"]["acknowledged_by"]["minimum"] == 0

    # The one closure that belongs here. A packet counts devices; the only
    # honest way this could become true is a different field.
    assert declared["properties"]["identities_included"]["const"] is False

    # And the one that does not. `state` stays a plain string in the published
    # contract: an enum in a document served under a pinned `$id` rejects a
    # document its own producer considers valid on the day a member is added.
    state = declared["properties"]["state"]
    assert state["type"] == "string"
    assert "enum" not in state and "const" not in state, (
        "`state` is an enum again. A consumer pinned to this $id would then "
        "reject a packet the producer considers valid the first time the "
        "vocabulary grows; habitable's own verifier is where it is closed."
    )
    assert REDUNDANCY_STATES, "the vocabulary is empty; this comparison reads nothing"
    for word in REDUNDANCY_STATES:
        assert f"'{word}'" in declared["description"], (
            f"the published schema's prose does not name the state {word!r} that "
            f"this project's producer can write"
        )
    assert declared["additionalProperties"] is True
