# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Every committed packet must validate against the schema published beside it.

`docs/packet-bundle.schema.json` is served under a public `$id`, and
`docs/embedding-the-verifier.md` tells a court clerk, an inspector or an opposing party
to run `jsonschema.validate` against it. Until this file existed nothing in the
repository did that, so the schema drifted from the packets twice without a red build:
the custody action enum was missing the two actions packet v4 added, and the item
object required `archive_timestamps`, a field v1 packets never carried.

This is a real JSON Schema 2020-12 validator (`jsonschema`, a dev-only dependency; the
runtime, `verify` and `kernel` installs never see it), run over every golden and
sample packet in the tree. The corpus is discovered, not listed, so a packet committed
later is validated without anyone remembering to add it here.

`archive_timestamps` is **required from packet_version 2 onward** (owner decision,
2026-09-18): the schema says so with a document-level `if`/`then` keyed on
`packet_version`, so a v1 packet validates without the field and a v2+ item that drops
it is rejected. The negative controls below prove each side of that, and that the
validator rejects an invalid packet at all.
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from habitable.verify import SUPPORTED_PACKET_VERSION

_ROOT = Path(__file__).resolve().parent.parent
_SCHEMA_PATH = _ROOT / "docs" / "packet-bundle.schema.json"
_BUNDLE_SCHEMA_DOC = _ROOT / "docs" / "bundle-schema.md"

# Where committed packets live: the golden corpus, and the synthetic sample the public
# site serves. Both are searched recursively for `bundle.json`.
_PACKET_ROOTS = (_ROOT / "tests" / "golden", _ROOT / "site")

# The corpus holds eight packets today. A floor rather than an equality, so adding a
# fixture does not jam every other pull request; its job is to make a discovery that
# found nothing fail instead of passing an empty parametrization.
_MIN_PACKETS = 8


def _packets() -> list[Path]:
    found: list[Path] = []
    for root in _PACKET_ROOTS:
        found.extend(sorted(root.rglob("bundle.json")))
    return found


def _load(path: Path) -> dict[str, Any]:
    loaded: Any = json.loads(path.read_text("utf-8"))
    assert isinstance(loaded, dict), f"{path} is not a JSON object"
    return loaded


def _validator() -> Draft202012Validator:
    schema = _load(_SCHEMA_PATH)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def _errors(bundle: dict[str, Any]) -> list[str]:
    """Every validation error, as `path: message`, in a stable order."""
    found = _validator().iter_errors(bundle)
    return sorted(
        f"/{'/'.join(str(p) for p in error.absolute_path)}: {error.message}" for error in found
    )


def _relative(path: Path) -> str:
    return path.relative_to(_ROOT).as_posix()


def test_the_published_schema_is_a_valid_2020_12_schema() -> None:
    schema = _load(_SCHEMA_PATH)
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    Draft202012Validator.check_schema(schema)


def test_the_corpus_was_found_and_spans_every_packet_version() -> None:
    """Non-vacuity: an empty discovery must not read as a clean one."""
    packets = _packets()
    assert len(packets) >= _MIN_PACKETS, f"found only {len(packets)} packet(s)"
    names = {_relative(path) for path in packets}
    assert "site/sample-packet/bundle.json" in names, "the public sample packet was not found"
    versions = {_load(path)["packet_version"] for path in packets}
    assert versions == set(range(1, SUPPORTED_PACKET_VERSION + 1)), (
        f"the corpus covers packet versions {sorted(versions)}, "
        f"not every version in 1..{SUPPORTED_PACKET_VERSION}"
    )


@pytest.mark.parametrize("packet", _packets(), ids=_relative)
def test_every_committed_packet_validates_against_the_published_schema(packet: Path) -> None:
    errors = _errors(_load(packet))
    assert not errors, f"{_relative(packet)} fails the published schema:\n" + "\n".join(errors)


# --- negative controls ------------------------------------------------------------
#
# A validator that accepts everything passes the test above. Each control starts from
# a committed packet that validates, applies one mutation, asserts the mutation
# actually landed (a sabotage that silently no-ops reads as a pass), and asserts the
# result is rejected for the reason the mutation introduced.


def _golden(name: str) -> dict[str, Any]:
    return _load(_ROOT / "tests" / "golden" / name / "bundle.json")


def _later_version_packets() -> list[Path]:
    return [path for path in _packets() if _load(path)["packet_version"] >= 2]


@pytest.mark.parametrize("packet", _later_version_packets(), ids=_relative)
def test_a_v2_or_later_item_without_archive_timestamps_is_rejected(packet: Path) -> None:
    bundle = _load(packet)
    assert not _errors(bundle), "the control must start from a packet that validates"
    mutated = copy.deepcopy(bundle)
    assert "archive_timestamps" in mutated["items"][0]
    del mutated["items"][0]["archive_timestamps"]
    assert "archive_timestamps" not in mutated["items"][0], "the mutation did not land"

    errors = _errors(mutated)
    assert errors == ["/items/0: 'archive_timestamps' is a required property"], errors


def test_a_v1_item_carries_no_archive_timestamps_and_is_accepted() -> None:
    bundle = _golden("packet-v1")
    assert bundle["packet_version"] == 1
    assert all("archive_timestamps" not in item for item in bundle["items"])
    assert not _errors(bundle)


def test_the_same_v1_item_is_rejected_once_the_packet_claims_v2() -> None:
    """The requirement is keyed on `packet_version`, not on the item alone."""
    mutated = _golden("packet-v1")
    mutated["packet_version"] = 2
    assert mutated["packet_version"] == 2, "the mutation did not land"
    errors = _errors(mutated)
    assert "/items/0: 'archive_timestamps' is a required property" in errors, errors


def test_an_unknown_custody_action_is_rejected() -> None:
    mutated = _golden("packet-v4")
    entry = mutated["custody_proof"]["entries"][0]
    entry["action"] = "teleported"
    assert mutated["custody_proof"]["entries"][0]["action"] == "teleported"
    errors = _errors(mutated)
    assert len(errors) == 1, errors
    assert errors[0].startswith("/custody_proof/entries/0/action: 'teleported' is not one of")


def test_an_unexpected_key_on_a_closed_object_is_rejected() -> None:
    mutated = _golden("packet-v4")
    mutated["custody_proof"]["entries"][0]["note"] = "added quietly"
    assert "note" in mutated["custody_proof"]["entries"][0]
    errors = _errors(mutated)
    assert len(errors) == 1, errors
    assert "Additional properties are not allowed ('note' was unexpected)" in errors[0]


# --- the prose that describes the closed objects ------------------------------------


def _closed_objects(node: Any, pointer: str = "") -> list[str]:
    found: list[str] = []
    if isinstance(node, dict):
        if node.get("additionalProperties") is False:
            found.append(pointer)
        for key, value in node.items():
            found.extend(_closed_objects(value, f"{pointer}/{key}"))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            found.extend(_closed_objects(value, f"{pointer}/{index}"))
    return found


def _doc_name(pointer: str) -> str:
    """`/$defs/a/properties/b/items` -> `a.b[]`, the spelling `bundle-schema.md` uses."""
    match = re.fullmatch(r"/\$defs/(\w+)((?:/properties/\w+)*)(/items)?", pointer)
    assert match is not None, f"closed object at an unexpected pointer: {pointer}"
    name = match.group(1) + match.group(2).replace("/properties/", ".")
    return name + ("[]" if match.group(3) else "")


def test_the_compatibility_section_names_every_closed_object() -> None:
    """Adding a field to a closed object is not additive; the doc must say which they are.

    Derived from the schema, so an object closed later fails here until the prose that
    tells a producer where the "additive within a major" promise does not hold names it.
    """
    closed = _closed_objects(_load(_SCHEMA_PATH))
    assert len(closed) >= 7, f"found only {len(closed)} closed object(s)"
    prose = _BUNDLE_SCHEMA_DOC.read_text("utf-8")
    missing = [_doc_name(p) for p in closed if f"`{_doc_name(p)}`" not in prose]
    assert not missing, f"docs/bundle-schema.md does not name the closed object(s) {missing}"
