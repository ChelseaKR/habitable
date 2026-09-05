# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""E2E-encrypted, redactable case sharing with an organizer."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path

import pytest

from habitable.artifact import add_relationship, capture_artifact
from habitable.canonical import JSONValue, canonical_json
from habitable.capture import capture
from habitable.errors import HabitableError, ShareError
from habitable.pairing import accept_pairing_material, create_pairing_material
from habitable.share import (
    _refuse_cross_scope_relationships,
    build_share_state,
    decode_share,
    encode_share,
    export_share,
    import_share,
)
from habitable.tsa import LocalRfc3161TSA
from habitable.vault import Vault


def _tenant_with_two_issues(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], tsa: LocalRfc3161TSA
) -> Vault:
    vault = make_vault(name="tenant", case_id="case-4B", unit="4B")
    i1 = vault.document.add_issue(category="mold", title="Mold", issue_id="i1")
    i2 = vault.document.add_issue(category="heat", title="No heat", issue_id="i2")
    vault.document.add_timeline_entry(i1, "observed", "spreading")
    capture(vault, make_jpeg("a.jpg", with_location=True), issue_id=i1, tsa=tsa)
    capture(vault, make_jpeg("b.jpg", with_location=True), issue_id=i2, tsa=tsa)
    vault.save()
    return vault


def test_share_round_trip_full_case(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], local_tsa: LocalRfc3161TSA
) -> None:
    tenant = _tenant_with_two_issues(make_vault, make_jpeg, local_tsa)
    organizer = make_vault(name="org", case_id="case-4B", unit="")

    blob = export_share(tenant, organizer.identity.public())
    # The sealed share leaks no plaintext (issue titles, unit) to a relay/courier.
    assert b"Mold" not in blob
    assert b"No heat" not in blob

    result = import_share(organizer, blob)
    assert result.captures_imported == 2
    assert {i.issue_id for i in organizer.document.issues()} == {"i1", "i2"}
    # The unit label merged in from the (non-redacted) share.
    assert organizer.document.get_meta("unit") == "4B"
    # The originals are present and re-verify on read.
    for cap in organizer.document.captures():
        assert organizer.has_original(cap.capture_id)
        organizer.read_original(cap.capture_id, cap.content_hash)


def test_share_subset_fails_before_queueing_a_sync_message(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], local_tsa: LocalRfc3161TSA
) -> None:
    tenant = _tenant_with_two_issues(make_vault, make_jpeg, local_tsa)
    organizer = make_vault(name="org", case_id="case-4B", unit="")
    peer = tenant.sync_peer(organizer.identity.public())
    assert peer is not None
    before_messages = dict(peer.sent_messages)

    with pytest.raises(ShareError, match="scoped shares are temporarily blocked"):
        export_share(tenant, organizer.identity.public(), issue_ids={"i1"})

    assert peer.sent_messages == before_messages
    assert organizer.document.issues() == []
    assert organizer.document.captures() == []


def test_full_case_share_can_redact_unit_label(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], local_tsa: LocalRfc3161TSA
) -> None:
    tenant = _tenant_with_two_issues(make_vault, make_jpeg, local_tsa)
    organizer = make_vault(name="org", case_id="case-4B", unit="")

    blob = export_share(tenant, organizer.identity.public(), redact_unit=True)
    import_share(organizer, blob)
    # The unit metadata field was omitted; the organizer still gets the full case.
    assert organizer.document.get_meta("unit") == ""
    assert {i.issue_id for i in organizer.document.issues()} == {"i1", "i2"}


def test_even_unknown_issue_selector_fails_as_a_scoped_share(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], local_tsa: LocalRfc3161TSA
) -> None:
    tenant = _tenant_with_two_issues(make_vault, make_jpeg, local_tsa)
    organizer = make_vault(name="org", case_id="case-4B")
    with pytest.raises(ShareError, match="scoped shares are temporarily blocked"):
        export_share(tenant, organizer.identity.public(), issue_ids={"nope"})


def test_share_not_addressed_to_us_opens_nothing(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], local_tsa: LocalRfc3161TSA
) -> None:
    tenant = _tenant_with_two_issues(make_vault, make_jpeg, local_tsa)
    organizer = make_vault(name="org", case_id="case-4B")
    stranger = make_vault(name="stranger", case_id="case-4B")

    blob = export_share(tenant, organizer.identity.public())
    # Sealed to the organizer's key: the stranger cannot open it.
    with pytest.raises(ShareError):
        import_share(stranger, blob)


def test_share_for_a_different_case_is_rejected(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], local_tsa: LocalRfc3161TSA
) -> None:
    tenant = _tenant_with_two_issues(make_vault, make_jpeg, local_tsa)
    organizer = make_vault(name="org", case_id="some-other-case", unit="")

    material = create_pairing_material(tenant, organizer.identity.public())
    # Pairing itself is case-bound, so an unsafe cross-case share cannot be created.
    with pytest.raises(HabitableError):
        accept_pairing_material(organizer, material)


def test_share_import_is_idempotent(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], local_tsa: LocalRfc3161TSA
) -> None:
    tenant = _tenant_with_two_issues(make_vault, make_jpeg, local_tsa)
    organizer = make_vault(name="org", case_id="case-4B", unit="")

    blob = export_share(tenant, organizer.identity.public())
    first = import_share(organizer, blob)
    second = import_share(organizer, blob)
    assert first.captures_imported == 2
    assert second.captures_imported == 0  # already held; nothing re-imported
    assert len(organizer.document.captures()) == 2


def test_share_file_encoding_round_trips() -> None:
    blob = b"\x00\x01sealed-bytes\xff"
    assert decode_share(encode_share(blob)) == blob
    with pytest.raises(ShareError):
        decode_share("not valid base64 !!!")


# --- the scoped-share hardening behind the hold (issue #279) -------------------
#
# `export_share` refuses every scope, so none of the behaviour below is reachable
# from the CLI, the app, or `export_share` itself. These call `build_share_state`
# directly for exactly that reason: the rules a scoped disclosure owes its
# recipient have to be pinned by something other than the refusal, or lifting the
# refusal ships their absence silently.


def _case_with_a_removed_issue(make_vault: Callable[..., Vault]) -> Vault:
    """A vault holding two live issues and one that was deleted.

    The deleted issue is the interesting one: its HLC add tag survives in the
    OR-set's ``removes``, carrying the wall clock and node id of the device that
    created it, long after the issue itself stops being an element.
    """
    vault = make_vault(name="tenant-removed", case_id="case-4B", unit="4B")
    vault.document.add_issue(category="mold", title="Mold", issue_id="i1")
    vault.document.add_issue(category="heat", title="No heat", issue_id="i2")
    vault.document.add_issue(category="pests", title="Roaches", issue_id="i3")
    vault.document.remove_issue("i3")
    vault.save()
    return vault


def _object(state: Mapping[str, JSONValue], *path: str) -> dict[str, JSONValue]:
    """Read a nested JSON object out of a CRDT state, asserting its shape as we go."""
    node: JSONValue = dict(state)
    for key in path:
        assert isinstance(node, dict), f"{key!r} is not inside an object"
        node = node[key]
    assert isinstance(node, dict), f"{path[-1]!r} is not an object"
    return node


def _strings(state: Mapping[str, JSONValue], *path: str) -> list[str]:
    """Read a nested JSON array of strings out of a CRDT state."""
    parent = _object(state, *path[:-1])
    values = parent[path[-1]]
    assert isinstance(values, list), f"{path[-1]!r} is not an array"
    return [str(value) for value in values]


def _tag_of(vault: Vault, issue_id: str) -> str:
    return _strings(vault.document.to_state(), "issues", "adds", issue_id)[0]


def test_a_scoped_state_prunes_removal_tags_naming_issues_outside_the_scope(
    make_vault: Callable[..., Vault],
) -> None:
    """The removal tags are add tags, and an add tag is an HLC that names a record.

    ``subset_state`` filters the OR-set's ``adds`` to the scope and passes
    ``removes`` through whole, so a share scoped to ``i1`` shipped the creation
    timestamp and node id of ``i3`` — an issue the scope exists to exclude, and one
    whose opaque id is ``HMAC(case_salt, that tag)``.
    """
    vault = _case_with_a_removed_issue(make_vault)
    removed_tag = _tag_of(vault, "i3")
    assert removed_tag in _strings(vault.document.to_state(), "issues", "removes")

    state = build_share_state(vault.document, {"i1"})

    assert _strings(state, "issues", "removes") == []
    assert removed_tag.encode() not in canonical_json(state)


def test_a_scoped_state_keeps_the_removal_tag_of_an_issue_inside_the_scope(
    make_vault: Callable[..., Vault],
) -> None:
    """Pruning is by scope, not a blanket deletion of removal history.

    A tag that cancels one of the disclosed issues still does its job: the
    recipient must see that ``i3`` was deleted when ``i3`` is what they were given.
    """
    vault = _case_with_a_removed_issue(make_vault)

    state = build_share_state(vault.document, {"i1", "i3"})

    assert _strings(state, "issues", "removes") == [_tag_of(vault, "i3")]


def test_a_scoped_state_withholds_the_case_salt(
    make_vault: Callable[..., Vault],
) -> None:
    """The salt is the HMAC key every exported identifier in the case derives from.

    A scoped recipient holding it can mint — and confirm offline — the id of any
    record whose HLC they can observe or guess, including the records the scope was
    drawn to withhold. Scoping the state without withholding the salt scopes nothing.
    """
    vault = _case_with_a_removed_issue(make_vault)
    salt = vault.document.get_meta("case_salt")
    assert salt, "the fixture vault should already carry a case salt"

    state = build_share_state(vault.document, {"i1"})

    assert "case_salt" not in _object(state, "meta")
    assert salt.encode() not in canonical_json(state)
    # Withholding the salt is not a licence to withhold the rest of the metadata:
    # a scoped share still says which unit it concerns unless asked to redact it.
    assert "unit" in _object(state, "meta")


def test_a_full_case_state_keeps_the_case_salt_because_ids_are_derived_from_it(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], local_tsa: LocalRfc3161TSA
) -> None:
    """The salt is load-bearing for the unscoped path, so the fix must not reach it.

    Every exported ``order_token`` and the whole custody-proof HLC mapping in
    ``packet.py`` are ``opaque_id`` values, so two devices on one case have to agree
    on the salt or the same event carries a different ordering token in each device's
    packets. Every vault mints its own salt at creation (``Vault.create`` calls
    ``ensure_case_salt``), and the register is last-writer-wins like any other
    metadata: agreement happens *only* because the salt rides in the shared state.
    Withhold it from a full-case share and two devices never converge. That is the
    difference the fix turns on — a full-case recipient was given every record the
    salt could name, and a scoped recipient was not.
    """
    tenant = _tenant_with_two_issues(make_vault, make_jpeg, local_tsa)
    organizer = make_vault(name="org", case_id="case-4B", unit="")
    assert organizer.document.get_meta("case_salt") != tenant.document.get_meta("case_salt")

    state = build_share_state(tenant.document, None)
    assert "case_salt" in _object(state, "meta")
    assert state == tenant.document.subset_state(None)  # the unscoped path is untouched

    organizer.document.merge(state)
    tenant.document.merge(organizer.document.to_state())

    salt = tenant.document.get_meta("case_salt")
    assert salt and organizer.document.get_meta("case_salt") == salt
    hlc = "2026-01-02T00:00:00.000Z-0001-node"
    assert organizer.document.opaque_id("cap", hlc) == tenant.document.opaque_id("cap", hlc)


def test_a_relationship_that_leaves_the_scope_is_refused_rather_than_dropped() -> None:
    """Silence is the one outcome ADR 0018 rules out for a link that does not fit.

    Dropping it leaves the recipient unable to tell a record that never had
    relationships from one whose relationships were removed — the "never deletes
    arbitrary links" clause of issue #262's exit criteria failing one layer down.
    """
    held: dict[str, JSONValue] = {
        "rel-inside": {"issue_id": "i1", "source_id": "cap-a", "target_id": "i1"},
        "rel-leaving": {"issue_id": "i1", "source_id": "cap-b", "target_id": "i2"},
        "rel-elsewhere": {"issue_id": "i2", "source_id": "cap-c", "target_id": "i2"},
    }
    disclosed: dict[str, JSONValue] = {"rel-inside": held["rel-inside"]}

    with pytest.raises(ShareError, match="rel-leaving") as raised:
        _refuse_cross_scope_relationships(held, disclosed, {"i1"})

    message = str(raised.value)
    # It names what it refused and what widening would cost, and it does not blame
    # the relationship that was never in scope in the first place.
    assert "1 relationship(s)" in message
    assert "rel-elsewhere" not in message
    assert "tenant's decision" in message


def test_relationships_wholly_inside_the_scope_are_not_refused() -> None:
    """The guard must not fire on the ordinary case, or it refuses every scope."""
    held: dict[str, JSONValue] = {
        "rel-inside": {"issue_id": "i1", "source_id": "cap-a", "target_id": "i1"},
        "rel-elsewhere": {"issue_id": "i2", "source_id": "cap-c", "target_id": "i2"},
    }
    disclosed: dict[str, JSONValue] = {"rel-inside": held["rel-inside"]}

    _refuse_cross_scope_relationships(held, disclosed, {"i1"})


def test_the_model_invariant_the_relationship_guard_stands_in_for(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], local_tsa: LocalRfc3161TSA
) -> None:
    """Today no document can hold a relationship whose endpoints span two issues.

    ``add_relationship`` requires both endpoints to belong to the relationship's own
    issue, so an *issue*-selected scope always contains them and the drop above is
    unreachable from a real vault. Pinned here because that is the whole reason the
    guard takes plain mappings: the invariant lives in ``model.py``, this file cannot
    see it change, and issue #262 restores ``--since`` beside ``--issue`` — a date
    scope filters captures by time and breaks the invariant on its first use.
    """
    vault = _tenant_with_two_issues(make_vault, make_jpeg, local_tsa)
    other_issue_capture = next(
        cap for cap in vault.document.captures() if cap.issue_id == "i2"
    ).capture_id

    with pytest.raises(HabitableError, match="endpoints must belong to the selected issue"):
        add_relationship(
            vault,
            issue_id="i1",
            relationship_type="documents_condition",
            source_id=other_issue_capture,
            target_id="i1",
        )


def test_a_scoped_state_is_still_a_well_formed_mergeable_crdt_state(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    """Hardening must not cost the property that makes a share a share.

    A pruned ``removes`` and a missing ``case_salt`` register are both still a valid
    subset of the same OR-set / LWW state, so merging one on a recipient's device
    stays a commutative, idempotent CRDT join.
    """
    tenant = _tenant_with_two_issues(make_vault, make_jpeg, local_tsa)
    request = tmp_path / "request.txt"
    request.write_text("synthetic repair request\n", encoding="utf-8")
    artifact = capture_artifact(
        tenant,
        request,
        issue_id="i1",
        artifact_type="repair_request",
        title="Repair request",
        source_assertion="tenant copy",
        occurred_at="2026-01-02",
        tsa=local_tsa,
    )
    add_relationship(
        tenant,
        issue_id="i1",
        relationship_type="documents_condition",
        source_id=artifact.artifact_id,
        target_id="i1",
    )
    organizer = make_vault(name="org-merge", case_id="case-4B", unit="")

    state = build_share_state(tenant.document, {"i1"})
    organizer.document.merge(state)
    organizer.document.merge(state)  # idempotent

    assert {issue.issue_id for issue in organizer.document.issues()} == {"i1"}
    assert [rel.issue_id for rel in organizer.document.relationships()] == ["i1"]
    # Merging a scoped state leaves the recipient on their own salt, so they cannot
    # re-derive the sender's identifiers for anything the scope withheld.
    assert organizer.document.get_meta("case_salt") != tenant.document.get_meta("case_salt")
