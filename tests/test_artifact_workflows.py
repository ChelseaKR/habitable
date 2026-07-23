# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif

from __future__ import annotations

import json
from collections.abc import Callable
from copy import deepcopy
from pathlib import Path
from typing import cast

import pytest

from habitable.artifact import add_relationship, capture_artifact
from habitable.canonical import JSONValue, canonical_json
from habitable.capture import capture
from habitable.errors import HabitableError
from habitable.evidence import CustodyLog
from habitable.model import CaseDocument
from habitable.packet import _write_signature, build_packet
from habitable.sync import LocalDirTransport, sync
from habitable.tsa import DevTSA, LocalRfc3161TSA
from habitable.vault import Vault
from habitable.verify import (
    _verify_v4_artifact,
    _verify_v4_profile_and_handoffs,
    _verify_v4_relationship,
    _verify_v4_workflows,
    verify_packet,
)


def test_artifact_uses_the_full_evidence_spine(
    make_vault: Callable[..., Vault], dev_tsa: DevTSA, tmp_path: Path
) -> None:
    vault = make_vault()
    issue_id = vault.document.add_issue(category="mold", title="Bathroom mold")
    source = tmp_path / "repair-request.pdf"
    source.write_bytes(b"%PDF-1.4\nsynthetic repair request\n%%EOF\n")

    result = capture_artifact(
        vault,
        source,
        issue_id=issue_id,
        artifact_type="repair_request",
        title="Repair request sent June 2",
        source_assertion="tenant copy",
        issuer="tenant",
        occurred_at="2026-06-02",
        accessible_description="Synthetic repair request.",
        tsa=dev_tsa,
    )

    assert result.timestamped
    artifact = vault.document.artifacts(issue_id)[0]
    assert artifact.artifact_id == result.artifact_id
    assert artifact.artifact_type == "repair_request"
    assert artifact.commitment()
    assert vault.read_original(artifact.artifact_id, artifact.content_hash).startswith(b"%PDF")
    assert vault.custody.verify().ok
    actions = [
        entry.action for entry in vault.custody.entries if entry.item_id == artifact.artifact_id
    ]
    assert actions == ["artifact_added", "fixity_checked", "timestamped", "artifact_added"]


def test_artifact_can_defer_timestamp(make_vault: Callable[..., Vault], tmp_path: Path) -> None:
    vault = make_vault()
    issue_id = vault.document.add_issue(category="no_heat")
    source = tmp_path / "notice.txt"
    source.write_text("Synthetic utility notice.", encoding="utf-8")

    result = capture_artifact(
        vault,
        source,
        issue_id=issue_id,
        artifact_type="utility_notice",
        title="Utility notice",
        source_assertion="tenant-received copy",
        occurred_at="2026-01-03",
    )

    assert not result.timestamped
    assert [item.capture_id for item in vault.deferred()] == [result.artifact_id]


def test_data_key_rotation_reencrypts_artifact_original(
    make_vault: Callable[..., Vault], tmp_path: Path
) -> None:
    vault = make_vault()
    issue_id = vault.document.add_issue(category="mold")
    source = tmp_path / "rotation.txt"
    source.write_text("Synthetic artifact for rotation.", encoding="utf-8")
    result = capture_artifact(
        vault,
        source,
        issue_id=issue_id,
        artifact_type="other_document",
        title="Rotation fixture",
        source_assertion="synthetic test",
        occurred_at="2026-01-03",
    )
    before = (vault.path / "originals" / f"{result.artifact_id}.enc").read_bytes()

    vault.rotate_dek("test-passphrase")
    after = (vault.path / "originals" / f"{result.artifact_id}.enc").read_bytes()
    reopened = Vault.open(vault.path, "test-passphrase")

    assert before != after
    assert reopened.read_original(result.artifact_id, result.content_hash) == source.read_bytes()


def test_typed_relationships_are_immutable_and_cycle_safe(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    dev_tsa: DevTSA,
) -> None:
    vault = make_vault()
    issue_id = vault.document.add_issue(category="mold")
    before = capture(vault, make_jpeg("before.jpg"), issue_id=issue_id, tsa=dev_tsa)
    after = capture(vault, make_jpeg("after.jpg"), issue_id=issue_id, tsa=dev_tsa)

    relationship_id = add_relationship(
        vault,
        issue_id=issue_id,
        relationship_type="before_of",
        source_id=before.capture_id,
        target_id=after.capture_id,
        assertion="Tenant-selected comparison.",
    )
    relationship = vault.document.relationships(issue_id)[0]
    assert relationship.relationship_id == relationship_id
    assert relationship.commitment()

    with pytest.raises(HabitableError, match="cycle"):
        vault.document.add_relationship(
            issue_id=issue_id,
            relationship_type="before_of",
            source_id=after.capture_id,
            target_id=before.capture_id,
        )
    with pytest.raises(HabitableError, match="cannot connect"):
        vault.document.add_relationship(
            issue_id=issue_id,
            relationship_type="documents_condition",
            source_id=before.capture_id,
            target_id=after.capture_id,
        )


def test_artifacts_relationships_and_profile_round_trip_case_state(
    make_vault: Callable[..., Vault], tmp_path: Path
) -> None:
    vault = make_vault()
    issue_id = vault.document.add_issue(category="mold")
    vault.document.set_use_case_profile("repair_delivery")
    source = tmp_path / "request.txt"
    source.write_text("Synthetic request.", encoding="utf-8")
    artifact = capture_artifact(
        vault,
        source,
        issue_id=issue_id,
        artifact_type="repair_request",
        title="Request",
        source_assertion="tenant copy",
        occurred_at="2026-02-03",
    )
    relationship_id = add_relationship(
        vault,
        issue_id=issue_id,
        relationship_type="documents_condition",
        source_id=artifact.artifact_id,
        target_id=issue_id,
    )

    state = vault.document.to_state()
    restored = CaseDocument.from_state(state, vault.document.clock)
    assert restored.use_case_profile() == "repair_delivery"
    assert restored.artifacts()[0].artifact_id == artifact.artifact_id
    assert restored.relationships()[0].relationship_id == relationship_id
    assert state["schema_version"] == 3


def test_packet_v4_verifies_artifact_relationship_profile_and_handoff(
    make_vault: Callable[..., Vault],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    vault = make_vault()
    issue_id = vault.document.add_issue(category="mold", title="Bathroom mold")
    vault.document.set_use_case_profile("repair_delivery")
    source = tmp_path / "request.txt"
    source.write_text("Synthetic repair request.", encoding="utf-8")
    artifact = capture_artifact(
        vault,
        source,
        issue_id=issue_id,
        artifact_type="repair_request",
        title="Repair request",
        source_assertion="tenant copy",
        occurred_at="2026-01-03",
        tsa=local_tsa,
    )
    relationship_id = add_relationship(
        vault,
        issue_id=issue_id,
        relationship_type="documents_condition",
        source_id=artifact.artifact_id,
        target_id=issue_id,
    )

    result = build_packet(
        vault,
        tmp_path / "packet-v4",
        generated_at="2026-01-05T00:00:00Z",
        make_pdf=False,
    )
    bundle = json.loads(result.bundle_path.read_text(encoding="utf-8"))

    assert bundle["packet_version"] == 4
    item = next(item for item in bundle["items"] if item["record_kind"] == "artifact")
    assert item["artifact"]["artifact_type"] == "repair_request"
    assert item["integrity"]["binding_stage"] == "semantic_binding"
    assert bundle["relationships"][0]["relationship_id"] == relationship_id
    assert bundle["use_case_profile"]["profile_id"] == "repair_delivery"
    assert bundle["handoff_views"][0]["presentation_only"] is True
    assert result.handoff_paths[0].exists()

    report = verify_packet(result.out_dir, trusted_certs=[local_tsa.certificate])
    assert report.structurally_intact
    assert report.evidence_ready


def test_artifact_relationship_and_profile_converge_over_peer_sync(
    make_vault: Callable[..., Vault],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    sender = make_vault("sender")
    recipient = make_vault("recipient", passphrase="recipient-passphrase")
    issue_id = sender.document.add_issue(category="no_heat", issue_id="no-heat")
    sender.document.set_use_case_profile("utility_outage")
    source = tmp_path / "utility-notice.txt"
    source.write_text("Synthetic outage notice.", encoding="utf-8")
    artifact = capture_artifact(
        sender,
        source,
        issue_id=issue_id,
        artifact_type="utility_notice",
        title="Outage notice",
        source_assertion="tenant-received copy",
        occurred_at="2026-01-03",
        tsa=local_tsa,
    )
    relationship_id = add_relationship(
        sender,
        issue_id=issue_id,
        relationship_type="documents_condition",
        source_id=artifact.artifact_id,
        target_id=issue_id,
    )
    transport = LocalDirTransport(tmp_path / "artifact-mailbox")

    sync(sender, recipient.identity.public(), transport, channel="case")
    result = sync(recipient, sender.identity.public(), transport, channel="case")

    assert result.captures_imported == 1
    imported = recipient.document.artifacts()[0]
    assert imported.artifact_id == artifact.artifact_id
    assert recipient.read_original(imported.artifact_id, imported.content_hash)
    assert recipient.document.relationships()[0].relationship_id == relationship_id
    assert recipient.document.use_case_profile() == "utility_outage"


@pytest.mark.parametrize("tamper", ["artifact", "relationship"])
def test_packet_v4_rejects_re_signed_semantic_tampering(
    tamper: str,
    make_vault: Callable[..., Vault],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    vault = make_vault()
    issue_id = vault.document.add_issue(category="mold")
    source = tmp_path / f"{tamper}.txt"
    source.write_text("Synthetic request.", encoding="utf-8")
    artifact = capture_artifact(
        vault,
        source,
        issue_id=issue_id,
        artifact_type="repair_request",
        title="Request",
        source_assertion="tenant copy",
        occurred_at="2026-01-03",
        tsa=local_tsa,
    )
    add_relationship(
        vault,
        issue_id=issue_id,
        relationship_type="documents_condition",
        source_id=artifact.artifact_id,
        target_id=issue_id,
    )
    out = tmp_path / f"packet-{tamper}"
    build_packet(vault, out, make_pdf=False)
    bundle = json.loads((out / "bundle.json").read_text(encoding="utf-8"))
    if tamper == "artifact":
        bundle["items"][0]["artifact"]["title"] = "Changed after custody binding"
    else:
        bundle["relationships"][0]["assertion"] = "Changed after custody binding"
    encoded = canonical_json(bundle)
    (out / "bundle.json").write_bytes(encoded)
    _write_signature(vault, out, encoded)

    report = verify_packet(out, trusted_certs=[local_tsa.certificate])
    assert not report.structurally_intact
    assert any("commitment does not match" in problem for problem in report.problems)


def _v4_bundle_and_custody(
    make_vault: Callable[..., Vault],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> tuple[dict[str, JSONValue], CustodyLog]:
    vault = make_vault("verifier-branches")
    issue_id = vault.document.add_issue(category="mold")
    vault.document.set_use_case_profile("repair_delivery")
    source = tmp_path / "verifier-branches.txt"
    source.write_text("Synthetic verifier branch fixture.", encoding="utf-8")
    artifact = capture_artifact(
        vault,
        source,
        issue_id=issue_id,
        artifact_type="repair_request",
        title="Request",
        source_assertion="synthetic test",
        occurred_at="2026-01-03",
        tsa=local_tsa,
    )
    add_relationship(
        vault,
        issue_id=issue_id,
        relationship_type="documents_condition",
        source_id=artifact.artifact_id,
        target_id=issue_id,
    )
    out = tmp_path / "verifier-branches-packet"
    build_packet(vault, out, make_pdf=False)
    bundle = cast(
        dict[str, JSONValue],
        json.loads((out / "bundle.json").read_text(encoding="utf-8")),
    )
    proof = bundle["custody_proof"]
    assert isinstance(proof, dict)
    records = proof["entries"]
    assert isinstance(records, list)
    record_maps = [cast(dict[str, JSONValue], record) for record in records]
    return bundle, CustodyLog.from_records(record_maps)


def test_packet_v4_artifact_verifier_rejects_each_signed_shape_violation(
    make_vault: Callable[..., Vault],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    bundle, custody = _v4_bundle_and_custody(make_vault, local_tsa, tmp_path)
    items = bundle["items"]
    assert isinstance(items, list)
    item = deepcopy(next(raw for raw in items if isinstance(raw, dict)))
    artifact = item["artifact"]
    integrity = item["integrity"]
    assert isinstance(artifact, dict)
    assert isinstance(integrity, dict)

    artifact.update(
        {
            "artifact_schema": 2,
            "artifact_id": "wrong",
            "issue_id": "wrong",
            "content_hash": "wrong",
            "media_type": "wrong",
            "artifact_type": "wrong",
            "title": "",
            "source": "",
            "occurred_at": "",
            "recorded_at": "",
        }
    )
    integrity.update(
        {
            "algorithm": "wrong",
            "custody_action": "wrong",
            "commitment": "wrong",
            "binding_stage": "wrong",
        }
    )
    problems = _verify_v4_artifact(item, custody)

    assert "artifact_schema must be 1" in problems
    assert "artifact_id does not match the item id" in problems
    assert "artifact issue_id does not match the item" in problems
    assert "artifact content_hash does not match the item" in problems
    assert "artifact media_type does not match the item" in problems
    assert "unknown artifact_type" in problems
    assert "integrity.algorithm must be sha256" in problems
    assert "integrity.custody_action must be artifact_added" in problems
    assert "artifact commitment does not match the signed fields" in problems
    assert "artifact binding_stage is invalid" in problems
    assert "no custody entry binds this artifact commitment" in problems


def test_packet_v4_relationship_verifier_rejects_shape_endpoint_and_binding_violations(
    make_vault: Callable[..., Vault],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    bundle, custody = _v4_bundle_and_custody(make_vault, local_tsa, tmp_path)
    relationships = bundle["relationships"]
    assert isinstance(relationships, list)
    relationship = deepcopy(cast(dict[str, JSONValue], relationships[0]))
    integrity = relationship["integrity"]
    assert isinstance(integrity, dict)
    relationship.update(
        {
            "relationship_schema": 2,
            "relationship_id": "",
            "issue_id": "",
            "relationship_type": "wrong",
            "source_id": "",
            "target_id": "",
        }
    )
    integrity.update(
        {
            "algorithm": "wrong",
            "custody_action": "wrong",
            "commitment": "wrong",
            "binding_stage": "wrong",
        }
    )
    problems = _verify_v4_relationship(relationship, custody, {})
    assert "relationship_schema must be 1" in problems
    assert "unknown relationship_type" in problems
    assert "relationship identifiers must not be empty" in problems
    assert "source_id and target_id must differ" in problems
    assert "relationship points to a missing endpoint" in problems
    assert "integrity.algorithm must be sha256" in problems
    assert "integrity.custody_action must be relationship_added" in problems
    assert "relationship commitment does not match the signed fields" in problems
    assert "relationship binding_stage is invalid" in problems
    assert "no custody entry binds this relationship commitment" in problems

    endpoint_problem = deepcopy(cast(dict[str, JSONValue], relationships[0]))
    endpoint_problem["issue_id"] = "issue-a"
    endpoint_problem["source_id"] = "capture-a"
    endpoint_problem["target_id"] = "capture-b"
    endpoint_messages = _verify_v4_relationship(
        endpoint_problem,
        custody,
        {
            "capture-a": ("issue-b", "capture"),
            "capture-b": ("issue-b", "capture"),
        },
    )
    assert "relationship endpoints must belong to its issue" in endpoint_messages
    assert "relationship endpoint types are invalid" in endpoint_messages


def test_packet_v4_profile_handoff_verifier_rejects_suppression_and_mismatch(
    make_vault: Callable[..., Vault],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    bundle, _custody = _v4_bundle_and_custody(make_vault, local_tsa, tmp_path)
    assert _verify_v4_profile_and_handoffs(bundle) == []

    assert "use_case_profile must be an object or null" in _verify_v4_profile_and_handoffs(
        {"use_case_profile": "wrong", "handoff_views": "wrong"}
    )
    no_profile = _verify_v4_profile_and_handoffs(
        {"use_case_profile": None, "handoff_views": ["wrong"]}
    )
    assert "handoff_views require a use_case_profile" in no_profile
    assert "handoff_views[0] must be an object" in no_profile

    broken = deepcopy(bundle)
    profile = broken["use_case_profile"]
    handoffs = broken["handoff_views"]
    assert isinstance(profile, dict)
    assert isinstance(handoffs, list)
    handoff = handoffs[0]
    assert isinstance(handoff, dict)
    profile.update(
        {
            "profile_schema": 2,
            "review_state": "wrong",
            "external_review_required": True,
        }
    )
    handoff.update(
        {
            "presentation_only": False,
            "source_of_truth": "wrong",
            "profile_id": "wrong",
            "profile": {},
            "disclosures": [],
        }
    )
    problems = _verify_v4_profile_and_handoffs(broken)
    assert "use_case_profile.profile_schema must be 1" in problems
    assert "use_case_profile.review_state is invalid" in problems
    assert "use_case_profile external-review flag is inconsistent" in problems
    assert "handoff_views[0] must be presentation_only" in problems
    assert "handoff_views[0] source_of_truth must be bundle.json" in problems
    assert "handoff_views[0] profile_id does not match" in problems
    assert "handoff_views[0] profile snapshot does not match" in problems
    assert "handoff_views[0] suppresses required disclosures" in problems


def test_packet_v4_workflow_verifier_rejects_counts_duplicates_and_cycles(
    make_vault: Callable[..., Vault],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    bundle, custody = _v4_bundle_and_custody(make_vault, local_tsa, tmp_path)
    broken = deepcopy(bundle)
    items = broken["items"]
    relationships = broken["relationships"]
    appendix = broken["appendix"]
    assert isinstance(items, list)
    assert isinstance(relationships, list)
    assert isinstance(appendix, dict)
    items.extend(["malformed", {"capture_id": "invalid-kind", "record_kind": "wrong"}])
    appendix["artifact_count"] = 999
    appendix["relationship_count"] = 999
    relationship = cast(dict[str, JSONValue], relationships[0])
    relationships.extend(["malformed", deepcopy(relationship)])
    reverse = deepcopy(relationship)
    reverse["relationship_id"] = "rel-reverse"
    reverse["source_id"], reverse["target_id"] = (
        relationship["target_id"],
        relationship["source_id"],
    )
    relationships.append(reverse)

    problems = _verify_v4_workflows(broken, custody)
    assert any("record_kind is invalid" in problem for problem in problems)
    assert "appendix.artifact_count does not match artifact items" in problems
    assert "appendix.relationship_count does not match relationships" in problems
    assert "malformed packet-v4 relationship" in problems
    assert any("duplicate relationship_id" in problem for problem in problems)
    assert "documents_condition relationship graph contains a cycle" in problems
