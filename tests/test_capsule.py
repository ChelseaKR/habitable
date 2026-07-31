# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

from habitable.capsule import build_capsule, import_capsule, verify_capsule
from habitable.capture import capture
from habitable.tsa import LocalRfc3161TSA
from habitable.vault import Vault


def test_capsule_export_verify_and_import_adapter(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    sender = make_vault("capsule-sender")
    issue = sender.document.add_issue(category="mold")
    captured = capture(sender, make_jpeg(), issue_id=issue, tsa=local_tsa)
    capsule = build_capsule(sender, captured.capture_id, tmp_path / "evidence.hcap")

    verdict = verify_capsule(capsule)
    assert verdict.ok
    assert verdict.record_id == captured.capture_id

    recipient = make_vault("capsule-recipient", case_id="recipient-case")
    recipient_issue = recipient.document.add_issue(category="mold")
    imported = import_capsule(recipient, capsule, issue_id=recipient_issue)
    artifact = recipient.document.artifacts()[0]
    assert imported.artifact_id == artifact.artifact_id
    assert artifact.artifact_type == "partner_export"
    assert artifact.issuer == sender.identity.public().fingerprint


def test_capsule_detects_tampering(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    tmp_path: Path,
) -> None:
    vault = make_vault()
    issue = vault.document.add_issue(category="mold")
    captured = capture(vault, make_jpeg(), issue_id=issue)
    capsule = build_capsule(vault, captured.capture_id, tmp_path / "evidence.hcap")
    raw = json.loads(capsule.read_text(encoding="utf-8"))
    raw["payload"]["record"]["content_hash"] = "0" * 64
    capsule.write_text(json.dumps(raw), encoding="utf-8")

    assert not verify_capsule(capsule).ok
