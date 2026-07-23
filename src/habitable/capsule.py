# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Small signed partner evidence capsules and a conservative import adapter."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from .artifact import ArtifactResult, capture_artifact
from .canonical import JSONValue, canonical_json, sha256_bytes
from .crypto import PublicIdentity, verify
from .errors import HabitableError
from .vault import Vault

__all__ = [
    "CAPSULE_SCHEMA_VERSION",
    "CapsuleVerification",
    "build_capsule",
    "import_capsule",
    "verify_capsule",
]

CAPSULE_SCHEMA_VERSION = 1
_MAX_CAPSULE_BYTES = 80 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class CapsuleVerification:
    ok: bool
    producer_fingerprint: str
    record_id: str
    content_hash: str
    problems: tuple[str, ...]


def build_capsule(
    vault: Vault,
    record_id: str,
    out_path: Path,
    *,
    include_original: bool = True,
) -> Path:
    """Write one signed, self-contained evidence record for a partner tool."""
    captures = {item.capture_id: item for item in vault.document.captures()}
    artifacts = {item.artifact_id: item for item in vault.document.artifacts()}
    if record_id in captures:
        record = captures[record_id]
        record_kind = "capture"
        semantic: dict[str, JSONValue] = {
            "capture_id": record.capture_id,
            "issue_id": record.issue_id,
            "content_hash": record.content_hash,
            "media_type": record.media_type,
            "captured_at": record.captured_at,
            "transcript": record.transcript,
        }
        content_hash = record.content_hash
    elif record_id in artifacts:
        artifact = artifacts[record_id]
        record_kind = "artifact"
        semantic = artifact.semantic_payload()
        semantic["commitment"] = artifact.commitment()
        content_hash = artifact.content_hash
    else:
        raise HabitableError(f"unknown evidence record: {record_id!r}")

    relationships = [
        {
            **relationship.semantic_payload(),
            "commitment": relationship.commitment(),
        }
        for relationship in vault.document.relationships()
        if record_id in {relationship.source_id, relationship.target_id}
    ]
    payload: dict[str, JSONValue] = {
        "kind": "habitable/evidence-capsule",
        "schema_version": CAPSULE_SCHEMA_VERSION,
        "record_kind": record_kind,
        "record": semantic,
        "relationships": cast(JSONValue, relationships),
        "original_b64": (
            base64.b64encode(vault.read_original(record_id, content_hash)).decode("ascii")
            if include_original
            else None
        ),
        "disclosures": [
            "The producer signature proves capsule integrity, not authorship of the source file.",
            "Issuer, source, chronology, and relationship labels remain assertions.",
            "No legal, medical, code-compliance, or admissibility conclusion is made.",
        ],
    }
    payload_bytes = canonical_json(payload)
    public = vault.identity.public()
    envelope: dict[str, JSONValue] = {
        "payload": payload,
        "producer": {
            "fingerprint": public.fingerprint,
            "sign_public": base64.b64encode(public.sign_public).decode("ascii"),
            "public_identity": public.encode(),
        },
        "payload_sha256": sha256_bytes(payload_bytes),
        "signature": base64.b64encode(vault.identity.sign(payload_bytes)).decode("ascii"),
    }
    out_path.write_bytes(canonical_json(envelope))
    return out_path


def verify_capsule(path: Path) -> CapsuleVerification:  # noqa: C901 -- hostile input audit
    """Verify a capsule without a vault, account, network, or trusted service."""
    problems: list[str] = []
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise HabitableError(f"could not read capsule: {exc}") from exc
    if len(raw) > _MAX_CAPSULE_BYTES:
        raise HabitableError("capsule exceeds the 80 MiB verification limit")
    try:
        envelope = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HabitableError("capsule is not valid JSON") from exc
    if not isinstance(envelope, dict):
        raise HabitableError("capsule envelope must be an object")
    payload = envelope.get("payload")
    producer = envelope.get("producer")
    if not isinstance(payload, dict) or not isinstance(producer, dict):
        raise HabitableError("capsule is missing payload or producer")
    payload_bytes = canonical_json(payload)
    digest = sha256_bytes(payload_bytes)
    if envelope.get("payload_sha256") != digest:
        problems.append("payload hash does not match")
    try:
        sign_public = base64.b64decode(str(producer.get("sign_public", "")), validate=True)
        signature = base64.b64decode(str(envelope.get("signature", "")), validate=True)
    except ValueError:
        sign_public = b""
        signature = b""
        problems.append("producer key or signature is malformed")
    if not sign_public or not verify(sign_public, payload_bytes, signature):
        problems.append("producer signature is invalid")
    try:
        public = PublicIdentity.decode(str(producer.get("public_identity", "")))
    except Exception:
        public = None
        problems.append("producer public identity is malformed")
    if public is not None and (
        public.sign_public != sign_public or public.fingerprint != producer.get("fingerprint")
    ):
        problems.append("producer fingerprint or signing key is inconsistent")
    if payload.get("kind") != "habitable/evidence-capsule":
        problems.append("capsule kind is invalid")
    if payload.get("schema_version") != CAPSULE_SCHEMA_VERSION:
        problems.append("capsule schema version is unsupported")
    record = payload.get("record")
    record_map = record if isinstance(record, dict) else {}
    record_kind = payload.get("record_kind")
    record_id = (
        str(record_map.get("capture_id", ""))
        if record_kind == "capture"
        else str(record_map.get("artifact_id", ""))
    )
    content_hash = str(record_map.get("content_hash", ""))
    original_b64 = payload.get("original_b64")
    if original_b64 is not None:
        try:
            original = base64.b64decode(str(original_b64), validate=True)
        except ValueError:
            original = b""
            problems.append("embedded original is malformed")
        if sha256_bytes(original) != content_hash:
            problems.append("embedded original does not match content_hash")
    if not record_id or len(content_hash) != 64:
        problems.append("record id or content hash is malformed")
    return CapsuleVerification(
        ok=not problems,
        producer_fingerprint=str(producer.get("fingerprint", "")),
        record_id=record_id,
        content_hash=content_hash,
        problems=tuple(problems),
    )


def import_capsule(
    vault: Vault,
    capsule_path: Path,
    *,
    issue_id: str,
    title: str = "Partner evidence capsule",
) -> ArtifactResult:
    """Import a verified capsule as a sealed ``partner_export`` artifact.

    The adapter preserves the signed capsule itself rather than silently
    re-authoring its embedded record into the recipient's case model.
    """
    verdict = verify_capsule(capsule_path)
    if not verdict.ok:
        raise HabitableError("cannot import an invalid capsule: " + "; ".join(verdict.problems))
    return capture_artifact(
        vault,
        capsule_path,
        issue_id=issue_id,
        artifact_type="partner_export",
        title=title,
        source_assertion="verified signed partner capsule",
        issuer=verdict.producer_fingerprint,
        occurred_at=datetime.now(tz=UTC).date().isoformat(),
        accessible_description=(
            f"Signed partner capsule for evidence record {verdict.record_id}; "
            "source assertions remain unverified."
        ),
        media_type="application/json",
    )
