# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Capture corroborating documents and connect evidence records.

Artifacts use the same local evidence spine as media captures: hash, encrypted
original, signed custody, immediate read-back fixity, RFC 3161 now-or-deferred,
and CRDT persistence.  Issuer/source fields remain human assertions unless a
separate signature proves otherwise.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from .canonical import sha256_file
from .errors import CaptureError, TimestampError
from .evidence import CustodyAction
from .tsa import TimestampAuthority, TimestampInfo, verify_token
from .usecases import ARTIFACT_TYPES, RELATIONSHIP_TYPES
from .vault import Vault

__all__ = ["ArtifactResult", "add_relationship", "capture_artifact"]

_MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
_DOCUMENT_TYPES = {
    ".pdf": "application/pdf",
    ".txt": "text/plain",
    ".md": "text/markdown",
    ".html": "text/html",
    ".htm": "text/html",
    ".eml": "message/rfc822",
    ".json": "application/json",
    ".csv": "text/csv",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
}


@dataclass(frozen=True, slots=True)
class ArtifactResult:
    artifact_id: str
    content_hash: str
    media_type: str
    timestamped: bool
    timestamp_info: TimestampInfo | None
    extra_authorities: tuple[str, ...] = field(default_factory=tuple)


def capture_artifact(
    vault: Vault,
    source: str | Path,
    *,
    issue_id: str,
    artifact_type: str,
    title: str,
    source_assertion: str,
    occurred_at: str,
    issuer: str = "",
    accessible_description: str = "",
    actor: str | None = None,
    tsa: TimestampAuthority | None = None,
    extra_tsas: Sequence[TimestampAuthority] = (),
    media_type: str | None = None,
    source_name: str | None = None,
) -> ArtifactResult:
    """Seal one document-like artifact and append its immutable case record."""
    src = Path(source)
    if not src.is_file():
        raise CaptureError(f"no such artifact file: {src}")
    try:
        size = src.stat().st_size
    except OSError as exc:
        raise CaptureError(f"could not inspect artifact: {src}") from exc
    if size > _MAX_ARTIFACT_BYTES:
        raise CaptureError("artifact exceeds the 64 MiB local safety limit")
    if artifact_type not in ARTIFACT_TYPES:
        raise CaptureError(f"unknown artifact type: {artifact_type!r}")

    digest = sha256_file(src)
    resolved_media_type = media_type or _DOCUMENT_TYPES.get(
        src.suffix.casefold(), "application/octet-stream"
    )
    actor_id = actor or vault.identity.public().fingerprint
    stamp = vault.document.clock.now()
    artifact_id = vault.document.opaque_id("art", stamp.encode())

    sealed_name = vault.seal_original(artifact_id, src, digest)
    vault.custody.append(
        CustodyAction.ARTIFACT_ADDED,
        artifact_id,
        actor=actor_id,
        hlc=stamp.encode(),
        details={"artifact_type": artifact_type, "media_type": resolved_media_type},
        private_details={"source": Path(source_name).name if source_name else src.name},
        identity=vault.identity,
    )
    vault.read_original(artifact_id, digest)
    vault.custody.append(
        CustodyAction.FIXITY_CHECKED,
        artifact_id,
        actor=actor_id,
        hlc=vault.document.clock.now().encode(),
        details={"content_hash": digest},
        identity=vault.identity,
    )

    info = _timestamp(vault, artifact_id, digest, actor_id, tsa)
    extra_authorities: list[str] = []
    if info is not None:
        for extra in extra_tsas:
            try:
                token = extra.stamp(digest)
                verify_token(token, digest)
            except TimestampError:
                continue
            vault.add_additional_token(artifact_id, token)
            vault.custody.append(
                CustodyAction.TIMESTAMPED,
                artifact_id,
                actor=actor_id,
                hlc=vault.document.clock.now().encode(),
                details={"tsa": token.tsa_name, "role": "additional"},
                identity=vault.identity,
            )
            extra_authorities.append(token.tsa_name)

    resolved_id = vault.document.add_artifact(
        issue_id=issue_id,
        artifact_type=artifact_type,
        title=title,
        source=source_assertion,
        issuer=issuer,
        occurred_at=occurred_at,
        content_hash=digest,
        media_type=resolved_media_type,
        sealed_name=sealed_name,
        accessible_description=accessible_description,
        artifact_id=artifact_id,
    )
    artifact = next(item for item in vault.document.artifacts() if item.artifact_id == resolved_id)
    vault.custody.append(
        CustodyAction.ARTIFACT_ADDED,
        artifact_id,
        actor=actor_id,
        hlc=vault.document.clock.now().encode(),
        details={"artifact_commitment": artifact.commitment(), "stage": "semantic_binding"},
        identity=vault.identity,
    )
    vault.save()
    return ArtifactResult(
        artifact_id=artifact_id,
        content_hash=digest,
        media_type=resolved_media_type,
        timestamped=info is not None,
        timestamp_info=info,
        extra_authorities=tuple(extra_authorities),
    )


def add_relationship(
    vault: Vault,
    *,
    issue_id: str,
    relationship_type: str,
    source_id: str,
    target_id: str,
    assertion: str = "",
    actor: str | None = None,
) -> str:
    """Append and custody-bind one explicit evidence relationship."""
    if relationship_type not in RELATIONSHIP_TYPES:
        raise CaptureError(f"unknown relationship type: {relationship_type!r}")
    relationship_id = vault.document.add_relationship(
        issue_id=issue_id,
        relationship_type=relationship_type,
        source_id=source_id,
        target_id=target_id,
        assertion=assertion,
    )
    relationship = next(
        item for item in vault.document.relationships() if item.relationship_id == relationship_id
    )
    vault.custody.append(
        CustodyAction.RELATIONSHIP_ADDED,
        relationship_id,
        actor=actor or vault.identity.public().fingerprint,
        hlc=vault.document.clock.now().encode(),
        details={
            "relationship_commitment": relationship.commitment(),
            "relationship_type": relationship_type,
        },
        identity=vault.identity,
    )
    vault.save()
    return relationship_id


def _timestamp(
    vault: Vault,
    artifact_id: str,
    digest: str,
    actor: str,
    tsa: TimestampAuthority | None,
) -> TimestampInfo | None:
    if tsa is None:
        vault.queue_deferred(artifact_id, digest)
        return None
    try:
        token = tsa.stamp(digest)
        info = verify_token(token, digest)
    except TimestampError:
        vault.queue_deferred(artifact_id, digest)
        return None
    vault.store_token(artifact_id, token)
    vault.custody.append(
        CustodyAction.TIMESTAMPED,
        artifact_id,
        actor=actor,
        hlc=vault.document.clock.now().encode(),
        details={"tsa": token.tsa_name},
        identity=vault.identity,
    )
    return info
