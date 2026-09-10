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
from .correspondence import MESSAGE_MEDIA_TYPE, Attachment, attachments, read_message
from .errors import CaptureError, TimestampError
from .evidence import CustodyAction
from .private_temp import PrivateTempWorkspace, private_temp_workspace
from .tsa import TimestampAuthority, TimestampInfo, verify_token
from .usecases import ARTIFACT_TYPES, RELATIONSHIP_TYPES
from .vault import Vault

__all__ = [
    "ArtifactResult",
    "CorrespondenceResult",
    "add_relationship",
    "capture_artifact",
    "capture_correspondence",
]

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


@dataclass(frozen=True, slots=True)
class CorrespondenceResult:
    """What one ``.eml`` capture produced: the message, and its attachments.

    ``declared`` is the attachment count read out of the *message's own* part walk,
    and ``attachments`` is what was sealed. The two are separate on purpose: a loop
    that sealed two parts of a two-part message and one that sealed two parts of a
    five-part message are indistinguishable from the sealed side, and only the first
    of those is the message the packet then describes.
    """

    message: ArtifactResult
    attachments: tuple[ArtifactResult, ...]
    relationship_ids: tuple[str, ...]
    declared: int
    unreadable: tuple[str, ...] = field(default_factory=tuple)

    @property
    def items(self) -> int:
        """Custody-bound items this capture created, message included."""
        return 1 + len(self.attachments)


def capture_correspondence(
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
    attachment_type: str = "other_document",
    actor: str | None = None,
    tsa: TimestampAuthority | None = None,
    extra_tsas: Sequence[TimestampAuthority] = (),
) -> CorrespondenceResult:
    """Seal one ``.eml`` and each of its attachments as custody-bound evidence.

    Issue #304. Sealing the message alone -- which is what ``capture_artifact`` does,
    and did before this existed -- puts the attachments *inside* an opaque blob: their
    bytes are in the record, and they are in no evidence list, no custody entry of
    their own and no item count. Issue #158 is the precedent for why that is not good
    enough: a capture whose bytes never reached the packet still verified clean.

    Order matters and is the reason this is not a loop in the CLI. The message is
    parsed and **refused before anything is sealed**, so a file that is not a message
    can never become an empty item; only then is the ``.eml`` sealed, and only then
    each readable attachment, each joined back to the message with a ``supports``
    relationship whose assertion states which part of which message it was.

    ``supports`` rather than a minted ``attachment_of``: the published schema's
    ``relationship_type`` is a closed enum, so a new value is a change a third party
    who pinned the ``$id`` would reject, and ``supports`` plus a precise assertion
    carries the same fact today. Whether the vocabulary should grow a term for it is
    an owner decision, recorded rather than taken here.

    An attachment whose content cannot be decoded is **named, not skipped**: it stays
    in ``declared``, appears in ``unreadable``, and the packet's own summary counts it
    among the attachments the message declares but not among those that were read.
    """
    src = Path(source)
    if not src.is_file():
        raise CaptureError(f"no such artifact file: {src}")
    if attachment_type not in ARTIFACT_TYPES:
        raise CaptureError(f"unknown artifact type: {attachment_type!r}")
    try:
        raw = src.read_bytes()
    except OSError as exc:
        raise CaptureError(f"could not read message: {src}") from exc

    # Refuse before sealing anything. `read_message` names the file in the refusal;
    # a message-shaped error with no path sends the reader into this module.
    message = read_message(raw, source=src.name)
    parts = attachments(message)

    sealed_message = capture_artifact(
        vault,
        src,
        issue_id=issue_id,
        artifact_type=artifact_type,
        title=title,
        source_assertion=source_assertion,
        occurred_at=occurred_at,
        issuer=issuer,
        accessible_description=accessible_description,
        actor=actor,
        tsa=tsa,
        extra_tsas=extra_tsas,
        media_type=MESSAGE_MEDIA_TYPE,
    )

    sealed: list[ArtifactResult] = []
    relationships: list[str] = []
    unreadable: list[str] = []
    with private_temp_workspace(forbidden_root=vault.path) as workspace:
        for part in parts:
            if part.payload is None:
                unreadable.append(_part_label(part, len(parts)))
                continue
            sealed_part, relationship_id = _seal_attachment(
                vault,
                part,
                workspace=workspace,
                message_id=sealed_message.artifact_id,
                total=len(parts),
                issue_id=issue_id,
                artifact_type=attachment_type,
                source_assertion=source_assertion,
                occurred_at=occurred_at,
                issuer=issuer,
                actor=actor,
                tsa=tsa,
                extra_tsas=extra_tsas,
            )
            sealed.append(sealed_part)
            relationships.append(relationship_id)

    return CorrespondenceResult(
        message=sealed_message,
        attachments=tuple(sealed),
        relationship_ids=tuple(relationships),
        declared=len(parts),
        unreadable=tuple(unreadable),
    )


def _part_label(part: Attachment, total: int) -> str:
    return f"attachment {part.index} of {total} ({part.filename or 'unnamed'}, {part.media_type})"


def _seal_attachment(
    vault: Vault,
    part: Attachment,
    *,
    workspace: PrivateTempWorkspace,
    message_id: str,
    total: int,
    issue_id: str,
    artifact_type: str,
    source_assertion: str,
    occurred_at: str,
    issuer: str,
    actor: str | None,
    tsa: TimestampAuthority | None,
    extra_tsas: Sequence[TimestampAuthority],
) -> tuple[ArtifactResult, str]:
    """Seal one decoded attachment and join it back to the message it came from."""
    assert part.payload is not None
    suffix = Path(part.filename).suffix if part.filename else ""
    path = workspace.write_bytes(part.payload, suffix=suffix or ".bin")
    try:
        result = capture_artifact(
            vault,
            path,
            issue_id=issue_id,
            artifact_type=artifact_type,
            title=f"Attachment {part.index} of {total}: {part.filename or 'unnamed'}",
            source_assertion=source_assertion,
            occurred_at=occurred_at,
            issuer=issuer,
            accessible_description="",
            actor=actor,
            tsa=tsa,
            extra_tsas=extra_tsas,
            media_type=part.media_type,
            source_name=part.filename or path.name,
        )
    finally:
        path.unlink(missing_ok=True)
    relationship_id = add_relationship(
        vault,
        issue_id=issue_id,
        relationship_type="supports",
        source_id=result.artifact_id,
        target_id=message_id,
        assertion=(
            f"Attachment {part.index} of {total} in the sealed message {message_id}, "
            f"declared as {part.filename or 'unnamed'} ({part.media_type})."
        ),
        actor=actor,
    )
    return result, relationship_id


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
