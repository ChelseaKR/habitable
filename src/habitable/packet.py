# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Assemble a court/inspector evidence packet.

A packet is a self-contained directory: a deterministic, signed ``bundle.json``;
shared copies processed under the configured metadata policy; and a paginated,
human-readable ``packet.pdf`` with an evidence appendix.

The privacy/verifiability bridge: a transformed shared copy has different bytes
from the sealed original and cannot be hashed back to the recorded ``content_hash``.
The packet therefore records a signed ``copied_for_sharing`` custody entry binding
the original's ``content_hash`` to the shared copy's ``shared_hash``. A recipient
can verify the copy they hold, the custody binding, and the RFC 3161 token over the
original hash. The default policy strips embedded metadata; a configured policy may
retain it. Pass ``include_originals=True`` to also embed byte-exact originals with
their full metadata for end-to-end fixity (a deliberate, higher-disclosure choice).
"""

from __future__ import annotations

import base64
import json
import shutil
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from .canonical import JSONValue, canonical_json, sha256_bytes, sha256_file
from .config import SharingPolicy
from .disclosure import ScopeStatement, proof_statement, scope_statement
from .errors import PacketError
from .evidence import CustodyAction, CustodyLog
from .exif import make_shared_copy
from .handoff import build_handoff_manifest, render_handoff_html
from .media import extract_poster_frame, make_shared_media_copy
from .model import Artifact, Capture, EvidenceRelationship, Issue, TimelineEntry
from .private_temp import PrivateTempWorkspace, private_temp_workspace
from .sensor import parse_sensor_csv
from .usecases import get_profile
from .vault import Vault

__all__ = ["PACKET_VERSION", "PacketResult", "build_packet"]

PACKET_VERSION = 4
_BUNDLE = "bundle.json"
_SIGNATURE = "bundle.sig.json"
_MEDIA = "media"
_ORIGINALS = "originals"
_PDF = "packet.pdf"
_HTML = "packet.html"
_INSPECTOR = "inspector.html"
_HANDOFF_PREFIX = "handoff-"

_EXT_BY_TYPE = {
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/tiff": ".tif",
    "image/webp": ".webp",
    # Video/audio (EXP-07): stripped via ffmpeg in habitable.media, not exif.py.
    "video/mp4": ".mp4",
    "video/quicktime": ".mov",
    "audio/mp4": ".m4a",
    "audio/mpeg": ".mp3",
    "audio/wav": ".wav",
}

# EXP-09: instrument-corroborated conditions. A data-file capture (a temperature
# logger's or moisture meter's CSV export) has no embedded location metadata to
# strip, so it is copied into the packet verbatim rather than sanitized like an
# image — and interpreted into a chart-ready series for the HTML/PDF renderers.
_DATA_EXT_BY_TYPE = {
    "text/csv": ".csv",
}

_DOCUMENT_EXT_BY_TYPE = {
    "application/pdf": ".pdf",
    "text/plain": ".txt",
    "text/markdown": ".md",
    "text/html": ".html",
    "message/rfc822": ".eml",
    "application/json": ".json",
}


@dataclass(frozen=True, slots=True)
class PacketResult:
    """What was produced and what it discloses."""

    out_dir: Path
    bundle_path: Path
    pdf_path: Path | None
    html_path: Path | None
    inspector_path: Path | None
    item_count: int
    timestamped_count: int
    includes_originals: bool
    disclosures: tuple[str, ...] = field(default_factory=tuple)
    handoff_paths: tuple[Path, ...] = field(default_factory=tuple)


def build_packet(
    vault: Vault,
    out_dir: Path,
    *,
    issue_id: str | None = None,
    since: str | None = None,
    include_originals: bool = False,
    make_pdf: bool = True,
    inspector_view: bool = False,
    handoff_profile: str | None = None,
    generated_at: str | None = None,
    policy: SharingPolicy | None = None,
) -> PacketResult:
    """Assemble and publish a complete packet without exposing partial output.

    Packet v3 exports the complete custody chain. Until a new packet version defines
    a scoped, rehashed custody view, ``issue_id`` and ``since`` fail before staging so
    an apparently narrow packet cannot reveal identifiers from excluded records.

    Rendering happens in a fresh sibling directory. Only after every artifact is
    complete and the updated custody log is persisted is that directory renamed
    into place. Re-exporting replaces the entire prior directory, so optional files
    from a higher-disclosure export cannot survive one that later omits them.
    """
    if issue_id is not None or since is not None:
        raise PacketError(
            "scoped packet exports are temporarily blocked: packet v4 carries the complete "
            "custody chain, which can reveal identifiers outside an issue or date scope; "
            "export the whole unit until a versioned scoped custody-view format is available"
        )

    sharing = policy or vault.config.sharing
    if sharing.export_custody_identities:
        raise PacketError(
            "custody identity export is not supported: packet v4 public custody proofs are "
            "always identity-stripped; set sharing.export_custody_identities to false"
        )

    parent = out_dir.parent
    parent.mkdir(parents=True, exist_ok=True)
    if out_dir.is_symlink() or (out_dir.exists() and not out_dir.is_dir()):
        raise PacketError(f"packet output must be a directory path: {out_dir}")

    stage = Path(tempfile.mkdtemp(prefix=f".{out_dir.name}.stage-", dir=parent))
    custody_before = vault.custody.to_vault_records()
    vault_saved = False
    try:
        staged = _build_packet_in_dir(
            vault,
            stage,
            packet_name=out_dir.name,
            issue_id=issue_id,
            since=since,
            include_originals=include_originals,
            make_pdf=make_pdf,
            inspector_view=inspector_view,
            handoff_profile=handoff_profile,
            generated_at=generated_at,
            policy=sharing,
        )
        vault.save()
        vault_saved = True
        _publish_staged_packet(stage, out_dir)
    except BaseException:
        # Packet construction appends sharing/export custody entries. If no
        # packet is published, restore both memory and the persisted log.
        vault.custody = CustodyLog.from_records(custody_before)
        if vault_saved:
            vault.save()
        raise
    finally:
        shutil.rmtree(stage, ignore_errors=True)

    return PacketResult(
        out_dir=out_dir,
        bundle_path=out_dir / _BUNDLE,
        pdf_path=(out_dir / _PDF) if staged.pdf_path is not None else None,
        html_path=(out_dir / _HTML) if staged.html_path is not None else None,
        inspector_path=(out_dir / _INSPECTOR) if staged.inspector_path is not None else None,
        item_count=staged.item_count,
        timestamped_count=staged.timestamped_count,
        includes_originals=staged.includes_originals,
        disclosures=staged.disclosures,
        handoff_paths=tuple(out_dir / path.name for path in staged.handoff_paths),
    )


def _build_packet_in_dir(  # noqa: C901 -- packet staging keeps one rollback boundary
    vault: Vault,
    out_dir: Path,
    *,
    packet_name: str,
    issue_id: str | None,
    since: str | None,
    include_originals: bool,
    make_pdf: bool,
    inspector_view: bool,
    handoff_profile: str | None,
    generated_at: str | None,
    policy: SharingPolicy | None,
) -> PacketResult:
    """Build every packet artifact inside a new, unpublished directory."""
    sharing = policy or vault.config.sharing
    out_dir.mkdir(parents=True, exist_ok=True)
    media_dir = out_dir / _MEDIA
    media_dir.mkdir(exist_ok=True)
    originals_dir = out_dir / _ORIGINALS
    if include_originals:
        originals_dir.mkdir(exist_ok=True)

    # Packet v4 requires every timeline assertion and workflow record to be bound
    # into custody. New records are bound when written; legacy/imported records
    # receive an explicitly labelled backfill binding here.
    vault.ensure_timeline_custody(persist=False)
    _ensure_extended_custody(vault)

    actor = vault.identity.public().fingerprint
    selected_issues = _select_issues(vault, issue_id)
    issue_ids = {issue.issue_id for issue in selected_issues}

    items: list[dict[str, JSONValue]] = []
    timestamped = 0
    with private_temp_workspace(forbidden_root=vault.path) as workspace:
        for capture in vault.document.captures():
            if capture.issue_id not in issue_ids:
                continue
            if since is not None and capture.captured_at < since:
                continue
            item = _build_item(
                vault,
                capture,
                sharing,
                media_dir,
                originals_dir,
                workspace,
                include_originals=include_originals,
                actor=actor,
            )
            items.append(item)
            if item.get("timestamp") is not None:
                timestamped += 1
        for artifact in vault.document.artifacts():
            if artifact.issue_id not in issue_ids:
                continue
            item = _build_artifact_item(
                vault,
                artifact,
                sharing,
                media_dir,
                originals_dir,
                workspace,
                include_originals=include_originals,
                actor=actor,
            )
            items.append(item)
            if item.get("timestamp") is not None:
                timestamped += 1

    # Record export actions in the chain of custody (signed), then persist.
    for item in items:
        vault.custody.append(
            CustodyAction.INCLUDED_IN_PACKET,
            str(item["capture_id"]),
            actor=actor,
            hlc=vault.document.clock.now().encode(),
            details={"packet": packet_name},
            identity=vault.identity,
        )

    # Exported identifiers and timestamps must not encode device wall-clock time or the
    # node id (packet v2). Ids are already opaque at mint time; the remaining raw HLC
    # strings — the timeline entries' and custody entries' ``hlc`` — are pseudonymized
    # here via the same per-case salt, so the shared bundle leaks neither.
    doc = vault.document

    def opaque_hlc(raw: str) -> str:
        return doc.opaque_id("hlc", raw)

    # State the current whole-unit boundary in English for the machine-readable
    # bundle; renderers localize it independently. Historical scope shapes remain in
    # the helper and schema so previously emitted packets keep rendering/verifying.
    scope_type = "issue" if issue_id else "unit"
    scope = scope_statement("en", scope_type=scope_type, issue_id=issue_id or "", since=since or "")
    disclosures = _disclosures(
        items,
        sharing,
        scope,
        include_originals=include_originals,
        awaiting=len(items) - timestamped,
        total=len(items),
    )
    timeline_entries = _timeline(vault, issue_ids)
    relationships = [
        relationship
        for relationship in vault.document.relationships()
        if relationship.issue_id in issue_ids
    ]
    selected_profile_id = handoff_profile or vault.document.use_case_profile()
    selected_profile = get_profile(selected_profile_id) if selected_profile_id else None
    bundle: dict[str, JSONValue] = {
        "packet_version": PACKET_VERSION,
        "case_id": vault.document.case_id,
        "unit": vault.document.get_meta("unit"),
        "scope": {
            "type": scope_type,
            "issue_id": issue_id or "",
            "since": since or "",
            "statement": scope.statement,
            "exclusions": cast(JSONValue, list(scope.exclusions)),
        },
        "generated_at": generated_at or _now_iso(),
        "producer_fingerprint": actor,
        "hash_algorithm": "sha256",
        "language": vault.config.language,
        "template": {
            "header": vault.config.packet_template.header,
            "footer": vault.config.packet_template.footer,
        },
        "issues": cast(JSONValue, [_issue_json(issue) for issue in selected_issues]),
        "timeline": cast(
            JSONValue, [_timeline_json(vault, entry, opaque_hlc) for entry in timeline_entries]
        ),
        "items": cast(JSONValue, items),
        "relationships": cast(
            JSONValue,
            [_relationship_json(vault, relationship, opaque_hlc) for relationship in relationships],
        ),
        "use_case_profile": (
            cast(JSONValue, selected_profile.to_json()) if selected_profile is not None else None
        ),
        "custody_proof": vault.custody.integrity_proof(hlc_map=opaque_hlc),
        "appendix": {
            "item_count": len(items),
            "timestamped_count": timestamped,
            "includes_originals": include_originals,
            "timeline_count": len(timeline_entries),
            "custody_bound_timeline_count": len(timeline_entries),
            "artifact_count": sum(1 for item in items if item.get("record_kind") == "artifact"),
            "relationship_count": len(relationships),
        },
        "disclosures": cast(JSONValue, list(disclosures)),
    }
    if selected_profile is not None:
        bundle["handoff_views"] = cast(
            JSONValue, [build_handoff_manifest(bundle, selected_profile)]
        )
    else:
        bundle["handoff_views"] = []
    bundle_bytes = canonical_json(bundle)
    bundle_path = out_dir / _BUNDLE
    bundle_path.write_bytes(bundle_bytes)
    _write_signature(vault, out_dir, bundle_bytes)
    # An accessible HTML rendering always accompanies the packet (the conformant
    # human-readable view; see docs/accessibility/ACR.md).
    from . import htmlpacket

    html_path = out_dir / _HTML
    htmlpacket.render_packet_html(bundle, media_dir, html_path)

    # An optional recipient-oriented (inspector) rollup of the same signed
    # bundle, organized room → condition → chronological timeline.
    inspector_path: Path | None = None
    if inspector_view:
        inspector_path = out_dir / _INSPECTOR
        htmlpacket.render_inspector_html(bundle, media_dir, inspector_path)

    handoff_paths: tuple[Path, ...] = ()
    if selected_profile is not None:
        handoff_path = out_dir / f"{_HANDOFF_PREFIX}{selected_profile.profile_id}.html"
        manifests = bundle.get("handoff_views")
        if isinstance(manifests, list) and manifests and isinstance(manifests[0], dict):
            render_handoff_html(
                manifests[0],
                handoff_path,
                language=vault.config.language,
            )
            handoff_paths = (handoff_path,)

    pdf_path: Path | None = None
    if make_pdf:
        from . import pdf as pdf_module

        pdf_path = out_dir / _PDF
        pdf_module.render_packet_pdf(bundle, media_dir, pdf_path)

    return PacketResult(
        out_dir=out_dir,
        bundle_path=bundle_path,
        pdf_path=pdf_path,
        html_path=html_path,
        inspector_path=inspector_path,
        item_count=len(items),
        timestamped_count=timestamped,
        includes_originals=include_originals,
        disclosures=disclosures,
        handoff_paths=handoff_paths,
    )


def _publish_staged_packet(staged: Path, target: Path) -> None:
    """Rename a complete sibling directory into place, restoring on failure.

    A directory containing files cannot be atomically overwritten portably. For
    an existing target, use two same-filesystem renames and retain the old packet
    only for the few instructions needed to install the new one. Any ordinary
    exception restores the old directory; successful publication removes it.
    """
    if not target.exists():
        staged.replace(target)
        return

    backup = Path(tempfile.mkdtemp(prefix=f".{target.name}.backup-", dir=target.parent))
    backup.rmdir()  # reserve a unique absent path for the rename
    target.replace(backup)
    try:
        staged.replace(target)
    except BaseException:
        backup.replace(target)
        raise

    try:
        shutil.rmtree(backup)
    except BaseException:
        # A stale broader export is a privacy failure. Roll back the newly
        # published directory instead of leaving the old packet in a hidden
        # backup beside it.
        target.replace(staged)
        backup.replace(target)
        raise


def _build_item(
    vault: Vault,
    capture: Capture,
    sharing: SharingPolicy,
    media_dir: Path,
    originals_dir: Path,
    workspace: PrivateTempWorkspace,
    *,
    include_originals: bool,
    actor: str,
) -> dict[str, JSONValue]:
    capture_id = capture.capture_id
    content_hash = capture.content_hash
    media_type = capture.media_type
    issue_id = capture.issue_id
    captured_at = capture.captured_at

    original_bytes = vault.read_original(capture_id, content_hash)
    ext = _EXT_BY_TYPE.get(media_type, "")
    data_ext = _DATA_EXT_BY_TYPE.get(media_type, "")
    is_video = media_type.startswith("video/")
    is_audio = media_type.startswith("audio/")
    shared_name = ""
    shared_hash = ""
    stripped = "skipped"
    poster_name = ""
    poster_hash = ""
    sensor: dict[str, JSONValue] | None = None

    if ext:  # a media type we know how to sanitize (image, or video/audio via ffmpeg)
        source = workspace.write_bytes(original_bytes, suffix=ext)
        shared_name = f"{capture_id}{ext}"
        try:
            if is_video or is_audio:
                report = make_shared_media_copy(source, media_dir / shared_name, sharing)
            else:
                report = make_shared_copy(source, media_dir / shared_name, sharing)

            # A poster frame is the accessible fallback for video (E-03/R-06-style alt
            # text has nothing to attach to for a moving image); best-effort -- a
            # missing ffmpeg or an unreadable frame degrades to transcript-only, it
            # never blocks packet assembly (R-03: media handling stays optional).
            if is_video:
                poster_path = media_dir / f"{capture_id}-poster.jpg"
                if extract_poster_frame(source, poster_path):
                    poster_name = poster_path.name
                    poster_hash = sha256_file(poster_path)
        finally:
            # Minimize the path-based copy's lifetime to this one sanitizer invocation;
            # the enclosing workspace remains a second cleanup boundary on failure.
            source.unlink(missing_ok=True)

        shared_hash = sha256_file(media_dir / shared_name)
        stripped = ", ".join(report.removed) or "none"

        custody_details: dict[str, str] = {
            "content_hash": content_hash,
            "shared_hash": shared_hash,
            "stripped": stripped,
        }
        if poster_name:
            custody_details["poster_hash"] = poster_hash
        vault.custody.append(
            CustodyAction.COPIED_FOR_SHARING,
            capture_id,
            actor=actor,
            hlc=vault.document.clock.now().encode(),
            details=custody_details,
            identity=vault.identity,
        )
    elif data_ext:  # an instrument data file (EXP-09): no location metadata to strip
        shared_name = f"{capture_id}{data_ext}"
        (media_dir / shared_name).write_bytes(original_bytes)
        shared_hash = sha256_file(media_dir / shared_name)
        stripped = "not applicable (data file; no embedded location metadata)"
        vault.custody.append(
            CustodyAction.COPIED_FOR_SHARING,
            capture_id,
            actor=actor,
            hlc=vault.document.clock.now().encode(),
            details={
                "content_hash": content_hash,
                "shared_hash": shared_hash,
                "stripped": stripped,
            },
            identity=vault.identity,
        )
        series = parse_sensor_csv(original_bytes)
        sensor = cast(dict[str, JSONValue], series.to_dict()) if series is not None else None

    if include_originals:
        (originals_dir / capture_id).write_bytes(original_bytes)

    token = vault.get_token(capture_id)
    archives = vault.get_archive_tokens(capture_id)
    additional = vault.get_additional_tokens(capture_id)
    return {
        "record_kind": "capture",
        "capture_id": capture_id,
        "issue_id": issue_id,
        "content_hash": content_hash,
        "media_type": media_type,
        "captured_at": captured_at,
        "shared_name": shared_name,
        "shared_hash": shared_hash,
        "stripped": stripped,
        "poster_name": poster_name,
        "poster_hash": poster_hash,
        "transcript": capture.transcript,
        "has_original": include_originals,
        "timestamp": cast(JSONValue, token.to_dict()) if token is not None else None,
        "archive_timestamps": cast(JSONValue, [a.to_dict() for a in archives]),
        "additional_timestamps": cast(JSONValue, [a.to_dict() for a in additional]),
        "sensor": sensor,
    }


def _build_artifact_item(
    vault: Vault,
    artifact: Artifact,
    sharing: SharingPolicy,
    media_dir: Path,
    originals_dir: Path,
    workspace: PrivateTempWorkspace,
    *,
    include_originals: bool,
    actor: str,
) -> dict[str, JSONValue]:
    """Build a packet item for a sealed document-like artifact."""
    original_bytes = vault.read_original(artifact.artifact_id, artifact.content_hash)
    image_ext = _EXT_BY_TYPE.get(artifact.media_type, "")
    document_ext = _DOCUMENT_EXT_BY_TYPE.get(artifact.media_type, "")
    data_ext = _DATA_EXT_BY_TYPE.get(artifact.media_type, "")
    shared_ext = image_ext or document_ext or data_ext or ".bin"
    shared_name = f"{artifact.artifact_id}{shared_ext}"

    if artifact.media_type.startswith("image/") and image_ext:
        source = workspace.write_bytes(original_bytes, suffix=image_ext)
        try:
            report = make_shared_copy(source, media_dir / shared_name, sharing)
        finally:
            source.unlink(missing_ok=True)
        stripped = ", ".join(report.removed) or "none"
    else:
        (media_dir / shared_name).write_bytes(original_bytes)
        stripped = (
            "not applicable (data file; no embedded location metadata)"
            if data_ext
            else "not sanitized (document may contain embedded metadata)"
        )

    shared_hash = sha256_file(media_dir / shared_name)
    vault.custody.append(
        CustodyAction.COPIED_FOR_SHARING,
        artifact.artifact_id,
        actor=actor,
        hlc=vault.document.clock.now().encode(),
        details={
            "content_hash": artifact.content_hash,
            "shared_hash": shared_hash,
            "stripped": stripped,
        },
        identity=vault.identity,
    )
    if include_originals:
        (originals_dir / artifact.artifact_id).write_bytes(original_bytes)

    token = vault.get_token(artifact.artifact_id)
    return {
        "record_kind": "artifact",
        "capture_id": artifact.artifact_id,
        "issue_id": artifact.issue_id,
        "content_hash": artifact.content_hash,
        "media_type": artifact.media_type,
        "captured_at": artifact.occurred_at,
        "shared_name": shared_name,
        "shared_hash": shared_hash,
        "stripped": stripped,
        "poster_name": "",
        "poster_hash": "",
        "transcript": artifact.accessible_description,
        "has_original": include_originals,
        "timestamp": cast(JSONValue, token.to_dict()) if token is not None else None,
        "archive_timestamps": cast(
            JSONValue,
            [token.to_dict() for token in vault.get_archive_tokens(artifact.artifact_id)],
        ),
        "additional_timestamps": cast(
            JSONValue,
            [token.to_dict() for token in vault.get_additional_tokens(artifact.artifact_id)],
        ),
        "sensor": None,
        "artifact": cast(JSONValue, artifact.semantic_payload()),
        "integrity": {
            "algorithm": "sha256",
            "commitment": artifact.commitment(),
            "custody_action": "artifact_added",
            "binding_stage": _extended_binding_stage(
                vault,
                artifact.artifact_id,
                "artifact_commitment",
                artifact.commitment(),
                CustodyAction.ARTIFACT_ADDED,
            ),
        },
    }


def _relationship_json(
    vault: Vault,
    relationship: EvidenceRelationship,
    opaque_hlc: Callable[[str], str],
) -> dict[str, JSONValue]:
    payload = relationship.semantic_payload()
    payload["order_token"] = opaque_hlc(relationship.hlc)
    payload["integrity"] = {
        "algorithm": "sha256",
        "commitment": relationship.commitment(),
        "custody_action": "relationship_added",
        "binding_stage": _extended_binding_stage(
            vault,
            relationship.relationship_id,
            "relationship_commitment",
            relationship.commitment(),
            CustodyAction.RELATIONSHIP_ADDED,
        ),
    }
    return payload


def _extended_binding_stage(
    vault: Vault,
    item_id: str,
    detail_key: str,
    commitment: str,
    action: CustodyAction,
) -> str:
    for entry in reversed(vault.custody.entries):
        if (
            entry.action == action
            and entry.item_id == item_id
            and entry.details.get(detail_key) == commitment
        ):
            return entry.details.get("stage", "recorded")
    return ""


def _ensure_extended_custody(vault: Vault) -> None:
    """Backfill explicit semantic bindings for legacy/imported workflow records."""
    actor = vault.identity.public().fingerprint
    for artifact in vault.document.artifacts():
        commitment = artifact.commitment()
        if _extended_binding_stage(
            vault,
            artifact.artifact_id,
            "artifact_commitment",
            commitment,
            CustodyAction.ARTIFACT_ADDED,
        ):
            continue
        vault.custody.append(
            CustodyAction.ARTIFACT_ADDED,
            artifact.artifact_id,
            actor=actor,
            hlc=vault.document.clock.now().encode(),
            details={"artifact_commitment": commitment, "stage": "import_binding"},
            identity=vault.identity,
        )
    for relationship in vault.document.relationships():
        commitment = relationship.commitment()
        if _extended_binding_stage(
            vault,
            relationship.relationship_id,
            "relationship_commitment",
            commitment,
            CustodyAction.RELATIONSHIP_ADDED,
        ):
            continue
        vault.custody.append(
            CustodyAction.RELATIONSHIP_ADDED,
            relationship.relationship_id,
            actor=actor,
            hlc=vault.document.clock.now().encode(),
            details={"relationship_commitment": commitment, "stage": "import_binding"},
            identity=vault.identity,
        )


def _select_issues(vault: Vault, issue_id: str | None) -> list[Issue]:
    issues = vault.document.issues()
    if issue_id is None:
        return list(issues)
    selected = [issue for issue in issues if issue.issue_id == issue_id]
    if not selected:
        raise PacketError(f"unknown issue: {issue_id!r}")
    return selected


def _timeline(vault: Vault, issue_ids: set[str]) -> list[TimelineEntry]:
    return [entry for entry in vault.document.timeline() if entry.issue_id in issue_ids]


def _issue_json(issue: Issue) -> dict[str, JSONValue]:
    return {
        "issue_id": issue.issue_id,
        "category": issue.category,
        "room": issue.room,
        "title": issue.title,
        "status": issue.status,
        "severity": issue.severity,
        "description": issue.description,
    }


def _timeline_json(
    vault: Vault, entry: TimelineEntry, opaque_hlc: Callable[[str], str]
) -> dict[str, JSONValue]:
    """Render a v3 timeline entry without reusing packet-v2 field meanings."""
    payload = entry.semantic_payload()
    commitment = entry.commitment()
    stage = vault.timeline_binding_stage(entry.entry_id, commitment)
    payload["order_token"] = opaque_hlc(entry.hlc)
    payload["integrity"] = {
        "algorithm": "sha256",
        "commitment": commitment,
        "custody_action": "note_added",
        "binding_stage": stage,
    }
    if entry.schema_version < 2:
        payload["migration"] = {
            "from_case_timeline_schema": entry.schema_version,
            "legacy_kind_preserved_as_other_label": True,
            "occurred_at_unknown": True,
            "source_unknown": True,
        }
    return payload


def _write_signature(vault: Vault, out_dir: Path, bundle_bytes: bytes) -> None:
    bundle_hash = sha256_bytes(bundle_bytes)
    signature = vault.identity.sign(bundle_hash.encode("ascii"))
    public = vault.identity.public()
    doc = {
        "producer_fingerprint": public.fingerprint,
        "sign_public": base64.b64encode(public.sign_public).decode("ascii"),
        "bundle_sha256": bundle_hash,
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    (out_dir / _SIGNATURE).write_text(json.dumps(doc, indent=2, sort_keys=True), encoding="utf-8")


def _disclosures(
    items: list[dict[str, JSONValue]],
    sharing: SharingPolicy,
    scope: ScopeStatement,
    *,
    include_originals: bool,
    awaiting: int,
    total: int,
) -> tuple[str, ...]:
    if sharing.strip_all_metadata:
        metadata = "all embedded metadata stripped from supported shared media"
    elif sharing.strip_location:
        metadata = (
            "EXIF GPS stripped from supported still-image shared copies; "
            "other embedded metadata may be retained"
        )
    else:
        metadata = (
            "shared-copy policy permits embedded metadata, including location, to be retained"
        )
    notes = [
        *scope.lines(),
        f"{len(items)} media item(s) included as shared copies",
        metadata,
        "custody identities not exported",
    ]
    data_items = sum(1 for item in items if item.get("sensor") is not None)
    if data_items:
        notes.append(
            f"{data_items} instrument data file(s) included verbatim "
            "(independent corroboration; no location metadata to strip)"
        )
    if include_originals:
        notes.append("sealed ORIGINALS embedded (full metadata, including any location)")
    if awaiting > 0:
        # An honest, non-fatal disclosure: awaiting items are not worthless — their
        # content hash still anchors them at capture; only the upper-bound date is missing.
        notes.append(
            proof_statement("en").awaiting_timestamp_note.format(awaiting=awaiting, total=total)
        )
    return tuple(notes)


def _now_iso() -> str:
    return datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
