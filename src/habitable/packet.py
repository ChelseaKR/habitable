# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Assemble a court/inspector evidence packet.

A packet is a self-contained directory: a deterministic, signed ``bundle.json``;
location-stripped shared copies of the media; and a paginated, human-readable
``packet.pdf`` with an evidence appendix.

The privacy/verifiability bridge: a shared copy has its metadata stripped, so its
bytes differ from the sealed original and cannot be hashed back to the recorded
``content_hash``. The packet therefore records a signed ``copied_for_sharing``
custody entry binding the original's ``content_hash`` to the shared copy's
``shared_hash``. A recipient can then verify the image they hold (via
``shared_hash``), the custody binding to ``content_hash``, and the RFC 3161 token
over ``content_hash`` — without the packet ever disclosing the home's location.
Pass ``include_originals=True`` to also embed the sealed originals for end-to-end
fixity (a deliberate, higher-disclosure choice).
"""

from __future__ import annotations

import base64
import json
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from .canonical import JSONValue, canonical_json, sha256_bytes, sha256_file
from .config import SharingPolicy
from .errors import PacketError
from .evidence import CustodyAction
from .exif import make_shared_copy
from .model import Capture, Issue, TimelineEntry
from .vault import Vault

__all__ = ["PACKET_VERSION", "PacketResult", "build_packet"]

PACKET_VERSION = 1
_BUNDLE = "bundle.json"
_SIGNATURE = "bundle.sig.json"
_MEDIA = "media"
_ORIGINALS = "originals"
_PDF = "packet.pdf"

_EXT_BY_TYPE = {
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/tiff": ".tif",
    "image/webp": ".webp",
}


@dataclass(frozen=True, slots=True)
class PacketResult:
    """What was produced and what it discloses."""

    out_dir: Path
    bundle_path: Path
    pdf_path: Path | None
    item_count: int
    timestamped_count: int
    includes_originals: bool
    disclosures: tuple[str, ...] = field(default_factory=tuple)


def build_packet(
    vault: Vault,
    out_dir: Path,
    *,
    issue_id: str | None = None,
    since: str | None = None,
    include_originals: bool = False,
    make_pdf: bool = True,
    generated_at: str | None = None,
    policy: SharingPolicy | None = None,
) -> PacketResult:
    """Assemble an evidence packet for one issue or a whole unit."""
    sharing = policy or vault.config.sharing
    out_dir.mkdir(parents=True, exist_ok=True)
    media_dir = out_dir / _MEDIA
    media_dir.mkdir(exist_ok=True)
    originals_dir = out_dir / _ORIGINALS
    if include_originals:
        originals_dir.mkdir(exist_ok=True)

    actor = vault.identity.public().fingerprint
    selected_issues = _select_issues(vault, issue_id)
    issue_ids = {issue.issue_id for issue in selected_issues}

    items: list[dict[str, JSONValue]] = []
    timestamped = 0
    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
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
                tmp_dir,
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
            details={"packet": out_dir.name},
            identity=vault.identity,
        )

    bundle: dict[str, JSONValue] = {
        "packet_version": PACKET_VERSION,
        "case_id": vault.document.case_id,
        "unit": vault.document.get_meta("unit"),
        "scope": {
            "type": "issue" if issue_id else "unit",
            "issue_id": issue_id or "",
            "since": since or "",
        },
        "generated_at": generated_at or _now_iso(),
        "producer_fingerprint": actor,
        "hash_algorithm": "sha256",
        "template": {
            "header": vault.config.packet_template.header,
            "footer": vault.config.packet_template.footer,
        },
        "issues": cast(JSONValue, [_issue_json(issue) for issue in selected_issues]),
        "timeline": cast(JSONValue, [_timeline_json(e) for e in _timeline(vault, issue_ids)]),
        "items": cast(JSONValue, items),
        "custody_proof": vault.custody.integrity_proof(),
        "appendix": {
            "item_count": len(items),
            "timestamped_count": timestamped,
            "includes_originals": include_originals,
        },
    }
    bundle_bytes = canonical_json(bundle)
    bundle_path = out_dir / _BUNDLE
    bundle_path.write_bytes(bundle_bytes)
    _write_signature(vault, out_dir, bundle_bytes)
    vault.save()

    pdf_path: Path | None = None
    if make_pdf:
        from . import pdf as pdf_module

        pdf_path = out_dir / _PDF
        pdf_module.render_packet_pdf(bundle, media_dir, pdf_path)

    disclosures = _disclosures(items, sharing, include_originals=include_originals)
    return PacketResult(
        out_dir=out_dir,
        bundle_path=bundle_path,
        pdf_path=pdf_path,
        item_count=len(items),
        timestamped_count=timestamped,
        includes_originals=include_originals,
        disclosures=disclosures,
    )


def _build_item(
    vault: Vault,
    capture: Capture,
    sharing: SharingPolicy,
    media_dir: Path,
    originals_dir: Path,
    tmp_dir: Path,
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
    shared_name = ""
    shared_hash = ""
    stripped = "skipped"

    if ext:  # an image we know how to sanitize
        source = tmp_dir / f"{capture_id}{ext}"
        source.write_bytes(original_bytes)
        shared_name = f"{capture_id}{ext}"
        report = make_shared_copy(source, media_dir / shared_name, sharing)
        shared_hash = sha256_file(media_dir / shared_name)
        stripped = ", ".join(report.removed) or "none"
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

    if include_originals:
        (originals_dir / capture_id).write_bytes(original_bytes)

    token = vault.get_token(capture_id)
    return {
        "capture_id": capture_id,
        "issue_id": issue_id,
        "content_hash": content_hash,
        "media_type": media_type,
        "captured_at": captured_at,
        "shared_name": shared_name,
        "shared_hash": shared_hash,
        "stripped": stripped,
        "has_original": include_originals,
        "timestamp": cast(JSONValue, token.to_dict()) if token is not None else None,
    }


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


def _timeline_json(entry: TimelineEntry) -> dict[str, JSONValue]:
    return {
        "entry_id": entry.entry_id,
        "issue_id": entry.issue_id,
        "kind": entry.kind,
        "text": entry.text,
        "hlc": entry.hlc,
    }


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
    items: list[dict[str, JSONValue]], sharing: SharingPolicy, *, include_originals: bool
) -> tuple[str, ...]:
    location = "stripped from shared copies" if sharing.strip_location else "RETAINED"
    identities = "not exported" if not sharing.export_custody_identities else "EXPORTED"
    notes = [
        f"{len(items)} media item(s) included as shared copies",
        f"location {location}",
        f"custody identities {identities}",
    ]
    if include_originals:
        notes.append("sealed ORIGINALS embedded (full metadata, including any location)")
    return tuple(notes)


def _now_iso() -> str:
    return datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
