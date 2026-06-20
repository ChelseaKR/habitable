# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""The capture pipeline: media in, evidence-grade record out.

Capture never blocks on the network. At capture the bytes are hashed, sealed
immutably, and a custody entry is appended — all offline. A trusted timestamp is
then obtained if an authority is reachable; otherwise the item is queued and
shown as *awaiting-timestamp* until connectivity lets the token be fetched with
:func:`resolve_deferred`.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from .canonical import sha256_file
from .errors import CaptureError, TimestampError
from .evidence import CustodyAction
from .exif import read_metadata
from .tsa import TimestampAuthority, TimestampInfo, retimestamp, verify_token
from .vault import Vault

__all__ = ["CaptureResult", "capture", "resolve_deferred", "retimestamp_all"]

_MEDIA_TYPES = {
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".heic": "image/heic",
    ".webp": "image/webp",
    ".tif": "image/tiff",
    ".tiff": "image/tiff",
    ".mp4": "video/mp4",
    ".mov": "video/quicktime",
}


@dataclass(frozen=True, slots=True)
class CaptureResult:
    """The outcome of capturing one item."""

    capture_id: str
    content_hash: str
    timestamped: bool
    timestamp_info: TimestampInfo | None
    had_location: bool
    media_type: str
    extra_authorities: tuple[str, ...] = field(default_factory=tuple)


def capture(
    vault: Vault,
    source: str | Path,
    *,
    issue_id: str,
    actor: str | None = None,
    tsa: TimestampAuthority | None = None,
    extra_tsas: Sequence[TimestampAuthority] = (),
    media_type: str | None = None,
) -> CaptureResult:
    """Capture a media file into the vault as an evidence-grade record.

    ``tsa`` is the primary timestamp authority; ``extra_tsas`` are additional,
    independent authorities stamped for redundancy so the proof does not rest on a
    single TSA (item R-16). Extra authorities are stamped only when the primary
    succeeds (i.e. the device is online); offline, the item is queued and resolved
    later against the primary."""
    src = Path(source)
    if not src.is_file():
        raise CaptureError(f"no such media file: {src}")

    digest = sha256_file(src)
    resolved_media_type = media_type or _MEDIA_TYPES.get(
        src.suffix.lower(), "application/octet-stream"
    )
    metadata = read_metadata(src)
    actor_id = actor or vault.identity.public().fingerprint

    stamp = vault.document.clock.now()
    capture_id = f"cap-{stamp.encode()}"

    # 1. Seal the original immutably (encrypted), bound to its content hash.
    sealed_name = vault.seal_original(capture_id, src, digest)

    # 2. Record capture in the chain of custody (signed).
    vault.custody.append(
        CustodyAction.CAPTURED,
        capture_id,
        actor=actor_id,
        hlc=stamp.encode(),
        details={"media_type": resolved_media_type},
        private_details={"source": src.name},  # tenant filename: vault-only, never exported
        identity=vault.identity,
    )

    # 3. Immediately re-check fixity from the sealed copy (defense in depth).
    vault.read_original(capture_id, digest)
    vault.custody.append(
        CustodyAction.FIXITY_CHECKED,
        capture_id,
        actor=actor_id,
        hlc=vault.document.clock.now().encode(),
        details={"content_hash": digest},
        identity=vault.identity,
    )

    # 4. Trusted timestamp now if possible, else queue it.
    info = _try_timestamp(vault, capture_id, digest, actor_id, tsa)

    # 4b. Redundant authorities (only meaningful once the primary stamped, i.e. online).
    extra_authorities: tuple[str, ...] = ()
    if info is not None and extra_tsas:
        extra_authorities = _stamp_additional(vault, capture_id, digest, actor_id, extra_tsas)

    # 5. Add the capture to the case document.
    captured_at = _exif_to_iso(metadata.capture_time) or _ms_to_iso(stamp.wall_ms)
    vault.document.add_capture(
        issue_id=issue_id,
        content_hash=digest,
        media_type=resolved_media_type,
        sealed_name=sealed_name,
        captured_at=captured_at,
        capture_id=capture_id,
    )
    vault.save()
    return CaptureResult(
        capture_id=capture_id,
        content_hash=digest,
        timestamped=info is not None,
        timestamp_info=info,
        had_location=metadata.has_location,
        media_type=resolved_media_type,
        extra_authorities=extra_authorities,
    )


def resolve_deferred(vault: Vault, tsa: TimestampAuthority) -> list[CaptureResult]:
    """Fetch trusted timestamps for every capture queued while offline."""
    results: list[CaptureResult] = []
    actor_id = vault.identity.public().fingerprint
    for item in vault.deferred():
        info = _stamp_and_record(vault, item.capture_id, item.digest, actor_id, tsa)
        vault.clear_deferred(item.capture_id)
        results.append(
            CaptureResult(
                capture_id=item.capture_id,
                content_hash=item.digest,
                timestamped=True,
                timestamp_info=info,
                had_location=False,
                media_type="",
            )
        )
    vault.save()
    return results


def retimestamp_all(vault: Vault, tsa: TimestampAuthority) -> int:
    """Archive-(re)timestamp every timestamped capture, extending proof lifetime.

    Stamps over each capture's most recent token so the proof survives the
    original authority's certificate or hash algorithm aging out. Returns the
    number of items archived.
    """
    actor = vault.identity.public().fingerprint
    count = 0
    for capture_record in vault.document.captures():
        latest = vault.latest_token(capture_record.capture_id)
        if latest is None:
            continue  # nothing to archive (still awaiting its first timestamp)
        archive = retimestamp(latest, tsa)
        vault.add_archive_token(capture_record.capture_id, archive)
        vault.custody.append(
            CustodyAction.TIMESTAMPED,
            capture_record.capture_id,
            actor=actor,
            hlc=vault.document.clock.now().encode(),
            details={"kind": "archive", "tsa": archive.tsa_name},
            identity=vault.identity,
        )
        count += 1
    vault.save()
    return count


def _try_timestamp(
    vault: Vault,
    capture_id: str,
    digest: str,
    actor_id: str,
    tsa: TimestampAuthority | None,
) -> TimestampInfo | None:
    if tsa is None:
        vault.queue_deferred(capture_id, digest)
        return None
    try:
        return _stamp_and_record(vault, capture_id, digest, actor_id, tsa)
    except TimestampError:
        # Offline or authority unreachable: queue and carry on. Never block capture.
        vault.queue_deferred(capture_id, digest)
        return None


def _stamp_additional(
    vault: Vault,
    capture_id: str,
    digest: str,
    actor_id: str,
    tsas: Sequence[TimestampAuthority],
) -> tuple[str, ...]:
    """Stamp ``digest`` against each redundant authority; return those that succeeded.

    A redundant authority that is unreachable is skipped (never blocks capture); the
    primary token already proves existence and others can be added later."""
    stamped: list[str] = []
    for tsa in tsas:
        try:
            token = tsa.stamp(digest)
            info = verify_token(token, digest)
        except TimestampError:
            continue
        vault.add_additional_token(capture_id, token)
        vault.custody.append(
            CustodyAction.TIMESTAMPED,
            capture_id,
            actor=actor_id,
            hlc=vault.document.clock.now().encode(),
            details={
                "tsa": token.tsa_name,
                "kind": token.kind,
                "gen_time": info.gen_time,
                "role": "additional",
            },
            identity=vault.identity,
        )
        stamped.append(token.tsa_name)
    return tuple(stamped)


def _stamp_and_record(
    vault: Vault, capture_id: str, digest: str, actor_id: str, tsa: TimestampAuthority
) -> TimestampInfo:
    token = tsa.stamp(digest)
    info = verify_token(token, digest)
    vault.store_token(capture_id, token)
    vault.custody.append(
        CustodyAction.TIMESTAMPED,
        capture_id,
        actor=actor_id,
        hlc=vault.document.clock.now().encode(),
        details={"tsa": token.tsa_name, "kind": token.kind, "gen_time": info.gen_time},
        identity=vault.identity,
    )
    return info


def _exif_to_iso(exif_time: str | None) -> str | None:
    if not exif_time:
        return None
    try:
        parsed = datetime.strptime(exif_time, "%Y:%m:%d %H:%M:%S").replace(tzinfo=UTC)
    except ValueError:
        return None
    return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")


def _ms_to_iso(wall_ms: int) -> str:
    return datetime.fromtimestamp(wall_ms / 1000, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
