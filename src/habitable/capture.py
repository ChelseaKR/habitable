# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""The capture pipeline: media in, evidence-grade record out.

Capture never blocks on the network. At capture the bytes are hashed, sealed
immutably, and a custody entry is appended — all offline. A timestamp token is
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
from .exif import MediaMetadata, read_metadata
from .media import AUDIO_EXTENSIONS, VIDEO_EXTENSIONS
from .media import probe_metadata as probe_media_metadata
from .obslog import log_event
from .tsa import TimestampAuthority, TimestampInfo, TimestampToken, retimestamp, verify_token
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
    ".m4a": "audio/mp4",
    ".mp3": "audio/mpeg",
    ".wav": "audio/wav",
    # EXP-09: an independent instrument's CSV export (temperature logger, moisture
    # meter, ...) is a capture type like any other — same hash/seal/timestamp
    # pipeline below, interpreted for rendering by habitable.sensor.
    ".csv": "text/csv",
}

_MEDIA_EXTENSIONS = VIDEO_EXTENSIONS | AUDIO_EXTENSIONS


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
    transcript: str = "",
    source_name: str | None = None,
) -> CaptureResult:
    """Capture a media file into the vault as an evidence-grade record.

    ``tsa`` is the primary timestamp authority; ``extra_tsas`` are additional,
    independent authorities stamped for redundancy so the proof does not rest on a
    single TSA (item R-16). Extra authorities are stamped only when the primary
    succeeds (i.e. the device is online); offline, the item is queued and resolved
    later against the primary.

    ``transcript`` is a plain-text description of what a video/audio recording
    shows or says (e.g. "Landlord, on 2026-06-01: 'I'm not fixing that.'"). It is
    the accessible fallback packet.build_packet renders alongside (or instead
    of) a poster frame, and the mechanism EXP-07 adds so temporal evidence can
    meet the same accessibility bar as a photo's alt text. Optional but strongly
    recommended for any video/audio capture -- an empty transcript is recorded
    and surfaced honestly (not hidden) in the packet, never silently dropped.

    ``source_name`` preserves a browser-provided filename in encrypted, vault-only
    custody metadata when the actual input path is a random private temporary file.
    It never affects hashing, media-type inference, or exported custody data.
    """
    src = Path(source)
    if not src.is_file():
        raise CaptureError(f"no such media file: {src}")

    digest = sha256_file(src)
    resolved_media_type = media_type or _MEDIA_TYPES.get(
        src.suffix.lower(), "application/octet-stream"
    )
    metadata = _read_media_metadata(src, resolved_media_type)
    actor_id = actor or vault.identity.public().fingerprint

    stamp = vault.document.clock.now()
    capture_id = vault.document.opaque_id("cap", stamp.encode())

    # 1. Seal the original immutably (encrypted), bound to its content hash.
    sealed_name = vault.seal_original(capture_id, src, digest)

    # 2. Record capture in the chain of custody (signed).
    vault.custody.append(
        CustodyAction.CAPTURED,
        capture_id,
        actor=actor_id,
        hlc=stamp.encode(),
        details={"media_type": resolved_media_type},
        private_details={
            "source": Path(source_name).name if source_name else src.name
        },  # tenant filename: vault-only, never exported
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
        transcript=transcript,
    )
    vault.save()
    # Metadata-only trace (no-op unless logging is opted in): media_type is a MIME
    # constant, the rest are booleans/counts. No filename, path, hash, or bytes.
    log_event(
        "capture",
        media_type=resolved_media_type,
        timestamped=info is not None,
        had_location=metadata.has_location,
        extra_authorities=len(extra_authorities),
    )
    return CaptureResult(
        capture_id=capture_id,
        content_hash=digest,
        timestamped=info is not None,
        timestamp_info=info,
        had_location=metadata.has_location,
        media_type=resolved_media_type,
        extra_authorities=extra_authorities,
    )


def resolve_deferred(
    vault: Vault,
    tsa: TimestampAuthority,
    extra_tsas: Sequence[TimestampAuthority] = (),
) -> list[CaptureResult]:
    """Fetch timestamp tokens for every capture queued while offline.

    Once the primary token is fetched, each item is *also* stamped against every
    configured redundant authority (``extra_tsas``), so a capture made in a dead
    zone gets the same multiple-authority proof as the online path (item R-16).
    The most at-risk captures — taken with no signal — no longer rest on a single
    TSA. An unreachable redundant authority is skipped, exactly as on capture.
    """
    results: list[CaptureResult] = []
    actor_id = vault.identity.public().fingerprint
    for item in vault.deferred():
        info = _stamp_and_record(vault, item.capture_id, item.digest, actor_id, tsa)
        extra_authorities = _stamp_additional(
            vault, item.capture_id, item.digest, actor_id, extra_tsas
        )
        vault.clear_deferred(item.capture_id)
        results.append(
            CaptureResult(
                capture_id=item.capture_id,
                content_hash=item.digest,
                timestamped=True,
                timestamp_info=info,
                had_location=False,
                media_type="",
                extra_authorities=extra_authorities,
            )
        )
    vault.save()
    log_event("resolve_deferred", resolved=len(results))
    return results


def retimestamp_all(
    vault: Vault,
    tsa: TimestampAuthority,
    extra_tsas: Sequence[TimestampAuthority] = (),
) -> int:
    """Archive-(re)timestamp every timestamped capture, extending proof lifetime.

    Stamps over each capture's most recent token so the proof survives the
    original authority's certificate or hash algorithm aging out. When
    ``extra_tsas`` are configured, each redundant authority adds a further link
    over the previous one in the same pass, threading multiple independent
    authorities into the (still strictly linear) archive chain — so the archive
    proof, like online capture, does not rest on a single authority (item R-16).
    A redundant authority that is unreachable is skipped and never fails the pass.
    Returns the number of captures archived.
    """
    actor = vault.identity.public().fingerprint
    count = 0
    records = [
        (capture_record.capture_id, capture_record.content_hash)
        for capture_record in vault.document.captures()
    ]
    records.extend(
        (artifact.artifact_id, artifact.content_hash) for artifact in vault.document.artifacts()
    )
    for record_id, _content_hash in records:
        latest = vault.latest_token(record_id)
        if latest is None:
            continue  # nothing to archive (still awaiting its first timestamp)
        archive = retimestamp(latest, tsa)
        vault.add_archive_token(record_id, archive)
        vault.custody.append(
            CustodyAction.TIMESTAMPED,
            record_id,
            actor=actor,
            hlc=vault.document.clock.now().encode(),
            details={"kind": "archive", "tsa": archive.tsa_name},
            identity=vault.identity,
        )
        _archive_against_extras(vault, record_id, archive, actor, extra_tsas)
        count += 1
    vault.save()
    log_event("retimestamp", archived=count)
    return count


def _archive_against_extras(
    vault: Vault,
    capture_id: str,
    previous: TimestampToken,
    actor_id: str,
    extra_tsas: Sequence[TimestampAuthority],
) -> None:
    """Extend the archive chain with a link from each redundant authority.

    Each extra authority re-timestamps the *previous* link, so the additional
    authorities thread into the same verifiable chain (``verify_archive_chain``
    requires each link to cover the one before it) rather than resting the
    re-timestamp on the primary authority alone (item R-16). An unreachable
    authority is skipped — a re-timestamp pass never fails because one redundant
    TSA is down.
    """
    for extra in extra_tsas:
        try:
            archive = retimestamp(previous, extra)
        except TimestampError:
            continue
        vault.add_archive_token(capture_id, archive)
        vault.custody.append(
            CustodyAction.TIMESTAMPED,
            capture_id,
            actor=actor_id,
            hlc=vault.document.clock.now().encode(),
            details={"kind": "archive", "tsa": archive.tsa_name, "role": "additional"},
            identity=vault.identity,
        )
        previous = archive


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


def _read_media_metadata(src: Path, resolved_media_type: str) -> MediaMetadata:
    """Dispatch metadata reading to the right toolchain for this media kind.

    Still images go through :mod:`habitable.exif` (piexif/Pillow); video/audio
    go through :mod:`habitable.media` (ffprobe), a different toolchain with a
    different optional-dependency story (EXP-07)."""
    if resolved_media_type == "text/csv":
        return MediaMetadata(
            media_format="text/csv",
            has_location=False,
            capture_time=None,
            fields_present=(),
        )
    if src.suffix.lower() in _MEDIA_EXTENSIONS or resolved_media_type.startswith(
        ("video/", "audio/")
    ):
        return probe_media_metadata(src)
    return read_metadata(src)


def _exif_to_iso(capture_time: str | None) -> str | None:
    """Parse a capture timestamp from either EXIF (``YYYY:MM:DD HH:MM:SS``) or
    ffprobe's ``creation_time`` tag (ISO 8601), whichever the source produced."""
    if not capture_time:
        return None
    try:
        parsed = datetime.strptime(capture_time, "%Y:%m:%d %H:%M:%S").replace(tzinfo=UTC)
        return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        pass
    try:
        iso_time = capture_time.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(iso_time)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None


def _ms_to_iso(wall_ms: int) -> str:
    return datetime.fromtimestamp(wall_ms / 1000, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
