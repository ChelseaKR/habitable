# SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0
# Copyright 2026 Chelsea Kelly-Reif
"""Independent verification of an evidence packet.

This is the module a skeptic runs. Given only a packet directory (and, optionally,
trusted TSA root certificates), it re-derives every hash, validates each timestamp
token, checks whether its authority chains to a caller-supplied trust root, verifies
the producer's signature over the whole bundle, validates packet-v3 timeline
commitments and links, and walks the chain of custody.

Those are deliberately separate claims.  A packet can be structurally intact while
its timestamps are untrusted (or still absent), and neither state is silently
promoted to ``evidence_ready``.  In particular, development timestamps are useful
for exercising the proof format but can never make evidence ready for review.

Licensing: this verifier, together with the pure modules it imports
(:mod:`habitable.canonical`, :mod:`habitable.crypto`, :mod:`habitable.evidence`,
:mod:`habitable.timeline`, :mod:`habitable.tsa`), is the "verification subset"
offered under Apache-2.0 as an additional permission (see NOTICE), so a court or
legal-aid group can embed and redistribute verification without the AGPL reaching
their code.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import TYPE_CHECKING, BinaryIO

from .canonical import JSONValue, canonical_json, sha256_bytes
from .crypto import verify as verify_signature
from .errors import VerificationError
from .evidence import CustodyLog
from .timeline import EVENT_TYPES, SOURCES, normalize_occurred_at
from .tsa import TimestampToken, verify_archive_chain, verify_token

if TYPE_CHECKING:
    from cryptography import x509

__all__ = ["ItemVerdict", "VerificationReport", "verify_packet"]

_BUNDLE = "bundle.json"
_SIGNATURE = "bundle.sig.json"
_MEDIA = "media"
_ORIGINALS = "originals"
_HASH_CHUNK = 1024 * 1024
_MAX_BUNDLE_BYTES = 256 * 1024 * 1024
_MAX_SIGNATURE_BYTES = 1024 * 1024

# Keep a hostile packet from turning verification into an unbounded read. This is
# deliberately much larger than the app and relay upload ceilings, so ordinary
# exported photos, recordings, and supported legacy packets retain ample headroom.
_MAX_REFERENCED_FILE_BYTES = 1024 * 1024 * 1024

# The newest packet format this verifier understands. The contract: every version
# from 1..SUPPORTED_PACKET_VERSION still verifies (guarded by the golden-packet
# corpus in tests/), and a newer-than-supported packet is rejected with a clear,
# non-crashing error rather than mis-verified.
SUPPORTED_PACKET_VERSION = 4

_ARTIFACT_TYPES = {
    "repair_request",
    "delivery_receipt",
    "landlord_response",
    "inspection_report",
    "utility_notice",
    "accommodation_request",
    "supporting_letter",
    "clinician_letter",
    "expense_receipt",
    "relocation_record",
    "partner_export",
    "other_document",
}
_RELATIONSHIP_TYPES = {
    "documents_condition",
    "sent_via",
    "delivery_receipt_for",
    "response_to",
    "before_of",
    "after_of",
    "inspection_finding_for",
    "repair_claim_for",
    "expense_caused_by",
    "supports",
}
_RELATIONSHIP_ENDPOINT_KINDS = {
    "documents_condition": {
        ("capture", "issue"),
        ("artifact", "issue"),
        ("timeline", "issue"),
    },
    "sent_via": {("artifact", "artifact"), ("timeline", "timeline")},
    "delivery_receipt_for": {
        ("artifact", "artifact"),
        ("artifact", "timeline"),
        ("timeline", "artifact"),
        ("timeline", "timeline"),
    },
    "response_to": {
        ("artifact", "artifact"),
        ("artifact", "timeline"),
        ("timeline", "artifact"),
        ("timeline", "timeline"),
    },
    "before_of": {("capture", "capture")},
    "after_of": {("capture", "capture")},
    "inspection_finding_for": {
        ("artifact", "issue"),
        ("artifact", "capture"),
        ("timeline", "issue"),
        ("timeline", "capture"),
    },
    "repair_claim_for": {
        ("artifact", "issue"),
        ("artifact", "capture"),
        ("timeline", "issue"),
        ("timeline", "capture"),
    },
    "expense_caused_by": {
        ("artifact", "issue"),
        ("artifact", "artifact"),
        ("artifact", "capture"),
        ("artifact", "timeline"),
    },
    "supports": {
        (source, target)
        for source in ("capture", "artifact", "timeline")
        for target in ("issue", "capture", "artifact", "timeline")
    },
}

# Referenced by name (not an inline `except (...)`) so the formatter cannot rewrite it
# to the parenthesis-free PEP 758 form, a SyntaxError on Python < 3.14. verify.py is
# the entry point of the Apache-2.0 verifier subset, kept portable for embedders who
# vendor it onto older interpreters (see docs/embedding-the-verifier.md).
_SIGNATURE_READ_ERRORS = (
    json.JSONDecodeError,
    UnicodeDecodeError,
    ValueError,
    OSError,
    VerificationError,
)

_SUMMARY_TEXT = {
    "en": {
        "intact": "intact",
        "not_intact": "NOT INTACT",
        "trusted": "trusted",
        "not_trusted": "NOT TRUSTED",
        "ready": "READY",
        "not_ready": "NOT READY",
        "summary": (
            "integrity: {integrity}; timestamp authority: {trust} "
            "({trusted_items}/{total} items); evidence readiness: {readiness}"
        ),
        "guidance_evidence_ready": (
            "Technical evidence readiness does not decide admissibility or any legal outcome."
        ),
        "guidance_integrity_failed": (
            "Not evidence-ready: one or more packet integrity checks failed."
        ),
        "guidance_no_items": "Not evidence-ready: the packet contains no evidence items.",
        "guidance_timestamp_missing": (
            "Not evidence-ready: one or more evidence items are awaiting a timestamp."
        ),
        "guidance_timestamp_invalid": (
            "Not evidence-ready: one or more attached timestamp tokens are invalid."
        ),
        "guidance_timestamp_authority_untrusted": (
            "Not evidence-ready: rerun with --trusted-cert PEM for an authority you "
            "independently trust. Development timestamps can never become trusted."
        ),
    },
    "es": {
        "intact": "íntegra",
        "not_intact": "NO ÍNTEGRA",
        "trusted": "confiable",
        "not_trusted": "NO CONFIABLE",
        "ready": "LISTA",
        "not_ready": "NO LISTA",
        "summary": (
            "integridad: {integrity}; autoridad del sello de tiempo: {trust} "
            "({trusted_items}/{total} elementos); preparación probatoria: {readiness}"
        ),
        "guidance_evidence_ready": (
            "La preparación técnica no determina la admisibilidad ni ningún resultado legal."
        ),
        "guidance_integrity_failed": (
            "No está lista como prueba: falló una o más comprobaciones de integridad."
        ),
        "guidance_no_items": (
            "No está lista como prueba: el expediente no contiene elementos probatorios."
        ),
        "guidance_timestamp_missing": (
            "No está lista como prueba: uno o más elementos esperan un sello de tiempo."
        ),
        "guidance_timestamp_invalid": (
            "No está lista como prueba: uno o más sellos de tiempo adjuntos no son válidos."
        ),
        "guidance_timestamp_authority_untrusted": (
            "No está lista como prueba: vuelva a ejecutar con --trusted-cert PEM para una "
            "autoridad que usted confíe de forma independiente. Los sellos de desarrollo "
            "nunca pueden volverse confiables."
        ),
    },
}

_ITEM_DETAIL_TEXT = {
    "en": {
        "shared_media": "shared media is missing or does not match its recorded hash",
        "custody_binding": "shared media is not bound to the original by custody",
        "original_fixity": "embedded original does not match its recorded hash",
        "timestamp_missing": "awaiting timestamp",
        "timestamp_invalid": "attached timestamp is invalid",
        "timestamp_untrusted": "timestamp is valid but its authority is not trusted",
        "timestamp_dev": "development timestamp is untrusted and never evidence-ready",
        "not_ready": "not evidence-ready",
    },
    "es": {
        "shared_media": "falta el archivo compartido o no coincide con su hash registrado",
        "custody_binding": "la custodia no vincula el archivo compartido con el original",
        "original_fixity": "el original incluido no coincide con su hash registrado",
        "timestamp_missing": "sello de tiempo pendiente",
        "timestamp_invalid": "el sello de tiempo adjunto no es válido",
        "timestamp_untrusted": ("el sello de tiempo es válido, pero su autoridad no es confiable"),
        "timestamp_dev": (
            "el sello de desarrollo no es confiable ni puede estar listo como prueba"
        ),
        "not_ready": "no está listo como prueba",
    },
}


@dataclass(frozen=True, slots=True)
class ItemVerdict:
    """The verification outcome for one media item."""

    capture_id: str
    content_hash: str
    timestamp_verified: bool
    gen_time: str
    tsa_name: str
    shared_media_ok: bool
    custody_binding_ok: bool
    original_fixity_ok: bool | None  # None when the sealed original is not included
    notes: tuple[str, ...] = field(default_factory=tuple)
    verified_authorities: tuple[str, ...] = field(default_factory=tuple)
    timestamp_authority_trusted: bool = False
    trusted_authorities: tuple[str, ...] = field(default_factory=tuple)
    timestamp_present: bool = False
    timestamp_kind: str = ""

    @property
    def structurally_intact(self) -> bool:
        """Whether media, custody binding, and any embedded original are intact.

        Timestamp presence, token validity, and authority trust are intentionally
        excluded: those are separate claims and must not redefine byte integrity.
        """
        return (
            self.shared_media_ok
            and self.custody_binding_ok
            and self.original_fixity_ok is not False
        )

    @property
    def cryptographically_verified(self) -> bool:
        """Legacy proof check: integrity plus a valid token, regardless of trust root."""
        return self.structurally_intact and self.timestamp_verified

    @property
    def evidence_ready(self) -> bool:
        """Whether this item passes integrity, token, and authority-trust checks."""
        return self.cryptographically_verified and self.timestamp_authority_trusted

    @property
    def ok(self) -> bool:
        """Backward-compatible field name, tightened to mean ``evidence_ready``.

        Older callers used ``ok`` for a valid token even when its authority was not
        trusted.  Keeping that meaning would continue the unsafe ambiguity this
        report is designed to remove, so callers that only need the old mechanical
        check should use :attr:`cryptographically_verified` explicitly.
        """
        return self.evidence_ready

    def human_detail(self, language: str = "en") -> str:
        """Return a localized, non-technical explanation of this item's failed checks."""
        text = _item_detail_text(language)
        reasons: list[str] = []
        if not self.shared_media_ok:
            reasons.append(text["shared_media"])
        if not self.custody_binding_ok:
            reasons.append(text["custody_binding"])
        if self.original_fixity_ok is False:
            reasons.append(text["original_fixity"])
        if not self.timestamp_verified:
            reasons.append(
                text["timestamp_invalid"] if self.timestamp_present else text["timestamp_missing"]
            )
        elif not self.timestamp_authority_trusted:
            key = "timestamp_dev" if self.timestamp_kind == "dev" else "timestamp_untrusted"
            reasons.append(text[key])
        return "; ".join(reasons) or text["not_ready"]


@dataclass(frozen=True, slots=True)
class VerificationReport:
    """The overall verdict on a packet."""

    packet_dir: Path
    signature_ok: bool
    custody_ok: bool
    custody_length: int
    items: tuple[ItemVerdict, ...]
    problems: tuple[str, ...]
    language: str = "en"

    @property
    def structurally_intact(self) -> bool:
        """Whether packet structure, signature, custody, and media checks pass."""
        return (
            self.signature_ok
            and self.custody_ok
            and not self.problems
            and all(item.structurally_intact for item in self.items)
        )

    @property
    def timestamp_authority_trusted(self) -> bool:
        """Whether every evidence item has a valid token anchored to a trusted root."""
        return bool(self.items) and all(item.timestamp_authority_trusted for item in self.items)

    @property
    def evidence_ready(self) -> bool:
        """Technical readiness: integrity plus trusted timestamp coverage for all items."""
        return (
            self.structurally_intact
            and bool(self.items)
            and all(item.evidence_ready for item in self.items)
        )

    @property
    def ok(self) -> bool:
        """Backward-compatible field name, now a fail-closed alias for evidence readiness."""
        return self.evidence_ready

    @property
    def verified_items(self) -> int:
        """Number of evidence-ready items (the historical field name is retained)."""
        return sum(1 for item in self.items if item.evidence_ready)

    @property
    def cryptographically_verified_items(self) -> int:
        """Items with intact bytes and a valid token, whether or not its root is trusted."""
        return sum(1 for item in self.items if item.cryptographically_verified)

    @property
    def trusted_timestamp_items(self) -> int:
        return sum(1 for item in self.items if item.timestamp_authority_trusted)

    @property
    def status(self) -> str:
        """Stable machine-readable reason for the overall readiness result."""
        if self.evidence_ready:
            return "evidence_ready"
        if not self.structurally_intact:
            return "integrity_failed"
        if not self.items:
            return "no_items"
        if not all(item.timestamp_verified for item in self.items):
            # An attached-but-invalid proof is an alarm even if another item merely
            # awaits a token; never let the calm missing state hide invalid material.
            if any(item.timestamp_present and not item.timestamp_verified for item in self.items):
                return "timestamp_invalid"
            return "timestamp_missing"
        return "timestamp_authority_untrusted"

    def summary(self, language: str | None = None) -> str:
        """Return a localized, claim-separated human summary."""
        text = _summary_text(language or self.language)
        total = len(self.items)
        return text["summary"].format(
            integrity=text["intact"] if self.structurally_intact else text["not_intact"],
            trust=(text["trusted"] if self.timestamp_authority_trusted else text["not_trusted"]),
            trusted_items=self.trusted_timestamp_items,
            total=total,
            readiness=text["ready"] if self.evidence_ready else text["not_ready"],
        )

    def guidance(self, language: str | None = None) -> str:
        """Return localized next-step/caveat text for :attr:`status`."""
        return _summary_text(language or self.language)[f"guidance_{self.status}"]


def _summary_text(language: str) -> dict[str, str]:
    return _SUMMARY_TEXT.get(language.lower().split("-", 1)[0], _SUMMARY_TEXT["en"])


def _item_detail_text(language: str) -> dict[str, str]:
    return _ITEM_DETAIL_TEXT.get(language.lower().split("-", 1)[0], _ITEM_DETAIL_TEXT["en"])


def verify_packet(
    packet_dir: Path, *, trusted_certs: list[x509.Certificate] | None = None
) -> VerificationReport:
    """Verify a packet directory end to end and return a structured report."""
    packet_dir = Path(packet_dir)
    bundle_bytes = _read_bundle_bytes(packet_dir)
    bundle = _parse_bundle(bundle_bytes)
    language = _s(bundle, "language") or "en"

    # Enforce the version contract before trusting the rest of the structure.
    version_problem = _check_packet_version(bundle)
    if version_problem is not None:
        return VerificationReport(
            packet_dir=packet_dir,
            signature_ok=_verify_signature(packet_dir, bundle_bytes),
            custody_ok=False,
            custody_length=0,
            items=(),
            problems=(version_problem,),
            language=language,
        )

    signature_ok = _verify_signature(packet_dir, bundle_bytes)
    custody_ok, custody_length, custody = _verify_custody(bundle)
    bindings = _sharing_bindings(custody)
    poster_bindings = _poster_bindings(custody)

    problems: list[str] = []
    items: list[ItemVerdict] = []
    for raw_item in _list(bundle, "items"):
        if not isinstance(raw_item, dict):
            problems.append("malformed item in bundle")
            continue
        items.append(
            _verify_item(
                raw_item,
                packet_dir,
                bindings,
                poster_bindings,
                trusted_certs,
                inspect_references=signature_ok,
            )
        )

    if bundle.get("packet_version") in {3, 4}:
        problems.extend(_verify_v3_timeline(bundle, custody))
    if bundle.get("packet_version") == 4:
        problems.extend(_verify_v4_workflows(bundle, custody))

    return VerificationReport(
        packet_dir=packet_dir,
        signature_ok=signature_ok,
        custody_ok=custody_ok,
        custody_length=custody_length,
        items=tuple(items),
        problems=tuple(problems),
        language=language,
    )


def _verify_item(  # noqa: C901 -- P1-4 follow-up: extract per-check helpers; left alone for
    # now rather than risk a regression in the standalone verifier under time pressure.
    item: Mapping[str, JSONValue],
    packet_dir: Path,
    bindings: dict[str, set[tuple[str, str]]],
    poster_bindings: dict[str, set[tuple[str, str]]],
    trusted_certs: list[x509.Certificate] | None,
    *,
    inspect_references: bool = True,
) -> ItemVerdict:
    capture_id = _s(item, "capture_id")
    content_hash = _s(item, "content_hash")
    media_type = _s(item, "media_type")
    shared_name = _s(item, "shared_name")
    shared_hash = _s(item, "shared_hash")
    poster_name = _s(item, "poster_name")
    poster_hash = _s(item, "poster_hash")
    transcript = _s(item, "transcript")
    has_original = item.get("has_original") is True
    notes: list[str] = []

    if not inspect_references and (shared_name or poster_name or has_original):
        notes.append("bundle signature invalid; referenced packet files were not read")

    # 1. Trusted timestamp(s) over the original content hash. The primary token plus any
    #    independent "additional" authorities give redundancy: the item counts as
    #    timestamped if AT LEAST ONE authority verifies, so the proof never rests on a
    #    single TSA (item R-16). With no additional tokens this is identical to before.
    timestamp_verified = False
    timestamp_authority_trusted = False
    timestamp_kind = ""
    gen_time = ""
    tsa_name = ""
    verified_authorities: list[str] = []
    trusted_authorities: list[str] = []
    token_raw = item.get("timestamp")
    timestamp_present = isinstance(token_raw, dict)
    if isinstance(token_raw, dict):
        try:
            token = TimestampToken.from_dict(token_raw)
            info = verify_token(token, content_hash, trusted_certs=trusted_certs)
            # Archive (re-)timestamps, if present, must chain back to this token.
            archive_raw = item.get("archive_timestamps")
            archives = (
                [TimestampToken.from_dict(a) for a in archive_raw if isinstance(a, dict)]
                if isinstance(archive_raw, list)
                else []
            )
            if archives:
                verify_archive_chain(content_hash, token, archives, trusted_certs=trusted_certs)
                notes.append(f"archive-timestamped ({len(archives)} link(s))")
            # Commit the primary verdict only after every attached archive link has
            # passed. A broken attached archive is an invalid proof, not an ignorable
            # decoration; a valid redundant authority below can still rescue the item.
            timestamp_verified = True
            timestamp_kind = info.kind
            gen_time = info.gen_time
            tsa_name = info.tsa_name
            verified_authorities.append(info.tsa_name)
            if info.trusted_chain:
                timestamp_authority_trusted = True
                trusted_authorities.append(info.tsa_name)
            else:
                notes.append(
                    info.note or "timestamp valid but authority not chained to a trusted root"
                )
        except Exception as exc:
            # A failed primary does not, by itself, condemn the item if a redundant
            # authority below still verifies the same content hash.
            notes.append(f"primary timestamp check failed: {exc}")
    else:
        notes.append("awaiting timestamp")

    # 1b. Independent redundant authorities over the same content hash.
    additional_raw = item.get("additional_timestamps")
    if isinstance(additional_raw, list):
        for extra_raw in additional_raw:
            if not isinstance(extra_raw, dict):
                continue
            timestamp_present = True
            try:
                extra = TimestampToken.from_dict(extra_raw)
                extra_info = verify_token(extra, content_hash, trusted_certs=trusted_certs)
            except Exception as exc:
                notes.append(f"additional timestamp check failed: {exc}")
                continue
            verified_authorities.append(extra_info.tsa_name)
            notes.append(f"also timestamped by {extra_info.tsa_name}")
            if extra_info.trusted_chain:
                timestamp_authority_trusted = True
                trusted_authorities.append(extra_info.tsa_name)
            else:
                notes.append(
                    extra_info.note
                    or f"additional authority {extra_info.tsa_name} not chained to a trusted root"
                )
            if not timestamp_verified:
                timestamp_verified = True
                timestamp_kind = extra_info.kind
                gen_time = extra_info.gen_time
                tsa_name = extra_info.tsa_name

    # 2. Shared media hashes to its recorded shared_hash.
    shared_media_ok = True
    if shared_name:
        if not inspect_references:
            shared_media_ok = False
        else:
            media_digest, media_problem = _hash_packet_reference(
                packet_dir, _MEDIA, shared_name, label="shared media"
            )
            if media_problem is not None:
                shared_media_ok = False
                notes.append(media_problem)
            elif media_digest != shared_hash:
                shared_media_ok = False
                notes.append("shared media does not match its recorded hash")
    else:
        notes.append("no shared media included for this item")

    # 3. Custody binds the shared copy to the sealed original's content hash.
    custody_binding_ok = True
    if shared_name:
        custody_binding_ok = (content_hash, shared_hash) in bindings.get(capture_id, set())
        if not custody_binding_ok:
            notes.append("no signed custody entry binds the shared copy to the original")

    # 3b. Video's poster frame (EXP-07), if present, hashes and binds the same way.
    if poster_name:
        if not inspect_references:
            shared_media_ok = False
        else:
            poster_digest, poster_problem = _hash_packet_reference(
                packet_dir, _MEDIA, poster_name, label="poster frame"
            )
            if poster_problem is not None:
                shared_media_ok = False
                notes.append(poster_problem)
            elif poster_digest != poster_hash:
                shared_media_ok = False
                notes.append("poster frame does not match its recorded hash")
            elif (content_hash, poster_hash) not in poster_bindings.get(capture_id, set()):
                custody_binding_ok = False
                notes.append("no signed custody entry binds the poster frame to the original")

    # 3c. Video/audio needs a transcript or poster frame to meet the accessibility
    #     gate (EXP-07 excellence bar); surfaced as a note, not a hard failure --
    #     this is a completeness signal, not a cryptographic integrity failure.
    if media_type.startswith(("video/", "audio/")) and not transcript and not poster_name:
        notes.append("no transcript or poster frame recorded for this item (accessibility gap)")

    # 4. If the sealed original is embedded, re-derive its content hash.
    original_fixity_ok: bool | None = None
    if has_original:
        if not inspect_references:
            original_fixity_ok = False
        else:
            original_digest, original_problem = _hash_packet_reference(
                packet_dir, _ORIGINALS, capture_id, label="embedded original"
            )
            if original_problem is not None:
                original_fixity_ok = False
                notes.append(original_problem)
            else:
                original_fixity_ok = original_digest == content_hash
                if not original_fixity_ok:
                    notes.append("embedded original failed fixity")

    return ItemVerdict(
        capture_id=capture_id,
        content_hash=content_hash,
        timestamp_verified=timestamp_verified,
        gen_time=gen_time,
        tsa_name=tsa_name,
        shared_media_ok=shared_media_ok,
        custody_binding_ok=custody_binding_ok,
        original_fixity_ok=original_fixity_ok,
        notes=tuple(notes),
        verified_authorities=tuple(verified_authorities),
        timestamp_authority_trusted=timestamp_authority_trusted,
        trusted_authorities=tuple(trusted_authorities),
        timestamp_present=timestamp_present,
        timestamp_kind=timestamp_kind,
    )


def _hash_packet_reference(  # noqa: C901 -- security checks are intentionally linear
    packet_dir: Path, directory: str, reference: str, *, label: str
) -> tuple[str | None, str | None]:
    """Hash one strictly confined packet file, returning ``(digest, problem)``.

    Bundle fields are attacker-controlled until proven otherwise. A file reference is
    therefore one basename, never a path. The directory and file are lstat-checked,
    resolved for containment, and rechecked after opening before any bytes are hashed.
    ``O_NOFOLLOW``/``O_NONBLOCK`` add final-component protection where the host exposes
    them. Path-based check/open operations are not atomic, so a concurrent directory
    replacement remains a documented residual race (see the embedding guide).
    """
    name_problem = _reference_name_problem(reference, label)
    if name_problem is not None:
        return None, name_problem
    try:
        root_before = packet_dir.lstat()
    except OSError:
        return None, "packet directory could not be safely inspected"
    if stat.S_ISLNK(root_before.st_mode):
        return None, "packet directory must not be a symlink"
    if not stat.S_ISDIR(root_before.st_mode):
        return None, "packet path is not a directory"

    directory_path = packet_dir / directory
    try:
        directory_before = directory_path.lstat()
    except FileNotFoundError:
        return None, f"{label} directory missing"
    except OSError:
        return None, f"{label} directory could not be safely inspected"
    if stat.S_ISLNK(directory_before.st_mode):
        return None, f"{label} directory must not be a symlink"
    if not stat.S_ISDIR(directory_before.st_mode):
        return None, f"{label} directory is not a regular directory"

    candidate = directory_path / reference
    try:
        file_before = candidate.lstat()
    except FileNotFoundError:
        return None, f"{label} file missing"
    except OSError:
        return None, f"{label} file could not be safely inspected"
    file_problem = _regular_file_problem(file_before, label)
    if file_problem is not None:
        return None, file_problem

    try:
        root_resolved = packet_dir.resolve(strict=True)
        directory_resolved = directory_path.resolve(strict=True)
        candidate_resolved = candidate.resolve(strict=True)
    except OSError:
        return None, f"{label} path could not be safely resolved"
    if not directory_resolved.is_relative_to(root_resolved):
        return None, f"{label} directory escapes the packet directory"
    if not candidate_resolved.is_relative_to(directory_resolved):
        return None, f"{label} path escapes its designated directory"

    file_fd = -1
    try:
        flags = (
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        file_fd = os.open(candidate, flags)
        handle = os.fdopen(file_fd, "rb", closefd=True)
        file_fd = -1  # ownership transferred to ``handle``
        with handle:
            opened = os.fstat(handle.fileno())
            file_problem = _regular_file_problem(opened, label)
            if file_problem is not None:
                return None, file_problem
            if _different_file(file_before, opened):
                return None, f"{label} file changed during safety checks"
            digest = _stream_sha256(handle)
            after = os.fstat(handle.fileno())
    except OSError:
        return None, f"{label} file could not be safely read"
    finally:
        _close_fd(file_fd)
    if digest is None:
        return None, _oversized_problem(label)
    if _file_changed_while_reading(opened, after):
        return None, f"{label} file changed while it was hashed"
    return digest, None


def _reference_name_problem(reference: str, label: str) -> str | None:
    """Reject every spelling that can be interpreted as more than one basename."""
    windows = PureWindowsPath(reference)
    posix = PurePosixPath(reference)
    if (
        not reference
        or reference in {".", ".."}
        or "\x00" in reference
        or "/" in reference
        or "\\" in reference
        or posix.is_absolute()
        or windows.is_absolute()
        or bool(windows.drive)
    ):
        return (
            f"{label} reference must be one basename "
            "(absolute paths, separators, drive names, and '..' are forbidden)"
        )
    return None


def _regular_file_problem(file_stat: os.stat_result, label: str) -> str | None:
    if stat.S_ISLNK(file_stat.st_mode):
        return f"{label} path must not be a symlink"
    if not stat.S_ISREG(file_stat.st_mode):
        return f"{label} path is not a regular file"
    if file_stat.st_size > _MAX_REFERENCED_FILE_BYTES:
        return _oversized_problem(label)
    return None


def _stream_sha256(handle: BinaryIO) -> str | None:
    """Hash at most the configured ceiling, including files that grow while read."""
    digest = hashlib.sha256()
    total = 0
    while chunk := handle.read(min(_HASH_CHUNK, _MAX_REFERENCED_FILE_BYTES + 1 - total)):
        total += len(chunk)
        if total > _MAX_REFERENCED_FILE_BYTES:
            return None
        digest.update(chunk)
    return digest.hexdigest()


def _oversized_problem(label: str) -> str:
    return f"{label} exceeds the {_MAX_REFERENCED_FILE_BYTES}-byte verification limit"


def _different_file(before: os.stat_result, after: os.stat_result) -> bool:
    return (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)


def _file_changed_while_reading(before: os.stat_result, after: os.stat_result) -> bool:
    return _different_file(before, after) or (before.st_size, before.st_mtime_ns) != (
        after.st_size,
        after.st_mtime_ns,
    )


def _close_fd(fd: int) -> None:
    if fd < 0:
        return
    with suppress(OSError):
        os.close(fd)


def _check_packet_version(bundle: Mapping[str, JSONValue]) -> str | None:
    """Return a problem string if the packet version is missing or too new, else None."""
    version = bundle.get("packet_version")
    if not isinstance(version, int) or isinstance(version, bool):
        return "bundle has no integer packet_version"
    if version < 1:
        return f"packet_version {version} is invalid; the oldest supported version is 1"
    if version > SUPPORTED_PACKET_VERSION:
        return (
            f"packet_version {version} is newer than supported "
            f"{SUPPORTED_PACKET_VERSION}; upgrade habitable to verify this packet"
        )
    return None


def _verify_v3_timeline(bundle: Mapping[str, JSONValue], custody: CustodyLog) -> list[str]:
    """Verify packet-v3 timeline semantics and custody commitments.

    This path is intentionally gated to v3.  Packet v1/v2 ``kind`` and ``hlc``
    retain their historical meanings and are never reinterpreted as the fields
    introduced here.
    """
    problems: list[str] = []
    raw_entries = _v3_array(bundle, "timeline", problems)
    raw_issues = _v3_array(bundle, "issues", problems)
    raw_items = _v3_array(bundle, "items", problems)
    appendix = _v3_object(bundle, "appendix", problems)

    entry_ids = [
        _s(raw, "entry_id") for raw in raw_entries if isinstance(raw, dict) and _s(raw, "entry_id")
    ]
    if len(entry_ids) != len(set(entry_ids)):
        problems.append("packet-v3 timeline contains duplicate entry_id values")
    event_by_id: dict[str, Mapping[str, JSONValue]] = {
        _s(raw, "entry_id"): raw
        for raw in raw_entries
        if isinstance(raw, dict) and _s(raw, "entry_id")
    }
    items_by_id: dict[str, Mapping[str, JSONValue]] = {
        _s(raw, "capture_id"): raw
        for raw in raw_items
        if isinstance(raw, dict) and _s(raw, "capture_id")
    }
    issue_ids = {
        _s(raw, "issue_id") for raw in raw_issues if isinstance(raw, dict) and _s(raw, "issue_id")
    }
    if appendix.get("timeline_count") != len(raw_entries):
        problems.append("appendix.timeline_count does not match timeline length")
    if appendix.get("custody_bound_timeline_count") != len(raw_entries):
        problems.append("appendix.custody_bound_timeline_count does not match timeline length")

    for raw in raw_entries:
        if not isinstance(raw, dict):
            problems.append("malformed packet-v3 timeline entry")
            continue
        entry_id = _s(raw, "entry_id") or "<missing>"
        if _s(raw, "issue_id") not in issue_ids:
            problems.append(f"timeline {entry_id}: issue_id is not present in this packet")
        problem = _verify_v3_timeline_entry(raw, custody)
        problems.extend(f"timeline {entry_id}: {message}" for message in problem)
        problems.extend(
            f"timeline {entry_id}: {message}"
            for message in _verify_v3_links(raw, event_by_id, items_by_id)
        )
    return problems


def _verify_v4_workflows(  # noqa: C901 -- ordered fail-closed checks remain linear
    bundle: Mapping[str, JSONValue], custody: CustodyLog
) -> list[str]:
    """Verify packet-v4 artifact, relationship, profile, and handoff structures."""
    problems: list[str] = []
    raw_items = _v3_array(bundle, "items", problems)
    raw_relationships = _v3_array(bundle, "relationships", problems)
    appendix = _v3_object(bundle, "appendix", problems)
    issues = {
        _s(raw, "issue_id")
        for raw in _v3_array(bundle, "issues", problems)
        if isinstance(raw, dict)
    }
    endpoints: dict[str, tuple[str, str]] = {
        issue_id: (issue_id, "issue") for issue_id in issues if issue_id
    }
    for raw in _v3_array(bundle, "timeline", problems):
        if isinstance(raw, dict):
            endpoints[_s(raw, "entry_id")] = (_s(raw, "issue_id"), "timeline")

    artifact_count = 0
    for raw in raw_items:
        if not isinstance(raw, dict):
            continue
        item_id = _s(raw, "capture_id")
        kind = _s(raw, "record_kind")
        if kind not in {"capture", "artifact"}:
            problems.append(f"item {item_id or '<missing>'}: record_kind is invalid")
            continue
        endpoints[item_id] = (_s(raw, "issue_id"), kind)
        if kind == "artifact":
            artifact_count += 1
            problems.extend(
                f"artifact {item_id or '<missing>'}: {message}"
                for message in _verify_v4_artifact(raw, custody)
            )

    if appendix.get("artifact_count") != artifact_count:
        problems.append("appendix.artifact_count does not match artifact items")
    if appendix.get("relationship_count") != len(raw_relationships):
        problems.append("appendix.relationship_count does not match relationships")

    graphs: dict[str, dict[str, set[str]]] = {}
    seen_relationships: set[str] = set()
    for raw in raw_relationships:
        if not isinstance(raw, dict):
            problems.append("malformed packet-v4 relationship")
            continue
        relationship_id = _s(raw, "relationship_id") or "<missing>"
        if relationship_id in seen_relationships:
            problems.append(f"relationship {relationship_id}: duplicate relationship_id")
        seen_relationships.add(relationship_id)
        messages = _verify_v4_relationship(raw, custody, endpoints)
        problems.extend(f"relationship {relationship_id}: {message}" for message in messages)
        relationship_type = _s(raw, "relationship_type")
        graphs.setdefault(relationship_type, {}).setdefault(_s(raw, "source_id"), set()).add(
            _s(raw, "target_id")
        )
    for relationship_type, graph in graphs.items():
        if _graph_has_cycle(graph):
            problems.append(f"{relationship_type} relationship graph contains a cycle")

    problems.extend(_verify_v4_profile_and_handoffs(bundle))
    return problems


def _verify_v4_artifact(  # noqa: C901 -- all signed fields are checked explicitly
    item: Mapping[str, JSONValue], custody: CustodyLog
) -> list[str]:
    problems: list[str] = []
    artifact = _map(item, "artifact")
    item_id = _s(item, "capture_id")
    if artifact.get("artifact_schema") != 1:
        problems.append("artifact_schema must be 1")
    if _s(artifact, "artifact_id") != item_id:
        problems.append("artifact_id does not match the item id")
    if _s(artifact, "issue_id") != _s(item, "issue_id"):
        problems.append("artifact issue_id does not match the item")
    if _s(artifact, "content_hash") != _s(item, "content_hash"):
        problems.append("artifact content_hash does not match the item")
    if _s(artifact, "media_type") != _s(item, "media_type"):
        problems.append("artifact media_type does not match the item")
    if _s(artifact, "artifact_type") not in _ARTIFACT_TYPES:
        problems.append("unknown artifact_type")
    for key in ("title", "source", "occurred_at", "recorded_at"):
        if not _s(artifact, key).strip():
            problems.append(f"{key} must not be empty")

    semantic = {
        key: artifact.get(key)
        for key in (
            "artifact_schema",
            "artifact_id",
            "issue_id",
            "artifact_type",
            "title",
            "source",
            "issuer",
            "occurred_at",
            "recorded_at",
            "content_hash",
            "media_type",
            "accessible_description",
        )
    }
    expected = sha256_bytes(canonical_json(semantic))
    integrity = _map(item, "integrity")
    stage = _s(integrity, "binding_stage")
    if integrity.get("algorithm") != "sha256":
        problems.append("integrity.algorithm must be sha256")
    if integrity.get("custody_action") != "artifact_added":
        problems.append("integrity.custody_action must be artifact_added")
    if _s(integrity, "commitment") != expected:
        problems.append("artifact commitment does not match the signed fields")
    if stage not in {"semantic_binding", "recorded", "import_binding"}:
        problems.append("artifact binding_stage is invalid")
    if not any(
        entry.action == "artifact_added"
        and entry.item_id == item_id
        and entry.details.get("artifact_commitment") == expected
        and entry.details.get("stage", "recorded") == stage
        for entry in custody.entries
    ):
        problems.append("no custody entry binds this artifact commitment")
    return problems


def _verify_v4_relationship(  # noqa: C901 -- shape, graph, and custody checks are explicit
    relationship: Mapping[str, JSONValue],
    custody: CustodyLog,
    endpoints: Mapping[str, tuple[str, str]],
) -> list[str]:
    problems: list[str] = []
    relationship_id = _s(relationship, "relationship_id")
    relationship_type = _s(relationship, "relationship_type")
    source_id = _s(relationship, "source_id")
    target_id = _s(relationship, "target_id")
    issue_id = _s(relationship, "issue_id")
    if relationship.get("relationship_schema") != 1:
        problems.append("relationship_schema must be 1")
    if relationship_type not in _RELATIONSHIP_TYPES:
        problems.append("unknown relationship_type")
    if not relationship_id or not issue_id or not source_id or not target_id:
        problems.append("relationship identifiers must not be empty")
    if source_id == target_id:
        problems.append("source_id and target_id must differ")
    source = endpoints.get(source_id)
    target = endpoints.get(target_id)
    if source is None or target is None:
        problems.append("relationship points to a missing endpoint")
    elif source[0] != issue_id or target[0] != issue_id:
        problems.append("relationship endpoints must belong to its issue")
    if (
        relationship_type in _RELATIONSHIP_ENDPOINT_KINDS
        and source is not None
        and target is not None
        and (source[1], target[1]) not in _RELATIONSHIP_ENDPOINT_KINDS[relationship_type]
    ):
        problems.append("relationship endpoint types are invalid")

    semantic = {
        key: relationship.get(key)
        for key in (
            "relationship_schema",
            "relationship_id",
            "issue_id",
            "relationship_type",
            "source_id",
            "target_id",
            "assertion",
            "recorded_at",
        )
    }
    expected = sha256_bytes(canonical_json(semantic))
    integrity = _map(relationship, "integrity")
    stage = _s(integrity, "binding_stage")
    if integrity.get("algorithm") != "sha256":
        problems.append("integrity.algorithm must be sha256")
    if integrity.get("custody_action") != "relationship_added":
        problems.append("integrity.custody_action must be relationship_added")
    if _s(integrity, "commitment") != expected:
        problems.append("relationship commitment does not match the signed fields")
    if stage not in {"recorded", "import_binding"}:
        problems.append("relationship binding_stage is invalid")
    if not any(
        entry.action == "relationship_added"
        and entry.item_id == relationship_id
        and entry.details.get("relationship_commitment") == expected
        and entry.details.get("stage", "recorded") == stage
        for entry in custody.entries
    ):
        problems.append("no custody entry binds this relationship commitment")
    return problems


def _verify_v4_profile_and_handoffs(  # noqa: C901 -- small signed manifest audit
    bundle: Mapping[str, JSONValue],
) -> list[str]:
    problems: list[str] = []
    raw_profile = bundle.get("use_case_profile")
    if raw_profile is not None and not isinstance(raw_profile, dict):
        problems.append("use_case_profile must be an object or null")
    if isinstance(raw_profile, dict):
        if raw_profile.get("profile_schema") != 1:
            problems.append("use_case_profile.profile_schema must be 1")
        review_state = _s(raw_profile, "review_state")
        external = raw_profile.get("external_review_required")
        if review_state not in {"maintainer_reviewed", "external_review_required"}:
            problems.append("use_case_profile.review_state is invalid")
        if external is not (review_state == "external_review_required"):
            problems.append("use_case_profile external-review flag is inconsistent")

    handoffs = bundle.get("handoff_views")
    if not isinstance(handoffs, list):
        return [*problems, "handoff_views must be an array"]
    if raw_profile is None and handoffs:
        problems.append("handoff_views require a use_case_profile")
    bundle_disclosures = bundle.get("disclosures")
    required_disclosures = (
        {value for value in bundle_disclosures if isinstance(value, str)}
        if isinstance(bundle_disclosures, list)
        else set()
    )
    if isinstance(raw_profile, dict):
        profile_disclosures = raw_profile.get("disclosures")
        if isinstance(profile_disclosures, list):
            required_disclosures.update(
                value for value in profile_disclosures if isinstance(value, str)
            )
    for index, handoff in enumerate(handoffs):
        if not isinstance(handoff, dict):
            problems.append(f"handoff_views[{index}] must be an object")
            continue
        if handoff.get("presentation_only") is not True:
            problems.append(f"handoff_views[{index}] must be presentation_only")
        if handoff.get("source_of_truth") != "bundle.json":
            problems.append(f"handoff_views[{index}] source_of_truth must be bundle.json")
        if isinstance(raw_profile, dict) and _s(handoff, "profile_id") != _s(
            raw_profile, "profile_id"
        ):
            problems.append(f"handoff_views[{index}] profile_id does not match")
        if isinstance(raw_profile, dict) and handoff.get("profile") != raw_profile:
            problems.append(f"handoff_views[{index}] profile snapshot does not match")
        handoff_disclosures = handoff.get("disclosures")
        disclosed = (
            {value for value in handoff_disclosures if isinstance(value, str)}
            if isinstance(handoff_disclosures, list)
            else set()
        )
        if not required_disclosures.issubset(disclosed):
            problems.append(f"handoff_views[{index}] suppresses required disclosures")
    return problems


def _graph_has_cycle(graph: Mapping[str, set[str]]) -> bool:
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str) -> bool:
        if node in visiting:
            return True
        if node in visited:
            return False
        visiting.add(node)
        if any(visit(target) for target in graph.get(node, ())):
            return True
        visiting.remove(node)
        visited.add(node)
        return False

    return any(visit(node) for node in graph)


def _v3_array(bundle: Mapping[str, JSONValue], key: str, problems: list[str]) -> list[JSONValue]:
    value = bundle.get(key)
    if isinstance(value, list):
        return value
    problems.append(f"packet-v3 {key} must be an array")
    return []


def _v3_object(
    bundle: Mapping[str, JSONValue], key: str, problems: list[str]
) -> Mapping[str, JSONValue]:
    value = bundle.get(key)
    if isinstance(value, dict):
        return value
    problems.append(f"packet-v3 {key} must be an object")
    return {}


def _verify_v3_timeline_entry(entry: Mapping[str, JSONValue], custody: CustodyLog) -> list[str]:
    return [
        *_v3_required_field_problems(entry),
        *_v3_event_source_problems(entry),
        *_v3_time_text_problems(entry),
        *_v3_link_shape_problems(entry),
        *_v3_integrity_problems(entry, custody),
    ]


def _v3_required_field_problems(entry: Mapping[str, JSONValue]) -> list[str]:
    problems = [] if entry.get("timeline_schema") == 2 else ["timeline_schema must be 2"]
    required = (
        "entry_id",
        "issue_id",
        "event_type",
        "other_label",
        "text",
        "occurred_at",
        "source",
        "source_detail",
        "recorded_at",
        "order_token",
    )
    for key in required:
        if not isinstance(entry.get(key), str):
            problems.append(f"{key} must be a string")
    for key in ("entry_id", "issue_id", "order_token"):
        value = entry.get(key)
        if isinstance(value, str) and not value.strip():
            problems.append(f"{key} must not be empty")
    for legacy_key in ("kind", "hlc"):
        if legacy_key in entry:
            problems.append(f"packet v3 must not reuse legacy field {legacy_key!r}")
    return problems


def _v3_event_source_problems(entry: Mapping[str, JSONValue]) -> list[str]:
    problems: list[str] = []
    event_type = _s(entry, "event_type")
    other_label = _s(entry, "other_label")
    source = _s(entry, "source")
    source_detail = _s(entry, "source_detail")
    migration = _map(entry, "migration")
    if event_type not in EVENT_TYPES:
        problems.append(f"unknown event_type {event_type!r}")
    if event_type == "other" and not other_label.strip():
        problems.append("Other event is missing other_label")
    if event_type != "other" and other_label.strip():
        problems.append("other_label is only valid for an Other event")
    if source not in SOURCES:
        problems.append(f"unknown source {source!r}")
    if source == "unspecified" and not migration:
        problems.append("source unspecified is only valid on an explicit legacy migration")
    if source == "other" and not source_detail.strip():
        problems.append("Other source is missing source_detail")
    if source != "other" and source_detail.strip():
        problems.append("source_detail is only valid for an Other source")
    return problems


def _v3_time_text_problems(entry: Mapping[str, JSONValue]) -> list[str]:
    problems: list[str] = []
    migration = _map(entry, "migration")
    occurred_at = _s(entry, "occurred_at")
    if not occurred_at and not migration:
        problems.append("occurred_at may be empty only on an explicit legacy migration")
    elif occurred_at:
        try:
            if normalize_occurred_at(occurred_at) != occurred_at:
                problems.append("occurred_at is not normalized")
        except Exception:
            problems.append("occurred_at is not a valid ISO date/time")
    if not _valid_recorded_at(_s(entry, "recorded_at")):
        problems.append("recorded_at must be an ISO UTC timestamp")
    if not _s(entry, "text").strip():
        problems.append("text must not be empty")
    problems.extend(_v3_migration_problems(entry))
    return problems


def _v3_migration_problems(entry: Mapping[str, JSONValue]) -> list[str]:
    if "migration" not in entry:
        return []
    raw_migration = entry.get("migration")
    if not isinstance(raw_migration, dict):
        return ["migration must be an object"]
    migration = raw_migration
    expected: dict[str, JSONValue] = {
        "from_case_timeline_schema": 1,
        "legacy_kind_preserved_as_other_label": True,
        "occurred_at_unknown": True,
        "source_unknown": True,
    }
    return [
        f"migration.{key} must be {value!r}"
        for key, value in expected.items()
        if migration.get(key) != value
    ]


def _v3_link_shape_problems(entry: Mapping[str, JSONValue]) -> list[str]:
    problems: list[str] = []
    links = _map(entry, "links")
    capture_ids = links.get("capture_ids")
    if not isinstance(capture_ids, list) or any(
        not isinstance(value, str) for value in capture_ids
    ):
        problems.append("links.capture_ids must be an array of strings")
    elif len(capture_ids) != len(set(capture_ids)):
        problems.append("links.capture_ids must not contain duplicates")
    for key in ("notice_entry_id", "receipt_entry_id", "response_entry_id"):
        if not isinstance(links.get(key), str):
            problems.append(f"links.{key} must be a string")
    return problems


def _v3_integrity_problems(entry: Mapping[str, JSONValue], custody: CustodyLog) -> list[str]:
    problems: list[str] = []
    semantic = _v3_timeline_semantic_payload(entry)
    expected_commitment = sha256_bytes(canonical_json(semantic))
    integrity = _map(entry, "integrity")
    migration = _map(entry, "migration")
    declared = _s(integrity, "commitment")
    stage = _s(integrity, "binding_stage")
    if integrity.get("algorithm") != "sha256":
        problems.append("integrity.algorithm must be sha256")
    if integrity.get("custody_action") != "note_added":
        problems.append("integrity.custody_action must be note_added")
    if declared != expected_commitment:
        problems.append("timeline commitment does not match the signed event fields")
    if stage not in {"recorded", "backfill", "migration"}:
        problems.append("timeline binding_stage is invalid")
    if migration and stage != "migration":
        problems.append("legacy migration must carry binding_stage=migration")
    if not migration and stage == "migration":
        problems.append("binding_stage=migration requires an explicit legacy migration")
    if not any(
        custody_entry.action == "note_added"
        and custody_entry.item_id == _s(entry, "entry_id")
        and custody_entry.details.get("timeline_schema") == "2"
        and custody_entry.details.get("timeline_sha256") == expected_commitment
        and custody_entry.details.get("stage") == stage
        for custody_entry in custody.entries
    ):
        problems.append("no custody entry binds this timeline commitment")
    return problems


def _verify_v3_links(
    entry: Mapping[str, JSONValue],
    events: Mapping[str, Mapping[str, JSONValue]],
    items: Mapping[str, Mapping[str, JSONValue]],
) -> list[str]:
    problems: list[str] = []
    links = _map(entry, "links")
    issue_id = _s(entry, "issue_id")
    raw_capture_ids = links.get("capture_ids")
    if isinstance(raw_capture_ids, list):
        for value in raw_capture_ids:
            if not isinstance(value, str):
                continue
            target = items.get(value)
            # A capture can be deliberately omitted by a packet's ``since`` scope;
            # the signed reference remains meaningful and is rendered as omitted.
            if target is not None and _s(target, "issue_id") != issue_id:
                problems.append(f"linked capture {value!r} belongs to another issue")

    expected_types = {
        "notice_entry_id": "notice_sent",
        "receipt_entry_id": "delivery_confirmed",
        "response_entry_id": "response_received",
    }
    for field_key, expected_type in expected_types.items():
        target_id = _s(links, field_key)
        if not target_id:
            continue
        target = events.get(target_id)
        if target is None:
            problems.append(f"links.{field_key} points to a missing timeline event")
        elif _s(target, "issue_id") != issue_id:
            problems.append(f"links.{field_key} points to another issue")
        elif _s(target, "event_type") != expected_type:
            problems.append(f"links.{field_key} does not point to a {expected_type} event")
    return problems


def _v3_timeline_semantic_payload(entry: Mapping[str, JSONValue]) -> dict[str, JSONValue]:
    """The exact packet-v3 fields committed by ``timeline_sha256``."""
    links = _map(entry, "links")
    capture_ids = links.get("capture_ids")
    safe_capture_ids: list[JSONValue] = capture_ids if isinstance(capture_ids, list) else []
    return {
        "timeline_schema": 2,
        "entry_id": _s(entry, "entry_id"),
        "issue_id": _s(entry, "issue_id"),
        "event_type": _s(entry, "event_type"),
        "other_label": _s(entry, "other_label"),
        "text": _s(entry, "text"),
        "occurred_at": _s(entry, "occurred_at"),
        "source": _s(entry, "source"),
        "source_detail": _s(entry, "source_detail"),
        "recorded_at": _s(entry, "recorded_at"),
        "links": {
            "capture_ids": safe_capture_ids,
            "notice_entry_id": _s(links, "notice_entry_id"),
            "receipt_entry_id": _s(links, "receipt_entry_id"),
            "response_entry_id": _s(links, "response_entry_id"),
        },
    }


def _valid_recorded_at(value: str) -> bool:
    if not value.endswith("Z"):
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _verify_signature(packet_dir: Path, bundle_bytes: bytes) -> bool:
    try:
        signature_bytes = _read_packet_control_file(
            packet_dir,
            _SIGNATURE,
            limit=_MAX_SIGNATURE_BYTES,
            required=False,
        )
        if signature_bytes is None:
            return False
        doc = json.loads(signature_bytes)
        if not isinstance(doc, dict):
            return False
        bundle_hash = sha256_bytes(bundle_bytes)
        if doc.get("bundle_sha256") != bundle_hash:
            return False
        public = doc.get("sign_public")
        signature = doc.get("signature")
        if not isinstance(public, str) or not isinstance(signature, str):
            return False
        return verify_signature(
            base64.b64decode(public), bundle_hash.encode("ascii"), base64.b64decode(signature)
        )
    except _SIGNATURE_READ_ERRORS:
        # Any malformed signature file is a failed signature, never a crash.
        return False


def _verify_custody(bundle: Mapping[str, JSONValue]) -> tuple[bool, int, CustodyLog]:
    proof = _map(bundle, "custody_proof")
    raw_entries = _list(proof, "entries")
    records: list[Mapping[str, JSONValue]] = [e for e in raw_entries if isinstance(e, dict)]
    try:
        # from_records can reject malformed entries (CustodyError); treat any
        # failure to parse or walk the chain as a broken chain, never a crash.
        custody = CustodyLog.from_records(records)
        result = custody.verify()
    except Exception:
        return False, len(records), CustodyLog([])
    declared_head = proof.get("head_hash")
    head_ok = declared_head == result.head_hash
    return (result.ok and head_ok), result.length, custody


def _sharing_bindings(custody: CustodyLog) -> dict[str, set[tuple[str, str]]]:
    """Map capture_id -> {(content_hash, shared_hash)} attested in custody."""
    bindings: dict[str, set[tuple[str, str]]] = {}
    for entry in custody.entries:
        if entry.action == "copied_for_sharing":
            content_hash = entry.details.get("content_hash", "")
            shared_hash = entry.details.get("shared_hash", "")
            bindings.setdefault(entry.item_id, set()).add((content_hash, shared_hash))
    return bindings


def _poster_bindings(custody: CustodyLog) -> dict[str, set[tuple[str, str]]]:
    """Map capture_id -> {(content_hash, poster_hash)} attested in custody (EXP-07)."""
    bindings: dict[str, set[tuple[str, str]]] = {}
    for entry in custody.entries:
        if entry.action == "copied_for_sharing":
            poster_hash = entry.details.get("poster_hash", "")
            if poster_hash:
                content_hash = entry.details.get("content_hash", "")
                bindings.setdefault(entry.item_id, set()).add((content_hash, poster_hash))
    return bindings


# --- parsing helpers ----------------------------------------------------------


def _read_bundle_bytes(packet_dir: Path) -> bytes:
    bundle_bytes = _read_packet_control_file(
        packet_dir,
        _BUNDLE,
        limit=_MAX_BUNDLE_BYTES,
        required=True,
    )
    if bundle_bytes is None:  # required=True always raises instead
        raise VerificationError(f"no {_BUNDLE} in {packet_dir}")
    return bundle_bytes


def _read_packet_control_file(  # noqa: C901 -- ordered hostile-file checks stay explicit
    packet_dir: Path,
    name: str,
    *,
    limit: int,
    required: bool,
) -> bytes | None:
    """Read one fixed packet control file without following hostile file types."""
    try:
        root_before = packet_dir.lstat()
    except OSError as exc:
        raise VerificationError("packet directory could not be safely inspected") from exc
    if stat.S_ISLNK(root_before.st_mode):
        raise VerificationError("packet directory must not be a symlink")
    if not stat.S_ISDIR(root_before.st_mode):
        raise VerificationError("packet path is not a directory")

    path = packet_dir / name
    try:
        file_before = path.lstat()
    except FileNotFoundError:
        if required:
            raise VerificationError(f"no {name} in {packet_dir}") from None
        return None
    except OSError as exc:
        raise VerificationError(f"{name} could not be safely inspected") from exc
    if stat.S_ISLNK(file_before.st_mode):
        raise VerificationError(f"{name} must not be a symlink")
    if not stat.S_ISREG(file_before.st_mode):
        raise VerificationError(f"{name} is not a regular file")
    if file_before.st_size > limit:
        raise VerificationError(f"{name} exceeds the {limit}-byte verification limit")

    try:
        root_resolved = packet_dir.resolve(strict=True)
        path_resolved = path.resolve(strict=True)
    except OSError as exc:
        raise VerificationError(f"{name} could not be safely resolved") from exc
    if path_resolved.parent != root_resolved:
        raise VerificationError(f"{name} escapes the packet directory")

    file_fd = -1
    try:
        flags = (
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        file_fd = os.open(path, flags)
        handle = os.fdopen(file_fd, "rb", closefd=True)
        file_fd = -1
        with handle:
            opened = os.fstat(handle.fileno())
            if not stat.S_ISREG(opened.st_mode) or _different_file(file_before, opened):
                raise VerificationError(f"{name} changed during safety checks")
            data = handle.read(limit + 1)
            after = os.fstat(handle.fileno())
    except VerificationError:
        raise
    except OSError as exc:
        raise VerificationError(f"{name} could not be safely read") from exc
    finally:
        _close_fd(file_fd)
    if len(data) > limit:
        raise VerificationError(f"{name} exceeds the {limit}-byte verification limit")
    if _file_changed_while_reading(opened, after):
        raise VerificationError(f"{name} changed while it was read")
    return data


def _parse_bundle(bundle_bytes: bytes) -> Mapping[str, JSONValue]:
    try:
        parsed = json.loads(bundle_bytes)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        # Hostile bytes may be malformed JSON *or* invalid UTF-8 (json.loads on
        # bytes raises UnicodeDecodeError). Both are a clean rejection, not a crash.
        raise VerificationError(f"bundle is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise VerificationError("bundle must be a JSON object")
    return parsed


def _s(mapping: Mapping[str, JSONValue], key: str) -> str:
    value = mapping.get(key)
    return value if isinstance(value, str) else ""


def _list(mapping: Mapping[str, JSONValue], key: str) -> list[JSONValue]:
    value = mapping.get(key)
    return value if isinstance(value, list) else []


def _map(mapping: Mapping[str, JSONValue], key: str) -> Mapping[str, JSONValue]:
    value = mapping.get(key)
    return value if isinstance(value, dict) else {}
