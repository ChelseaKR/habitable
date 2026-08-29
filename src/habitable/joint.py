# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""A joint submission index over packets that were already signed separately.

Candidate #13 in ``docs/novel-use-cases-plan.md``: an organizer holds several
tenants' finished packets and needs to hand a court, inspector, or agency **one
navigable building-wide submission** instead of a pile of unrelated folders.

The thing this must not become is a merged record. Combining several households'
custody chains into one would re-open exactly the scoped/rehashed custody-view
problem workstream A is still closing, and it would replace N independently
checkable proofs with one the recipient has to take on faith. So this module
merges nothing. It writes a **table of contents**:

* Each row names one packet directory that already exists, exactly as its own
  producer exported it. Nothing inside a member packet is read for rewriting,
  re-signing, re-hashing, or copying. The member packets are not touched at all.
* Each row binds that member by the SHA-256 of its ``bundle.json`` bytes. That
  is the same digest the member's own ``bundle.sig.json`` is a signature over,
  so a swapped or edited member is a digest mismatch at check time.
* Each row records the verdict :func:`habitable.verify.verify_packet` gave at
  build time, and :func:`check_joint_index` re-derives every one of them from
  the packets themselves. The index is therefore never a trust root: it asserts
  nothing a recipient cannot recompute, and ``habitable joint check`` is how
  they recompute it.

**The index is not itself signed or sealed, and says so.** Its members are; it
is not. Anyone who can write the file can add or drop a row, and no field inside
a file an attacker controls can stop that. What the digests do buy is that no
*listed* packet can be substituted quietly, and :func:`check_joint_index` also
reports packet directories present on disk that the index does not list, so a
smuggled-in extra folder is surfaced rather than absorbed. Authenticating the
index itself needs a decision this project has not made yet, because there is no
answer to *whose key* speaks for an organizer's presentation; see
``docs/adr/0015-joint-multi-tenant-submission-index.md``.

Nothing here opens a network connection, reads a vault, or needs a key. An
organizer runs it on packets they were handed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from html import escape
from pathlib import Path
from typing import cast

from cryptography import x509

from .canonical import JSONValue, canonical_json, sha256_bytes
from .errors import HabitableError
from .i18n import cli_text
from .verify import verify_packet

__all__ = [
    "JOINT_DISCLOSURES",
    "JOINT_INDEX_FILE",
    "JOINT_INDEX_HTML",
    "JOINT_INDEX_VERSION",
    "JointCheck",
    "JointIndexResult",
    "JointMember",
    "MemberCheck",
    "build_joint_index",
    "check_joint_index",
]

#: Bump when a field a reader depends on changes meaning. A joint index is not a
#: packet: it carries no evidence of its own, so it is versioned on its own line
#: and ``packet_version`` is untouched by anything in this module.
JOINT_INDEX_VERSION = 1

JOINT_INDEX_FILE = "joint_index.json"
JOINT_INDEX_HTML = "index.html"

_BUNDLE = "bundle.json"

#: What the index says about itself, in every rendering and in the JSON. These
#: are the three conclusions a joint submission invites and cannot support.
JOINT_DISCLOSURES: tuple[str, ...] = (
    "joint_index_presentation_only",
    "joint_index_unsigned",
    "joint_index_no_common_cause",
)


@dataclass(frozen=True, slots=True)
class JointMember:
    """One already-exported packet, as the index lists it.

    Every field is copied from, or computed over, bytes already inside the
    member packet the index sits beside. Nothing here is derived from a source
    the recipient does not also hold, and no per-household identifier is copied
    that the member's own ``bundle.json`` does not already carry.
    """

    #: Directory name, relative to the index file. Always a single path segment.
    path: str
    label: str
    bundle_sha256: str
    packet_version: int
    generated_at: str
    language: str
    producer_fingerprint: str
    seal_present: bool
    status: str
    structurally_intact: bool
    evidence_ready: bool
    item_count: int
    verified_items: int
    problems: tuple[str, ...] = ()

    def to_json(self) -> dict[str, JSONValue]:
        return {
            "path": self.path,
            "label": self.label,
            "bundle_sha256": self.bundle_sha256,
            "packet_version": self.packet_version,
            "generated_at": self.generated_at,
            "language": self.language,
            "producer_fingerprint": self.producer_fingerprint,
            "seal_present": self.seal_present,
            "status": self.status,
            "structurally_intact": self.structurally_intact,
            "evidence_ready": self.evidence_ready,
            "item_count": self.item_count,
            "verified_items": self.verified_items,
            "problems": cast(JSONValue, list(self.problems)),
        }


@dataclass(frozen=True, slots=True)
class JointIndexResult:
    """A written joint index, and where its two files landed."""

    root: Path
    index_path: Path
    html_path: Path
    members: tuple[JointMember, ...]
    generated_at: str

    @property
    def member_count(self) -> int:
        return len(self.members)

    @property
    def ready_count(self) -> int:
        """Members the verifier called evidence-ready at build time."""
        return sum(1 for member in self.members if member.evidence_ready)

    @property
    def all_ready(self) -> bool:
        return bool(self.members) and self.ready_count == self.member_count


@dataclass(frozen=True, slots=True)
class MemberCheck:
    """What re-checking one listed member found, now, from the packet itself."""

    path: str
    label: str
    recorded_sha256: str
    observed_sha256: str
    present: bool
    status: str
    evidence_ready: bool
    problems: tuple[str, ...] = ()

    @property
    def digest_matches(self) -> bool:
        """Whether the packet on disk is still the one the index listed.

        A missing member has no observed digest, so this is false rather than
        vacuously true: an absent packet must never read as an unchanged one.
        """
        return self.present and self.observed_sha256 == self.recorded_sha256

    @property
    def ok(self) -> bool:
        return self.digest_matches and self.evidence_ready


@dataclass(frozen=True, slots=True)
class JointCheck:
    """The verdict on a joint index, re-derived from the member packets."""

    index_path: Path
    members: tuple[MemberCheck, ...] = ()
    unlisted: tuple[str, ...] = ()
    problems: tuple[str, ...] = field(default_factory=tuple)

    @property
    def ok(self) -> bool:
        """Fail closed: an empty index, any problem, any drifted or unlisted
        member, and any member the verifier did not call evidence-ready all
        make this false."""
        return (
            bool(self.members)
            and not self.problems
            and not self.unlisted
            and all(member.ok for member in self.members)
        )

    @property
    def matched_count(self) -> int:
        return sum(1 for member in self.members if member.digest_matches)

    @property
    def ready_count(self) -> int:
        return sum(1 for member in self.members if member.evidence_ready)

    def to_json(self) -> dict[str, JSONValue]:
        return {
            "joint_index_version": JOINT_INDEX_VERSION,
            "index_path": str(self.index_path),
            "ok": self.ok,
            "member_count": len(self.members),
            "matched_count": self.matched_count,
            "ready_count": self.ready_count,
            "unlisted": cast(JSONValue, list(self.unlisted)),
            "problems": cast(JSONValue, list(self.problems)),
            "members": cast(
                JSONValue,
                [
                    {
                        "path": member.path,
                        "label": member.label,
                        "recorded_sha256": member.recorded_sha256,
                        "observed_sha256": member.observed_sha256,
                        "present": member.present,
                        "digest_matches": member.digest_matches,
                        "status": member.status,
                        "evidence_ready": member.evidence_ready,
                        "ok": member.ok,
                        "problems": cast(JSONValue, list(member.problems)),
                    }
                    for member in self.members
                ],
            ),
        }


def discover_packet_dirs(root: Path) -> tuple[Path, ...]:
    """Every immediate subdirectory of ``root``, in a deterministic order.

    A subdirectory without a ``bundle.json`` is an error rather than a skip: an
    organizer who put a folder in the submission meant it to be in the
    submission, and silently leaving it out of the index would produce a table
    of contents that is wrong in the one direction nobody checks.
    """
    root = Path(root)
    if not root.is_dir():
        raise HabitableError(f"not a directory: {root}")
    found = sorted((child for child in root.iterdir() if child.is_dir()), key=lambda p: p.name)
    for child in found:
        if not (child / _BUNDLE).is_file():
            raise HabitableError(
                f"{child.name} is in the submission folder but has no {_BUNDLE}; "
                "move it out, or export it as a packet first"
            )
    if not found:
        raise HabitableError(f"no packet directories found in {root}")
    return tuple(found)


def build_joint_index(
    root: Path,
    *,
    trusted_certs: list[x509.Certificate] | None = None,
    generated_at: str | None = None,
    language: str = "en",
) -> JointIndexResult:
    """Index every packet directory under ``root`` and write the two output files.

    ``root`` is the submission folder the organizer assembled: one subdirectory
    per already-exported packet. The member packets are opened read-only and are
    never modified, copied, re-signed, or re-hashed.

    ``trusted_certs`` is the recipient-policy anchor set, exactly as
    ``habitable verify`` takes it. Without one, no member can be evidence-ready,
    which is the fail-closed direction ADR 0008 chose and is not softened here.
    """
    packet_dirs = discover_packet_dirs(root)
    members = tuple(_member_for(packet_dir, trusted_certs) for packet_dir in packet_dirs)
    stamp = generated_at or _now_iso()
    document = _index_document(members, stamp)

    index_path = Path(root) / JOINT_INDEX_FILE
    index_path.write_bytes(canonical_json(cast(JSONValue, document)))
    html_path = Path(root) / JOINT_INDEX_HTML
    html_path.write_text(_render_index_html(members, stamp, language), encoding="utf-8")

    return JointIndexResult(
        root=Path(root),
        index_path=index_path,
        html_path=html_path,
        members=members,
        generated_at=stamp,
    )


def check_joint_index(
    index_path: Path,
    *,
    trusted_certs: list[x509.Certificate] | None = None,
) -> JointCheck:
    """Re-derive every claim in a joint index from the packets beside it.

    This reads the index only to learn *what it claims*. Every verdict it
    returns is computed from the member packets, so a doctored index cannot talk
    its way to ``ok``: the digest it records is compared against the bytes on
    disk, and the readiness it records is thrown away and recomputed.
    """
    index_path = Path(index_path)
    root = index_path.parent
    document, problems = _read_index(index_path)
    if problems:
        return JointCheck(index_path=index_path, problems=tuple(problems))

    listed = _listed_members(document)
    checks = tuple(_check_member(root, entry, trusted_certs) for entry in listed)
    return JointCheck(
        index_path=index_path,
        members=checks,
        unlisted=_unlisted_dirs(root, {check.path for check in checks}),
    )


def _member_for(packet_dir: Path, trusted_certs: list[x509.Certificate] | None) -> JointMember:
    """Read one packet's own facts and its verifier verdict, changing nothing."""
    bundle_bytes = (packet_dir / _BUNDLE).read_bytes()
    bundle = _load_mapping(bundle_bytes)
    report = verify_packet(packet_dir, trusted_certs=trusted_certs)
    unit = _text(bundle.get("unit"))
    return JointMember(
        path=packet_dir.name,
        label=unit or packet_dir.name,
        bundle_sha256=sha256_bytes(bundle_bytes),
        packet_version=_whole(bundle.get("packet_version")),
        generated_at=_text(bundle.get("generated_at")),
        language=_text(bundle.get("language")) or "en",
        producer_fingerprint=_text(bundle.get("producer_fingerprint")),
        seal_present=report.seal.present,
        status=report.status,
        structurally_intact=report.structurally_intact,
        evidence_ready=report.evidence_ready,
        item_count=len(report.items),
        verified_items=report.verified_items,
        problems=tuple(report.problems),
    )


def _index_document(members: tuple[JointMember, ...], generated_at: str) -> dict[str, JSONValue]:
    """The written index. Every claim in it is re-derivable from the members."""
    return {
        "joint_index_version": JOINT_INDEX_VERSION,
        "generated_at": generated_at,
        "member_count": len(members),
        # Stated as fields rather than left to a reader's assumption, and
        # asserted by tests, because these three are the whole safety argument.
        "presentation_only": True,
        "custody_merged": False,
        "index_signed": False,
        "source_of_truth": "each member packet's own bundle.json",
        "disclosures": cast(JSONValue, list(JOINT_DISCLOSURES)),
        "members": cast(JSONValue, [member.to_json() for member in members]),
    }


def _read_index(index_path: Path) -> tuple[dict[str, JSONValue], list[str]]:
    """Load the index, refusing anything this version cannot honestly read."""
    try:
        raw = index_path.read_bytes()
    except OSError as exc:
        return {}, [f"joint index could not be read: {exc}"]
    try:
        document = _load_mapping(raw)
    except HabitableError as exc:
        return {}, [str(exc)]
    version = _whole(document.get("joint_index_version"))
    if version != JOINT_INDEX_VERSION:
        return {}, [
            f"joint index version {version} is not supported by this build "
            f"(expected {JOINT_INDEX_VERSION})"
        ]
    if not isinstance(document.get("members"), list):
        return {}, ["joint index has no member list"]
    return document, []


def _listed_members(document: dict[str, JSONValue]) -> list[dict[str, JSONValue]]:
    raw = document.get("members")
    entries = raw if isinstance(raw, list) else []
    return [entry for entry in entries if isinstance(entry, dict)]


def _check_member(
    root: Path,
    entry: dict[str, JSONValue],
    trusted_certs: list[x509.Certificate] | None,
) -> MemberCheck:
    """Recompute one listed member's digest and verdict from the packet on disk."""
    path = _text(entry.get("path"))
    recorded = _text(entry.get("bundle_sha256"))
    label = _text(entry.get("label")) or path
    if _unsafe_segment(path):
        return MemberCheck(
            path=path,
            label=label,
            recorded_sha256=recorded,
            observed_sha256="",
            present=False,
            status="rejected_path",
            evidence_ready=False,
            problems=("index names a path that is not a plain packet directory",),
        )
    packet_dir = root / path
    try:
        bundle_bytes = (packet_dir / _BUNDLE).read_bytes()
    except OSError as exc:
        return MemberCheck(
            path=path,
            label=label,
            recorded_sha256=recorded,
            observed_sha256="",
            present=False,
            status="missing",
            evidence_ready=False,
            problems=(f"listed packet could not be read: {exc}",),
        )
    report = verify_packet(packet_dir, trusted_certs=trusted_certs)
    return MemberCheck(
        path=path,
        label=label,
        recorded_sha256=recorded,
        observed_sha256=sha256_bytes(bundle_bytes),
        present=True,
        status=report.status,
        evidence_ready=report.evidence_ready,
        problems=tuple(report.problems),
    )


def _unlisted_dirs(root: Path, listed: set[str]) -> tuple[str, ...]:
    """Packet directories sitting beside the index that it does not mention.

    An index that quietly ignores a folder someone added to the submission is
    worse than no index: the recipient reads a complete-looking table of
    contents over an incomplete set.
    """
    try:
        children = sorted(child.name for child in root.iterdir() if child.is_dir())
    except OSError:
        return ()
    return tuple(
        name for name in children if name not in listed and (root / name / _BUNDLE).is_file()
    )


def _unsafe_segment(name: str) -> bool:
    """Whether a recorded path is anything other than one plain directory name."""
    return (
        not name or name in {".", ".."} or "/" in name or "\\" in name or Path(name).is_absolute()
    )


def _load_mapping(raw: bytes) -> dict[str, JSONValue]:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HabitableError(f"not valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise HabitableError("expected a JSON object")
    return cast(dict[str, JSONValue], value)


def _text(value: JSONValue | None) -> str:
    return value if isinstance(value, str) else ""


def _whole(value: JSONValue | None) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _render_index_html(members: tuple[JointMember, ...], generated_at: str, language: str) -> str:
    """One self-contained, semantic table of contents, EN or ES.

    No script, no external resource, no color-only status: each row states its
    own readiness in words, because a recipient reading this in a courthouse
    may be doing so on a printout or with a screen reader.
    """
    locale = "es" if language == "es" else "en"
    rows = "".join(_render_row(member, locale) for member in members)
    notes = "".join(f"<li>{escape(cli_text(key, locale))}</li>" for key in JOINT_DISCLOSURES)
    ready = sum(1 for member in members if member.evidence_ready)
    counts = cli_text("joint_html_counts", locale, members=len(members), ready=ready)
    return (
        f'<!DOCTYPE html>\n<html lang="{locale}">\n<head>\n'
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{escape(cli_text('joint_html_title', locale))}</title>\n"
        "</head>\n<body>\n<main>\n"
        f"<h1>{escape(cli_text('joint_html_title', locale))}</h1>\n"
        f"<p>{escape(cli_text('joint_html_generated', locale, at=generated_at))}</p>\n"
        f"<p>{escape(counts)}</p>\n"
        "<table>\n"
        f"<caption>{escape(cli_text('joint_html_caption', locale))}</caption>\n"
        "<thead><tr>"
        f'<th scope="col">{escape(cli_text("joint_col_label", locale))}</th>'
        f'<th scope="col">{escape(cli_text("joint_col_packet", locale))}</th>'
        f'<th scope="col">{escape(cli_text("joint_col_items", locale))}</th>'
        f'<th scope="col">{escape(cli_text("joint_col_state", locale))}</th>'
        f'<th scope="col">{escape(cli_text("joint_col_digest", locale))}</th>'
        "</tr></thead>\n"
        f"<tbody>{rows}</tbody>\n</table>\n"
        f"<h2>{escape(cli_text('joint_html_limits', locale))}</h2>\n"
        f"<ul>{notes}</ul>\n"
        "</main>\n</body>\n</html>\n"
    )


def _render_row(member: JointMember, locale: str) -> str:
    state = cli_text(_state_key(member), locale)
    return (
        "<tr>"
        f'<th scope="row">{escape(member.label)}</th>'
        f'<td><a href="{escape(member.path)}/packet.html">{escape(member.path)}</a></td>'
        f"<td>{member.verified_items}/{member.item_count}</td>"
        f"<td>{escape(state)}</td>"
        f"<td><code>{escape(member.bundle_sha256)}</code></td>"
        "</tr>"
    )


def _state_key(member: JointMember) -> str:
    if member.evidence_ready:
        return "joint_state_ready"
    if not member.structurally_intact:
        return "joint_state_broken"
    return "joint_state_unanchored"
