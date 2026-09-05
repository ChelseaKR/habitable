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

**The index carries no signature of its own**, because this project has no
notion of an organizer identity and ADR 0011 already declined to name people in
evidence. What it can carry is an **authority seal**: an RFC 3161 token over the
SHA-256 of the finished index, exactly as ADR 0011 seals a packet. That is what
speaks for the *list*, which recomputing member digests cannot do. Digests prove
no listed packet was substituted; only a seal over the index makes a packet
*dropped* from the submission detectable, because dropping one changes the bytes
an authority countersigned and no attacker can mint a replacement token.

The seal follows ADR 0011's rules without softening any of them. A present seal
is always checked against the index in front of it. An absent one is a state, not
a failure, until a recipient passes ``require_seal``: no field inside a file an
attacker controls can stop them deleting the sidecar, so making that assertion is
the recipient's to make. ``seal_not_after`` catches the residual an authority
cannot help with, since a re-sealed list is provably younger than the submission
that reached them. Nothing is sealed by default; an organizer names an authority,
because that is the one part of this module that touches the network. See
``docs/adr/0015-joint-multi-tenant-submission-index.md`` and
``docs/adr/0016-authority-seal-over-the-joint-index.md``.

Nothing here reads a vault or needs a key, and nothing reaches the network
unless the organizer names a sealing authority. An organizer runs it on packets
they were handed.
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
from .tsa import TimestampAuthority, TimestampInfo, TimestampToken, verify_token
from .verify import SealVerdict, verify_packet

__all__ = [
    "JOINT_DISCLOSURES",
    "JOINT_INDEX_FILE",
    "JOINT_INDEX_HTML",
    "JOINT_INDEX_VERSION",
    "JOINT_SIG_FILE",
    "JointCheck",
    "JointIndexResult",
    "JointMember",
    "MemberCheck",
    "build_joint_index",
    "check_joint_index",
    "seal_statement",
]

#: Bump when a field a reader depends on changes meaning. A joint index is not a
#: packet: it carries no evidence of its own, so it is versioned on its own line
#: and ``packet_version`` is untouched by anything in this module.
JOINT_INDEX_VERSION = 1

JOINT_INDEX_FILE = "joint_index.json"
JOINT_INDEX_HTML = "index.html"
#: The seal sidecar. It sits outside the index for the same reason
#: ``bundle.sig.json`` sits outside ``bundle.json``: a token over the index's
#: own digest cannot live inside the bytes it covers.
JOINT_SIG_FILE = "joint_index.sig.json"

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
    #: Whether an authority countersigned the finished index, and what to tell
    #: the operator either way. Sealing never fails the build: an unreachable
    #: authority costs the index its seal, not its existence (ADR 0011's rule,
    #: applied here by ADR 0016).
    sealed: bool = False
    seal_note: str = ""
    sig_path: Path | None = None

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
    #: What an authority countersigned about the whole index, if anything. Seal
    #: *problems* reach ``problems`` and therefore ``ok``; a merely absent,
    #: unasserted seal does not. Same contract as ADR 0011 gives a packet.
    seal: SealVerdict = field(default_factory=SealVerdict)

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
            "index_seal": {
                "present": self.seal.present,
                "verified": self.seal.verified,
                "trusted": self.seal.trusted,
                "ok": self.seal.ok,
                "required": self.seal.required,
                "kind": self.seal.kind,
                "tsa_name": self.seal.tsa_name,
                "gen_time": self.seal.gen_time,
                "notes": cast(JSONValue, list(self.seal.notes)),
            },
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


def seal_statement(seal: SealVerdict, locale: str = "en") -> str:
    """One sentence about the index seal a recipient can act on, including "none".

    Deliberately not folded into the written index or its HTML. A rendering that
    announced its own seal would be making a claim an attacker removes by
    deleting one file, which is the reason ADR 0011 kept the packet seal out of
    `disclosures` too. The seal is reported at check time, to the person holding
    the submission, or not at all.
    """
    if not seal.present:
        return cli_text("joint_seal_absent", locale)
    if not seal.verified:
        return cli_text("joint_seal_broken", locale)
    key = "joint_seal_sealed" if seal.trusted else "joint_seal_sealed_untrusted"
    return cli_text(key, locale, tsa=seal.tsa_name or "?", gen_time=seal.gen_time or "?")


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
    tsa: TimestampAuthority | None = None,
) -> JointIndexResult:
    """Index every packet directory under ``root`` and write its output files.

    ``root`` is the submission folder the organizer assembled: one subdirectory
    per already-exported packet. The member packets are opened read-only and are
    never modified, copied, re-signed, or re-hashed.

    ``trusted_certs`` is the recipient-policy anchor set, exactly as
    ``habitable verify`` takes it. Without one, no member can be evidence-ready,
    which is the fail-closed direction ADR 0008 chose and is not softened here.

    ``tsa`` countersigns the finished index. The index lists the members, so a
    token over its bytes binds *which* packets the submission contains, which is
    the one thing recomputing each member's digest cannot establish. Sealing
    never fails the build: an unreachable authority costs the index its seal,
    not its existence (ADR 0016, following ADR 0011).
    """
    packet_dirs = discover_packet_dirs(root)
    members = tuple(_member_for(packet_dir, trusted_certs) for packet_dir in packet_dirs)
    stamp = generated_at or _now_iso()
    document = _index_document(members, stamp)

    index_path = Path(root) / JOINT_INDEX_FILE
    index_bytes = canonical_json(cast(JSONValue, document))
    index_path.write_bytes(index_bytes)
    html_path = Path(root) / JOINT_INDEX_HTML
    html_path.write_text(_render_index_html(members, stamp, language), encoding="utf-8")
    token, note = _seal_index(sha256_bytes(index_bytes), tsa)
    sig_path = _write_sidecar(Path(root), sha256_bytes(index_bytes), token)

    return JointIndexResult(
        root=Path(root),
        index_path=index_path,
        html_path=html_path,
        members=members,
        generated_at=stamp,
        sealed=token is not None,
        seal_note=note,
        sig_path=sig_path,
    )


def _seal_index(
    index_hash: str, tsa: TimestampAuthority | None
) -> tuple[dict[str, str] | None, str]:
    """Ask ``tsa`` to countersign the finished index; never fail the build.

    The note is returned rather than logged, because a message that misstates
    its own cause is the kind of thing this project treats as a defect: "no
    authority was supplied" and "the authority could not be reached" are
    different facts and the operator gets whichever one is true.
    """
    if tsa is None:
        return None, "joint_seal_none"
    try:
        return tsa.stamp(index_hash).to_dict(), "joint_seal_ok"
    except Exception:
        # Any authority failure, network or otherwise. The index is the point;
        # the seal is the improvement, so the improvement is what is lost.
        return None, "joint_seal_failed"


def _write_sidecar(root: Path, index_hash: str, token: dict[str, str] | None) -> Path | None:
    """Write the seal sidecar, or remove a stale one when nothing sealed.

    Removing matters: rebuilding an index without an authority must not leave
    the previous run's token sitting beside new bytes it does not cover. A
    retained seal is a false claim, and ``check_joint_index`` would correctly
    call it one, but the honest place to prevent it is here.
    """
    sig_path = root / JOINT_SIG_FILE
    if token is None:
        sig_path.unlink(missing_ok=True)
        return None
    document: dict[str, JSONValue] = {
        "index_sha256": index_hash,
        "index_seal": cast(JSONValue, token),
    }
    sig_path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return sig_path


def check_joint_index(
    index_path: Path,
    *,
    trusted_certs: list[x509.Certificate] | None = None,
    require_seal: bool = False,
    seal_not_after: str | None = None,
) -> JointCheck:
    """Re-derive every claim in a joint index from the packets beside it.

    This reads the index only to learn *what it claims*. Every verdict it
    returns is computed from the member packets, so a doctored index cannot talk
    its way to ``ok``: the digest it records is compared against the bytes on
    disk, and the readiness it records is thrown away and recomputed.

    ``require_seal`` demands that an authority countersigned the index itself,
    which is what makes a *dropped* member detectable: recomputing digests can
    only speak for members still on the list. As in ADR 0011, a present seal is
    always checked, and this flag is what makes an absent or unanchored one a
    failure rather than a note.

    ``seal_not_after`` is an ISO 8601 UTC instant the recipient names, normally
    the day the submission reached them. A seal minted after it means the index
    bytes came into existence after the submission arrived.
    """
    index_path = Path(index_path)
    root = index_path.parent
    raw = _read_index_bytes(index_path)
    seal, seal_problems = _verify_index_seal(
        root,
        raw,
        trusted_certs=trusted_certs,
        required=require_seal,
        not_after=seal_not_after,
    )
    document, problems = _parse_index(raw)
    if problems:
        return JointCheck(
            index_path=index_path, problems=tuple(problems + seal_problems), seal=seal
        )

    listed = _listed_members(document)
    checks = tuple(_check_member(root, entry, trusted_certs) for entry in listed)
    return JointCheck(
        index_path=index_path,
        members=checks,
        unlisted=_unlisted_dirs(root, {check.path for check in checks}),
        problems=tuple(seal_problems),
        seal=seal,
    )


def _verify_index_seal(
    root: Path,
    raw: bytes | None,
    *,
    trusted_certs: list[x509.Certificate] | None,
    required: bool,
    not_after: str | None,
) -> tuple[SealVerdict, list[str]]:
    """Check the authority countersignature over the whole index.

    The three rules are ADR 0011's, unchanged, because the situation is
    identical: a present seal is always checked against the bytes in front of
    it; an absent seal is a state rather than a failure until the recipient
    says otherwise; and every assertion fails closed, so an unreadable deadline
    or a deadline asserted against an unsealed index is a problem rather than a
    quietly skipped check.
    """
    problems: list[str] = []
    deadline, deadline_problem = _seal_deadline(not_after)
    if deadline_problem is not None:
        problems.append(deadline_problem)

    record = _seal_record(root)
    if record is None or raw is None:
        if required:
            problems.append(
                "index seal required, but this submission carries no authority seal "
                "over its list of packets"
            )
        if not_after is not None and deadline_problem is None:
            problems.append("seal date asserted, but this index carries no authority seal to date")
        return SealVerdict(required=required), problems

    index_hash = sha256_bytes(raw)
    try:
        info = verify_token(
            TimestampToken.from_dict(record), index_hash, trusted_certs=trusted_certs
        )
    except Exception as exc:
        # A malformed record and a token whose imprint is some *other* index both
        # mean the same thing to a recipient: this seal does not cover the list in
        # front of them. A hostile token must never escape as a crash.
        problems.append(f"index seal does not cover this list of packets: {exc}")
        return SealVerdict(present=True, required=required, notes=(str(exc),)), problems

    notes: list[str] = []
    if not info.trusted_chain:
        notes.append(info.note or "index seal valid but authority not chained to a trusted root")
        if required:
            problems.append(
                "index seal required, but its authority does not chain to a certificate "
                "you supplied"
            )
    problems.extend(_seal_deadline_problems(info, deadline=deadline, not_after=not_after))
    return (
        SealVerdict(
            present=True,
            verified=True,
            trusted=info.trusted_chain,
            kind=info.kind,
            tsa_name=info.tsa_name,
            gen_time=info.gen_time,
            required=required,
            notes=tuple(notes),
        ),
        problems,
    )


def _seal_record(root: Path) -> dict[str, JSONValue] | None:
    """The stored token, or None when there is no readable, well-formed sidecar."""
    try:
        raw = (root / JOINT_SIG_FILE).read_bytes()
    except OSError:
        return None
    try:
        document = _load_mapping(raw)
    except HabitableError:
        return None
    seal = document.get("index_seal")
    return seal if isinstance(seal, dict) else None


def _seal_deadline(not_after: str | None) -> tuple[datetime | None, str | None]:
    """Parse the recipient's ``--seal-not-after`` assertion, failing closed."""
    if not_after is None:
        return None, None
    parsed = _parse_iso_utc(not_after.strip())
    if parsed is None:
        return None, (
            f"seal date {not_after!r} is not a valid ISO 8601 UTC instant "
            "(for example 2026-08-27T00:00:00Z)"
        )
    return parsed, None


def _seal_deadline_problems(
    info: TimestampInfo, *, deadline: datetime | None, not_after: str | None
) -> list[str]:
    """Compare when the index was sealed against the instant the recipient named."""
    if deadline is None:
        return []
    sealed_at = _parse_iso_utc(info.gen_time)
    if sealed_at is None:
        return ["index seal carries an unreadable generation time"]
    if sealed_at > deadline:
        return [
            f"index seal was minted at {info.gen_time}, after the {not_after} you "
            "supplied: this list of packets did not exist when the submission reached you"
        ]
    return []


def _parse_iso_utc(value: str) -> datetime | None:
    """Parse an ISO 8601 instant to an aware UTC datetime, or None if unusable.

    A bare date is read as midnight UTC and a naive instant as UTC, matching
    ``verify.py`` exactly: every time this project writes is UTC, and guessing a
    local zone would make the same submission pass in one country and fail in
    another.
    """
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


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


def _read_index_bytes(index_path: Path) -> bytes | None:
    """The exact index bytes, which are what a seal covers, or None."""
    try:
        return index_path.read_bytes()
    except OSError:
        return None


def _parse_index(raw: bytes | None) -> tuple[dict[str, JSONValue], list[str]]:
    """Parse the index, refusing anything this version cannot honestly read."""
    if raw is None:
        return {}, ["joint index could not be read"]
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
