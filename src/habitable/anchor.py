# SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0
# Copyright 2026 Chelsea Kelly-Reif
"""External anchoring: closing the hostile-keyholder gap (EXP-01).

``threat-model.md`` §5 is explicit about the sharpest limit of the chain of
custody: it is tamper-*evident*, not tamper-*proof*, against the person who holds
the vault key. A hostile keyholder can discard the whole local log and write a
new, internally-consistent one — and nothing in the log itself can tell a
recipient that happened, because the log is the only witness to its own history.

An **anchor** closes that gap by asking a party outside the vault to attest, at a
moment in time, "this exact exported custody-chain head hash existed." Concretely,
:func:`create_anchor` timestamps the same privacy-preserving custody proof head
that a packet exports: a 32-byte SHA-256 value over redacted entries whose HLCs
have been mapped to opaque per-case identifiers. That value reveals nothing about
case contents or raw device-clock/node metadata, and it is timestamped with one or
more trusted timestamp authorities, exactly the same mechanism already used to
timestamp capture content (:mod:`habitable.tsa`). Because the head hash commits
(via the hash chain) to every entry at or before it, a valid anchor is proof that
the *entire exported chain up to that point* existed by the anchor's time:
rewriting any of it afterward would produce a different head hash and no longer
match the anchor.

Anchoring cadence is a policy choice: anchoring after every capture is the
strongest guarantee but the most calls to a TSA; periodic anchoring (e.g. once
per session) is cheaper but widens the window in which an undetected rewrite
could occur. Either way, the exported packet carries every anchor recorded, and
the standalone verifier (:mod:`habitable.verify`) walks each one, checks it
against the custody chain it shipped with, and reports the bound from the most
recent (largest-coverage) verified anchor: "this chain provably existed by
`<time>`," through however many entries that anchor covers.

Licensing: this module is part of the Apache-2.0 verification subset (see
NOTICE) — :func:`verify_anchor_records` has no vault dependency, so a court or
legal-aid group can embed and redistribute anchor verification without the
AGPL reaching their code. :func:`create_anchor` (which needs a live vault and an
authority) is AGPL-only, same as the rest of the producer-side path.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, cast

from .canonical import JSONValue
from .errors import AnchorError
from .evidence import CustodyLog
from .tsa import TimestampAuthority, TimestampInfo, TimestampToken, verify_token

if TYPE_CHECKING:
    from cryptography import x509

    from .vault import Vault

__all__ = [
    "AnchorRecord",
    "AnchorVerdict",
    "create_anchor",
    "latest_anchor_bound",
    "verify_anchor_records",
]


@dataclass(frozen=True, slots=True)
class AnchorRecord:
    """One external anchor: a set of timestamps over a specific custody-chain head.

    ``chain_length`` is the number of custody entries committed to by
    ``head_hash`` at the moment of anchoring, so a verifier can locate exactly
    which entry the anchor covers even after later entries are appended.
    """

    head_hash: str
    chain_length: int
    created_at: str  # ISO 8601 UTC, the local clock's view (not itself trusted)
    tokens: tuple[TimestampToken, ...]

    def to_dict(self) -> dict[str, JSONValue]:
        return {
            "head_hash": self.head_hash,
            "chain_length": self.chain_length,
            "created_at": self.created_at,
            "tokens": cast(JSONValue, [token.to_dict() for token in self.tokens]),
        }

    @classmethod
    def from_dict(cls, raw: dict[str, JSONValue]) -> AnchorRecord:
        head_hash = raw.get("head_hash")
        chain_length = raw.get("chain_length")
        created_at = raw.get("created_at")
        tokens_raw = raw.get("tokens")
        if not isinstance(head_hash, str) or not head_hash:
            raise AnchorError("anchor record missing head_hash")
        if not isinstance(chain_length, int) or isinstance(chain_length, bool):
            raise AnchorError("anchor record missing integer chain_length")
        if not isinstance(created_at, str):
            raise AnchorError("anchor record missing created_at")
        if not isinstance(tokens_raw, list) or not tokens_raw:
            raise AnchorError("anchor record has no tokens")
        tokens = tuple(TimestampToken.from_dict(t) for t in tokens_raw if isinstance(t, dict))
        return cls(
            head_hash=head_hash, chain_length=chain_length, created_at=created_at, tokens=tokens
        )


@dataclass(frozen=True, slots=True)
class AnchorVerdict:
    """The result of checking one anchor record against a custody chain."""

    record: AnchorRecord
    chain_matches: bool  # the recorded head_hash matches the chain at chain_length
    verified_infos: tuple[TimestampInfo, ...]  # one per token that verified
    problems: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return self.chain_matches and bool(self.verified_infos)

    @property
    def earliest_gen_time(self) -> str:
        """The earliest verified timestamp covering this anchor (empty if none)."""
        times = sorted(info.gen_time for info in self.verified_infos)
        return times[0] if times else ""


def create_anchor(
    vault: Vault,
    tsas: Sequence[TimestampAuthority],
    *,
    now: str | None = None,
) -> AnchorRecord:
    """Timestamp the vault's current export-safe custody-chain head with each authority.

    Raises :class:`AnchorError` if the chain is empty (nothing to anchor yet) or
    no authority is given. The record is appended to the vault's anchor store —
    callers are responsible for calling this before export so the anchor ships
    inside the packet.
    """
    if not tsas:
        raise AnchorError("no timestamp authority configured for anchoring")
    chain_length = len(vault.custody)
    if chain_length == 0:
        raise AnchorError("custody chain is empty — nothing to anchor yet")
    head_hash = _exported_custody_head_hash(vault)
    tokens = tuple(tsa.stamp(head_hash) for tsa in tsas)
    record = AnchorRecord(
        head_hash=head_hash,
        chain_length=chain_length,
        created_at=now or _now_iso(),
        tokens=tokens,
    )
    vault.add_anchor(record)
    return record


def _exported_custody_head_hash(vault: Vault) -> str:
    proof = vault.custody.integrity_proof(hlc_map=lambda raw: vault.document.opaque_id("hlc", raw))
    head_hash = proof.get("head_hash")
    if not isinstance(head_hash, str):
        raise AnchorError("could not compute export-safe custody head")
    return head_hash


def verify_anchor_records(
    records: Sequence[AnchorRecord],
    custody: CustodyLog,
    *,
    trusted_certs: list[x509.Certificate] | None = None,
) -> list[AnchorVerdict]:
    """Check each anchor record against ``custody`` and its own tokens.

    An anchor is only trusted if *both* hold: the head hash it committed to
    matches the actual entry at ``chain_length`` in the shipped chain (so the
    anchor cannot be swapped for one over a different, more convenient chain),
    and at least one of its tokens verifies against that hash.
    """
    entries = custody.entries
    verdicts: list[AnchorVerdict] = []
    for record in records:
        problems: list[str] = []
        chain_matches = False
        if record.chain_length < 1:
            problems.append("anchor covers an empty chain")
        elif record.chain_length > len(entries):
            problems.append(
                f"anchor covers {record.chain_length} entries but the packet has only "
                f"{len(entries)}"
            )
        elif entries[record.chain_length - 1].entry_hash != record.head_hash:
            problems.append("anchor head_hash does not match the custody chain at that length")
        else:
            chain_matches = True

        verified: list[TimestampInfo] = []
        for token in record.tokens:
            try:
                verified.append(verify_token(token, record.head_hash, trusted_certs=trusted_certs))
            except Exception as exc:
                problems.append(f"anchor token from {token.tsa_name!r} failed: {exc}")
        verdicts.append(
            AnchorVerdict(
                record=record,
                chain_matches=chain_matches,
                verified_infos=tuple(verified),
                problems=tuple(problems),
            )
        )
    return verdicts


def latest_anchor_bound(verdicts: Sequence[AnchorVerdict]) -> tuple[str, int]:
    """The tightest available "this chain provably existed by" bound.

    Per threat-model.md §5/§6, anchoring mitigates the hostile-keyholder gap "for
    events before the last anchor" — so the useful bound comes from the *most
    recent* (largest ``chain_length``) anchor that both matches the shipped chain
    and has at least one verified token, using the earliest gen_time among that
    anchor's own (possibly redundant, multi-TSA) tokens. Returns
    ``(gen_time, chain_length)``, or ``("", 0)`` if no anchor verified.
    """
    ok = [v for v in verdicts if v.ok]
    if not ok:
        return "", 0
    best = max(ok, key=lambda v: v.record.chain_length)
    return best.earliest_gen_time, best.record.chain_length


def _now_iso() -> str:
    return datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
