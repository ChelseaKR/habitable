# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""The evidence engine: content fixity and an append-only chain of custody.

A photo is only as good as the answer to "how do we know it wasn't edited?" This
module provides the two answers habitable rests on:

* **Fixity.** :func:`verify_fixity` recomputes a sealed file's SHA-256 and refuses
  to proceed if it does not match what was recorded at capture.
* **Chain of custody.** :class:`CustodyLog` is an append-only, hash-linked log:
  each entry commits to the previous entry's hash, so any insertion, deletion, or
  reordering breaks the chain detectably.

Privacy note: each entry's hash binds a *salted commitment* to the actor, not the
actor in the clear. The exported (packet) form drops the actor and salt entirely,
so a recipient can confirm the chain is intact **without** learning who viewed or
copied an item. The clear identity stays in the union's vault.
"""

from __future__ import annotations

import base64
import os
from collections.abc import Mapping
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path

from .canonical import HASH_ALGORITHM, JSONValue, canonical_json, sha256_bytes, sha256_file
from .crypto import Identity, verify
from .errors import CustodyError, FixityError

__all__ = [
    "GENESIS_PREV_HASH",
    "CustodyAction",
    "CustodyEntry",
    "CustodyLog",
    "CustodyVerification",
    "ItemCustodySummary",
    "content_hash",
    "fixity_ok",
    "verify_fixity",
]

GENESIS_PREV_HASH = "0" * 64


class CustodyAction(StrEnum):
    """The kinds of events the chain of custody records about an item."""

    CAPTURED = "captured"
    IMPORTED = "imported"
    FIXITY_CHECKED = "fixity_checked"
    TIMESTAMPED = "timestamped"
    VIEWED = "viewed"
    COPIED_FOR_SHARING = "copied_for_sharing"
    INCLUDED_IN_PACKET = "included_in_packet"
    NOTE_ADDED = "note_added"


# --- content fixity -----------------------------------------------------------


def content_hash(path: Path) -> str:
    """The SHA-256 of a file's bytes (the content hash recorded at capture)."""
    return sha256_file(path)


def fixity_ok(path: Path, expected_hash: str) -> bool:
    """Return whether ``path`` still hashes to ``expected_hash``."""
    return sha256_file(path) == expected_hash


def verify_fixity(path: Path, expected_hash: str) -> None:
    """Raise :class:`FixityError` if ``path`` does not match ``expected_hash``."""
    actual = sha256_file(path)
    if actual != expected_hash:
        raise FixityError(
            f"fixity check failed for {path.name}: "
            f"expected {expected_hash[:12]}…, found {actual[:12]}…"
        )


# --- chain of custody ---------------------------------------------------------


def _actor_commitment(salt_hex: str, actor: str) -> str:
    """A preimage-resistant commitment to ``actor`` under a secret salt."""
    return sha256_bytes(f"{salt_hex}:{actor}".encode())


@dataclass(frozen=True, slots=True)
class CustodyEntry:
    """One link in the chain of custody.

    Public fields (exported in a packet) prove integrity; ``actor``/``actor_salt``/
    ``signature`` are vault-only and blank in the exported form.
    """

    seq: int
    action: str
    item_id: str
    hlc: str
    actor_commitment: str
    details: Mapping[str, str]
    prev_hash: str
    entry_hash: str
    actor: str = ""
    actor_salt: str = ""
    signature: str = ""

    def public_payload(self) -> dict[str, JSONValue]:
        """The exact structure the entry hash is taken over (no clear identity)."""
        return {
            "seq": self.seq,
            "action": self.action,
            "item_id": self.item_id,
            "hlc": self.hlc,
            "actor_commitment": self.actor_commitment,
            "details": {k: self.details[k] for k in sorted(self.details)},
            "prev_hash": self.prev_hash,
        }

    def recompute_hash(self) -> str:
        return sha256_bytes(canonical_json(self.public_payload()))

    def redacted(self) -> CustodyEntry:
        """Drop clear identity, salt, and signature — the form safe to export."""
        return replace(self, actor="", actor_salt="", signature="")

    def to_export_dict(self) -> dict[str, JSONValue]:
        payload = self.public_payload()
        payload["entry_hash"] = self.entry_hash
        return payload

    def to_vault_dict(self) -> dict[str, JSONValue]:
        payload = self.to_export_dict()
        payload["actor"] = self.actor
        payload["actor_salt"] = self.actor_salt
        payload["signature"] = self.signature
        return payload

    @classmethod
    def from_dict(cls, raw: Mapping[str, JSONValue]) -> CustodyEntry:
        details_raw = raw.get("details", {})
        if not isinstance(details_raw, dict):
            raise CustodyError("custody entry 'details' must be an object")
        details = {str(k): str(v) for k, v in details_raw.items()}
        return cls(
            seq=_int(raw, "seq"),
            action=_str(raw, "action"),
            item_id=_str(raw, "item_id"),
            hlc=_str(raw, "hlc"),
            actor_commitment=_str(raw, "actor_commitment"),
            details=details,
            prev_hash=_str(raw, "prev_hash"),
            entry_hash=_str(raw, "entry_hash"),
            actor=_str(raw, "actor", ""),
            actor_salt=_str(raw, "actor_salt", ""),
            signature=_str(raw, "signature", ""),
        )


@dataclass(frozen=True, slots=True)
class ItemCustodySummary:
    """A per-item digest of the chain (no identities)."""

    item_id: str
    entries: int
    last_action: str
    head_hash: str


@dataclass(frozen=True, slots=True)
class CustodyVerification:
    """The result of walking a chain of custody."""

    ok: bool
    length: int
    head_hash: str
    items: Mapping[str, ItemCustodySummary]
    signatures_checked: int = 0


class CustodyLog:
    """An append-only, hash-linked chain of custody for a case."""

    __slots__ = ("_entries",)

    def __init__(self, entries: list[CustodyEntry] | None = None) -> None:
        self._entries: list[CustodyEntry] = list(entries or [])

    @property
    def entries(self) -> tuple[CustodyEntry, ...]:
        return tuple(self._entries)

    @property
    def head_hash(self) -> str:
        return self._entries[-1].entry_hash if self._entries else GENESIS_PREV_HASH

    def __len__(self) -> int:
        return len(self._entries)

    def append(
        self,
        action: CustodyAction | str,
        item_id: str,
        *,
        actor: str,
        hlc: str,
        details: Mapping[str, str] | None = None,
        identity: Identity | None = None,
    ) -> CustodyEntry:
        """Append an entry, hash-linked to the current head."""
        salt_hex = os.urandom(16).hex()
        commitment = _actor_commitment(salt_hex, actor)
        skeleton = CustodyEntry(
            seq=len(self._entries) + 1,
            action=str(action),
            item_id=item_id,
            hlc=hlc,
            actor_commitment=commitment,
            details=dict(details or {}),
            prev_hash=self.head_hash,
            entry_hash="",
        )
        entry_hash = skeleton.recompute_hash()
        signature = ""
        if identity is not None:
            signature = base64.b64encode(identity.sign(entry_hash.encode("ascii"))).decode("ascii")
        entry = replace(
            skeleton,
            entry_hash=entry_hash,
            actor=actor,
            actor_salt=salt_hex,
            signature=signature,
        )
        self._entries.append(entry)
        return entry

    def verify(
        self, *, signer_keys: Mapping[str, bytes] | None = None
    ) -> CustodyVerification:
        """Walk the chain; raise :class:`CustodyError` on any break.

        If ``signer_keys`` maps an actor commitment to an Ed25519 public key, each
        signed entry is also signature-checked.
        """
        prev = GENESIS_PREV_HASH
        items: dict[str, ItemCustodySummary] = {}
        sigs_checked = 0
        for index, entry in enumerate(self._entries):
            expected_seq = index + 1
            if entry.seq != expected_seq:
                raise CustodyError(
                    f"custody chain out of order at position {index}: "
                    f"seq {entry.seq} (expected {expected_seq})"
                )
            if entry.prev_hash != prev:
                raise CustodyError(f"custody chain broken at seq {entry.seq}: prev_hash mismatch")
            if entry.recompute_hash() != entry.entry_hash:
                raise CustodyError(f"custody entry seq {entry.seq} has been altered")
            if signer_keys is not None and entry.signature:
                pub = signer_keys.get(entry.actor_commitment)
                if pub is not None:
                    sig = base64.b64decode(entry.signature)
                    if not verify(pub, entry.entry_hash.encode("ascii"), sig):
                        raise CustodyError(f"custody entry seq {entry.seq} signature invalid")
                    sigs_checked += 1
            prev = entry.entry_hash
            items[entry.item_id] = ItemCustodySummary(
                item_id=entry.item_id,
                entries=items[entry.item_id].entries + 1 if entry.item_id in items else 1,
                last_action=entry.action,
                head_hash=entry.entry_hash,
            )
        return CustodyVerification(
            ok=True,
            length=len(self._entries),
            head_hash=prev,
            items=items,
            signatures_checked=sigs_checked,
        )

    def integrity_proof(self) -> dict[str, JSONValue]:
        """A compact, identity-free proof that the chain is intact.

        Includes the redacted entries (which verify standalone) plus a summary, so
        a packet can demonstrate custody without exporting who did what.
        """
        verification = self.verify()
        return {
            "algorithm": HASH_ALGORITHM,
            "length": verification.length,
            "head_hash": verification.head_hash,
            "items": {
                item_id: {
                    "entries": summary.entries,
                    "last_action": summary.last_action,
                    "head_hash": summary.head_hash,
                }
                for item_id, summary in sorted(verification.items.items())
            },
            "entries": [entry.redacted().to_export_dict() for entry in self._entries],
        }

    # --- serialization --------------------------------------------------------

    def to_vault_records(self) -> list[dict[str, JSONValue]]:
        return [entry.to_vault_dict() for entry in self._entries]

    def to_export_records(self) -> list[dict[str, JSONValue]]:
        return [entry.redacted().to_export_dict() for entry in self._entries]

    @classmethod
    def from_records(cls, records: list[Mapping[str, JSONValue]]) -> CustodyLog:
        return cls([CustodyEntry.from_dict(record) for record in records])


# --- typed helpers ------------------------------------------------------------

_MISSING = object()


def _str(raw: Mapping[str, JSONValue], key: str, default: str | object = _MISSING) -> str:
    value = raw.get(key, default)
    if not isinstance(value, str):
        raise CustodyError(f"custody field {key!r} must be a string")
    return value


def _int(raw: Mapping[str, JSONValue], key: str) -> int:
    value = raw.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise CustodyError(f"custody field {key!r} must be an integer")
    return value
