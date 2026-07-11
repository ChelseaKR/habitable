# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""The encrypted case vault: everything on the device, nothing readable off it.

A vault is a directory holding one case. Sealed originals, the CRDT document, the
chain of custody, the device identity, and the deferred-timestamp queue are all
encrypted at rest under a data key that is itself wrapped by the user's
passphrase. The only plaintext is ``config.toml`` (committed policy, no secrets)
and ``keyfile.json`` (the passphrase-wrapped data key).

Reading a sealed original always re-checks its fixity, so corruption or tampering
surfaces as an error rather than a quietly altered exhibit.
"""

from __future__ import annotations

import json
import re
import secrets
import tomllib
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .canonical import JSONValue, canonical_json, sha256_bytes
from .clock import HybridLogicalClock, wall_clock_ms
from .config import Config, default_config_toml
from .crypto import (
    Identity,
    PublicIdentity,
    SymmetricKey,
    create_keyfile,
    export_recovery_blob,
    harden_keyfile,
    import_recovery_blob,
    open_keyfile,
)
from .errors import FixityError, VaultError
from .evidence import CustodyAction, CustodyLog
from .model import CaseDocument
from .syncstate import PeerAuthorization
from .threshold import create_recovery_bundle, recover_dek
from .tsa import TimestampToken

__all__ = ["CaptureSize", "DeferredItem", "StorageFootprint", "Vault", "human_bytes"]

_CONFIG = "config.toml"
_KEYFILE = "keyfile.json"
_CASE = "case.enc"
_CUSTODY = "custody.enc"
_IDENTITY = "identity.enc"
_NODE = "node.enc"
_DEFERRED = "deferred.enc"
_ORIGINALS = "originals"
_TOKENS = "tokens"
# Local-only record of which captures each sync peer has already confirmed holding
# (FIX-02: incremental sync deltas). Never merged via the CRDT and never exported —
# it is purely an optimization so a later ``sync.export_message`` can skip re-sending
# sealed originals a peer already told us they have.
_PEER_HAVE = "peer_have.enc"
# Pairing keys, exact allowlisted identities, replay ids, receipts, and imported
# source-custody proofs. This is encrypted local policy state, never CRDT-merged.
_SYNC_SECURITY = "sync_security.enc"

# Pre-FIX-01 vaults wrote the device node_id into plaintext config.toml; this
# matches that line so a legacy vault can be migrated (the value moves into the
# encrypted vault and the plaintext line is stripped) on first open.
_LEGACY_NODE_ID_LINE = re.compile(r"^\s*node_id\s*=")


@dataclass(frozen=True, slots=True)
class DeferredItem:
    """A capture awaiting a timestamp token (created while offline)."""

    capture_id: str
    digest: str


@dataclass(frozen=True, slots=True)
class CaptureSize:
    """The on-disk cost of one capture's sealed original."""

    capture_id: str
    sealed_bytes: int


@dataclass(frozen=True, slots=True)
class StorageFootprint:
    """How much space a case occupies on the device, and why (item R-03).

    A sealed original is kept twice by design: the encrypted original stays in
    the vault forever, and a location-stripped *shared copy* of roughly the same
    size is produced whenever the case is exported. Surfacing both — plus the
    small metadata overhead — lets a tenant on a low-end device budget honestly
    instead of being surprised by the doubling.
    """

    sealed_originals_bytes: int
    shared_copies_bytes: int
    metadata_bytes: int
    total_bytes: int
    per_capture: tuple[CaptureSize, ...]


def human_bytes(count: int) -> str:
    """A short, human-readable size using decimal (SI) units: ``6100000`` → ``6.1 MB``."""
    if count < 1000:
        return f"{count} bytes"
    size = float(count)
    for unit in ("KB", "MB", "GB", "TB"):
        size /= 1000.0
        if size < 1000.0:
            return f"{size:.1f} {unit}"
    return f"{size:.1f} PB"


class Vault:
    """An open (unlocked) case vault."""

    def __init__(
        self,
        path: Path,
        config: Config,
        dek: SymmetricKey,
        identity: Identity,
        document: CaseDocument,
        custody: CustodyLog,
        deferred: list[DeferredItem],
        peer_have: Mapping[str, Iterable[str]] | None = None,
        sync_peers: Mapping[str, PeerAuthorization] | None = None,
    ) -> None:
        self.path = path
        self.config = config
        self._dek = dek
        self.identity = identity
        self.document = document
        self.custody = custody
        self._deferred = deferred
        self._peer_have: dict[str, set[str]] = {
            fingerprint: set(capture_ids) for fingerprint, capture_ids in (peer_have or {}).items()
        }
        self._sync_peers = dict(sync_peers or {})

    # --- lifecycle ------------------------------------------------------------

    @classmethod
    def create(
        cls,
        path: Path,
        passphrase: str,
        *,
        case_id: str,
        unit: str = "",
        building: str = "",
        language: str = "en",
        time_source: Callable[[], int] = wall_clock_ms,
    ) -> Vault:
        """Initialize a brand-new encrypted vault at ``path``."""
        if (path / _KEYFILE).exists():
            raise VaultError(f"a vault already exists at {path}")
        path.mkdir(parents=True, exist_ok=True)
        (path / _ORIGINALS).mkdir(exist_ok=True)
        (path / _TOKENS).mkdir(exist_ok=True)

        # A random, passphrase-independent device id. Deriving it from the
        # passphrase (as pre-FIX-01 did) made the passphrase offline-brute-forceable
        # from plaintext config.toml and from every exported packet id; a random id
        # severs that link. It is stored *inside* the encrypted vault, never in
        # plaintext, and is stable for the life of the vault (it tiebreaks the clock).
        node_id = secrets.token_hex(8)
        config = Config.default(language=language)
        (path / _CONFIG).write_text(default_config_toml(language=language), encoding="utf-8")

        keyfile, dek = create_keyfile(passphrase)
        (path / _KEYFILE).write_text(keyfile, encoding="utf-8")

        identity = Identity.generate()
        clock = HybridLogicalClock(node_id, time_source=time_source)
        document = CaseDocument(case_id, clock, identity=identity)
        document.ensure_case_salt()  # so exported ids are opaque from the first mint
        if unit:
            document.set_meta("unit", unit)
        if building:
            document.set_meta("building", building)
        vault = cls(path, config, dek, identity, document, CustodyLog(), [])
        vault._write_blob(_IDENTITY, identity.serialize())
        vault._write_blob(_NODE, canonical_json({"node_id": node_id}))
        vault.save()
        return vault

    @classmethod
    def open(
        cls,
        path: Path,
        passphrase: str,
        *,
        time_source: Callable[[], int] = wall_clock_ms,
    ) -> Vault:
        """Open and decrypt an existing vault."""
        keyfile_path = path / _KEYFILE
        if not keyfile_path.exists():
            raise VaultError(f"no vault at {path}")
        config = Config.from_toml(path / _CONFIG)
        dek = open_keyfile(keyfile_path.read_text(encoding="utf-8"), passphrase)

        identity = Identity.deserialize(_read_blob(path, dek, _IDENTITY))
        node_id = _load_node_id(path, dek)
        clock = HybridLogicalClock(node_id, time_source=time_source)
        case_state = _decode_json(_read_blob(path, dek, _CASE))
        if not isinstance(case_state, dict):
            raise VaultError("corrupt case state")
        document = CaseDocument.from_state(case_state, clock)
        document.set_identity(identity)
        document.catch_up_clock()

        custody_records = _decode_json(_read_blob(path, dek, _CUSTODY))
        custody = CustodyLog.from_records(_as_record_list(custody_records))

        deferred_raw = _decode_json(_read_blob(path, dek, _DEFERRED))
        deferred = [
            DeferredItem(capture_id=str(item["capture_id"]), digest=str(item["digest"]))
            for item in _as_record_list(deferred_raw)
        ]
        peer_have = _load_peer_have(path, dek)
        sync_peers = _load_sync_peers(path, dek)
        return cls(
            path,
            config,
            dek,
            identity,
            document,
            custody,
            deferred,
            peer_have,
            sync_peers,
        )

    # --- key management -------------------------------------------------------

    def add_timeline_event(
        self,
        issue_id: str,
        *,
        event_type: str,
        text: str,
        occurred_at: str,
        source: str,
        other_label: str = "",
        source_detail: str = "",
        capture_ids: tuple[str, ...] = (),
        notice_entry_id: str = "",
        receipt_entry_id: str = "",
        response_entry_id: str = "",
    ) -> str:
        """Record, custody-bind, and persist one Timeline 2.0 event.

        The immutable event is committed into a ``note_added`` custody entry at
        creation time.  That custody entry is Ed25519-signed inside the vault; a
        packet-v3 export redacts the actor and signs the whole bundle while keeping
        the commitment independently checkable.
        """
        entry_id = self.document.add_timeline_event(
            issue_id,
            event_type=event_type,
            text=text,
            occurred_at=occurred_at,
            source=source,
            other_label=other_label,
            source_detail=source_detail,
            capture_ids=capture_ids,
            notice_entry_id=notice_entry_id,
            receipt_entry_id=receipt_entry_id,
            response_entry_id=response_entry_id,
        )
        if event_type == "recurrence":
            self.document.update_issue(issue_id, status="open")
        entry = next(item for item in self.document.timeline() if item.entry_id == entry_id)
        self._append_timeline_binding(entry_id, entry.commitment(), stage="recorded")
        self.save()
        return entry_id

    def ensure_timeline_custody(self, *, persist: bool = True) -> None:
        """Backfill honest custody bindings before a packet-v3 export.

        Old case states had no timeline custody event.  The backfill does not claim
        otherwise: its exported binding carries ``stage=migration``.  New events
        written through :meth:`add_timeline_event` already have ``stage=recorded``
        and are left untouched, making repeat exports idempotent.

        Packet staging passes ``persist=False`` so its atomic publish wrapper owns
        the save/rollback boundary; direct callers retain the safe persisted default.
        """
        changed = False
        for entry in self.document.timeline():
            commitment = entry.commitment()
            binding_stage = self.timeline_binding_stage(entry.entry_id, commitment)
            valid_stages = {"migration"} if entry.schema_version < 2 else {"recorded", "backfill"}
            if binding_stage in valid_stages:
                continue
            stage = "migration" if entry.schema_version < 2 else "backfill"
            self._append_timeline_binding(entry.entry_id, commitment, stage=stage)
            changed = True
        if changed and persist:
            self.save()

    def timeline_binding_stage(self, entry_id: str, commitment: str) -> str:
        """Return the stage of a matching custody commitment, or ``""``."""
        for custody_entry in reversed(self.custody.entries):
            stage = custody_entry.details.get("stage", "")
            if (
                custody_entry.action == CustodyAction.NOTE_ADDED
                and custody_entry.item_id == entry_id
                and custody_entry.details.get("timeline_schema") == "2"
                and custody_entry.details.get("timeline_sha256") == commitment
                and stage in {"recorded", "backfill", "migration"}
            ):
                return stage
        return ""

    def _append_timeline_binding(self, entry_id: str, commitment: str, *, stage: str) -> None:
        actor = self.identity.public().fingerprint
        self.custody.append(
            CustodyAction.NOTE_ADDED,
            entry_id,
            actor=actor,
            hlc=self.document.clock.now().encode(),
            details={
                "timeline_schema": "2",
                "timeline_sha256": commitment,
                "stage": stage,
            },
            identity=self.identity,
        )

    def rotate_passphrase(self, new_passphrase: str) -> None:
        """Re-wrap the in-memory data key under a new passphrase.

        Cheap by design: the bulk data is never re-encrypted — only the small
        passphrase-wrapped key is replaced.
        """
        (self.path / _KEYFILE).write_text(
            export_recovery_blob(self._dek, new_passphrase), encoding="utf-8"
        )

    def harden_key(self, passphrase: str, *, profile: str = "hardened") -> None:
        """Re-derive the KEK at a stronger KDF cost profile (FIX-08's `key harden`).

        Same DEK, same passphrase -- only the KDF cost that protects the keyfile
        against offline brute force goes up. Cheap by design (only the small wrapped
        key is rewritten), but every future unlock pays the new profile's cost. See
        ``KDF_PROFILES`` in :mod:`habitable.crypto` and docs/crypto-spec.md sec 3.1.
        """
        (self.path / _KEYFILE).write_text(
            harden_keyfile(self._dek, passphrase, profile=profile), encoding="utf-8"
        )

    def rotate_dek(self, passphrase: str) -> None:
        """Generate a fresh data key and re-encrypt every blob and sealed original under it.

        Unlike :meth:`rotate_passphrase` (which only re-wraps the *same* DEK), this
        replaces the key itself -- the correct remedy when the DEK, not just the
        passphrase, is suspected compromised. Expensive (touches every encrypted blob
        and every sealed original) but bounded and rare.

        Every sealed original is decrypted and its fixity re-checked against the
        content_hash already recorded in the case document (via :meth:`read_original`)
        before it is re-sealed under the new key, so silent corruption cannot ride
        along into the re-encryption. All of that slow work happens *before* any file
        on disk is touched: each new-key ciphertext is first staged next to its
        original as a ``*.new`` sibling, and only once every one of them has been
        written does a final pass swap them into place with a same-filesystem rename
        (an atomic operation per file). A crash during the slow staging phase leaves
        the old, still-valid vault completely untouched. A crash during the brief swap
        phase (fast metadata-only renames, no cryptography) could leave a partially
        migrated vault whose ``*.new`` leftovers make manual recovery possible -- an
        accepted, documented tradeoff (see docs/crypto-spec.md sec 7) rather than a
        full transactional guarantee.
        """
        new_dek = SymmetricKey.generate()
        staged: list[tuple[Path, Path]] = []
        try:
            originals_dir = self.path / _ORIGINALS
            for cap in self.document.captures():
                sealed = originals_dir / cap.sealed_name
                if not cap.sealed_name or not sealed.exists():
                    continue
                raw = self.read_original(cap.capture_id, cap.content_hash)
                aad = f"original:{cap.capture_id}:{cap.content_hash}".encode()
                dest = sealed.with_name(sealed.name + ".new")
                dest.write_bytes(new_dek.encrypt(raw, aad=aad))
                staged.append((sealed, dest))

            for name, plaintext in self._blob_plaintexts():
                final = self.path / name
                dest = final.with_name(final.name + ".new")
                dest.write_bytes(new_dek.encrypt(plaintext, aad=name.encode()))
                staged.append((final, dest))

            keyfile_final = self.path / _KEYFILE
            keyfile_dest = keyfile_final.with_name(keyfile_final.name + ".new")
            keyfile_dest.write_text(export_recovery_blob(new_dek, passphrase), encoding="utf-8")
            staged.append((keyfile_final, keyfile_dest))

            for final, dest in staged:
                dest.replace(final)
        except BaseException:
            for _final, dest in staged:
                dest.unlink(missing_ok=True)
            raise

        self._dek = new_dek

    def _blob_plaintexts(self) -> list[tuple[str, bytes]]:
        """Plaintext contents of every non-original encrypted blob (for DEK rotation)."""
        deferred_json: JSONValue = [
            {"capture_id": item.capture_id, "digest": item.digest} for item in self._deferred
        ]
        peer_have_json: JSONValue = {
            fingerprint: cast(JSONValue, sorted(capture_ids))
            for fingerprint, capture_ids in self._peer_have.items()
        }
        sync_security_json: JSONValue = {
            fingerprint: peer.to_json() for fingerprint, peer in sorted(self._sync_peers.items())
        }
        return [
            (_CASE, canonical_json(self.document.to_state())),
            (_CUSTODY, canonical_json(_records_to_json(self.custody.to_vault_records()))),
            (_DEFERRED, canonical_json(deferred_json)),
            (_IDENTITY, self.identity.serialize()),
            (_NODE, canonical_json({"node_id": self.document.clock.node_id})),
            (_PEER_HAVE, canonical_json(peer_have_json)),
            (_SYNC_SECURITY, canonical_json(sync_security_json)),
        ]

    def export_recovery(self, recovery_passphrase: str) -> str:
        """Return an encrypted recovery backup of the data key.

        Store this somewhere safe and separate. With it (and its passphrase) the
        vault can be reopened even if the main passphrase is lost; without any
        backup, a lost passphrase means the data is unrecoverable — by design.
        """
        return export_recovery_blob(self._dek, recovery_passphrase)

    @staticmethod
    def restore_keyfile(
        path: Path, recovery_blob: str, recovery_passphrase: str, new_passphrase: str
    ) -> None:
        """Rebuild a vault's keyfile from a recovery backup, under a new passphrase."""
        dek = import_recovery_blob(recovery_blob, recovery_passphrase)
        (path / _KEYFILE).write_text(export_recovery_blob(dek, new_passphrase), encoding="utf-8")

    def export_social_shares(
        self, threshold: int, stewards: Sequence[str]
    ) -> tuple[str, list[str]]:
        """Split recovery custody so any ``threshold`` of ``stewards`` can recover (EXP-11).

        Returns ``(bundle_json, [share_json, ...])`` — one share per steward. No
        single steward can reconstruct the data key; any ``threshold`` of them
        can, together with the (non-secret) bundle. This makes distributed
        custody cryptographic rather than a matter of social convention, so no
        one custodian is the honeypot. Store shares apart, held by different
        people.
        """
        return create_recovery_bundle(self._dek, threshold, stewards)

    @staticmethod
    def restore_from_shares(
        path: Path, bundle_blob: str, share_blobs: Sequence[str], new_passphrase: str
    ) -> None:
        """Rebuild a vault's keyfile from a recovery bundle and a quorum of shares (EXP-11)."""
        dek = recover_dek(bundle_blob, share_blobs)
        (path / _KEYFILE).write_text(export_recovery_blob(dek, new_passphrase), encoding="utf-8")

    def save(self) -> None:
        """Persist document, custody, deferred work, inventory, and sync trust state."""
        self._write_blob(_CASE, canonical_json(self.document.to_state()))
        self._write_blob(
            _CUSTODY, canonical_json(_records_to_json(self.custody.to_vault_records()))
        )
        deferred_json: JSONValue = [
            {"capture_id": item.capture_id, "digest": item.digest} for item in self._deferred
        ]
        self._write_blob(_DEFERRED, canonical_json(deferred_json))
        peer_have_json: JSONValue = {
            fingerprint: cast(JSONValue, sorted(capture_ids))
            for fingerprint, capture_ids in self._peer_have.items()
        }
        self._write_blob(_PEER_HAVE, canonical_json(peer_have_json))

        sync_security_json: JSONValue = {
            fingerprint: peer.to_json() for fingerprint, peer in sorted(self._sync_peers.items())
        }
        self._write_blob(_SYNC_SECURITY, canonical_json(sync_security_json))

    # --- authenticated sync peers --------------------------------------------

    def authorize_sync_peer(
        self,
        identity: PublicIdentity,
        pairing_id: str,
        key: bytes,
        *,
        replace: bool = False,
    ) -> None:
        """Allowlist one exact identity under authenticated pairing material.

        Replacing an existing pairing is never implicit: the invitation issuer
        must explicitly request replacement, while accepting a stale invitation
        fails closed instead of rolling a newer key back.
        """
        if len(key) != 32 or not pairing_id:
            raise VaultError("invalid sync pairing material")
        fingerprint = identity.fingerprint
        existing = self._sync_peers.get(fingerprint)
        if existing is not None:
            same = (
                existing.identity == identity.encode()
                and existing.pairing_id == pairing_id
                and existing.key == key
            )
            if same:
                return
            if not replace:
                raise VaultError(
                    f"peer {fingerprint} is already paired; create a fresh pairing explicitly"
                )
        self._sync_peers[fingerprint] = PeerAuthorization(
            identity=identity.encode(), pairing_id=pairing_id, key=key
        )

    def sync_peer(self, identity: PublicIdentity) -> PeerAuthorization | None:
        """Return the authorization only when the complete identity matches."""
        peer = self._sync_peers.get(identity.fingerprint)
        if peer is None or peer.identity != identity.encode():
            return None
        return peer

    def sync_peer_by_fingerprint(self, fingerprint: str) -> PeerAuthorization | None:
        """Return an allowlisted peer by fingerprint (callers still check full identity)."""
        return self._sync_peers.get(fingerprint)

    def record_sync_message_sent(
        self, identity: PublicIdentity, message_id: str, message_digest: str
    ) -> None:
        peer = self.sync_peer(identity)
        if peer is None:
            raise VaultError("cannot record a message for an unauthorized peer")
        peer.sent_messages[message_id] = message_digest

    def has_seen_sync_message(self, identity: PublicIdentity, message_id: str) -> bool:
        peer = self.sync_peer(identity)
        return peer is not None and message_id in peer.seen_message_ids

    def mark_sync_message_seen(self, identity: PublicIdentity, message_id: str) -> None:
        peer = self.sync_peer(identity)
        if peer is None:
            raise VaultError("cannot record replay state for an unauthorized peer")
        peer.seen_message_ids.add(message_id)

    def queue_sync_receipt(
        self, identity: PublicIdentity, message_id: str, receipt: dict[str, JSONValue]
    ) -> None:
        peer = self.sync_peer(identity)
        if peer is None:
            raise VaultError("cannot queue a receipt for an unauthorized peer")
        peer.pending_receipts[message_id] = receipt

    def pending_sync_receipts(self, identity: PublicIdentity) -> tuple[dict[str, JSONValue], ...]:
        peer = self.sync_peer(identity)
        if peer is None:
            return ()
        return tuple(peer.pending_receipts[key] for key in sorted(peer.pending_receipts))

    def record_verified_sync_receipt(
        self, identity: PublicIdentity, message_id: str, receipt: dict[str, JSONValue]
    ) -> None:
        peer = self.sync_peer(identity)
        if peer is None:
            raise VaultError("cannot record a receipt from an unauthorized peer")
        peer.verified_receipts[message_id] = receipt

    def verified_sync_receipt(
        self, identity: PublicIdentity, message_id: str
    ) -> Mapping[str, JSONValue] | None:
        peer = self.sync_peer(identity)
        return None if peer is None else peer.verified_receipts.get(message_id)

    def sent_sync_message_digest(self, identity: PublicIdentity, message_id: str) -> str | None:
        peer = self.sync_peer(identity)
        return None if peer is None else peer.sent_messages.get(message_id)

    def record_source_custody(
        self, identity: PublicIdentity, capture_id: str, proof: dict[str, JSONValue]
    ) -> None:
        peer = self.sync_peer(identity)
        if peer is None:
            raise VaultError("cannot record source custody from an unauthorized peer")
        proof_id = sha256_bytes(canonical_json(proof))
        peer.source_custody_proofs[proof_id] = proof
        peer.capture_custody[capture_id] = proof_id

    def source_custody(
        self, identity: PublicIdentity, capture_id: str
    ) -> Mapping[str, JSONValue] | None:
        peer = self.sync_peer(identity)
        if peer is None:
            return None
        proof_id = peer.capture_custody.get(capture_id)
        return None if proof_id is None else peer.source_custody_proofs.get(proof_id)

    # --- sync peer inventory (FIX-02) ------------------------------------------

    def known_peer_captures(self, peer_fingerprint: str) -> frozenset[str]:
        """Capture ids ``peer_fingerprint`` has previously told us it already holds.

        Used by :func:`habitable.sync.export_message` to skip re-sending a sealed
        original the recipient already confirmed having, instead of re-embedding
        every capture on every sync exchange.
        """
        return frozenset(self._peer_have.get(peer_fingerprint, ()))

    def record_peer_captures(self, peer_fingerprint: str, capture_ids: Iterable[str]) -> None:
        """Remember that ``peer_fingerprint`` holds ``capture_ids`` (additive, never shrinks).

        Called on import with the sender's own declared inventory (from the sealed
        "have" manifest), never from anything a relay or third party could see.
        """
        self._peer_have.setdefault(peer_fingerprint, set()).update(capture_ids)

    # --- sealed originals -----------------------------------------------------

    def seal_original(self, capture_id: str, source: Path, content_hash: str) -> str:
        """Encrypt and store an original's bytes immutably; return the sealed name."""
        raw = source.read_bytes()
        if sha256_bytes(raw) != content_hash:
            raise FixityError(f"source {source.name} changed during capture")
        return self.store_original_bytes(capture_id, raw, content_hash)

    def store_original_bytes(self, capture_id: str, raw: bytes, content_hash: str) -> str:
        """Seal already-in-memory original bytes (e.g. received over sync)."""
        if sha256_bytes(raw) != content_hash:
            raise FixityError(f"received bytes for {capture_id} do not match content hash")
        sealed_name = f"{capture_id}.enc"
        aad = f"original:{capture_id}:{content_hash}".encode()
        (self.path / _ORIGINALS / sealed_name).write_bytes(self._dek.encrypt(raw, aad=aad))
        return sealed_name

    def has_original(self, capture_id: str) -> bool:
        return (self.path / _ORIGINALS / f"{capture_id}.enc").exists()

    def read_original(self, capture_id: str, content_hash: str) -> bytes:
        """Decrypt a sealed original and re-verify its fixity before returning it."""
        sealed = self.path / _ORIGINALS / f"{capture_id}.enc"
        if not sealed.exists():
            raise VaultError(f"sealed original missing for {capture_id}")
        aad = f"original:{capture_id}:{content_hash}".encode()
        raw = self._dek.decrypt(sealed.read_bytes(), aad=aad)
        if sha256_bytes(raw) != content_hash:
            raise FixityError(f"sealed original for {capture_id} failed fixity on read")
        return raw

    # --- storage footprint (R-03) ---------------------------------------------

    def storage_footprint(self) -> StorageFootprint:
        """Measure the case's on-device storage, distinguishing kept-twice copies.

        Sealed originals live under ``originals/`` (one ``.enc`` per capture);
        everything else in the vault (encrypted state blobs, tokens, config, the
        keyfile) is counted as metadata. The *shared copies* line reports the
        by-design doubling: each sealed original is copied again, at roughly the
        same size, into any exported packet, so a with-originals export needs
        about twice the sealed-originals space. Reporting it up front keeps the
        footprint honest on low-end devices.
        """
        originals_dir = self.path / _ORIGINALS
        per_capture: list[CaptureSize] = []
        sealed = 0
        if originals_dir.is_dir():
            for entry in sorted(originals_dir.iterdir()):
                if entry.is_file() and entry.suffix == ".enc":
                    size = entry.stat().st_size
                    sealed += size
                    per_capture.append(CaptureSize(capture_id=entry.stem, sealed_bytes=size))
        on_disk = sum(f.stat().st_size for f in self.path.rglob("*") if f.is_file())
        metadata = on_disk - sealed
        shared = sealed  # the shareable copy kept (by design) once the case is exported
        return StorageFootprint(
            sealed_originals_bytes=sealed,
            shared_copies_bytes=shared,
            metadata_bytes=metadata,
            total_bytes=sealed + shared + metadata,
            per_capture=tuple(per_capture),
        )

    # --- timestamp tokens -----------------------------------------------------

    def store_token(self, capture_id: str, token: TimestampToken) -> None:
        path = self.path / _TOKENS / f"{capture_id}.json"
        path.write_text(json.dumps(token.to_dict(), indent=2, sort_keys=True), encoding="utf-8")

    def get_token(self, capture_id: str) -> TimestampToken | None:
        path = self.path / _TOKENS / f"{capture_id}.json"
        if not path.exists():
            return None
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise VaultError(f"corrupt token record for {capture_id}")
        return TimestampToken.from_dict(raw)

    def add_additional_token(self, capture_id: str, token: TimestampToken) -> None:
        """Append a redundant primary timestamp from another authority.

        Unlike an archive token (which chains *over* the primary token), an additional
        token is an independent RFC 3161 token over the same content hash, so the proof
        does not rest on a single authority (see docs/research, item R-16)."""
        path = self.path / _TOKENS / f"{capture_id}.additional.json"
        existing = json.loads(path.read_text(encoding="utf-8")) if path.exists() else []
        if not isinstance(existing, list):
            raise VaultError(f"corrupt additional-token record for {capture_id}")
        existing.append(token.to_dict())
        path.write_text(json.dumps(existing, indent=2, sort_keys=True), encoding="utf-8")

    def get_additional_tokens(self, capture_id: str) -> list[TimestampToken]:
        path = self.path / _TOKENS / f"{capture_id}.additional.json"
        if not path.exists():
            return []
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, list):
            raise VaultError(f"corrupt additional-token record for {capture_id}")
        return [TimestampToken.from_dict(item) for item in raw if isinstance(item, dict)]

    def add_archive_token(self, capture_id: str, token: TimestampToken) -> None:
        """Append an archive (re-)timestamp for a capture."""
        path = self.path / _TOKENS / f"{capture_id}.archive.json"
        existing = json.loads(path.read_text(encoding="utf-8")) if path.exists() else []
        if not isinstance(existing, list):
            raise VaultError(f"corrupt archive-token record for {capture_id}")
        existing.append(token.to_dict())
        path.write_text(json.dumps(existing, indent=2, sort_keys=True), encoding="utf-8")

    def get_archive_tokens(self, capture_id: str) -> list[TimestampToken]:
        path = self.path / _TOKENS / f"{capture_id}.archive.json"
        if not path.exists():
            return []
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, list):
            raise VaultError(f"corrupt archive-token record for {capture_id}")
        return [TimestampToken.from_dict(item) for item in raw if isinstance(item, dict)]

    def latest_token(self, capture_id: str) -> TimestampToken | None:
        """The most recent token for a capture (the last archive, else the primary)."""
        archives = self.get_archive_tokens(capture_id)
        return archives[-1] if archives else self.get_token(capture_id)

    # --- deferred-timestamp queue ---------------------------------------------

    def queue_deferred(self, capture_id: str, digest: str) -> None:
        self._deferred.append(DeferredItem(capture_id=capture_id, digest=digest))

    def deferred(self) -> tuple[DeferredItem, ...]:
        return tuple(self._deferred)

    def clear_deferred(self, capture_id: str) -> None:
        self._deferred = [item for item in self._deferred if item.capture_id != capture_id]

    # --- internals ------------------------------------------------------------

    def _write_blob(self, name: str, plaintext: bytes) -> None:
        (self.path / name).write_bytes(self._dek.encrypt(plaintext, aad=name.encode()))


def _read_blob(path: Path, dek: SymmetricKey, name: str) -> bytes:
    blob_path = path / name
    if not blob_path.exists():
        raise VaultError(f"vault file missing: {name}")
    return dek.decrypt(blob_path.read_bytes(), aad=name.encode())


def _load_node_id(path: Path, dek: SymmetricKey) -> str:
    """Return the vault's device node_id, migrating a pre-FIX-01 vault if needed.

    Current vaults store the node_id in an encrypted blob. A pre-FIX-01 vault kept
    it in plaintext ``config.toml`` (derived from the passphrase); on first open we
    move that value — unchanged, so existing packet ids stay stable and the
    append-only custody chain is untouched — into the encrypted store and strip it
    from the plaintext file. The value itself is legacy and cannot be un-leaked from
    ids already exported; new vaults never had the leak.
    """
    if (path / _NODE).exists():
        record = _decode_json(_read_blob(path, dek, _NODE))
        node_id = record.get("node_id") if isinstance(record, dict) else None
        if isinstance(node_id, str) and node_id:
            # A migration interrupted between writing the encrypted blob and
            # stripping the plaintext line would otherwise leave the leaked,
            # passphrase-derived value in config.toml forever (this branch
            # returns early on every later open). Re-strip: a no-op on healthy
            # vaults, the missing half of the migration on interrupted ones.
            _strip_plaintext_node_id(path / _CONFIG)
            return node_id
        raise VaultError("corrupt node identity record")

    legacy = _legacy_node_id(path / _CONFIG)
    if legacy is None:
        raise VaultError("vault has no device node identity and no legacy value to migrate")
    (path / _NODE).write_bytes(dek.encrypt(canonical_json({"node_id": legacy}), aad=_NODE.encode()))
    _strip_plaintext_node_id(path / _CONFIG)
    return legacy


def _legacy_node_id(config_path: Path) -> str | None:
    """Read a pre-FIX-01 plaintext ``node_id`` from ``config.toml``, if present."""
    try:
        raw = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except OSError, tomllib.TOMLDecodeError:
        return None
    value = raw.get("node_id")
    return value if isinstance(value, str) and value else None


def _strip_plaintext_node_id(config_path: Path) -> None:
    """Surgically remove the plaintext ``node_id`` line, preserving all other config."""
    try:
        text = config_path.read_text(encoding="utf-8")
    except OSError:
        return
    kept = [line for line in text.splitlines(keepends=True) if not _LEGACY_NODE_ID_LINE.match(line)]
    if len(kept) != len(text.splitlines(keepends=True)):
        config_path.write_text("".join(kept), encoding="utf-8")


def _load_peer_have(path: Path, dek: SymmetricKey) -> dict[str, set[str]]:
    """Load the local, never-exported record of each peer's known inventory.

    Absent on a vault created before FIX-02 (or one that has never synced), in
    which case every peer starts with an empty known set and the first exchange
    with them falls back to sending every original, exactly as before.
    """
    if not (path / _PEER_HAVE).exists():
        return {}
    raw = _decode_json(_read_blob(path, dek, _PEER_HAVE))
    if not isinstance(raw, dict):
        raise VaultError("corrupt peer-have record")
    result: dict[str, set[str]] = {}
    for fingerprint, capture_ids in raw.items():
        if not isinstance(capture_ids, list):
            raise VaultError("corrupt peer-have record")
        result[fingerprint] = {cid for cid in capture_ids if isinstance(cid, str)}
    return result


def _load_sync_peers(path: Path, dek: SymmetricKey) -> dict[str, PeerAuthorization]:
    """Load local sync authorization; legacy vaults start with no authorized peers."""
    if not (path / _SYNC_SECURITY).exists():
        return {}
    raw = _decode_json(_read_blob(path, dek, _SYNC_SECURITY))
    if not isinstance(raw, dict):
        raise VaultError("corrupt sync security record")
    peers: dict[str, PeerAuthorization] = {}
    for fingerprint, record in raw.items():
        peer = PeerAuthorization.from_json(record)
        try:
            identity = PublicIdentity.decode(peer.identity)
        except Exception as exc:
            raise VaultError("corrupt sync peer identity") from exc
        if identity.fingerprint != fingerprint:
            raise VaultError("sync peer fingerprint does not match its identity")
        peers[fingerprint] = peer
    return peers


def _decode_json(data: bytes) -> JSONValue:
    parsed: JSONValue = json.loads(data)
    return parsed


def _records_to_json(records: list[dict[str, JSONValue]]) -> JSONValue:
    return [dict(record) for record in records]


def _as_record_list(value: JSONValue) -> list[Mapping[str, JSONValue]]:
    if not isinstance(value, list):
        raise VaultError("expected a JSON array of records")
    out: list[Mapping[str, JSONValue]] = []
    for item in value:
        if not isinstance(item, dict):
            raise VaultError("expected a JSON object record")
        out.append(item)
    return out
