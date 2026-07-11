# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""The encrypted case vault and its persistent at-rest boundary.

A vault is a directory holding one case. Sealed originals, the CRDT document,
chain of custody, device identity, and deferred-timestamp queue are encrypted at
rest under a data key that is itself wrapped by the user's passphrase. Timestamp
tokens are consolidated into per-capture AEAD-encrypted sidecars under the same
data key. The vault also contains plaintext ``config.toml`` policy and the wrapped
``keyfile.json``. Path-based media tools receive short-lived plaintext working
copies in a private OS-temporary workspace outside the vault; unlinking those
files is cleanup, not guaranteed physical erasure.

Reading a sealed original always re-checks its fixity, so corruption or tampering
surfaces as an error rather than a quietly altered exhibit.
"""

from __future__ import annotations

import base64
import binascii
import errno
import json
import os
import re
import secrets
import stat
import tomllib
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager, suppress
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
from .errors import CryptoError, FixityError, TimestampError, VaultError
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
_SIDECAR_SUFFIX = ".tokens.enc"
_TOKEN_SIDECAR_VERSION = 1
_TOKEN_AAD_PREFIX = b"habitable:timestamp-token-sidecar:v1:"
_TOKEN_SIDECAR_NAME = re.compile(r"^[0-9a-f]{64}\.tokens\.enc$")
_TOKEN_ATOMIC_TEMP = re.compile(r"^\.token-atomic-[0-9a-f]{32}\.tmp$")
_MAX_TOKEN_SIDECAR_BYTES = 32 * 1024 * 1024
_MAX_TOKEN_PLAINTEXT_BYTES = 24 * 1024 * 1024
_MAX_LEGACY_TOKEN_BYTES = 16 * 1024 * 1024
_MAX_TOKEN_DATA_BYTES = 8 * 1024 * 1024
_MAX_TOKEN_TEXT_CHARS = 4096
_MAX_TOKENS_PER_LIST = 256
_MAX_TOKEN_JSON_NESTING = 64
_MAX_TOKEN_JSON_STRUCTURAL_TOKENS = 8192
_MAX_TOKEN_JSON_NUMBER_CHARS = 128
_MAX_TOKEN_DIRECTORY_ENTRIES = 4096
_MAX_TOKEN_TEMP_ENTRIES = 64
# Local-only record of which captures each sync peer has already confirmed holding
# (FIX-02: incremental sync deltas). Never merged via the CRDT and never exported —
# it is purely an optimization so a later ``sync.export_message`` can skip re-sending
# sealed originals a peer already told us they have.
_PEER_HAVE = "peer_have.enc"
# Pairing keys, exact allowlisted identities, replay ids, receipts, and imported
# source-custody proofs. This is encrypted local policy state, never CRDT-merged.
_SYNC_SECURITY = "sync_security.enc"
_SAVE_BLOBS = (_CASE, _CUSTODY, _DEFERRED, _PEER_HAVE, _SYNC_SECURITY)
_SAVE_JOURNAL = ".save-transaction.json"
_MAX_SAVE_JOURNAL_BYTES = 4096
_SAVE_TRANSACTION_ID = re.compile(r"^[0-9a-f]{32}$")
_SAVE_ARTIFACT = re.compile(
    rf"^\.save-[0-9a-f]{{32}}-(?:{'|'.join(re.escape(name) for name in _SAVE_BLOBS)})"
    r"\.(?:new|old)$"
)
_ATOMIC_TEMP = re.compile(r"^\.save-atomic-[0-9a-f]{32}\.tmp$")
_KEYFILE_FORWARD_REPAIR_ARTIFACT = re.compile(r"^\.keyfile-forward-repair-[0-9a-f]{32}\.tmp$")
_KEYFILE_ALTERNATE_RECOVERY_ARTIFACT = re.compile(
    rf"^{re.escape(_KEYFILE)}\.recovery-[0-9a-f]{{32}}\.new$"
)
_MAX_ROOT_ROTATION_SCAN_ENTRIES = 256

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

    The default packet needs two media-sized copies: the encrypted original stays
    in the vault and a policy-processed shared copy is exported. This estimate does
    not include an optional byte-exact packet original added by ``--include-originals``.
    """

    sealed_originals_bytes: int
    shared_copies_bytes: int
    metadata_bytes: int
    total_bytes: int
    per_capture: tuple[CaptureSize, ...]


@dataclass(frozen=True, slots=True)
class _SaveTransaction:
    """Non-secret recovery metadata for one multi-blob vault save."""

    transaction_id: str
    phase: str
    existing: frozenset[str]


@dataclass(frozen=True, slots=True)
class _TokenSidecar:
    """Validated primary, redundant, and archive tokens for one capture."""

    capture_id: str
    primary: TimestampToken | None = None
    additional: tuple[TimestampToken, ...] = ()
    archive: tuple[TimestampToken, ...] = ()


@dataclass(slots=True)
class _PathRotationStage:
    """One pre-registered root/original/keyfile DEK-rotation stage."""

    final: Path
    destination: Path
    generation: os.stat_result | None = None
    publish_descriptor: int = -1


@dataclass(slots=True)
class _TokenRotationStage:
    """One pre-registered descriptor-relative token DEK-rotation stage."""

    final_name: str
    destination_name: str
    generation: os.stat_result | None = None


@dataclass(frozen=True, slots=True)
class _TokenDirectory:
    """A no-follow descriptor anchoring every operation beneath ``tokens/``."""

    path: Path
    descriptor: int

    def stat(self, name: str) -> os.stat_result:
        return os.stat(name, dir_fd=self.descriptor, follow_symlinks=False)

    def exists(self, name: str) -> bool:
        try:
            self.stat(name)
        except FileNotFoundError:
            return False
        return True

    def unlink(self, name: str, *, missing_ok: bool = False) -> None:
        try:
            os.unlink(name, dir_fd=self.descriptor)
        except FileNotFoundError:
            if not missing_ok:
                raise

    def replace(self, source: str, destination: str) -> None:
        os.rename(
            source,
            destination,
            src_dir_fd=self.descriptor,
            dst_dir_fd=self.descriptor,
        )

    def fsync(self) -> bool:
        try:
            os.fsync(self.descriptor)
        except OSError as exc:
            if os.name == "nt" or exc.errno in _UNSUPPORTED_DIRECTORY_FSYNC:
                return False
            raise
        return True

    def assert_attached(self) -> None:
        """Fail if the pinned directory is no longer the vault's ``tokens/`` entry."""
        try:
            opened = os.fstat(self.descriptor)
            current = self.path.lstat()
        except OSError as exc:
            raise VaultError("timestamp-token directory changed during operation") from exc
        if (
            not stat.S_ISDIR(opened.st_mode)
            or not stat.S_ISDIR(current.st_mode)
            or opened.st_dev != current.st_dev
            or (opened.st_ino and current.st_ino and opened.st_ino != current.st_ino)
        ):
            raise VaultError("timestamp-token directory changed during operation")


def _secure_token_directory_operations_supported() -> bool:
    return (
        bool(getattr(os, "O_DIRECTORY", 0))
        and bool(getattr(os, "O_NOFOLLOW", 0))
        and os.scandir in os.supports_fd
        and os.mkdir in os.supports_dir_fd
        and os.open in os.supports_dir_fd
        and os.stat in os.supports_dir_fd
        and os.stat in os.supports_follow_symlinks
        and os.unlink in os.supports_dir_fd
        and os.rename in os.supports_dir_fd
    )


def _require_secure_token_directory_operations() -> None:
    if not _secure_token_directory_operations_supported():
        raise VaultError(
            "this platform cannot securely anchor timestamp-token storage; vaults are unsupported"
        )


def _prepare_new_vault_directory(path: Path) -> None:
    """Create an empty, real vault tree before any key or case state is written."""
    _require_secure_token_directory_operations()
    try:
        before = path.lstat()
    except FileNotFoundError:
        try:
            path.mkdir(parents=True, exist_ok=False)
            before = path.lstat()
        except OSError as exc:
            raise VaultError("vault destination could not be created safely") from exc
    except OSError as exc:
        raise VaultError("vault destination is unavailable") from exc
    if not stat.S_ISDIR(before.st_mode):
        raise VaultError("vault destination must be a real directory")

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise VaultError("vault destination cannot be securely opened") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISDIR(opened.st_mode) or (
            before.st_dev != opened.st_dev
            or (before.st_ino and opened.st_ino and before.st_ino != opened.st_ino)
        ):
            raise VaultError("vault destination changed while opening")
        with os.scandir(descriptor) as entries:
            if next(entries, None) is not None:
                raise VaultError("vault destination must be empty")
        try:
            os.mkdir(_ORIGINALS, 0o700, dir_fd=descriptor)
            os.mkdir(_TOKENS, 0o700, dir_fd=descriptor)
        except OSError as exc:
            raise VaultError("vault destination changed during initialization") from exc
    finally:
        os.close(descriptor)

    # Prove the newly-created token child can be securely reopened before any
    # config, keyfile, or encrypted state is committed to this destination.
    with _open_token_directory(path):
        pass


@contextmanager
def _open_token_directory(vault_path: Path) -> Iterator[_TokenDirectory]:
    """Open ``tokens/`` once and keep all child operations anchored to that fd."""
    _require_secure_token_directory_operations()
    path = vault_path / _TOKENS
    try:
        before = path.lstat()
    except OSError as exc:
        raise VaultError("timestamp-token directory is unavailable") from exc
    if not stat.S_ISDIR(before.st_mode):
        raise VaultError("timestamp-token directory must be a real directory")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise VaultError("timestamp-token directory cannot be securely opened") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISDIR(opened.st_mode) or (
            before.st_dev != opened.st_dev
            or (before.st_ino and opened.st_ino and before.st_ino != opened.st_ino)
        ):
            raise VaultError("timestamp-token directory changed while opening")
        directory = _TokenDirectory(path, descriptor)
        directory.assert_attached()
        try:
            yield directory
        except BaseException:
            raise
        else:
            directory.assert_attached()
    finally:
        os.close(descriptor)


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
        self._legacy_token_migration_complete = False

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
        _prepare_new_vault_directory(path)

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
        # A newly-created token directory has no plaintext generation to migrate.
        vault._legacy_token_migration_complete = True
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
        _recover_interrupted_save(path)
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
        vault = cls(
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
        # Successful unlock is the authority to migrate pre-encryption token JSON.
        # Publishing the encrypted aggregate precedes plaintext cleanup, so a crash
        # leaves either the legacy generation or a recoverable both-present state.
        vault._migrate_legacy_tokens()
        return vault

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
        # Legacy plaintext token records must enter the encrypted boundary before
        # rotation inventories variable sidecars. This is idempotent after open.
        self._migrate_legacy_tokens()
        new_dek = SymmetricKey.generate()
        staged_files: list[_PathRotationStage] = []
        staged_tokens: list[_TokenRotationStage] = []
        keyfile_final = self.path / _KEYFILE
        keyfile_dest = keyfile_final.with_name(keyfile_final.name + ".new")
        keyfile_stage = _PathRotationStage(keyfile_final, keyfile_dest)
        keyfile_bytes: bytes | None = None
        publication_attempted = False
        keyfile_commit_attempted = False
        with _open_token_directory(self.path) as token_dir:
            self._assert_no_stale_root_rotation_stages(keyfile_dest)
            try:
                originals_dir = self.path / _ORIGINALS
                for cap in self.document.captures():
                    sealed = originals_dir / cap.sealed_name
                    if not cap.sealed_name or not sealed.exists():
                        continue
                    raw = self.read_original(cap.capture_id, cap.content_hash)
                    aad = f"original:{cap.capture_id}:{cap.content_hash}".encode()
                    dest = sealed.with_name(sealed.name + ".new")
                    ciphertext = new_dek.encrypt(raw, aad=aad)
                    stage = _PathRotationStage(sealed, dest)
                    staged_files.append(stage)
                    _write_private_path_stage_and_fsync(stage, ciphertext)

                for name, plaintext in self._blob_plaintexts():
                    final = self.path / name
                    dest = final.with_name(final.name + ".new")
                    ciphertext = new_dek.encrypt(plaintext, aad=name.encode())
                    stage = _PathRotationStage(final, dest)
                    staged_files.append(stage)
                    _write_private_path_stage_and_fsync(stage, ciphertext)

                self._stage_rotated_token_sidecars(token_dir, new_dek, staged_tokens)

                keyfile_bytes = export_recovery_blob(new_dek, passphrase).encode("utf-8")
                _write_private_path_stage_and_fsync(keyfile_stage, keyfile_bytes)

                path_stage_directories = _dek_rotation_path_stage_directories(
                    staged_files, keyfile_stage
                )
                _fsync_dek_rotation_directories(token_dir, path_stage_directories)
                _assert_dek_rotation_stages_owned(
                    token_dir, staged_files, staged_tokens, keyfile_stage
                )
                _open_path_rotation_stage_readonly(keyfile_stage)

                # From this point forward preserve the complete remaining new-key
                # generation even if the first rename raises. An asynchronous
                # exception can arrive after the kernel committed rename but before
                # Python could record success; conservative preservation avoids
                # deleting the only wrapped key for possibly-published ciphertext.
                publication_attempted = True
                for path_stage in staged_files:
                    _assert_path_rotation_stage_owned(path_stage)
                    path_stage.destination.replace(path_stage.final)
                for token_stage in staged_tokens:
                    _assert_token_rotation_stage_owned(token_dir, token_stage)
                    token_dir.replace(token_stage.destination_name, token_stage.final_name)
                # Commit every new-key data/original/token rename before the
                # wrapped key is replaced as the final generation marker.
                _fsync_dek_rotation_directories(token_dir, path_stage_directories)
                keyfile_commit_attempted = True
                _assert_path_rotation_stage_owned(keyfile_stage)
                keyfile_stage.destination.replace(keyfile_stage.final)
                if not _published_keyfile_matches_open_stage(keyfile_stage, keyfile_bytes):
                    raise VaultError("published DEK-rotation keyfile changed")
                # Every live generation now uses the new key. Update memory before
                # late durability calls so a reported flush failure cannot pair a
                # fully swapped vault with the old in-memory key.
                self._dek = new_dek
                _fsync_directory(self.path)
                _close_path_rotation_publish_descriptor(keyfile_stage, suppress_errors=True)
            except BaseException as rotation_error:
                # Before publication is attempted, every live file still uses the
                # old key and staging is disposable. After the first attempt, an
                # exception cannot prove rename did not commit, so deleting the new
                # generation could destroy the only recovery path for new-key data.
                if publication_attempted and keyfile_commit_attempted:
                    # Every data rename was durably ordered before the commit
                    # attempt, so current memory must use the new key even if
                    # proof or forward repair reports a secondary error.
                    self._dek = new_dek
                try:
                    _recover_failed_dek_rotation(
                        token_dir,
                        staged_files,
                        staged_tokens,
                        keyfile_stage,
                        keyfile_bytes,
                        publication_attempted=publication_attempted,
                        keyfile_commit_attempted=keyfile_commit_attempted,
                        rotation_error=rotation_error,
                    )
                finally:
                    _close_path_rotation_publish_descriptor(keyfile_stage, suppress_errors=True)
                raise

    def _assert_no_stale_root_rotation_stages(self, keyfile_dest: Path) -> None:
        staged_paths = [self.path / f"{name}.new" for name, _plaintext in self._blob_plaintexts()]
        for capture in self.document.captures():
            if capture.sealed_name:
                sealed = self.path / _ORIGINALS / capture.sealed_name
                staged_paths.append(sealed.with_name(sealed.name + ".new"))
        staged_paths.append(keyfile_dest)
        stale = next((path for path in staged_paths if _path_entry_exists(path)), None)
        if stale is None:
            stale = _first_keyfile_rotation_recovery_artifact(self.path)
        if stale is not None:
            raise VaultError(
                f"stale DEK-rotation staging file requires manual recovery: {stale.name}"
            )

    def _stage_rotated_token_sidecars(
        self,
        directory: _TokenDirectory,
        new_dek: SymmetricKey,
        staged: list[_TokenRotationStage],
    ) -> None:
        for final_name in _token_sidecar_entry_names(directory):
            record = self._read_token_sidecar_entry(directory, final_name)
            dest_name = final_name + ".new"
            if directory.exists(dest_name):
                raise VaultError(
                    "stale timestamp-token DEK-rotation staging file requires "
                    f"manual recovery: {dest_name}"
                )
            ciphertext = new_dek.encrypt(
                _encode_token_sidecar(record),
                aad=_token_sidecar_aad(final_name),
            )
            # Register intent before creation so an exception immediately after
            # the writer returns cannot strand an otherwise untracked stage.
            stage = _TokenRotationStage(final_name, dest_name)
            staged.append(stage)
            _write_private_token_stage_and_fsync(directory, stage, ciphertext)

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
        """Persist all mutable state as one recoverable multi-file transaction.

        The encrypted file format and names stay unchanged. New ciphertext and encrypted
        backups are flushed in this directory before a non-secret prepared journal is
        published. An interrupted prepared transaction rolls back on the next save/open;
        a committed transaction only needs its temporary artifacts removed.
        """
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
        plaintexts = (
            (_CASE, canonical_json(self.document.to_state())),
            (_CUSTODY, canonical_json(_records_to_json(self.custody.to_vault_records()))),
            (_DEFERRED, canonical_json(deferred_json)),
            (_PEER_HAVE, canonical_json(peer_have_json)),
            (_SYNC_SECURITY, canonical_json(sync_security_json)),
        )
        encrypted = tuple(
            (name, self._dek.encrypt(plaintext, aad=name.encode()))
            for name, plaintext in plaintexts
        )
        _transactionally_replace_save_blobs(self.path, encrypted)

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
        default-packet doubling: each sealed original is copied again, at roughly
        the same size, as shared media. A packet built with ``--include-originals``
        adds another byte-exact copy that this estimate does not count.
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
        """Store the primary token without exposing its metadata at rest."""
        record = self._load_token_sidecar(capture_id) or _TokenSidecar(capture_id)
        self._write_token_sidecar(
            _TokenSidecar(capture_id, _validated_token(token), record.additional, record.archive)
        )

    def get_token(self, capture_id: str) -> TimestampToken | None:
        record = self._load_token_sidecar(capture_id)
        return None if record is None else record.primary

    def add_additional_token(self, capture_id: str, token: TimestampToken) -> None:
        """Append a redundant primary timestamp from another authority.

        Unlike an archive token (which chains *over* the primary token), an additional
        token is an independent RFC 3161 token over the same content hash, so the proof
        does not rest on a single authority (see docs/research, item R-16)."""
        record = self._load_token_sidecar(capture_id) or _TokenSidecar(capture_id)
        additional = (*record.additional, _validated_token(token))
        _check_token_count(additional, "additional-token", capture_id)
        self._write_token_sidecar(
            _TokenSidecar(capture_id, record.primary, additional, record.archive)
        )

    def get_additional_tokens(self, capture_id: str) -> list[TimestampToken]:
        record = self._load_token_sidecar(capture_id)
        return [] if record is None else list(record.additional)

    def add_archive_token(self, capture_id: str, token: TimestampToken) -> None:
        """Append an archive (re-)timestamp for a capture."""
        record = self._load_token_sidecar(capture_id) or _TokenSidecar(capture_id)
        archive = (*record.archive, _validated_token(token))
        _check_token_count(archive, "archive-token", capture_id)
        self._write_token_sidecar(
            _TokenSidecar(capture_id, record.primary, record.additional, archive)
        )

    def get_archive_tokens(self, capture_id: str) -> list[TimestampToken]:
        record = self._load_token_sidecar(capture_id)
        return [] if record is None else list(record.archive)

    def latest_token(self, capture_id: str) -> TimestampToken | None:
        """The most recent token for a capture (the last archive, else the primary)."""
        archives = self.get_archive_tokens(capture_id)
        return archives[-1] if archives else self.get_token(capture_id)

    def _token_sidecar_path(self, capture_id: str) -> Path:
        return self.path / _TOKENS / _token_sidecar_name(capture_id)

    def _load_token_sidecar(self, capture_id: str) -> _TokenSidecar | None:
        self._migrate_legacy_tokens()
        name = _token_sidecar_name(capture_id)
        with _open_token_directory(self.path) as directory:
            if not directory.exists(name):
                return None
            return self._read_token_sidecar_entry(directory, name, expected_capture_id=capture_id)

    def _read_token_sidecar_path(
        self, path: Path, *, expected_capture_id: str | None = None
    ) -> _TokenSidecar:
        if path.parent != self.path / _TOKENS:
            raise VaultError("invalid encrypted timestamp-token sidecar name")
        with _open_token_directory(self.path) as directory:
            return self._read_token_sidecar_entry(
                directory, path.name, expected_capture_id=expected_capture_id
            )

    def _read_token_sidecar_entry(
        self,
        directory: _TokenDirectory,
        name: str,
        *,
        expected_capture_id: str | None = None,
    ) -> _TokenSidecar:
        if not _TOKEN_SIDECAR_NAME.fullmatch(name):
            raise VaultError("invalid encrypted timestamp-token sidecar name")
        try:
            ciphertext = _read_bounded_regular_entry(directory, name, _MAX_TOKEN_SIDECAR_BYTES)
            plaintext = self._dek.decrypt(ciphertext, aad=_token_sidecar_aad(name))
            record = _decode_token_sidecar(plaintext)
        except (CryptoError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise VaultError(f"corrupt encrypted timestamp-token sidecar: {name}") from exc
        if name != _token_sidecar_name(record.capture_id):
            raise VaultError("encrypted timestamp-token sidecar capture id does not match its name")
        if expected_capture_id is not None and record.capture_id != expected_capture_id:
            raise VaultError("encrypted timestamp-token sidecar belongs to another capture")
        return record

    def _write_token_sidecar(self, record: _TokenSidecar) -> None:
        with _open_token_directory(self.path) as directory:
            self._write_token_sidecar_entry(directory, record)

    def _write_token_sidecar_entry(
        self,
        directory: _TokenDirectory,
        record: _TokenSidecar,
        *,
        migration_names: Mapping[str, str] | None = None,
    ) -> None:
        name = _token_sidecar_name(record.capture_id)
        entries = _bounded_token_directory_entries(directory)
        _remove_orphan_token_temps(directory, entries)
        live_count = sum(not _TOKEN_ATOMIC_TEMP.fullmatch(entry) for entry in entries)
        if not directory.exists(name) and live_count >= _MAX_TOKEN_DIRECTORY_ENTRIES:
            migration_overlap = False
            if live_count == _MAX_TOKEN_DIRECTORY_ENTRIES and migration_names is not None:
                migration_overlap = _legacy_migration_names_match_record(
                    directory, entries, record, migration_names
                )
            if not migration_overlap:
                raise VaultError("timestamp-token directory is at its live-entry limit")
        plaintext = _encode_token_sidecar(record)
        ciphertext = self._dek.encrypt(plaintext, aad=_token_sidecar_aad(name))
        if len(ciphertext) > _MAX_TOKEN_SIDECAR_BYTES:
            raise VaultError("encrypted timestamp-token sidecar is too large")
        _atomic_replace_private_entry(directory, name, ciphertext)

    def _migrate_legacy_tokens(self) -> None:
        """Durably replace plaintext token JSON after a successful unlock."""
        if self._legacy_token_migration_complete:
            return
        with _open_token_directory(self.path) as directory:
            entries = _bounded_token_directory_entries(directory, allow_migration_overlap=True)
            _remove_orphan_token_temps(directory, entries)
            groups = _legacy_token_groups(directory, entries)
            self._validate_migration_overlap(directory, entries, groups)
            for legacy_capture_id in sorted(groups):
                names = groups[legacy_capture_id]
                self._migrate_legacy_token_group(directory, legacy_capture_id, names)
        self._legacy_token_migration_complete = True

    def _validate_migration_overlap(
        self,
        directory: _TokenDirectory,
        entries: Sequence[str],
        groups: Mapping[str, Mapping[str, str]],
    ) -> None:
        live_count = sum(not _TOKEN_ATOMIC_TEMP.fullmatch(name) for name in entries)
        if live_count <= _MAX_TOKEN_DIRECTORY_ENTRIES:
            return
        present = set(entries)
        candidates = [
            capture_id for capture_id in groups if _token_sidecar_name(capture_id) in present
        ]
        if len(candidates) != 1:
            raise VaultError(
                "timestamp-token directory has too many entries without a valid migration overlap"
            )
        capture_id = candidates[0]
        legacy_names = groups[capture_id]
        encrypted = self._read_token_sidecar_entry(
            directory, _token_sidecar_name(capture_id), expected_capture_id=capture_id
        )
        legacy = _read_legacy_token_sidecar(directory, capture_id, legacy_names)
        if live_count - len(
            legacy_names
        ) > _MAX_TOKEN_DIRECTORY_ENTRIES or not _remaining_legacy_tokens_match(
            encrypted, legacy, legacy_names
        ):
            raise VaultError(
                "timestamp-token directory has too many entries without a valid migration overlap"
            )

    def _migrate_legacy_token_group(
        self,
        directory: _TokenDirectory,
        capture_id: str,
        names: Mapping[str, str],
    ) -> None:
        snapshots = _snapshot_legacy_token_entries(directory, names.values())
        legacy = _read_legacy_token_sidecar(directory, capture_id, names)
        encrypted_name = _token_sidecar_name(capture_id)
        if directory.exists(encrypted_name):
            encrypted = self._read_token_sidecar_entry(
                directory, encrypted_name, expected_capture_id=capture_id
            )
            if not _remaining_legacy_tokens_match(encrypted, legacy, names):
                raise VaultError(
                    f"encrypted and legacy timestamp-token records disagree for {capture_id}"
                )
        else:
            self._write_token_sidecar_entry(directory, legacy, migration_names=names)
            if (
                self._read_token_sidecar_entry(
                    directory, encrypted_name, expected_capture_id=capture_id
                )
                != legacy
            ):
                raise VaultError(f"timestamp-token migration verification failed for {capture_id}")
        _remove_migrated_token_entries(directory, tuple(names.values()), snapshots)

    # --- deferred-timestamp queue ---------------------------------------------

    def queue_deferred(self, capture_id: str, digest: str) -> None:
        self._deferred.append(DeferredItem(capture_id=capture_id, digest=digest))

    def deferred(self) -> tuple[DeferredItem, ...]:
        return tuple(self._deferred)

    def clear_deferred(self, capture_id: str) -> None:
        self._deferred = [item for item in self._deferred if item.capture_id != capture_id]

    # --- internals ------------------------------------------------------------

    def _write_blob(self, name: str, plaintext: bytes) -> None:
        _atomic_replace_file(
            self.path / name,
            self._dek.encrypt(plaintext, aad=name.encode()),
        )


def _token_sidecar_name(capture_id: str) -> str:
    encoded_capture_id = _capture_id_bytes(capture_id)
    return f"{sha256_bytes(encoded_capture_id)}{_SIDECAR_SUFFIX}"


def _token_sidecar_aad(filename: str) -> bytes:
    if not _TOKEN_SIDECAR_NAME.fullmatch(filename):
        raise VaultError("invalid encrypted timestamp-token sidecar name")
    digest = filename.removesuffix(_SIDECAR_SUFFIX)
    return _TOKEN_AAD_PREFIX + digest.encode("ascii")


def _validate_capture_id(capture_id: str) -> None:
    _capture_id_bytes(capture_id)


def _capture_id_bytes(capture_id: str) -> bytes:
    if not isinstance(capture_id, str):
        raise VaultError("timestamp-token capture id must be text")
    if not capture_id:
        raise VaultError("timestamp-token capture id must not be empty")
    if len(capture_id) > _MAX_TOKEN_TEXT_CHARS:
        raise VaultError("timestamp-token capture id is too large")
    try:
        return capture_id.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise VaultError("timestamp-token capture id must be valid UTF-8") from exc


def _validated_token(token: TimestampToken) -> TimestampToken:
    if not isinstance(token, TimestampToken):
        raise VaultError("timestamp token has an invalid type")
    if not isinstance(token.kind, str) or not isinstance(token.tsa_name, str):
        raise VaultError("timestamp-token metadata must be text")
    try:
        token.kind.encode("utf-8")
        token.tsa_name.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise VaultError("timestamp-token metadata must be valid UTF-8") from exc
    if not isinstance(token.data, bytes):
        raise VaultError("timestamp-token data must be bytes")
    if len(token.kind) > _MAX_TOKEN_TEXT_CHARS or len(token.tsa_name) > _MAX_TOKEN_TEXT_CHARS:
        raise VaultError("timestamp-token metadata is too large")
    if len(token.data) > _MAX_TOKEN_DATA_BYTES:
        raise VaultError("timestamp token is too large")
    return token


def _token_to_json(token: TimestampToken) -> dict[str, JSONValue]:
    validated = _validated_token(token)
    return {
        "kind": validated.kind,
        "tsa_name": validated.tsa_name,
        "token_b64": base64.b64encode(validated.data).decode("ascii"),
    }


def _encode_token_sidecar(record: _TokenSidecar) -> bytes:
    _validate_capture_id(record.capture_id)
    _check_token_count(record.additional, "additional-token", record.capture_id)
    _check_token_count(record.archive, "archive-token", record.capture_id)
    payload: dict[str, JSONValue] = {
        "version": _TOKEN_SIDECAR_VERSION,
        "capture_id": record.capture_id,
        "primary": None if record.primary is None else _token_to_json(record.primary),
        "additional": [_token_to_json(token) for token in record.additional],
        "archive": [_token_to_json(token) for token in record.archive],
    }
    encoded = canonical_json(payload)
    if len(encoded) > _MAX_TOKEN_PLAINTEXT_BYTES:
        raise VaultError("timestamp-token sidecar plaintext is too large")
    return encoded


def _check_token_json_nesting(text: str) -> None:
    """Bound JSON shape before parsing, independently of mutable interpreter limits."""
    depth = 0
    structural_tokens = 0
    number_chars = 0

    for character in _token_json_characters_outside_strings(text):
        if character in "{}[],:":
            structural_tokens += 1
            if structural_tokens > _MAX_TOKEN_JSON_STRUCTURAL_TOKENS:
                raise ValueError("timestamp-token JSON has too many structural tokens")
        if character in "{[":
            depth += 1
            if depth > _MAX_TOKEN_JSON_NESTING:
                raise ValueError("timestamp-token JSON nesting is too deep")
        elif character in "}]" and depth:
            # Full delimiter matching remains json.loads' responsibility.
            depth -= 1
        if character in "-+0123456789.eE":
            number_chars += 1
            if number_chars > _MAX_TOKEN_JSON_NUMBER_CHARS:
                raise ValueError("timestamp-token JSON number is too long")
        else:
            number_chars = 0


def _token_json_characters_outside_strings(text: str) -> Iterator[str]:
    """Yield only JSON text outside quoted strings, honoring backslash escapes."""
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
            continue
        yield character


def _parse_token_json_int(value: str) -> int:
    if len(value) > _MAX_TOKEN_JSON_NUMBER_CHARS:
        raise ValueError("timestamp-token JSON integer is too long")
    return int(value)


def _decode_token_sidecar(data: bytes) -> _TokenSidecar:
    if len(data) > _MAX_TOKEN_PLAINTEXT_BYTES:
        raise VaultError("timestamp-token sidecar plaintext is too large")
    try:
        text = data.decode("utf-8")
        _check_token_json_nesting(text)
        raw: JSONValue = json.loads(text, parse_int=_parse_token_json_int)
    except (UnicodeDecodeError, RecursionError, ValueError) as exc:
        raise VaultError("corrupt encrypted timestamp-token sidecar JSON") from exc
    expected = {"version", "capture_id", "primary", "additional", "archive"}
    if not isinstance(raw, dict) or set(raw) != expected:
        raise VaultError("corrupt encrypted timestamp-token sidecar structure")
    if type(raw["version"]) is not int or raw["version"] != _TOKEN_SIDECAR_VERSION:
        raise VaultError("unsupported encrypted timestamp-token sidecar version")
    capture_id = raw["capture_id"]
    if not isinstance(capture_id, str):
        raise VaultError("corrupt encrypted timestamp-token sidecar capture id")
    _validate_capture_id(capture_id)
    primary_raw = raw["primary"]
    if primary_raw is not None and not isinstance(primary_raw, dict):
        raise VaultError(f"corrupt token record for {capture_id}")
    primary = (
        None if primary_raw is None else _decode_timestamp_token(primary_raw, "token", capture_id)
    )
    additional = _decode_token_list(raw["additional"], "additional-token", capture_id)
    archive = _decode_token_list(raw["archive"], "archive-token", capture_id)
    return _TokenSidecar(capture_id, primary, additional, archive)


def _decode_token_list(raw: JSONValue, label: str, capture_id: str) -> tuple[TimestampToken, ...]:
    if not isinstance(raw, list):
        raise VaultError(f"corrupt {label} record for {capture_id}")
    _check_token_count(raw, label, capture_id)
    tokens: list[TimestampToken] = []
    for item in raw:
        if not isinstance(item, dict):
            raise VaultError(f"corrupt {label} record for {capture_id}")
        tokens.append(_decode_timestamp_token(item, label, capture_id))
    return tuple(tokens)


def _decode_timestamp_token(
    raw: Mapping[str, JSONValue], label: str, capture_id: str
) -> TimestampToken:
    if set(raw) != {"kind", "tsa_name", "token_b64"}:
        raise VaultError(f"corrupt {label} record for {capture_id}")
    kind = raw["kind"]
    tsa_name = raw["tsa_name"]
    token_b64 = raw["token_b64"]
    if not isinstance(kind, str) or not isinstance(tsa_name, str) or not isinstance(token_b64, str):
        raise VaultError(f"corrupt {label} record for {capture_id}")
    try:
        strict_data = base64.b64decode(token_b64, validate=True)
        token = TimestampToken.from_dict(raw)
    except (binascii.Error, TimestampError, ValueError) as exc:
        raise VaultError(f"corrupt {label} record for {capture_id}") from exc
    if token.data != strict_data:
        raise VaultError(f"corrupt {label} record for {capture_id}")
    return _validated_token(token)


def _first_keyfile_rotation_recovery_artifact(directory: Path) -> Path | None:
    """Return one exact recovery artifact without unbounded root enumeration."""
    with os.scandir(directory) as scanned:
        for entry_count, entry in enumerate(scanned, start=1):
            if entry_count > _MAX_ROOT_ROTATION_SCAN_ENTRIES:
                raise VaultError(
                    "vault root has too many entries for safe DEK rotation; "
                    "manual recovery is required"
                )
            if _KEYFILE_FORWARD_REPAIR_ARTIFACT.fullmatch(
                entry.name
            ) or _KEYFILE_ALTERNATE_RECOVERY_ARTIFACT.fullmatch(entry.name):
                return directory / entry.name
    return None


def _check_token_count(tokens: Sequence[object], label: str, capture_id: str) -> None:
    if len(tokens) > _MAX_TOKENS_PER_LIST:
        raise VaultError(f"{label} record has too many tokens for {capture_id}")


def _bounded_token_directory_entries(
    directory: _TokenDirectory, *, allow_migration_overlap: bool = False
) -> list[str]:
    entries: list[str] = []
    temporary_count = 0
    live_count = 0
    live_limit = _MAX_TOKEN_DIRECTORY_ENTRIES + int(allow_migration_overlap)
    with os.scandir(directory.descriptor) as scanned:
        for entry in scanned:
            name = entry.name
            if _TOKEN_ATOMIC_TEMP.fullmatch(name):
                temporary_count += 1
                if temporary_count > _MAX_TOKEN_TEMP_ENTRIES:
                    raise VaultError("timestamp-token directory has too many temporary entries")
            else:
                live_count += 1
            if live_count > live_limit:
                raise VaultError("timestamp-token directory has too many entries")
            entries.append(name)
    return entries


def _token_sidecar_entry_names(directory: _TokenDirectory) -> list[str]:
    return sorted(
        name
        for name in _bounded_token_directory_entries(directory)
        if _TOKEN_SIDECAR_NAME.fullmatch(name)
    )


def _legacy_token_groups(
    directory: _TokenDirectory, entries: Iterable[str]
) -> dict[str, dict[str, str]]:
    groups: dict[str, dict[str, str]] = {}
    for name in sorted(entries):
        if not name.endswith(".json"):
            continue
        raw = _read_legacy_token_json_value(directory, name)
        if isinstance(raw, dict):
            # A primary for capture id ``tenant.additional`` has the same
            # filename as the additional component for ``tenant``. The legacy
            # writer's object-versus-list shape is the only unambiguous signal.
            capture_id = name.removesuffix(".json")
            kind = "primary"
        elif isinstance(raw, list) and name.endswith(".additional.json"):
            capture_id = name.removesuffix(".additional.json")
            kind = "additional"
        elif isinstance(raw, list) and name.endswith(".archive.json"):
            capture_id = name.removesuffix(".archive.json")
            kind = "archive"
        else:
            detail = "legacy timestamp-token file has an invalid top-level shape"
            if isinstance(raw, list):
                detail = "corrupt token record: plain legacy JSON requires an object"
            raise VaultError(f"{detail}: {name}")
        _validate_capture_id(capture_id)
        group = groups.setdefault(capture_id, {})
        if kind in group:
            raise VaultError(f"ambiguous legacy timestamp-token records for {capture_id}")
        group[kind] = name
    return groups


def _legacy_migration_names_match_record(
    directory: _TokenDirectory,
    entries: Iterable[str],
    record: _TokenSidecar,
    names: Mapping[str, str],
) -> bool:
    """Validate one cap-overlap group without reclassifying the whole directory."""
    expected_names = {
        "primary": f"{record.capture_id}.json",
        "additional": f"{record.capture_id}.additional.json",
        "archive": f"{record.capture_id}.archive.json",
    }
    if (
        not names
        or not set(names).issubset(expected_names)
        or any(expected_names[kind] != name for kind, name in names.items())
        or not set(names.values()).issubset(entries)
    ):
        return False
    legacy = _read_legacy_token_sidecar(directory, record.capture_id, names)
    return _remaining_legacy_tokens_match(record, legacy, names)


def _remaining_legacy_tokens_match(
    encrypted: _TokenSidecar, legacy: _TokenSidecar, names: Mapping[str, str]
) -> bool:
    """Compare only components still present after a possibly partial cleanup."""
    return (
        ("primary" not in names or encrypted.primary == legacy.primary)
        and ("additional" not in names or encrypted.additional == legacy.additional)
        and ("archive" not in names or encrypted.archive == legacy.archive)
    )


def _read_legacy_token_sidecar(
    directory: _TokenDirectory, capture_id: str, names: Mapping[str, str]
) -> _TokenSidecar:
    primary: TimestampToken | None = None
    if name := names.get("primary"):
        raw = _read_legacy_token_json(directory, name, "token", capture_id)
        if not isinstance(raw, dict):
            raise VaultError(f"corrupt token record for {capture_id}")
        primary = _decode_timestamp_token(raw, "token", capture_id)
    additional = _read_legacy_token_list(
        directory, names.get("additional"), "additional-token", capture_id
    )
    archive = _read_legacy_token_list(directory, names.get("archive"), "archive-token", capture_id)
    return _TokenSidecar(capture_id, primary, additional, archive)


def _read_legacy_token_list(
    directory: _TokenDirectory, name: str | None, label: str, capture_id: str
) -> tuple[TimestampToken, ...]:
    if name is None:
        return ()
    raw = _read_legacy_token_json(directory, name, label, capture_id)
    return _decode_token_list(raw, label, capture_id)


def _read_legacy_token_json(
    directory: _TokenDirectory, name: str, label: str, capture_id: str
) -> JSONValue:
    return _read_legacy_token_json_value(
        directory,
        name,
        parse_error=f"corrupt {label} record for {capture_id}",
    )


def _read_legacy_token_json_value(
    directory: _TokenDirectory, name: str, *, parse_error: str | None = None
) -> JSONValue:
    # Keep no-follow, regular-file, race, and size failures precise. Only the
    # parser boundary is normalized into a controlled corrupt-record error.
    data = _read_bounded_regular_entry(directory, name, _MAX_LEGACY_TOKEN_BYTES)
    try:
        text = data.decode("utf-8")
        _check_token_json_nesting(text)
        raw: JSONValue = json.loads(text, parse_int=_parse_token_json_int)
    except (UnicodeDecodeError, RecursionError, ValueError) as exc:
        message = parse_error or f"corrupt token record in legacy file: {name}"
        raise VaultError(message) from exc
    return raw


type _FileSnapshot = tuple[int, int, int, int, int]


def _snapshot_legacy_token_entries(
    directory: _TokenDirectory, names: Iterable[str]
) -> dict[str, _FileSnapshot]:
    snapshots: dict[str, _FileSnapshot] = {}
    for name in names:
        try:
            info = directory.stat(name)
        except OSError as exc:
            raise VaultError(f"legacy timestamp-token file is unavailable: {name}") from exc
        if not stat.S_ISREG(info.st_mode):
            raise VaultError(f"legacy timestamp-token file must be regular: {name}")
        snapshots[name] = (
            info.st_dev,
            info.st_ino,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )
    return snapshots


def _remove_migrated_token_entries(
    directory: _TokenDirectory,
    names: tuple[str, ...],
    snapshots: Mapping[str, _FileSnapshot],
) -> None:
    """Remove only the exact legacy generation that was encrypted and verified."""
    for name in names:
        try:
            info = directory.stat(name)
        except OSError as exc:
            raise VaultError(f"legacy timestamp-token file changed before cleanup: {name}") from exc
        current = (
            info.st_dev,
            info.st_ino,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )
        if not stat.S_ISREG(info.st_mode) or current != snapshots[name]:
            raise VaultError(f"legacy timestamp-token file changed before cleanup: {name}")
    for name in names:
        directory.unlink(name)
    if names:
        directory.fsync()


def _discard_dek_rotation_stages(
    token_directory: _TokenDirectory,
    staged_files: Sequence[_PathRotationStage],
    staged_tokens: Sequence[_TokenRotationStage],
    keyfile_stage: _PathRotationStage,
) -> None:
    """Discard a wholly unpublished new-key generation."""
    for path_stage in staged_files:
        _unlink_path_rotation_stage(path_stage)
    for token_stage in staged_tokens:
        _unlink_token_rotation_stage(token_directory, token_stage)
    _unlink_path_rotation_stage(keyfile_stage)


def _recover_failed_dek_rotation(
    token_directory: _TokenDirectory,
    staged_files: Sequence[_PathRotationStage],
    staged_tokens: Sequence[_TokenRotationStage],
    keyfile_stage: _PathRotationStage,
    keyfile_bytes: bytes | None,
    *,
    publication_attempted: bool,
    keyfile_commit_attempted: bool,
    rotation_error: BaseException,
) -> None:
    if not publication_attempted:
        try:
            _discard_dek_rotation_stages(
                token_directory, staged_files, staged_tokens, keyfile_stage
            )
        except BaseException as cleanup_error:
            rotation_error.add_note(
                "prepublication DEK-rotation stage cleanup also failed: " + repr(cleanup_error)
            )
            _copy_exception_notes(cleanup_error, rotation_error)
        try:
            _fsync_dek_rotation_directories(
                token_directory,
                _dek_rotation_path_stage_directories(staged_files, keyfile_stage),
            )
        except BaseException as cleanup_sync_error:
            rotation_error.add_note(
                "prepublication DEK-rotation cleanup directory sync also failed: "
                + repr(cleanup_sync_error)
            )
            _copy_exception_notes(cleanup_sync_error, rotation_error)
        return
    if keyfile_commit_attempted:
        _repair_committed_keyfile_if_needed(keyfile_stage, keyfile_bytes, rotation_error)
        return
    if keyfile_bytes is not None and not _path_rotation_stage_has_expected_bytes(
        keyfile_stage, keyfile_bytes
    ):
        _preserve_alternate_keyfile_recovery(keyfile_stage.final, keyfile_bytes, rotation_error)


def _repair_committed_keyfile_if_needed(
    stage: _PathRotationStage,
    expected_bytes: bytes | None,
    rotation_error: BaseException,
) -> None:
    if expected_bytes is None:
        rotation_error.add_note("DEK-rotation keyfile bytes were unavailable for repair")
        return
    if _published_keyfile_matches_open_stage(stage, expected_bytes):
        return
    try:
        _forward_repair_published_keyfile(stage, expected_bytes)
    except BaseException as repair_error:
        rotation_error.add_note("forward keyfile repair also failed: " + repr(repair_error))
        _copy_exception_notes(repair_error, rotation_error)
        _preserve_alternate_keyfile_recovery(stage.final, expected_bytes, rotation_error)


def _preserve_alternate_keyfile_recovery(
    final: Path, expected_bytes: bytes, rotation_error: BaseException
) -> None:
    try:
        recovery_path = _write_alternate_keyfile_recovery(final, expected_bytes)
        rotation_error.add_note("new DEK recovery keyfile preserved at " + str(recovery_path))
    except BaseException as recovery_error:
        rotation_error.add_note("alternate keyfile recovery also failed: " + repr(recovery_error))
        _copy_exception_notes(recovery_error, rotation_error)


def _copy_exception_notes(source: BaseException, destination: BaseException) -> None:
    for note in getattr(source, "__notes__", ()):
        destination.add_note(note)


def _unlink_path_rotation_stage(stage: _PathRotationStage) -> None:
    """Remove only the exact path generation created by this rotation."""
    if stage.generation is None:
        return
    try:
        current = stage.destination.lstat()
    except FileNotFoundError:
        return
    if _same_regular_file_generation(current, stage.generation):
        stage.destination.unlink()


def _unlink_token_rotation_stage(directory: _TokenDirectory, stage: _TokenRotationStage) -> None:
    """Remove only the exact descriptor-relative generation created by this rotation."""
    if stage.generation is None:
        return
    try:
        current = directory.stat(stage.destination_name)
    except FileNotFoundError:
        return
    if _same_regular_file_generation(current, stage.generation):
        directory.unlink(stage.destination_name)


def _assert_dek_rotation_stages_owned(
    token_directory: _TokenDirectory,
    staged_files: Sequence[_PathRotationStage],
    staged_tokens: Sequence[_TokenRotationStage],
    keyfile_stage: _PathRotationStage,
) -> None:
    for path_stage in staged_files:
        _assert_path_rotation_stage_owned(path_stage)
    for token_stage in staged_tokens:
        _assert_token_rotation_stage_owned(token_directory, token_stage)
    _assert_path_rotation_stage_owned(keyfile_stage)


def _dek_rotation_path_stage_directories(
    staged_files: Sequence[_PathRotationStage], keyfile_stage: _PathRotationStage
) -> tuple[Path, ...]:
    return tuple(
        sorted(
            {keyfile_stage.destination.parent}
            | {stage.destination.parent for stage in staged_files},
            key=lambda path: str(path),
        )
    )


def _fsync_dek_rotation_directories(
    token_directory: _TokenDirectory, path_directories: Iterable[Path]
) -> None:
    for directory_path in path_directories:
        _fsync_directory(directory_path)
    token_directory.fsync()


def _assert_path_rotation_stage_owned(stage: _PathRotationStage) -> None:
    if stage.generation is None:
        raise VaultError(
            f"DEK-rotation staging file was not safely created: {stage.destination.name}"
        )
    try:
        current = stage.destination.lstat()
    except OSError as exc:
        raise VaultError(f"DEK-rotation staging file changed: {stage.destination.name}") from exc
    if not _same_regular_file_generation(current, stage.generation):
        raise VaultError(f"DEK-rotation staging file changed: {stage.destination.name}")


def _open_path_rotation_stage_readonly(stage: _PathRotationStage) -> None:
    """Open and pin the exact keyfile stage across its publication rename."""
    _assert_path_rotation_stage_owned(stage)
    flags = (
        os.O_RDONLY
        | os.O_NOFOLLOW
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_BINARY", 0)
    )
    descriptor = -1
    try:
        descriptor = os.open(stage.destination, flags)
        opened = os.fstat(descriptor)
        if stage.generation is None or not _same_regular_file_generation(opened, stage.generation):
            raise VaultError(f"DEK-rotation staging file changed: {stage.destination.name}")
        stage.publish_descriptor = descriptor
    except BaseException:
        try:
            if descriptor >= 0:
                os.close(descriptor)
        finally:
            stage.publish_descriptor = -1
        raise


def _published_keyfile_matches_open_stage(
    stage: _PathRotationStage, expected_bytes: bytes | None
) -> bool:
    descriptor = stage.publish_descriptor
    recorded = stage.generation
    if descriptor < 0 or expected_bytes is None or recorded is None:
        return False
    try:
        current = stage.final.lstat()
        before = os.fstat(descriptor)
        if (
            not _same_regular_file_generation(current, before)
            or not stat.S_ISREG(before.st_mode)
            or before.st_dev != recorded.st_dev
            or before.st_ino != recorded.st_ino
            or before.st_size != recorded.st_size
            or before.st_mtime_ns != recorded.st_mtime_ns
            or stat.S_IMODE(before.st_mode) != stat.S_IMODE(recorded.st_mode)
            or before.st_size != len(expected_bytes)
        ):
            return False
        os.lseek(descriptor, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        remaining = len(expected_bytes) + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        current_after = stage.final.lstat()
    except OSError:
        return False
    return (
        _same_regular_file_generation(before, after)
        and _same_regular_file_generation(current_after, after)
        and b"".join(chunks) == expected_bytes
    )


def _forward_repair_published_keyfile(stage: _PathRotationStage, expected_bytes: bytes) -> None:
    """Atomically restore the wrapped new key after a final-commit race."""
    repair = _PathRotationStage(
        stage.final,
        stage.final.with_name(f".keyfile-forward-repair-{secrets.token_hex(16)}.tmp"),
    )
    try:
        _write_private_path_stage_and_fsync(repair, expected_bytes)
        _fsync_directory(repair.destination.parent)
        _open_path_rotation_stage_readonly(repair)
        repair.destination.replace(repair.final)
        _fsync_directory(repair.final.parent)
        if not _published_keyfile_matches_open_stage(repair, expected_bytes):
            raise VaultError("forward-repaired DEK-rotation keyfile verification failed")
    except BaseException as exc:
        verified_path = _verified_keyfile_recovery_path(repair, expected_bytes)
        if verified_path is None:
            exc.add_note("no verified forward-repair artifact retained")
        else:
            exc.add_note("forward-repair artifact retained at " + str(verified_path))
        raise
    finally:
        _close_path_rotation_publish_descriptor(repair, suppress_errors=True)


def _write_alternate_keyfile_recovery(final: Path, expected_bytes: bytes) -> Path:
    """Durably retain one bounded, unambiguous recovery artifact for a partial publish."""
    recovery = _PathRotationStage(
        final,
        final.with_name(f"{final.name}.recovery-{secrets.token_hex(16)}.new"),
    )
    try:
        _write_private_path_stage_and_fsync(recovery, expected_bytes)
        if not _path_rotation_stage_has_expected_bytes(recovery, expected_bytes):
            raise VaultError("alternate DEK-rotation keyfile recovery verification failed")
        _fsync_directory(recovery.destination.parent)
    except BaseException as exc:
        if _path_rotation_stage_has_expected_bytes(recovery, expected_bytes):
            exc.add_note("alternate recovery artifact retained at " + str(recovery.destination))
        else:
            exc.add_note("no verified alternate recovery artifact retained")
        raise
    return recovery.destination


def _verified_keyfile_recovery_path(
    stage: _PathRotationStage, expected_bytes: bytes
) -> Path | None:
    if _path_rotation_stage_has_expected_bytes(stage, expected_bytes):
        return stage.destination
    if _published_keyfile_matches_open_stage(stage, expected_bytes):
        return stage.final
    return None


def _path_rotation_stage_has_expected_bytes(
    stage: _PathRotationStage, expected_bytes: bytes
) -> bool:
    recorded = stage.generation
    if recorded is None:
        return False
    flags = (
        os.O_RDONLY
        | os.O_NOFOLLOW
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_BINARY", 0)
    )
    descriptor = -1
    try:
        current = stage.destination.lstat()
        if not _same_regular_file_generation(current, recorded):
            return False
        descriptor = os.open(stage.destination, flags)
        before = os.fstat(descriptor)
        if not _same_regular_file_generation(before, recorded) or before.st_size != len(
            expected_bytes
        ):
            return False
        chunks: list[bytes] = []
        remaining = len(expected_bytes) + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        current_after = stage.destination.lstat()
    except OSError:
        return False
    finally:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)
    return (
        _same_regular_file_generation(before, after)
        and _same_regular_file_generation(current_after, after)
        and b"".join(chunks) == expected_bytes
    )


def _close_path_rotation_publish_descriptor(
    stage: _PathRotationStage, *, suppress_errors: bool = False
) -> None:
    descriptor = stage.publish_descriptor
    if descriptor < 0:
        return
    stage.publish_descriptor = -1
    if suppress_errors:
        with suppress(OSError):
            os.close(descriptor)
    else:
        os.close(descriptor)


def _assert_token_rotation_stage_owned(
    directory: _TokenDirectory, stage: _TokenRotationStage
) -> None:
    if stage.generation is None:
        raise VaultError(
            "timestamp-token DEK-rotation staging file was not safely created: "
            f"{stage.destination_name}"
        )
    try:
        current = directory.stat(stage.destination_name)
    except OSError as exc:
        raise VaultError(
            f"timestamp-token DEK-rotation staging file changed: {stage.destination_name}"
        ) from exc
    if not _same_regular_file_generation(current, stage.generation):
        raise VaultError(
            f"timestamp-token DEK-rotation staging file changed: {stage.destination_name}"
        )


def _transactionally_replace_save_blobs(path: Path, encrypted: Sequence[tuple[str, bytes]]) -> None:
    """Publish one coherent generation of normal mutable vault state."""
    if tuple(name for name, _ciphertext in encrypted) != _SAVE_BLOBS:
        raise VaultError("internal error: incomplete vault save transaction")
    _recover_interrupted_save(path)
    transaction = _stage_save_transaction(path, encrypted)
    try:
        for name in _SAVE_BLOBS:
            staged = _save_artifact(path, transaction.transaction_id, name, "new")
            if not _is_regular_entry(staged):
                raise VaultError(f"staged vault file missing: {name}")
            _replace_path(staged, path / name)
        _fsync_directory(path)
        committed = _SaveTransaction(
            transaction.transaction_id,
            "committed",
            transaction.existing,
        )
        _write_save_journal(path, committed)
        _cleanup_save_transaction(path, committed)
    except BaseException:
        try:
            _recover_interrupted_save(path)
        except BaseException as recovery_error:
            raise VaultError(
                "vault save failed and automatic recovery could not complete"
            ) from recovery_error
        raise


def _stage_save_transaction(path: Path, encrypted: Sequence[tuple[str, bytes]]) -> _SaveTransaction:
    transaction_id = secrets.token_hex(16)
    existing = frozenset(name for name in _SAVE_BLOBS if _path_entry_exists(path / name))
    transaction = _SaveTransaction(transaction_id, "prepared", existing)
    try:
        for name, ciphertext in encrypted:
            staged = _save_artifact(path, transaction_id, name, "new")
            _write_new_file_and_fsync(staged, ciphertext)
            if name in existing:
                backup = _save_artifact(path, transaction_id, name, "old")
                _copy_regular_file_and_fsync(path / name, backup)
        _fsync_directory(path)
        _write_save_journal(path, transaction)
    except BaseException:
        try:
            if _path_entry_exists(path / _SAVE_JOURNAL):
                _recover_interrupted_save(path)
            else:
                _discard_save_artifacts(path, transaction)
        except BaseException as cleanup_error:
            raise VaultError("could not clean up an unprepared vault save") from cleanup_error
        raise
    return transaction


def _recover_interrupted_save(path: Path) -> None:
    """Roll back a prepared save or finish cleanup for a committed save."""
    journal = path / _SAVE_JOURNAL
    if not _path_entry_exists(journal):
        _remove_orphan_save_artifacts(path)
        return
    transaction = _read_save_journal(journal)
    try:
        if transaction.phase == "prepared":
            for name in _SAVE_BLOBS:
                live = path / name
                if name in transaction.existing:
                    backup = _save_artifact(path, transaction.transaction_id, name, "old")
                    if not _path_entry_exists(backup):
                        raise VaultError(f"vault save backup missing: {name}")
                    _atomic_restore_regular_file(live, backup)
                else:
                    live.unlink(missing_ok=True)
            _fsync_directory(path)
            _finalize_prepared_rollback(path, transaction)
        else:
            missing = [name for name in _SAVE_BLOBS if not _is_regular_entry(path / name)]
            if missing:
                raise VaultError(
                    "committed vault save is missing state file(s): " + ", ".join(missing)
                )
            _cleanup_save_transaction(path, transaction)
    except VaultError:
        raise
    except OSError as exc:
        raise VaultError(f"could not recover interrupted vault save: {exc}") from exc


def _write_save_journal(path: Path, transaction: _SaveTransaction) -> None:
    payload: JSONValue = {
        "version": 1,
        "transaction_id": transaction.transaction_id,
        "phase": transaction.phase,
        "existing": cast(JSONValue, sorted(transaction.existing)),
    }
    _atomic_replace_file(path / _SAVE_JOURNAL, canonical_json(payload))


def _read_save_journal(path: Path) -> _SaveTransaction:
    try:
        record = json.loads(_read_bounded_regular_file(path, _MAX_SAVE_JOURNAL_BYTES))
    except VaultError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VaultError("interrupted vault save journal is unreadable") from exc
    if not isinstance(record, dict) or record.get("version") != 1:
        raise VaultError("interrupted vault save journal has an unsupported format")
    transaction_id = record.get("transaction_id")
    phase = record.get("phase")
    existing_raw = record.get("existing")
    if not isinstance(transaction_id, str) or not _SAVE_TRANSACTION_ID.fullmatch(transaction_id):
        raise VaultError("interrupted vault save journal has an invalid transaction id")
    if phase not in {"prepared", "committed"}:
        raise VaultError("interrupted vault save journal has an invalid phase")
    if not isinstance(existing_raw, list) or not all(
        isinstance(name, str) for name in existing_raw
    ):
        raise VaultError("interrupted vault save journal has an invalid file inventory")
    existing = frozenset(existing_raw)
    if len(existing) != len(existing_raw) or not existing.issubset(_SAVE_BLOBS):
        raise VaultError("interrupted vault save journal has an invalid file inventory")
    return _SaveTransaction(transaction_id, phase, existing)


def _cleanup_save_transaction(path: Path, transaction: _SaveTransaction) -> None:
    """Finish committed cleanup, with the committed journal removed last."""
    _discard_save_artifacts(path, transaction)
    (path / _SAVE_JOURNAL).unlink(missing_ok=True)
    _fsync_directory(path)


def _finalize_prepared_rollback(path: Path, transaction: _SaveTransaction) -> None:
    """Commit the restored old generation before its backup copies are removed.

    If cleanup is interrupted after the prepared marker is durably absent, the next
    open sees only harmless orphan copies and can remove them without another rollback.
    """
    (path / _SAVE_JOURNAL).unlink()
    _fsync_directory(path)
    _discard_save_artifacts(path, transaction)


def _discard_save_artifacts(path: Path, transaction: _SaveTransaction) -> None:
    for name in _SAVE_BLOBS:
        _save_artifact(path, transaction.transaction_id, name, "new").unlink(missing_ok=True)
        _save_artifact(path, transaction.transaction_id, name, "old").unlink(missing_ok=True)
    for entry in path.iterdir():
        if _ATOMIC_TEMP.fullmatch(entry.name):
            entry.unlink(missing_ok=True)
    _fsync_directory(path)


def _remove_orphan_save_artifacts(path: Path) -> None:
    if not path.is_dir():
        return
    removed = False
    for entry in path.iterdir():
        if _SAVE_ARTIFACT.fullmatch(entry.name) or _ATOMIC_TEMP.fullmatch(entry.name):
            entry.unlink(missing_ok=True)
            removed = True
    if removed:
        _fsync_directory(path)


def _save_artifact(path: Path, transaction_id: str, name: str, suffix: str) -> Path:
    return path / f".save-{transaction_id}-{name}.{suffix}"


def _path_entry_exists(path: Path) -> bool:
    """Return true for any directory entry, including a broken symlink or FIFO."""
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


def _is_regular_entry(path: Path) -> bool:
    try:
        return stat.S_ISREG(path.lstat().st_mode)
    except OSError:
        return False


def _open_regular_readonly(path: Path) -> tuple[int, int]:
    """Open a recovery input without following links or blocking on a FIFO."""
    try:
        before = path.lstat()
    except OSError as exc:
        raise VaultError(f"vault save recovery file is unavailable: {path.name}") from exc
    if not stat.S_ISREG(before.st_mode):
        raise VaultError(f"vault save recovery file must be regular: {path.name}")
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise VaultError(f"vault save recovery file cannot be opened: {path.name}") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (
            before.st_dev != opened.st_dev
            or (before.st_ino and opened.st_ino and before.st_ino != opened.st_ino)
            or before.st_size != opened.st_size
            or before.st_mtime_ns != opened.st_mtime_ns
            or before.st_ctime_ns != opened.st_ctime_ns
        ):
            raise VaultError(f"vault save recovery file changed while opening: {path.name}")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor, opened.st_size


def _copy_regular_file_and_fsync(source: Path, destination: Path) -> None:
    descriptor, expected_size = _open_regular_readonly(source)
    try:
        with os.fdopen(descriptor, "rb") as input_file:
            descriptor = -1
            with destination.open("xb") as output_file:
                copied = 0
                while chunk := input_file.read(1024 * 1024):
                    written = output_file.write(chunk)
                    if written != len(chunk):
                        raise OSError(f"short write for {destination.name}")
                    copied += written
                if copied != expected_size:
                    raise VaultError(f"vault save recovery file changed: {source.name}")
                output_file.flush()
                os.fsync(output_file.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _atomic_restore_regular_file(destination: Path, backup: Path) -> None:
    temporary = destination.with_name(f".save-atomic-{secrets.token_hex(16)}.tmp")
    try:
        _copy_regular_file_and_fsync(backup, temporary)
        _replace_path(temporary, destination)
        _fsync_directory(destination.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _read_bounded_regular_file(path: Path, max_bytes: int) -> bytes:
    descriptor, size = _open_regular_readonly(path)
    try:
        if size > max_bytes:
            raise VaultError(f"vault save recovery file is too large: {path.name}")
        with os.fdopen(descriptor, "rb") as input_file:
            descriptor = -1
            data = input_file.read(max_bytes + 1)
        if len(data) != size or len(data) > max_bytes:
            raise VaultError(f"vault save recovery file changed while reading: {path.name}")
        return data
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_bounded_regular_entry(directory: _TokenDirectory, name: str, max_bytes: int) -> bytes:
    """Read a direct token-directory entry without consulting its mutable path."""
    try:
        before = directory.stat(name)
    except OSError as exc:
        raise VaultError(f"timestamp-token file is unavailable: {name}") from exc
    if not stat.S_ISREG(before.st_mode):
        raise VaultError(f"timestamp-token file must be regular: {name}")
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, dir_fd=directory.descriptor)
    except OSError as exc:
        raise VaultError(f"timestamp-token file cannot be opened: {name}") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (
            before.st_dev != opened.st_dev
            or (before.st_ino and opened.st_ino and before.st_ino != opened.st_ino)
            or before.st_size != opened.st_size
            or before.st_mtime_ns != opened.st_mtime_ns
            or before.st_ctime_ns != opened.st_ctime_ns
        ):
            raise VaultError(f"timestamp-token file changed while opening: {name}")
        if opened.st_size > max_bytes:
            raise VaultError(f"timestamp-token file is too large: {name}")
        with os.fdopen(descriptor, "rb") as input_file:
            descriptor = -1
            data = input_file.read(max_bytes + 1)
            after = os.fstat(input_file.fileno())
        if (
            not stat.S_ISREG(after.st_mode)
            or opened.st_dev != after.st_dev
            or (opened.st_ino and after.st_ino and opened.st_ino != after.st_ino)
            or opened.st_size != after.st_size
            or opened.st_mtime_ns != after.st_mtime_ns
            or opened.st_ctime_ns != after.st_ctime_ns
            or len(data) != opened.st_size
            or len(data) > max_bytes
        ):
            raise VaultError(f"timestamp-token file changed while reading: {name}")
        return data
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _atomic_replace_file(path: Path, data: bytes) -> None:
    """Flush a same-directory temporary file, replace ``path``, and sync its directory."""
    temporary = path.with_name(f".save-atomic-{secrets.token_hex(16)}.tmp")
    try:
        _write_new_file_and_fsync(temporary, data)
        _replace_path(temporary, path)
        _fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _atomic_replace_private_entry(directory: _TokenDirectory, name: str, data: bytes) -> None:
    """Atomically publish flushed ciphertext with owner-only POSIX permissions."""
    temporary = f".token-atomic-{secrets.token_hex(16)}.tmp"
    try:
        _write_private_entry_and_fsync(directory, temporary, data)
        directory.replace(temporary, name)
        directory.fsync()
    finally:
        directory.unlink(temporary, missing_ok=True)


def _write_private_entry_and_fsync(directory: _TokenDirectory, name: str, data: bytes) -> None:
    stage = _TokenRotationStage(name, name)
    _write_private_token_stage_and_fsync(directory, stage, data)


def _write_private_token_stage_and_fsync(
    directory: _TokenDirectory, stage: _TokenRotationStage, data: bytes
) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_BINARY", 0)
    )
    descriptor = -1
    try:
        descriptor = os.open(
            stage.destination_name,
            flags,
            0o600,
            dir_fd=directory.descriptor,
        )
        stage.generation = os.fstat(descriptor)
        _write_all_private_and_fsync(descriptor, stage.destination_name, data)
        stage.generation = os.fstat(descriptor)
        try:
            os.close(descriptor)
        finally:
            descriptor = -1
    except BaseException:
        try:
            if descriptor >= 0:
                with suppress(OSError):
                    stage.generation = os.fstat(descriptor)
                try:
                    os.close(descriptor)
                finally:
                    descriptor = -1
        finally:
            _unlink_token_rotation_stage(directory, stage)
        raise


def _write_private_path_stage_and_fsync(stage: _PathRotationStage, data: bytes) -> None:
    """Exclusively create one no-follow, owner-only, fully flushed path stage."""
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_BINARY", 0)
    )
    descriptor = -1
    try:
        descriptor = os.open(stage.destination, flags, 0o600)
        stage.generation = os.fstat(descriptor)
        _write_all_private_and_fsync(descriptor, stage.destination.name, data)
        stage.generation = os.fstat(descriptor)
        try:
            os.close(descriptor)
        finally:
            descriptor = -1
    except BaseException:
        try:
            if descriptor >= 0:
                with suppress(OSError):
                    stage.generation = os.fstat(descriptor)
                try:
                    os.close(descriptor)
                finally:
                    descriptor = -1
        finally:
            _unlink_path_rotation_stage(stage)
        raise


def _write_all_private_and_fsync(descriptor: int, name: str, data: bytes) -> None:
    if os.name == "posix":
        os.fchmod(descriptor, 0o600)
    view = memoryview(data)
    written = 0
    while written < len(view):
        count = os.write(descriptor, view[written:])
        if count <= 0:
            raise OSError(f"short write for {name}")
        written += count
    os.fsync(descriptor)


def _same_regular_file_generation(current: os.stat_result, expected: os.stat_result) -> bool:
    return (
        stat.S_ISREG(current.st_mode)
        and current.st_dev == expected.st_dev
        and current.st_ino == expected.st_ino
        and current.st_size == expected.st_size
        and current.st_mtime_ns == expected.st_mtime_ns
        and current.st_ctime_ns == expected.st_ctime_ns
    )


def _write_new_file_and_fsync(path: Path, data: bytes) -> None:
    with path.open("xb") as handle:
        written = handle.write(data)
        if written != len(data):
            raise OSError(f"short write for {path.name}")
        handle.flush()
        os.fsync(handle.fileno())


def _remove_orphan_token_temps(directory: _TokenDirectory, entries: Iterable[str]) -> None:
    removed = False
    for name in entries:
        if _TOKEN_ATOMIC_TEMP.fullmatch(name):
            directory.unlink(name, missing_ok=True)
            removed = True
    if removed:
        directory.fsync()


def _replace_path(source: Path, destination: Path) -> None:
    source.replace(destination)


_UNSUPPORTED_DIRECTORY_FSYNC = {
    errno.EACCES,
    errno.EBADF,
    errno.EINVAL,
    errno.EPERM,
    getattr(errno, "ENOTSUP", errno.EINVAL),
    getattr(errno, "EOPNOTSUPP", errno.EINVAL),
}


def _fsync_directory(path: Path) -> bool:
    """Sync directory entries when the host/filesystem exposes that operation."""
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        if os.name == "nt" or exc.errno in _UNSUPPORTED_DIRECTORY_FSYNC:
            return False
        raise
    try:
        try:
            os.fsync(descriptor)
        except OSError as exc:
            if os.name == "nt" or exc.errno in _UNSUPPORTED_DIRECTORY_FSYNC:
                return False
            raise
    finally:
        os.close(descriptor)
    return True


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
