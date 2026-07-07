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
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from .canonical import JSONValue, canonical_json, sha256_bytes
from .clock import HybridLogicalClock, wall_clock_ms
from .config import Config, default_config_toml
from .crypto import (
    Identity,
    SymmetricKey,
    create_keyfile,
    export_recovery_blob,
    import_recovery_blob,
    open_keyfile,
)
from .errors import FixityError, VaultError
from .evidence import CustodyLog
from .model import CaseDocument
from .tsa import TimestampToken

__all__ = ["DeferredItem", "Vault"]

_CONFIG = "config.toml"
_KEYFILE = "keyfile.json"
_CASE = "case.enc"
_CUSTODY = "custody.enc"
_IDENTITY = "identity.enc"
_NODE = "node.enc"
_DEFERRED = "deferred.enc"
_ORIGINALS = "originals"
_TOKENS = "tokens"

# Pre-FIX-01 vaults wrote the device node_id into plaintext config.toml; this
# matches that line so a legacy vault can be migrated (the value moves into the
# encrypted vault and the plaintext line is stripped) on first open.
_LEGACY_NODE_ID_LINE = re.compile(r"^\s*node_id\s*=")


@dataclass(frozen=True, slots=True)
class DeferredItem:
    """A capture awaiting a trusted timestamp (created while offline)."""

    capture_id: str
    digest: str


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
    ) -> None:
        self.path = path
        self.config = config
        self._dek = dek
        self.identity = identity
        self.document = document
        self.custody = custody
        self._deferred = deferred

    # --- lifecycle ------------------------------------------------------------

    @classmethod
    def create(
        cls,
        path: Path,
        passphrase: str,
        *,
        case_id: str,
        unit: str = "",
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
        document = CaseDocument(case_id, clock)
        if unit:
            document.set_meta("unit", unit)
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
        document.catch_up_clock()

        custody_records = _decode_json(_read_blob(path, dek, _CUSTODY))
        custody = CustodyLog.from_records(_as_record_list(custody_records))

        deferred_raw = _decode_json(_read_blob(path, dek, _DEFERRED))
        deferred = [
            DeferredItem(capture_id=str(item["capture_id"]), digest=str(item["digest"]))
            for item in _as_record_list(deferred_raw)
        ]
        return cls(path, config, dek, identity, document, custody, deferred)

    # --- key management -------------------------------------------------------

    def rotate_passphrase(self, new_passphrase: str) -> None:
        """Re-wrap the in-memory data key under a new passphrase.

        Cheap by design: the bulk data is never re-encrypted — only the small
        passphrase-wrapped key is replaced.
        """
        (self.path / _KEYFILE).write_text(
            export_recovery_blob(self._dek, new_passphrase), encoding="utf-8"
        )

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

    def save(self) -> None:
        """Persist the document, custody log, and deferred queue (encrypted)."""
        self._write_blob(_CASE, canonical_json(self.document.to_state()))
        self._write_blob(
            _CUSTODY, canonical_json(_records_to_json(self.custody.to_vault_records()))
        )
        deferred_json: JSONValue = [
            {"capture_id": item.capture_id, "digest": item.digest} for item in self._deferred
        ]
        self._write_blob(_DEFERRED, canonical_json(deferred_json))

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
