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
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from .canonical import JSONValue, canonical_json, sha256_bytes
from .clock import HybridLogicalClock, wall_clock_ms
from .config import Config, default_config_toml
from .crypto import Identity, SymmetricKey, create_keyfile, open_keyfile
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
_DEFERRED = "deferred.enc"
_ORIGINALS = "originals"
_TOKENS = "tokens"


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

        node_id = sha256_bytes(case_id.encode() + passphrase.encode())[:16]
        config = Config.default(node_id, language=language)
        (path / _CONFIG).write_text(
            default_config_toml(node_id, language=language), encoding="utf-8"
        )

        keyfile, dek = create_keyfile(passphrase)
        (path / _KEYFILE).write_text(keyfile, encoding="utf-8")

        identity = Identity.generate()
        clock = HybridLogicalClock(node_id, time_source=time_source)
        document = CaseDocument(case_id, clock)
        if unit:
            document.set_meta("unit", unit)
        vault = cls(path, config, dek, identity, document, CustodyLog(), [])
        vault._write_blob(_IDENTITY, identity.serialize())
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
        clock = HybridLogicalClock(config.node_id, time_source=time_source)
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
        sealed_name = f"{capture_id}.enc"
        aad = f"original:{capture_id}:{content_hash}".encode()
        (self.path / _ORIGINALS / sealed_name).write_bytes(self._dek.encrypt(raw, aad=aad))
        return sealed_name

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
