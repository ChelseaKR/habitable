# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Versioned, file-based configuration.

Policy is committed config a union edits for itself: which timestamp authorities
to trust, which peers to sync with, whether shared copies strip location, and the
default language. There is nothing to administer centrally — this file *is* the
administration surface, and it is plain TOML so it diffs and reviews cleanly.
"""

from __future__ import annotations

import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import ConfigError

__all__ = [
    "CONFIG_SCHEMA_VERSION",
    "Config",
    "PeerConfig",
    "SharingPolicy",
    "TSAConfig",
    "default_config_toml",
]

CONFIG_SCHEMA_VERSION = 1

# Public, free RFC 3161 timestamp authorities are configured by default so a union
# never has to pay for or host one. The dev authority is for offline tests/demos
# only and is clearly labelled as non-production everywhere it appears.
_DEFAULT_TSAS = (
    ("freetsa", "rfc3161", "https://freetsa.org/tsr"),
    ("digicert", "rfc3161", "http://timestamp.digicert.com"),
)


@dataclass(frozen=True, slots=True)
class TSAConfig:
    """A timestamp authority habitable may use to prove content existence time."""

    name: str
    kind: str  # "rfc3161" | "dev"
    url: str = ""

    def __post_init__(self) -> None:
        if self.kind not in {"rfc3161", "dev"}:
            raise ConfigError(f"unknown timestamp-authority kind: {self.kind!r}")
        if self.kind == "rfc3161" and not self.url:
            raise ConfigError(f"rfc3161 authority {self.name!r} requires a url")


@dataclass(frozen=True, slots=True)
class PeerConfig:
    """A peer to sync a case with, over a local directory or a relay."""

    name: str
    transport: str  # "local" | "relay"
    location: str  # directory path (local) or relay base URL (relay)
    room: str = ""  # relay room/mailbox id (relay transport only)

    def __post_init__(self) -> None:
        if self.transport not in {"local", "relay"}:
            raise ConfigError(f"unknown peer transport: {self.transport!r}")
        if self.transport == "relay" and not self.room:
            raise ConfigError(f"relay peer {self.name!r} requires a room")


@dataclass(frozen=True, slots=True)
class SharingPolicy:
    """What a shared/exported copy discloses. Defaults minimize disclosure."""

    strip_location: bool = True
    strip_all_metadata: bool = True
    export_custody_identities: bool = False


@dataclass(frozen=True, slots=True)
class Config:
    """Resolved habitable configuration for one device."""

    node_id: str
    schema_version: int = CONFIG_SCHEMA_VERSION
    language: str = "en"
    timestamp_authorities: Sequence[TSAConfig] = field(default_factory=tuple)
    sync_peers: Sequence[PeerConfig] = field(default_factory=tuple)
    sharing: SharingPolicy = field(default_factory=SharingPolicy)

    @classmethod
    def default(cls, node_id: str, *, language: str = "en") -> Config:
        """A sensible default config: public RFC 3161 authorities, strict sharing."""
        return cls(
            node_id=node_id,
            language=language,
            timestamp_authorities=tuple(
                TSAConfig(name=n, kind=k, url=u) for n, k, u in _DEFAULT_TSAS
            ),
        )

    @classmethod
    def from_toml(cls, path: Path) -> Config:
        """Load and validate a config TOML file."""
        try:
            raw = tomllib.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise ConfigError(f"config not found: {path}") from exc
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise ConfigError(f"could not read config {path}: {exc}") from exc
        return cls.from_mapping(raw)

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> Config:
        """Build a :class:`Config` from a parsed mapping, validating as we go."""
        version = _opt_int(raw, "schema_version", CONFIG_SCHEMA_VERSION)
        if version > CONFIG_SCHEMA_VERSION:
            raise ConfigError(
                f"config schema_version {version} is newer than supported "
                f"{CONFIG_SCHEMA_VERSION}; upgrade habitable"
            )
        node_id = _require_str(raw, "node_id")

        tsas = tuple(
            TSAConfig(
                name=_require_str(t, "name"),
                kind=_require_str(t, "kind"),
                url=_opt_str(t, "url", ""),
            )
            for t in _tables(raw, "timestamp_authorities")
        )
        peers = tuple(
            PeerConfig(
                name=_require_str(p, "name"),
                transport=_require_str(p, "transport"),
                location=_require_str(p, "location"),
                room=_opt_str(p, "room", ""),
            )
            for p in _tables(raw, "sync_peers")
        )
        sharing_raw = raw.get("sharing")
        sharing = SharingPolicy()
        if sharing_raw is not None:
            if not isinstance(sharing_raw, Mapping):
                raise ConfigError("[sharing] must be a table")
            sharing = SharingPolicy(
                strip_location=_opt_bool(sharing_raw, "strip_location", True),
                strip_all_metadata=_opt_bool(sharing_raw, "strip_all_metadata", True),
                export_custody_identities=_opt_bool(
                    sharing_raw, "export_custody_identities", False
                ),
            )
        return cls(
            node_id=node_id,
            schema_version=version,
            language=_opt_str(raw, "language", "en"),
            timestamp_authorities=tsas,
            sync_peers=peers,
            sharing=sharing,
        )


def default_config_toml(node_id: str, *, language: str = "en") -> str:
    """Render a default config file for ``habitable init`` to write."""
    lines = [
        "# habitable configuration — committed policy a union edits for itself.",
        "# This file holds no secrets; keys live in the encrypted vault, not here.",
        f"schema_version = {CONFIG_SCHEMA_VERSION}",
        f'node_id = "{node_id}"',
        f'language = "{language}"',
        "",
        "[sharing]",
        "# Shared/exported copies minimize disclosure by default.",
        "strip_location = true",
        "strip_all_metadata = true",
        "export_custody_identities = false",
        "",
        "# Trusted timestamp authorities (RFC 3161). Multiple = no single point of trust.",
    ]
    for name, kind, url in _DEFAULT_TSAS:
        lines += [
            "[[timestamp_authorities]]",
            f'name = "{name}"',
            f'kind = "{kind}"',
            f'url = "{url}"',
            "",
        ]
    lines += [
        "# Sync peers (added with `habitable peer add`). Example:",
        "# [[sync_peers]]",
        '# name = "organizer-phone"',
        '# transport = "relay"      # or "local"',
        '# location = "https://relay.example.org"',
        '# room = "<shared-room-id>"',
        "",
    ]
    return "\n".join(lines)


# --- typed extraction helpers (keep tomllib's Any from leaking into the API) ---


def _tables(raw: Mapping[str, Any], key: str) -> list[Mapping[str, Any]]:
    value = raw.get(key, [])
    if not isinstance(value, Sequence) or isinstance(value, str | bytes):
        raise ConfigError(f"[{key}] must be an array of tables")
    out: list[Mapping[str, Any]] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise ConfigError(f"each entry in [{key}] must be a table")
        out.append(item)
    return out


def _require_str(raw: Mapping[str, Any], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value:
        raise ConfigError(f"missing or invalid required string: {key!r}")
    return value


def _opt_str(raw: Mapping[str, Any], key: str, default: str) -> str:
    value = raw.get(key, default)
    if not isinstance(value, str):
        raise ConfigError(f"{key!r} must be a string")
    return value


def _opt_bool(raw: Mapping[str, Any], key: str, default: bool) -> bool:
    value = raw.get(key, default)
    if not isinstance(value, bool):
        raise ConfigError(f"{key!r} must be a boolean")
    return value


def _opt_int(raw: Mapping[str, Any], key: str, default: int) -> int:
    value = raw.get(key, default)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ConfigError(f"{key!r} must be an integer")
    return value
