# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Versioned, file-based configuration.

Policy is committed config a union edits for itself: which timestamp authorities
to trust, which peers to sync with, how packet shared copies handle metadata, and the
default language. There is nothing to administer centrally — this file *is* the
administration surface, and it is plain TOML so it diffs and reviews cleanly.
"""

from __future__ import annotations

import re
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

from .errors import ConfigError

__all__ = [
    "CONFIG_SCHEMA_VERSION",
    "Config",
    "LetterTemplate",
    "NetworkPolicy",
    "PacketTemplate",
    "PeerConfig",
    "SharingPolicy",
    "TSAConfig",
    "default_config_toml",
]

CONFIG_SCHEMA_VERSION = 1

# Review dates are plain calendar days and nothing else. Written `[0-9]` rather
# than `\d` on purpose: `\d` matches every Unicode decimal digit, so a fullwidth
# or Devanagari "2026" would satisfy the pattern and then raise deep inside
# `date.fromisoformat` instead of being named here as a bad config value.
_REVIEW_DATE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")


def _require_review_date(value: str, key: str) -> None:
    """Accept "" (unset) or a strict ``YYYY-MM-DD`` calendar date, else fail closed.

    Strictness is the point. ``date.fromisoformat`` alone accepts ``20260826`` and
    full timestamps, and a value that parses in one place but not another is how a
    date that was meant to expire quietly never does.
    """
    if not value:
        return
    if not _REVIEW_DATE.match(value):
        raise ConfigError(f"{key!r} must be a YYYY-MM-DD date, got {value!r}")
    try:
        date.fromisoformat(value)
    except ValueError as exc:
        raise ConfigError(f"{key!r} is not a real calendar date: {value!r}") from exc


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
    """How packet shared-media copies handle metadata. Defaults minimize disclosure."""

    strip_location: bool = True
    strip_all_metadata: bool = True
    # Retained for config compatibility. Packet v3 has no identity-bearing public
    # custody format, so packet export fails closed when this is true.
    export_custody_identities: bool = False


@dataclass(frozen=True, slots=True)
class NetworkPolicy:
    """When habitable is allowed to use a (possibly paid) network link (item R-19).

    A desktop CLI cannot reliably tell a metered cellular link from free Wi-Fi, so
    this is an explicit *gate*, not an auto-detected state: with ``allow_metered``
    false, network operations (relay sync, RFC 3161 timestamp fetches) refuse until
    the user re-runs with ``--allow-metered`` or on a link they consider free.
    """

    allow_metered: bool = True


@dataclass(frozen=True, slots=True)
class PacketTemplate:
    """Jurisdiction-specific wording for exported packets (presentation only).

    Adapting wording to a jurisdiction must never change the verification
    protocol — these strings appear in the PDF and the bundle, nothing more.
    """

    header: str = ""
    footer: str = ""


@dataclass(frozen=True, slots=True)
class LetterTemplate:
    """Defaults and locally-verified wording for generated repair-request letters.

    Like :class:`PacketTemplate`, this is presentation/policy a union edits for
    itself: who the letter is from, who it goes to, and which jurisdiction *framing*
    to use. ``jurisdiction`` selects a built-in :class:`~habitable.letter.LetterProfile`
    by key (e.g. ``"generic"``, ``"us_habitability"``); the built-ins make no
    statute-specific claim. A union that has confirmed its local law can override the
    header/footer text here. None of this changes how the underlying evidence verifies.

    ``header``/``footer`` are the documented home for a *locally verified* statutory
    citation (``docs/letter-generator.md``), which is the one string in this project
    that can go stale on a date nobody is watching: a statute is amended, a local
    ordinance is repealed, and the citation keeps going out on correspondence
    carrying a tenant's name. The three ``local_law_*`` fields date that wording and
    give it an expiry, so :func:`habitable.letter.build_letter` can leave stale
    wording out and say it did. See
    ``docs/adr/0013-dated-expiring-letter-jurisdiction-framing.md``.
    """

    sender_name: str = ""
    sender_contact: str = ""
    recipient_name: str = ""
    recipient_address: str = ""
    jurisdiction: str = "generic"
    cure_period_days: int = 0  # 0 = fall back to the profile's default
    header: str = ""
    footer: str = ""
    #: Who checked the ``header``/``footer`` wording against local law. Free text:
    #: a person, a legal-aid clinic, a union's housing committee.
    local_law_reviewer: str = ""
    #: ``YYYY-MM-DD`` the wording was last checked, or "" for undated.
    local_law_reviewed_at: str = ""
    #: ``YYYY-MM-DD`` the check goes stale, or "" for no expiry. On and after this
    #: date the wording is left out of generated letters rather than sent unchecked.
    local_law_expires_at: str = ""

    def __post_init__(self) -> None:
        # Validated here rather than only at TOML load, so a caller constructing a
        # template programmatically cannot smuggle in a date that never compares
        # true and therefore silently never expires.
        _require_review_date(self.local_law_reviewed_at, "local_law_reviewed_at")
        _require_review_date(self.local_law_expires_at, "local_law_expires_at")


@dataclass(frozen=True, slots=True)
class Config:
    """Resolved habitable configuration for one device.

    Note: the device ``node_id`` deliberately does *not* live here. It is a secret
    the clock uses as a tiebreaker, and pre-FIX-01 it was derived from the vault
    passphrase and written to this plaintext file — a brute-force oracle for a
    seized device. It now lives, random and passphrase-independent, inside the
    encrypted vault (see ``vault.py``); any legacy ``node_id`` key in a config
    file is ignored here and migrated out of plaintext on open.
    """

    schema_version: int = CONFIG_SCHEMA_VERSION
    language: str = "en"
    timestamp_authorities: Sequence[TSAConfig] = field(default_factory=tuple)
    sync_peers: Sequence[PeerConfig] = field(default_factory=tuple)
    sharing: SharingPolicy = field(default_factory=SharingPolicy)
    network: NetworkPolicy = field(default_factory=NetworkPolicy)
    packet_template: PacketTemplate = field(default_factory=PacketTemplate)
    letter: LetterTemplate = field(default_factory=LetterTemplate)

    @classmethod
    def default(cls, *, language: str = "en") -> Config:
        """A sensible default config: public RFC 3161 authorities, strict sharing."""
        return cls(
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
        # A legacy ``node_id`` key may still be present in pre-FIX-01 config files;
        # it is intentionally not read here (see the Config docstring).

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
        network_raw = raw.get("network")
        network = NetworkPolicy()
        if network_raw is not None:
            if not isinstance(network_raw, Mapping):
                raise ConfigError("[network] must be a table")
            network = NetworkPolicy(
                allow_metered=_opt_bool(network_raw, "allow_metered", True),
            )
        template_raw = raw.get("packet_template")
        template = PacketTemplate()
        if template_raw is not None:
            if not isinstance(template_raw, Mapping):
                raise ConfigError("[packet_template] must be a table")
            template = PacketTemplate(
                header=_opt_str(template_raw, "header", ""),
                footer=_opt_str(template_raw, "footer", ""),
            )
        letter_raw = raw.get("letter")
        letter = LetterTemplate()
        if letter_raw is not None:
            if not isinstance(letter_raw, Mapping):
                raise ConfigError("[letter] must be a table")
            letter = LetterTemplate(
                sender_name=_opt_str(letter_raw, "sender_name", ""),
                sender_contact=_opt_str(letter_raw, "sender_contact", ""),
                recipient_name=_opt_str(letter_raw, "recipient_name", ""),
                recipient_address=_opt_str(letter_raw, "recipient_address", ""),
                jurisdiction=_opt_str(letter_raw, "jurisdiction", "generic"),
                cure_period_days=_opt_int(letter_raw, "cure_period_days", 0),
                header=_opt_str(letter_raw, "header", ""),
                footer=_opt_str(letter_raw, "footer", ""),
                local_law_reviewer=_opt_str(letter_raw, "local_law_reviewer", ""),
                local_law_reviewed_at=_opt_str(letter_raw, "local_law_reviewed_at", ""),
                local_law_expires_at=_opt_str(letter_raw, "local_law_expires_at", ""),
            )
        return cls(
            schema_version=version,
            language=_opt_str(raw, "language", "en"),
            timestamp_authorities=tsas,
            sync_peers=peers,
            sharing=sharing,
            network=network,
            packet_template=template,
            letter=letter,
        )


def default_config_toml(*, language: str = "en") -> str:
    """Render a default config file for ``habitable init`` to write."""
    lines = [
        "# habitable configuration — committed policy a union edits for itself.",
        "# This file holds no secrets; keys and the device id live in the encrypted",
        "# vault, not here.",
        f"schema_version = {CONFIG_SCHEMA_VERSION}",
        f'language = "{language}"',
        "",
        "[sharing]",
        "# Packet shared-media copies minimize disclosure by default.",
        "strip_location = true",
        "strip_all_metadata = true",
        "# Reserved compatibility flag; packet export currently requires false.",
        "export_custody_identities = false",
        "",
        "[network]",
        "# Whether habitable may use a possibly-metered link for relay sync and",
        "# RFC 3161 timestamp fetches. A desktop CLI cannot detect metered links,",
        "# so this is an explicit gate: set false (or pass --wifi-only) to refuse",
        "# network operations until you re-run with --allow-metered or on Wi-Fi.",
        "allow_metered = true",
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
        "# Optional packet wording for your jurisdiction (presentation only;",
        "# it never changes how a packet verifies). Example:",
        "# [packet_template]",
        '# header = "Submitted under <your state> habitability law"',
        '# footer = "Prepared by <your tenant union>. Not legal advice."',
        "",
        "# Optional defaults for generated repair-request letters (presentation only).",
        "# jurisdiction selects a built-in framing profile "
        "(generic | us_habitability | ew_disrepair);",
        "# the built-ins make no statute-specific claim. Override wording you have",
        "# locally confirmed via header/footer. Not legal advice. Example:",
        "# [letter]",
        '# sender_name = "<your name>"',
        '# sender_contact = "<phone or email>"',
        '# recipient_name = "<landlord or property manager>"',
        '# recipient_address = "<mailing address>"',
        '# jurisdiction = "generic"',
        "# cure_period_days = 14",
        '# header = "Notice under <your state> habitability law, § <verified citation>"',
        '# footer = "Prepared with <your tenant union>. Not legal advice."',
        "",
        "# Who checked that header/footer wording against local law, and when. A",
        "# statute you cited correctly in 2026 can be amended in 2027, and the letter",
        "# goes out under a tenant's name. On and after local_law_expires_at habitable",
        "# leaves that wording OUT of the letter and tells you it did, rather than",
        "# sending an unchecked citation. Leave the dates empty and the wording is",
        "# used as-is and reported as undated.",
        '# local_law_reviewer = "<person or legal-aid clinic who checked it>"',
        '# local_law_reviewed_at = "2026-08-26"',
        '# local_law_expires_at = "2027-08-26"',
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
