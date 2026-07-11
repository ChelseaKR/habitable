# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Exception hierarchy for habitable.

Every failure mode an evidence tool cares about has a named, catchable type, so
callers (and the CLI) can react precisely and the export path can refuse to
present a compromised item rather than failing opaquely.
"""

from __future__ import annotations

__all__ = [
    "CaptureError",
    "ConfigError",
    "CryptoError",
    "CustodyError",
    "FixityError",
    "HabitableError",
    "LetterError",
    "PacketError",
    "ShareError",
    "SyncError",
    "TimestampError",
    "VaultError",
    "VaultLockedError",
    "VerificationError",
]


class HabitableError(Exception):
    """Base class for every error raised by habitable."""


class ConfigError(HabitableError):
    """Configuration is missing, malformed, or internally inconsistent."""


class CryptoError(HabitableError):
    """A cryptographic operation failed (bad key, failed authentication, ...)."""


class VaultError(HabitableError):
    """The case vault is malformed or an operation on it is invalid."""


class VaultLockedError(VaultError):
    """An operation needs an unlocked vault but no key has been supplied."""


class FixityError(HabitableError):
    """Stored bytes do not match their recorded content hash.

    Raised on a failed fixity check: silent corruption or tampering of a sealed
    original is surfaced, never passed through as if intact.
    """


class CustodyError(HabitableError):
    """The append-only chain of custody is broken, reordered, or unverifiable."""


class TimestampError(HabitableError):
    """A trusted-timestamp operation failed or a token did not verify."""


class CaptureError(HabitableError):
    """Media could not be captured/imported as evidence-grade."""


class PacketError(HabitableError):
    """An evidence packet could not be assembled."""


class VerificationError(HabitableError):
    """A packet (or one of its items) failed independent verification."""


class SyncError(HabitableError):
    """Peer-to-peer synchronization failed."""


class ShareError(HabitableError):
    """A case could not be shared or received."""


class LetterError(HabitableError):
    """A repair-request / notice letter could not be generated."""
