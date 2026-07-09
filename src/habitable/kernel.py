# SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0
# Copyright 2026 Chelsea Kelly-Reif
"""The reusable, local-first evidence kernel — a stable, embeddable public surface.

This module is the single import target for the tamper-evidence *kernel*: the small,
correct, fail-closed spine that other civic tools (a wage-theft documenter, an
environmental-hazard logger, any "prove this record wasn't altered after the fact"
tool) need. It re-exports — and thereby *names as public and versioned* — the pure,
verification-facing subset of habitable:

    * canonical serialization + SHA-256          (``habitable.canonical``)
    * chain-of-custody model + verification       (``habitable.evidence``)
    * RFC 3161 timestamp model + token verify      (``habitable.tsa``)
    * Ed25519 signature verification + identity      (``habitable.crypto`` — verify half)
    * the packet verifier + its report                (``habitable.verify``)

Everything re-exported here is offered under **Apache-2.0** as an additional permission
(GPLv3 §7) — see ``NOTICE`` — so a court, legal-aid group, or a second civic tool can
embed and redistribute verification without the AGPL reaching their code. Importing this
module pulls in only that subset (no relay/sync/cli/app/capture/vault), guarded by
``tests/test_guards.py`` and ``tests/test_kernel_golden.py``.

Stability contract
------------------
``KERNEL_API_VERSION`` is **semantic versioning for the names exported here and the wire
formats they produce**, independent of the habitable application version. Within a major:

    * names in ``__all__`` are not removed and keep their meaning;
    * ``canonical_json`` bytes, ``sha256_bytes`` output, and the custody entry-hash rule
      are frozen — pinned byte-for-byte by ``tests/golden/kernel/vectors.json``;
    * the packet ``packet_version`` gates its own compatibility (see ``verify`` and the
      committed golden-packet corpus).

A breaking change to any of the above is a major bump with a migration note in
``CHANGELOG.md``. See ``docs/evidence-kernel.md`` for the full spec and adoption guide.
"""

from __future__ import annotations

from habitable.canonical import (
    HASH_ALGORITHM,
    JSONValue,
    canonical_json,
    sha256_bytes,
    sha256_file,
)
from habitable.crypto import PublicIdentity
from habitable.crypto import verify as verify_signature
from habitable.evidence import (
    GENESIS_PREV_HASH,
    CustodyAction,
    CustodyEntry,
    CustodyLog,
    CustodyVerification,
    ItemCustodySummary,
    content_hash,
    fixity_ok,
    verify_fixity,
)
from habitable.tsa import (
    TimestampAuthority,
    TimestampInfo,
    TimestampToken,
    TokenKind,
    verify_archive_chain,
    verify_token,
)
from habitable.verify import (
    SUPPORTED_PACKET_VERSION,
    ItemVerdict,
    VerificationReport,
    verify_packet,
)

#: Name of the kernel as an installable/embeddable unit (see ``docs/evidence-kernel.md``).
KERNEL_NAME = "habitable-evidence-kernel"

#: Semantic version of the *kernel public API and wire formats*, independent of the
#: habitable application version in ``pyproject.toml``. Bump per the contract above.
KERNEL_API_VERSION = "1.0.0"

# Grouped by layer in the module docstring and import block above; kept alphabetical
# here so it stays diff-stable as the surface grows.
__all__ = [
    "GENESIS_PREV_HASH",
    "HASH_ALGORITHM",
    "KERNEL_API_VERSION",
    "KERNEL_NAME",
    "SUPPORTED_PACKET_VERSION",
    "CustodyAction",
    "CustodyEntry",
    "CustodyLog",
    "CustodyVerification",
    "ItemCustodySummary",
    "ItemVerdict",
    "JSONValue",
    "PublicIdentity",
    "TimestampAuthority",
    "TimestampInfo",
    "TimestampToken",
    "TokenKind",
    "VerificationReport",
    "canonical_json",
    "content_hash",
    "fixity_ok",
    "sha256_bytes",
    "sha256_file",
    "verify_archive_chain",
    "verify_fixity",
    "verify_packet",
    "verify_signature",
    "verify_token",
]
