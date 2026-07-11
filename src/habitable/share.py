# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""End-to-end-encrypted case sharing with a tenant-union organizer.

Sync (:mod:`habitable.sync`) keeps two devices on *the same* case in step. Sharing
is the one-way cousin: a tenant hands a case to an organizer who was not previously
on it, without any server ever being able to read it. The ``unit`` metadata field can be
omitted, but other full-case content can still identify the unit.
Issue-subset sharing is temporarily blocked because sync v2 carries a complete custody
proof that can reveal identifiers outside the selected subset.

How it preserves end-to-end encryption
--------------------------------------
A share is exactly a sync message, reusing the same primitives:

* The tenant builds a full-case CRDT state, optionally with the unit label redacted,
  and attaches the case's sealed originals.
* The devices first exchange signed, recipient-sealed, case-bound pairing
  material. The exact expected identity and pairing key are pinned in each
  encrypted vault; a public id alone is not authorization.
* The payload is **signed** by the tenant's device key, authenticated with the
  pairing key, and **sealed** to the
  organizer's X25519 public key (:func:`habitable.crypto.seal_to`, an ephemeral-key
  ECIES box). Only the holder of the organizer's private key can open it; a relay,
  a courier, or a cloud drive used to move the ``.share`` file sees ciphertext only.
* On receipt the organizer's device verifies the signature, checks the share is for
  the case they opened, re-checks each original's fixity, validates any RFC 3161
  token, and merges the CRDT state. Because the model is a CRDT, receiving the same
  share twice changes nothing.

Trust / key-exchange model (see ``docs/sharing-trust-model.md``)
---------------------------------------------------------------
Trust is **direct and out-of-band**, with no central directory. The organizer runs
``habitable id`` and gives the tenant their public identity; the tenant confirms the
short fingerprint over a trusted channel (in person, a verified call) before sharing
— this is the human step that defeats a man-in-the-middle. The devices then use
``sync-pair-create`` / ``sync-pair-accept`` before the tenant seals the case.
The server is never trusted: it cannot read, forge, or authorize a recipient.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass

from .crypto import PublicIdentity
from .errors import ShareError
from .sync import export_message, import_messages
from .vault import Vault

__all__ = [
    "ShareResult",
    "decode_share",
    "encode_share",
    "export_share",
    "import_share",
]


@dataclass(frozen=True, slots=True)
class ShareResult:
    """What a received share contributed to the organizer's vault."""

    case_id: str
    captures_imported: int
    merged: bool


def export_share(
    vault: Vault,
    recipient: PublicIdentity,
    *,
    issue_ids: set[str] | None = None,
    redact_unit: bool = False,
) -> bytes:
    """Seal a full case to ``recipient``, returning sealed bytes.

    ``issue_ids`` is retained as an API/CLI compatibility parameter, but any value
    other than ``None`` fails before state attestation or sync-message construction.
    ``redact_unit`` may still omit the ``unit`` metadata field from an otherwise
    full-case state. It is field-level omission, not an anonymity guarantee.
    The result is signed and sealed — safe to move over any untrusted channel.
    """
    if issue_ids is not None:
        raise ShareError(
            "scoped shares are temporarily blocked: sync v2 carries the complete custody "
            "chain, which can reveal identifiers outside the selected issues; share the "
            "whole case until a versioned scoped custody-view protocol is available"
        )

    vault.document.attest_unsigned_fields()
    state = vault.document.subset_state(None, redact_meta=redact_unit)
    return export_message(vault, recipient, state=state)


def import_share(vault: Vault, blob: bytes) -> ShareResult:
    """Open a sealed share addressed to this device and merge it into ``vault``.

    Rejects a share addressed to a different case (the recipient must have opened a
    vault for the same ``case_id``). Signature, fixity, and timestamp checks all run
    inside :func:`habitable.sync.import_messages`; a share not addressed to this
    device (wrong key) merges nothing rather than raising.
    """
    result = import_messages(vault, [blob], require_case_id=vault.document.case_id)
    if result.messages_merged == 0:
        if result.replays_skipped:
            return ShareResult(
                case_id=vault.document.case_id,
                captures_imported=0,
                merged=True,
            )
        raise ShareError(
            "no share opened: it is not sealed to this device's key, or not a share message"
        )
    return ShareResult(
        case_id=vault.document.case_id,
        captures_imported=result.captures_imported,
        merged=True,
    )


def encode_share(blob: bytes) -> str:
    """Wrap sealed share bytes as a single base64 line for a portable ``.share`` file."""
    return base64.b64encode(blob).decode("ascii")


def decode_share(text: str) -> bytes:
    """Read sealed share bytes from a ``.share`` file produced by :func:`encode_share`."""
    try:
        return base64.b64decode(text.strip(), validate=True)
    except ValueError as exc:
        raise ShareError("share file is not valid base64") from exc
