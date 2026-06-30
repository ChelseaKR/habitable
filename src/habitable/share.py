# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""End-to-end-encrypted case sharing with a tenant-union organizer.

Sync (:mod:`habitable.sync`) keeps two devices on *the same* case in step. Sharing
is the one-way cousin: a tenant hands a case — or a **redactable subset of it** — to
an organizer who was not previously on the case, without any server ever being able
to read it.

How it preserves end-to-end encryption
--------------------------------------
A share is exactly a sync message, reusing the same primitives:

* The tenant builds a CRDT state with :meth:`CaseDocument.subset_state`, optionally
  scoped to chosen issues and with the unit label redacted. Only the sealed
  originals for the selected issues are attached.
* That payload is **signed** by the tenant's device key and **sealed** to the
  organizer's X25519 public key (:func:`habitable.crypto.seal_to`, an ephemeral-key
  ECIES box). Only the holder of the organizer's private key can open it; a relay,
  a courier, or a cloud drive used to move the ``.share`` file sees ciphertext only.
* On receipt the organizer's device verifies the signature, checks the share is for
  the case they opened, re-checks each original's fixity, validates any RFC 3161
  token, and merges the CRDT subset. Because the model is a CRDT, receiving the same
  share twice changes nothing.

Trust / key-exchange model (see ``docs/sharing-trust-model.md``)
---------------------------------------------------------------
Trust is **direct and out-of-band**, with no central directory. The organizer runs
``habitable id`` and gives the tenant their public identity; the tenant confirms the
short fingerprint over a trusted channel (in person, a verified call) before sharing
— this is the human step that defeats a man-in-the-middle. The tenant then seals the
(possibly redacted) subset to that key. The server is never trusted: it cannot read,
forge (messages are signed), or silently substitute a recipient (the tenant pins the
fingerprint they verified).
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
    """Seal a case (or a redactable subset) to ``recipient``, returning sealed bytes.

    ``issue_ids`` of ``None`` shares the whole case; a set shares only those issues,
    their timeline entries, and their captures. ``redact_unit`` drops the case's unit
    label from the shared CRDT state so a subset need not reveal which unit it is.
    The result is signed and sealed — safe to move over any untrusted channel.
    """
    selected: set[str] | None = None
    if issue_ids is not None:
        known = {issue.issue_id for issue in vault.document.issues()}
        unknown = issue_ids - known
        if unknown:
            raise ShareError(f"unknown issue(s) to share: {', '.join(sorted(unknown))}")
        selected = set(issue_ids)

    state = vault.document.subset_state(selected, redact_meta=redact_unit)
    capture_ids = (
        None
        if selected is None
        else {c.capture_id for c in vault.document.captures() if c.issue_id in selected}
    )
    return export_message(vault, recipient, state=state, capture_ids=capture_ids)


def import_share(vault: Vault, blob: bytes) -> ShareResult:
    """Open a sealed share addressed to this device and merge it into ``vault``.

    Rejects a share addressed to a different case (the recipient must have opened a
    vault for the same ``case_id``). Signature, fixity, and timestamp checks all run
    inside :func:`habitable.sync.import_messages`; a share not addressed to this
    device (wrong key) merges nothing rather than raising.
    """
    result = import_messages(vault, [blob], require_case_id=vault.document.case_id)
    if result.messages_merged == 0:
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
