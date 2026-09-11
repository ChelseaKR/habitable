# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Move a sealed original to external storage without moving the evidence.

A low-end phone fills up, and video fills it fastest (RR-08, research item R-03).
Before this module the only way to reclaim that space was to delete a photograph,
which deletes the case. This gives the tenant the other option: carry the bytes
away on a USB stick or an SD card, and leave behind everything that makes them
evidence.

**Offloading is a storage decision, not an evidentiary one.** What stays in the
vault after an offload is the content hash committed at capture, every timestamp
token over that hash, and the whole chain of custody -- none of which the bytes
were ever part of. What leaves is one AEAD container whose key stays in the
vault. The chain is *extended*, not rewritten: a ``note_added`` entry records
that the original moved, and a second records it coming back, so the log says
where the bytes have been rather than pretending they never left.

Two consequences are deliberate and are stated wherever a reader can see them:

* **A packet cannot carry an item whose bytes are not here.** ``habitable export``
  refuses by default and names the captures to restore. The opt-in
  (``--allow-offloaded``) produces a packet that says which items are missing
  their bytes; :mod:`habitable.verify` reports that item as offloaded and still
  does *not* call it evidence-ready, because a content hash and a timestamp with
  nothing behind them are not evidence a human can look at (issue #158).
* **Sync cannot send bytes this device does not hold.** ``habitable sync`` refuses
  up front rather than failing deep inside the exporter.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .errors import HabitableError
from .evidence import CUSTODY_EVENT_OFFLOADED, CUSTODY_EVENT_RESTORED, CustodyAction
from .obslog import log_event
from .vault import OffloadRecord, Vault

__all__ = ["OffloadResult", "offload_item", "offloaded_item_ids", "restore_item"]


@dataclass(frozen=True, slots=True)
class OffloadResult:
    """What one offload or restore did, for the caller to print."""

    capture_id: str
    content_hash: str
    container_name: str
    container_hash: str
    reclaimed_bytes: int


def offloaded_item_ids(vault: Vault) -> tuple[str, ...]:
    """Every item on this device whose sealed original is on external storage."""
    return tuple(record.capture_id for record in vault.offloaded_records())


def _content_hash_of(vault: Vault, item_id: str) -> str:
    """The content hash a capture or a sealed artifact committed at capture.

    Both record kinds seal an original the same way, so both can be offloaded;
    resolving the hash through the case document rather than through the caller
    keeps a mistyped hash from ever reaching the container's AAD.
    """
    for capture in vault.document.captures():
        if capture.capture_id == item_id:
            return capture.content_hash
    for artifact in vault.document.artifacts():
        if artifact.artifact_id == item_id:
            return artifact.content_hash
    raise HabitableError(f"unknown evidence record: {item_id!r}")


def offload_item(
    vault: Vault,
    item_id: str,
    destination: Path,
    *,
    label: str = "",
    actor: str | None = None,
) -> OffloadResult:
    """Move one sealed original to ``destination`` and record the move.

    The custody entry is appended *after* :meth:`Vault.offload_original` has
    written the container, read it back, decrypted it and re-hashed it, so the
    chain never claims a move that did not happen. It is a ``note_added`` entry
    carrying ``details["event"] = "offloaded"`` rather than a new
    ``CustodyAction`` member: see :mod:`habitable.evidence` for why the
    vocabulary is not extended here.
    """
    content_hash = _content_hash_of(vault, item_id)
    actor_id = actor or vault.identity.public().fingerprint
    stamp = vault.document.clock.now()
    record = vault.offload_original(
        item_id,
        content_hash,
        destination,
        label=label,
        offloaded_at=stamp.encode(),
    )
    vault.custody.append(
        CustodyAction.NOTE_ADDED,
        item_id,
        actor=actor_id,
        hlc=vault.document.clock.now().encode(),
        details={
            "event": CUSTODY_EVENT_OFFLOADED,
            "content_hash": content_hash,
            "container_hash": record.container_hash,
        },
        # Which drive, and where it is, is a fact about a person's home. It stays
        # in the vault-only half of the entry, which is never hashed and never
        # exported, exactly like the tenant's source filename at capture.
        private_details=_private_details(record, destination),
        identity=vault.identity,
    )
    vault.save()
    log_event(
        "offload",
        event=CUSTODY_EVENT_OFFLOADED,
        bytes=record.sealed_bytes,
        content_hash=content_hash[:12],
    )
    return _result(record)


def restore_item(
    vault: Vault,
    item_id: str,
    source: Path,
    *,
    actor: str | None = None,
) -> OffloadResult:
    """Re-attach an offloaded original from ``source``, or refuse.

    A container whose bytes no longer hash to what was recorded when it was
    written is refused before it is decrypted, and nothing in the vault changes.
    """
    actor_id = actor or vault.identity.public().fingerprint
    record = vault.restore_original(item_id, source)
    vault.custody.append(
        CustodyAction.NOTE_ADDED,
        item_id,
        actor=actor_id,
        hlc=vault.document.clock.now().encode(),
        details={
            "event": CUSTODY_EVENT_RESTORED,
            "content_hash": record.content_hash,
            "container_hash": record.container_hash,
        },
        private_details=_private_details(record, source),
        identity=vault.identity,
    )
    vault.save()
    log_event(
        "offload",
        event=CUSTODY_EVENT_RESTORED,
        bytes=record.sealed_bytes,
        content_hash=record.content_hash[:12],
    )
    return _result(record)


def _private_details(record: OffloadRecord, path: Path) -> dict[str, str]:
    details = {"container_path": str(path)}
    if record.target_label:
        details["target_label"] = record.target_label
    return details


def _result(record: OffloadRecord) -> OffloadResult:
    return OffloadResult(
        capture_id=record.capture_id,
        content_hash=record.content_hash,
        container_name=record.container_name,
        container_hash=record.container_hash,
        reclaimed_bytes=record.sealed_bytes,
    )
