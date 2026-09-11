# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Offloading a sealed original to external storage (issue #296, RR-08).

The property under test throughout is that offloading moves *bytes* and nothing
else: the content hash the timestamp token covers, the tokens, and the chain of
custody all stay, and the chain is extended rather than rewritten.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from habitable.capture import capture
from habitable.errors import FixityError, HabitableError, VaultError
from habitable.evidence import CUSTODY_EVENT_OFFLOADED, CUSTODY_EVENT_RESTORED
from habitable.offload import offload_item, offloaded_item_ids, restore_item
from habitable.tsa import DevTSA
from habitable.vault import OFFLOAD_CONTAINER_SUFFIX, Vault


def _case(make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path]) -> tuple[Vault, str]:
    vault = make_vault()
    issue = vault.document.add_issue(category="mold", room="bathroom", title="mold above the bath")
    result = capture(vault, make_jpeg("evidence.jpg"), issue_id=issue, tsa=DevTSA())
    vault.save()
    return vault, result.capture_id


def test_offload_then_restore_returns_byte_identical_original(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], tmp_path: Path
) -> None:
    """The first `Done when`: a round trip gives back exactly the bytes that left.

    Compared against the plaintext read *before* the offload, not against the
    source file, so a re-seal that changed the bytes could not pass by hashing
    something else.
    """
    vault, capture_id = _case(make_vault, make_jpeg)
    content_hash = vault.document.captures()[0].content_hash
    before = vault.read_original(capture_id, content_hash)
    drive = tmp_path / "usb"
    drive.mkdir()

    offload_item(vault, capture_id, drive, label="green USB stick")
    assert not vault.has_original(capture_id)
    assert vault.is_offloaded(capture_id)
    assert (drive / f"{capture_id}{OFFLOAD_CONTAINER_SUFFIX}").is_file()

    restore_item(vault, capture_id, drive)
    assert vault.has_original(capture_id)
    assert not vault.is_offloaded(capture_id)
    assert vault.read_original(capture_id, content_hash) == before


def test_offload_removes_exactly_the_sealed_bytes_it_reports(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], tmp_path: Path
) -> None:
    """`reclaimed_bytes` is the sealed original's size, measured, not estimated."""
    vault, capture_id = _case(make_vault, make_jpeg)
    drive = tmp_path / "usb"
    drive.mkdir()
    before = vault.storage_footprint()

    result = offload_item(vault, capture_id, drive)
    after = vault.storage_footprint()

    assert result.reclaimed_bytes > 0
    assert before.sealed_originals_bytes - after.sealed_originals_bytes == result.reclaimed_bytes


def test_offloading_a_small_capture_can_make_the_vault_larger(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], tmp_path: Path
) -> None:
    """Measured, and the reason `offload` never prints "you saved N bytes".

    The offload record and the two custody entries are themselves stored, so the
    vault grows by a few hundred bytes every time. For a phone-sized video that
    is noise; for the synthetic 731-byte JPEG in this suite it is larger than the
    original, and the vault ends up bigger than it started. A feature that
    reported the sealed size as a saving would be publishing an absence as a
    value in the direction that flatters it, so the CLI reports the sealed bytes
    removed and then re-measures what is on the device.
    """
    vault, capture_id = _case(make_vault, make_jpeg)
    drive = tmp_path / "usb"
    drive.mkdir()
    before = vault.storage_footprint().on_disk_bytes

    result = offload_item(vault, capture_id, drive)
    after = vault.storage_footprint().on_disk_bytes

    assert result.reclaimed_bytes < 4096  # the fixture JPEG is tiny
    assert after > before - result.reclaimed_bytes


def test_the_custody_chain_is_extended_and_still_verifies(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], tmp_path: Path
) -> None:
    """Offload and restore each append exactly one entry, and nothing before them moves.

    "An unchanged custody chain head" cannot mean the head hash is the same
    afterwards -- a chain that recorded nothing would be a chain that lied about
    where the bytes went. What must not change is the history: every entry that
    existed before the offload is byte-identical after the round trip, and the
    chain still walks.
    """
    vault, capture_id = _case(make_vault, make_jpeg)
    drive = tmp_path / "usb"
    drive.mkdir()
    before = vault.custody.entries

    offload_item(vault, capture_id, drive)
    restore_item(vault, capture_id, drive)

    after = vault.custody.entries
    assert after[: len(before)] == before
    assert len(after) == len(before) + 2
    assert [entry.details.get("event") for entry in after[len(before) :]] == [
        CUSTODY_EVENT_OFFLOADED,
        CUSTODY_EVENT_RESTORED,
    ]
    assert vault.custody.verify().head_hash == vault.custody.head_hash


def test_the_content_hash_and_timestamp_token_are_untouched_by_a_round_trip(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], tmp_path: Path
) -> None:
    """Offload is a storage decision: the evidentiary facts must be identical after it."""
    vault, capture_id = _case(make_vault, make_jpeg)
    drive = tmp_path / "usb"
    drive.mkdir()
    before_hash = vault.document.captures()[0].content_hash
    token = vault.get_token(capture_id)
    assert token is not None
    before_token = token.to_dict()

    offload_item(vault, capture_id, drive)
    # Still true while the bytes are away: this is the "custody-bound stub".
    assert vault.document.captures()[0].content_hash == before_hash
    during = vault.get_token(capture_id)
    assert during is not None and during.to_dict() == before_token

    restore_item(vault, capture_id, drive)
    after = vault.get_token(capture_id)
    assert after is not None and after.to_dict() == before_token
    assert vault.document.captures()[0].content_hash == before_hash


def test_restoring_altered_container_bytes_is_refused_and_names_the_mismatch(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], tmp_path: Path
) -> None:
    """The second `Done when`. One flipped byte on the drive must not become evidence."""
    vault, capture_id = _case(make_vault, make_jpeg)
    drive = tmp_path / "usb"
    drive.mkdir()
    record = offload_item(vault, capture_id, drive)
    container = drive / record.container_name

    data = bytearray(container.read_bytes())
    data[-1] ^= 0x01
    container.write_bytes(bytes(data))

    with pytest.raises(FixityError) as excinfo:
        restore_item(vault, capture_id, drive)
    message = str(excinfo.value)
    assert "does not match the hash recorded" in message
    assert record.container_hash[:12] in message
    # Refused, and nothing changed: still offloaded, still no bytes on the device.
    assert vault.is_offloaded(capture_id)
    assert not vault.has_original(capture_id)


def test_a_truncated_container_is_refused_rather_than_half_restored(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], tmp_path: Path
) -> None:
    """A drive that lost the tail of the file is the likeliest real corruption."""
    vault, capture_id = _case(make_vault, make_jpeg)
    drive = tmp_path / "usb"
    drive.mkdir()
    record = offload_item(vault, capture_id, drive)
    container = drive / record.container_name
    container.write_bytes(container.read_bytes()[:-64])

    with pytest.raises(FixityError):
        restore_item(vault, capture_id, drive)
    assert not vault.has_original(capture_id)


def test_a_missing_drive_is_named_rather_than_crashed_on(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], tmp_path: Path
) -> None:
    vault, capture_id = _case(make_vault, make_jpeg)
    drive = tmp_path / "usb"
    drive.mkdir()
    offload_item(vault, capture_id, drive)

    elsewhere = tmp_path / "not-the-drive"
    elsewhere.mkdir()
    with pytest.raises(VaultError, match="right drive"):
        restore_item(vault, capture_id, elsewhere)


def test_offloading_an_unknown_item_is_refused(
    make_vault: Callable[..., Vault], tmp_path: Path
) -> None:
    vault = make_vault()
    drive = tmp_path / "usb"
    drive.mkdir()
    with pytest.raises(HabitableError, match="unknown evidence record"):
        offload_item(vault, "cap-doesnotexist", drive)


def test_offloading_twice_is_refused(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], tmp_path: Path
) -> None:
    vault, capture_id = _case(make_vault, make_jpeg)
    drive = tmp_path / "usb"
    drive.mkdir()
    offload_item(vault, capture_id, drive)
    second = tmp_path / "usb2"
    second.mkdir()
    with pytest.raises(VaultError, match="already offloaded"):
        offload_item(vault, capture_id, second)


def test_restoring_an_item_that_was_never_offloaded_is_refused(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], tmp_path: Path
) -> None:
    vault, capture_id = _case(make_vault, make_jpeg)
    with pytest.raises(VaultError, match="not offloaded"):
        restore_item(vault, capture_id, tmp_path)


def test_offloading_to_a_path_that_is_not_a_directory_is_refused(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], tmp_path: Path
) -> None:
    """A typo must not silently create a folder inside the phone's own storage."""
    vault, capture_id = _case(make_vault, make_jpeg)
    with pytest.raises(VaultError, match="not a directory"):
        offload_item(vault, capture_id, tmp_path / "usb-typo")


def test_an_existing_container_is_never_overwritten(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], tmp_path: Path
) -> None:
    vault, capture_id = _case(make_vault, make_jpeg)
    drive = tmp_path / "usb"
    drive.mkdir()
    (drive / f"{capture_id}{OFFLOAD_CONTAINER_SUFFIX}").write_bytes(b"someone else's file")
    with pytest.raises(VaultError, match="already at"):
        offload_item(vault, capture_id, drive)
    assert vault.has_original(capture_id)


def test_the_external_container_is_not_the_plaintext(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], tmp_path: Path
) -> None:
    """A USB stick is the one place this project's bytes leave the vault's disk.

    The floor is that the container is neither the plaintext nor readable under
    the wrong key; the AEAD tag does the rest.
    """
    vault, capture_id = _case(make_vault, make_jpeg)
    content_hash = vault.document.captures()[0].content_hash
    plaintext = vault.read_original(capture_id, content_hash)
    assert plaintext[:3] == b"\xff\xd8\xff"  # a real JPEG went in
    drive = tmp_path / "usb"
    drive.mkdir()
    record = offload_item(vault, capture_id, drive)

    container = (drive / record.container_name).read_bytes()
    assert plaintext not in container
    assert container[:3] != b"\xff\xd8\xff"


def test_the_container_key_survives_a_dek_rotation(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], tmp_path: Path
) -> None:
    """The reason the container has its own key instead of using the vault DEK.

    `key rotate-dek` re-encrypts every sealed original under a new key. It cannot
    reach a USB stick, so a container encrypted under the old DEK would be lost
    for good. The key travels inside the vault blob rotation re-encrypts.
    """
    vault, capture_id = _case(make_vault, make_jpeg)
    content_hash = vault.document.captures()[0].content_hash
    before = vault.read_original(capture_id, content_hash)
    drive = tmp_path / "usb"
    drive.mkdir()
    offload_item(vault, capture_id, drive)

    vault.rotate_dek("test-passphrase")
    reopened = Vault.open(vault.path, "test-passphrase")
    assert reopened.is_offloaded(capture_id)
    restore_item(reopened, capture_id, drive)
    assert reopened.read_original(capture_id, content_hash) == before


def test_the_offload_record_survives_close_and_reopen(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], tmp_path: Path
) -> None:
    vault, capture_id = _case(make_vault, make_jpeg)
    drive = tmp_path / "usb"
    drive.mkdir()
    offload_item(vault, capture_id, drive)

    reopened = Vault.open(vault.path, "test-passphrase")
    assert offloaded_item_ids(reopened) == (capture_id,)
    record = reopened.offload_record(capture_id)
    assert record is not None and record.target_label == ""


def test_an_offload_interrupted_before_the_unlink_is_finished_on_open(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], tmp_path: Path
) -> None:
    """The crash window between "key persisted" and "bytes deleted".

    The container was written, read back and decrypted before the record was
    saved, so finishing is the safe direction. Simulated by putting the sealed
    original back beside a durable record, which is exactly the on-disk state
    such a crash leaves.
    """
    vault, capture_id = _case(make_vault, make_jpeg)
    content_hash = vault.document.captures()[0].content_hash
    plaintext = vault.read_original(capture_id, content_hash)
    drive = tmp_path / "usb"
    drive.mkdir()
    offload_item(vault, capture_id, drive)
    vault.store_original_bytes(capture_id, plaintext, content_hash)  # clears the record
    # Re-offload, then recreate the interrupted state by hand.
    (drive / f"{capture_id}{OFFLOAD_CONTAINER_SUFFIX}").unlink()
    offload_item(vault, capture_id, drive)
    sealed = vault.path / "originals" / f"{capture_id}.enc"
    assert not sealed.exists()
    sealed.write_bytes(b"a stale sealed original the crash left behind")

    reopened = Vault.open(vault.path, "test-passphrase")
    assert reopened.is_offloaded(capture_id)
    assert not sealed.exists()
    # And the real bytes are still recoverable from the drive.
    restore_item(reopened, capture_id, drive)
    assert reopened.read_original(capture_id, content_hash) == plaintext


def test_syncing_the_bytes_back_clears_the_offload_record(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], tmp_path: Path
) -> None:
    """`store_original_bytes` is the seam every re-arrival goes through.

    Without the record being cleared there, a peer that sent the original back
    would leave a record claiming the bytes are on a USB stick sitting beside the
    bytes -- and the next `Vault.open` would delete the bytes that just arrived.
    """
    vault, capture_id = _case(make_vault, make_jpeg)
    content_hash = vault.document.captures()[0].content_hash
    plaintext = vault.read_original(capture_id, content_hash)
    drive = tmp_path / "usb"
    drive.mkdir()
    offload_item(vault, capture_id, drive)

    vault.store_original_bytes(capture_id, plaintext, content_hash)
    vault.save()
    assert not vault.is_offloaded(capture_id)

    reopened = Vault.open(vault.path, "test-passphrase")
    assert reopened.has_original(capture_id)
    assert reopened.read_original(capture_id, content_hash) == plaintext


def test_the_storage_breakdown_separates_offloaded_from_never_held(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], tmp_path: Path
) -> None:
    """Both are absent from originals/; only one of them is something she did.

    A single `captures_without_a_sealed_original` bucket would tell a tenant who
    just freed space that her photograph is missing.
    """
    vault, capture_id = _case(make_vault, make_jpeg)
    drive = tmp_path / "usb"
    drive.mkdir()
    sealed_bytes = vault.storage_footprint().per_capture[0].sealed_bytes

    offload_item(vault, capture_id, drive)
    footprint = vault.storage_footprint()

    assert footprint.per_capture == ()
    assert footprint.captures_without_a_sealed_original == ()
    assert [(entry.capture_id, entry.sealed_bytes) for entry in footprint.offloaded] == [
        (capture_id, sealed_bytes)
    ]
