# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Offloading a sealed original to external storage (issue #296, RR-08).

The property under test throughout is that offloading moves *bytes* and nothing
else: the content hash the timestamp token covers, the tokens, and the chain of
custody all stay, and the chain is extended rather than rewritten.
"""

from __future__ import annotations

import importlib
import json
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

import pytest

from habitable.capture import capture
from habitable.cli import main
from habitable.errors import FixityError, HabitableError, PacketError, SyncError, VaultError
from habitable.evidence import CUSTODY_EVENT_OFFLOADED, CUSTODY_EVENT_RESTORED
from habitable.offload import offload_item, offloaded_item_ids, restore_item
from habitable.packet import build_packet
from habitable.sync import export_message
from habitable.tsa import DevTSA, LocalRfc3161TSA
from habitable.vault import OFFLOAD_CONTAINER_SUFFIX, Vault, human_bytes
from habitable.verify import verify_packet


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


# --- what an offloaded original does to a packet (issue #296) -----------------


def _two_capture_case(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    tsa: LocalRfc3161TSA,
) -> tuple[Vault, str, str]:
    vault = make_vault()
    issue = vault.document.add_issue(category="mold", room="bathroom", title="Mold", issue_id="i1")
    first = capture(vault, make_jpeg("a.jpg"), issue_id=issue, tsa=tsa)
    second = capture(vault, make_jpeg("b.jpg"), issue_id=issue, tsa=tsa)
    vault.save()
    return vault, first.capture_id, second.capture_id


def test_export_refuses_by_default_and_names_the_offloaded_item(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    """Refusing is the default because restoring is one command away.

    The message has to carry the capture id and the way back, or a tenant is
    told her export failed and not what to do about it.
    """
    vault, first, _ = _two_capture_case(make_vault, make_jpeg, local_tsa)
    drive = tmp_path / "usb"
    drive.mkdir()
    offload_item(vault, first, drive)

    with pytest.raises(PacketError) as excinfo:
        build_packet(vault, tmp_path / "packet", generated_at="2026-01-02T00:10:00Z")
    message = str(excinfo.value)
    assert first in message
    assert "habitable restore" in message
    assert "--allow-offloaded" in message
    assert not (tmp_path / "packet").exists()


def test_an_offloaded_packet_names_the_item_and_is_not_evidence_ready(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    """The third `Done when`, mapped onto the verdicts this verifier actually has.

    There is no READY-with-limits tier: `structurally_intact`, `evidence_ready`
    and the authority claim are the three, and #158 made "an item with no
    evidence bytes" defeat the first of them. A packet is not allowed to buy
    readiness back by declaring the absence, or any hand-crafted bundle could
    write the same three keys. What the declaration buys is a true explanation:
    the report names the item, says its original is on external storage, and
    says this packet cannot check that.
    """
    vault, first, second = _two_capture_case(make_vault, make_jpeg, local_tsa)
    drive = tmp_path / "usb"
    drive.mkdir()
    offload_item(vault, first, drive)

    out = tmp_path / "packet"
    build_packet(vault, out, generated_at="2026-01-02T00:10:00Z", allow_offloaded=True)
    report = verify_packet(out, trusted_certs=[local_tsa.certificate])

    assert report.signature_ok and report.custody_ok
    assert not report.structurally_intact
    assert not report.evidence_ready
    verdicts = {item.capture_id: item for item in report.items}
    offloaded = verdicts[first]
    assert offloaded.offload_declared
    assert not offloaded.evidence_present
    assert "moved to external storage" in " ".join(offloaded.notes)
    assert "cannot check that claim" in " ".join(offloaded.notes)
    # Everything the token covers still verifies for the offloaded item.
    assert offloaded.timestamp_verified and offloaded.timestamp_authority_trusted
    # And the item whose bytes are here is untouched.
    assert verdicts[second].structurally_intact and verdicts[second].evidence_ready


def test_the_bundle_and_appendix_count_the_offloaded_item(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    """`offloaded_count` is emitted on every packet, so zero is a statement."""
    vault, first, _ = _two_capture_case(make_vault, make_jpeg, local_tsa)
    drive = tmp_path / "usb"
    drive.mkdir()
    offload_item(vault, first, drive)
    out = tmp_path / "packet"
    build_packet(vault, out, generated_at="2026-01-02T00:10:00Z", allow_offloaded=True)

    bundle = json.loads((out / "bundle.json").read_text(encoding="utf-8"))
    assert bundle["appendix"]["offloaded_count"] == 1
    items = {item["capture_id"]: item for item in bundle["items"]}
    offloaded = items[first]
    assert offloaded["offload"] == {
        "state": "offloaded",
        "offloaded_at": offloaded["offload"]["offloaded_at"],
        "container_hash": offloaded["offload"]["container_hash"],
    }
    assert offloaded["shared_name"] == "" and offloaded["has_original"] is False
    assert offloaded["content_hash"] and offloaded["timestamp"] is not None
    # The key is present only on the item it describes; the other item does not
    # carry an empty one that a reader could mistake for "checked, not offloaded".
    others = [item for capture_id, item in items.items() if capture_id != first]
    assert others and all("offload" not in item for item in others)


def test_a_packet_with_no_offload_still_states_the_zero(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    """The absent-key trap: "nothing is offloaded" must be said, not inferred."""
    vault, _, _ = _two_capture_case(make_vault, make_jpeg, local_tsa)
    out = tmp_path / "packet"
    build_packet(vault, out, generated_at="2026-01-02T00:10:00Z")
    bundle = json.loads((out / "bundle.json").read_text(encoding="utf-8"))
    assert bundle["appendix"]["offloaded_count"] == 0
    assert all("offload" not in item for item in bundle["items"])


def test_the_offloaded_item_gets_no_bytes_even_under_include_originals(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    """`--include-originals` says what the export was asked to do; `has_original`
    says what is in the directory. For this item nothing is, and the packet must
    not claim an embedded original a verifier would then fail to hash."""
    vault, first, second = _two_capture_case(make_vault, make_jpeg, local_tsa)
    drive = tmp_path / "usb"
    drive.mkdir()
    offload_item(vault, first, drive)
    out = tmp_path / "packet"
    build_packet(
        vault,
        out,
        generated_at="2026-01-02T00:10:00Z",
        include_originals=True,
        allow_offloaded=True,
    )
    bundle = json.loads((out / "bundle.json").read_text(encoding="utf-8"))
    items = {item["capture_id"]: item for item in bundle["items"]}
    assert items[first]["has_original"] is False
    assert items[second]["has_original"] is True
    assert not (out / "originals" / first).exists()
    assert (out / "originals" / second).exists()


def test_the_disclosures_count_shared_copies_not_items(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    """The packet's headline claim must not say it carries bytes it does not."""
    vault, first, _ = _two_capture_case(make_vault, make_jpeg, local_tsa)
    drive = tmp_path / "usb"
    drive.mkdir()
    offload_item(vault, first, drive)
    out = tmp_path / "packet"
    result = build_packet(vault, out, generated_at="2026-01-02T00:10:00Z", allow_offloaded=True)
    joined = " | ".join(result.disclosures)
    assert "1 of 2 media item(s) included as shared copies" in joined
    assert "1 item(s) carry NO evidence bytes in this packet" in joined


def test_the_human_packet_says_why_the_photo_is_not_there(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    """packet.html is what a recipient actually opens; an empty figure is not an answer."""
    vault, first, _ = _two_capture_case(make_vault, make_jpeg, local_tsa)
    drive = tmp_path / "usb"
    drive.mkdir()
    offload_item(vault, first, drive)
    out = tmp_path / "packet"
    build_packet(vault, out, generated_at="2026-01-02T00:10:00Z", allow_offloaded=True)

    html = (out / "packet.html").read_text(encoding="utf-8")
    assert "moved to external storage" in html
    assert "NONE — sealed original on external storage" in html


def test_the_spanish_packet_says_it_in_spanish(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    """EN/ES packet copy for the offloaded state is in this issue's own scope."""
    vault, first, _ = _two_capture_case(make_vault, make_jpeg, local_tsa)
    vault.document.set_meta("language", "es")
    vault.config = replace(vault.config, language="es")
    drive = tmp_path / "usb"
    drive.mkdir()
    offload_item(vault, first, drive)
    out = tmp_path / "packet"
    build_packet(vault, out, generated_at="2026-01-02T00:10:00Z", allow_offloaded=True)
    html = (out / "packet.html").read_text(encoding="utf-8")
    assert "almacenamiento externo" in html


def test_an_unrecognized_offload_claim_is_not_an_excuse(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    """A bundle is attacker-controlled: only the one defined state counts.

    Every field here can be written by anyone, so the verifier must not treat an
    arbitrary `offload` value as the recognized declaration. The verdict is
    identical either way -- this pins the *explanation* to a claim the
    vocabulary defines, so a bundle cannot make a byteless item read as a
    deliberate, understood state by writing `offload: true`.
    """
    vault, first, _ = _two_capture_case(make_vault, make_jpeg, local_tsa)
    drive = tmp_path / "usb"
    drive.mkdir()
    offload_item(vault, first, drive)
    out = tmp_path / "packet"
    build_packet(vault, out, generated_at="2026-01-02T00:10:00Z", allow_offloaded=True)

    bundle_path = out / "bundle.json"
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    for item in bundle["items"]:
        if item["capture_id"] == first:
            item["offload"] = {"state": "somewhere-else"}
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

    report = verify_packet(out, trusted_certs=[local_tsa.certificate])
    verdict = next(item for item in report.items if item.capture_id == first)
    assert not verdict.offload_declared
    assert not verdict.evidence_present
    assert "carries no checkable evidence bytes" in " ".join(verdict.notes)


def test_sync_refuses_rather_than_dying_on_a_missing_sealed_original(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    tmp_path: Path,
) -> None:
    """Sync sends bytes this device holds; an offloaded original is not one of them."""
    sender = make_vault("sender")
    receiver = make_vault("receiver")
    issue = sender.document.add_issue(category="mold", room="bath", title="Mold", issue_id="i1")
    result = capture(sender, make_jpeg("a.jpg"), issue_id=issue, tsa=DevTSA())
    sender.save()
    drive = tmp_path / "usb"
    drive.mkdir()
    offload_item(sender, result.capture_id, drive)

    with pytest.raises(SyncError) as excinfo:
        export_message(sender, receiver.identity.public())
    assert result.capture_id in str(excinfo.value)
    assert "habitable restore" in str(excinfo.value)


# --- the CLI surface ----------------------------------------------------------


def test_the_cli_round_trips_and_says_what_is_on_the_drive(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    dev_tsa: DevTSA,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """`offload` never prints a saving; it prints what left and re-measures the device.

    The vault grows by the record and the custody entries, so "you saved N" would
    be a number the phone does not show. The measured `on_disk` line is the one a
    tenant can check against her own storage screen.
    """
    vault = make_vault()
    issue = vault.document.add_issue(category="mold", room="bath", issue_id="i1")
    item = capture(vault, make_jpeg("p.jpg"), issue_id=issue, tsa=dev_tsa).capture_id
    vault.save()
    drive = tmp_path / "usb"
    drive.mkdir()
    args = ["--vault", str(vault.path), "--passphrase", "test-passphrase"]

    assert main(["offload", *args, item, "--to", str(drive), "--label", "green stick"]) == 0
    out = capsys.readouterr().out
    assert item in out
    assert "on external storage" in out
    assert "it holds the only copy of this file" in out
    reopened = Vault.open(vault.path, "test-passphrase")
    assert f"this case now takes {human_bytes(reopened.storage_footprint().on_disk_bytes)}" in out

    assert main(["status", *args, "--storage"]) == 0
    out = capsys.readouterr().out
    assert "moved to external storage" in out
    assert "sealed original not on this device" not in out

    assert main(["restore", *args, item, "--from", str(drive)]) == 0
    out = capsys.readouterr().out
    assert "back on this device and re-hashed" in out
    assert Vault.open(vault.path, "test-passphrase").has_original(item)


def test_the_cli_refuses_an_altered_container_with_exit_1(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    dev_tsa: DevTSA,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    vault = make_vault()
    issue = vault.document.add_issue(category="mold", room="bath", issue_id="i1")
    item = capture(vault, make_jpeg("p.jpg"), issue_id=issue, tsa=dev_tsa).capture_id
    vault.save()
    drive = tmp_path / "usb"
    drive.mkdir()
    args = ["--vault", str(vault.path), "--passphrase", "test-passphrase"]
    assert main(["offload", *args, item, "--to", str(drive)]) == 0
    capsys.readouterr()

    container = next(drive.glob(f"*{OFFLOAD_CONTAINER_SUFFIX}"))
    data = bytearray(container.read_bytes())
    data[0] ^= 0xFF
    container.write_bytes(bytes(data))

    assert main(["restore", *args, item, "--from", str(drive)]) == 1
    captured = capsys.readouterr()
    assert "does not match the hash recorded" in captured.err
    assert not Vault.open(vault.path, "test-passphrase").has_original(item)


def test_the_status_hint_tells_a_full_phone_what_it_can_do(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    dev_tsa: DevTSA,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """RR-08's other half: naming the big capture is only useful with an action.

    `docs/mobile.md` used to advise exporting a packet to reclaim space, which
    adds a copy and removes nothing. The breakdown now ends with the operation
    that does.
    """
    vault = make_vault()
    issue = vault.document.add_issue(category="mold", room="bath", issue_id="i1")
    capture(vault, make_jpeg("p.jpg"), issue_id=issue, tsa=dev_tsa)
    vault.save()

    assert (
        main(["status", "--vault", str(vault.path), "--passphrase", "test-passphrase", "--storage"])
        == 0
    )
    out = capsys.readouterr().out
    assert "habitable offload <capture> --to <folder>" in out
    assert "habitable restore" in out


def test_a_failed_container_write_leaves_the_sealed_original_alone(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], tmp_path: Path
) -> None:
    """The ordering argument, exercised: prove the container, then destroy the copy.

    A drive that cannot be written to is the cheapest way to reach the failure
    path. What matters is not the error but what survives it: the bytes are
    still in the vault, no record claims otherwise, and a later export is a
    complete one.
    """
    vault, capture_id = _case(make_vault, make_jpeg)
    content_hash = vault.document.captures()[0].content_hash
    before = vault.read_original(capture_id, content_hash)
    drive = tmp_path / "readonly-usb"
    drive.mkdir()
    drive.chmod(0o500)
    try:
        with pytest.raises(OSError):
            offload_item(vault, capture_id, drive)
    finally:
        drive.chmod(0o700)

    assert vault.has_original(capture_id)
    assert not vault.is_offloaded(capture_id)
    assert vault.read_original(capture_id, content_hash) == before


def test_a_container_that_reads_back_wrong_costs_nothing(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The readback step, exercised. Written because a control found it uncovered.

    `offload_original` re-reads the container off the drive, re-hashes it and
    decrypts it before deleting the only other copy. Sabotaging that check ran
    the whole suite green, which means nothing reached it: a real drive that
    truncates a write silently is exactly the failure the step exists for, and
    no fixture produces one. A writer that drops the last eight bytes does.

    The module handle comes from ``importlib`` rather than ``from ... import``,
    so patching cannot silently miss a re-bound name.
    """
    vault_module = importlib.import_module("habitable.vault")
    vault, capture_id = _case(make_vault, make_jpeg)
    content_hash = vault.document.captures()[0].content_hash
    before = vault.read_original(capture_id, content_hash)
    drive = tmp_path / "usb"
    drive.mkdir()

    real = vault_module._write_offload_container

    def truncating_write(container: Path, ciphertext: bytes) -> None:
        real(container, ciphertext[:-8])

    monkeypatch.setattr(vault_module, "_write_offload_container", truncating_write)
    with pytest.raises(VaultError, match="did not read back"):
        offload_item(vault, capture_id, drive)

    assert vault.has_original(capture_id)
    assert not vault.is_offloaded(capture_id)
    assert vault.read_original(capture_id, content_hash) == before
    # The half-written container is removed rather than left to be restored from.
    assert list(drive.iterdir()) == []
