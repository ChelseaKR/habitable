# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Peer-to-peer sync over a directory and over the relay."""

from __future__ import annotations

import base64
import threading
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from habitable import relay as relay_mod
from habitable.capture import capture
from habitable.errors import SyncError
from habitable.relay import RelayStore, make_server
from habitable.sync import (
    LocalDirTransport,
    PaddingTransport,
    RelayClient,
    import_messages,
    sync,
)
from habitable.tsa import LocalRfc3161TSA
from habitable.vault import Vault

SENTINEL = "PLAINTEXT-SENTINEL-mold-on-bathroom-ceiling"


def _seed(vault: Vault, make_jpeg: Callable[..., Path], tsa: LocalRfc3161TSA) -> str:
    issue = vault.document.add_issue(category="mold", room="bath", title=SENTINEL, issue_id="i1")
    capture(vault, make_jpeg(with_location=True), issue_id=issue, tsa=tsa)
    return issue


def test_directory_sync_converges(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    a = make_vault("A")
    b = make_vault("B", passphrase="pw-b")
    _seed(a, make_jpeg, local_tsa)
    transport = LocalDirTransport(tmp_path / "mbox")
    sync(a, b.identity.public(), transport, channel="room")
    result = sync(b, a.identity.public(), transport, channel="room")

    assert result.captures_imported == 1
    assert [i.issue_id for i in b.document.issues()] == ["i1"]
    capture_record = b.document.captures()[0]
    assert b.read_original(capture_record.capture_id, capture_record.content_hash)
    assert b.get_token(capture_record.capture_id) is not None
    assert b.custody.verify().ok

    # Idempotent: re-importing changes nothing.
    again = import_messages(b, transport.fetch("room"))
    assert again.captures_imported == 0


def test_message_isolation(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    a = make_vault("A")
    b = make_vault("B", passphrase="pw-b")
    c = make_vault("C", passphrase="pw-c")
    _seed(a, make_jpeg, local_tsa)
    transport = LocalDirTransport(tmp_path / "mbox")
    sync(a, b.identity.public(), transport, channel="room")  # sealed to B only
    # C cannot open a message addressed to B.
    result = import_messages(c, transport.fetch("room"))
    assert result.captures_imported == 0 and result.messages_merged == 0


@pytest.fixture
def relay_url() -> Iterator[tuple[str, RelayStore]]:
    store = RelayStore()
    server = make_server("127.0.0.1", 0, store)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}", store
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _no_content_markers(a: Vault, image_bytes: bytes) -> list[bytes]:
    """Every plaintext that must NEVER appear in a stored/transmitted blob."""
    return [
        SENTINEL.encode(),  # the note text (rides in the CRDT state)
        image_bytes[:64],  # raw original image bytes (ride in captures[].original_b64)
        base64.b64encode(image_bytes)[:64],  # ...nor their base64 form
        a.identity.public().fingerprint.encode(),  # the sender identity (in the envelope)
    ]


def test_relay_sync_is_end_to_end_encrypted(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    relay_url: tuple[str, RelayStore],
) -> None:
    url, store = relay_url
    a = make_vault("A")
    b = make_vault("B", passphrase="pw-b")
    issue = a.document.add_issue(category="mold", room="bath", title=SENTINEL, issue_id="i1")
    photo = make_jpeg("unique-source.jpg", with_location=True)
    image_bytes = photo.read_bytes()
    capture(a, photo, issue_id=issue, tsa=local_tsa)

    client = RelayClient(url)
    sync(a, b.identity.public(), client, channel="room-relay")
    result = sync(b, a.identity.public(), client, channel="room-relay")

    assert result.captures_imported == 1
    assert b.custody.verify().ok
    # "Ciphertext in, ciphertext out": no plaintext of any kind — note text, raw or
    # base64 image bytes, or the sender's own identity — appears in a stored blob or in
    # the base64 the relay GET handler serves back.
    blobs = store.fetch("room-relay")
    assert blobs
    served_back = b"".join(base64.b64encode(blob) for blob in blobs)
    for marker in _no_content_markers(a, image_bytes):
        for blob in blobs:
            assert marker not in blob
        assert marker not in served_back
    assert store.metrics()["posted"] >= 2


def test_relay_client_sends_a_matching_room_token(
    relay_url: tuple[str, RelayStore],
) -> None:
    """Both peers derive the same per-channel token, so writes round-trip (no 403)."""
    url, store = relay_url
    client = RelayClient(url)
    client.post("room-token", b"sealed-1")
    client.post("room-token", b"sealed-2")  # same channel -> same token -> accepted
    assert store.fetch("room-token") == [b"sealed-1", b"sealed-2"]


def test_relay_client_raises_clear_error_when_room_full(
    relay_url: tuple[str, RelayStore],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    url, _store = relay_url
    monkeypatch.setattr(relay_mod, "_MAX_MESSAGES_PER_ROOM", 1)
    client = RelayClient(url)
    client.post("room-full", b"first")  # fills the room
    with pytest.raises(SyncError, match="full"):
        client.post("room-full", b"second")


def test_relay_client_raises_clear_error_when_token_rejected(
    relay_url: tuple[str, RelayStore],
) -> None:
    url, store = relay_url
    # Someone else claims the room first with a different token (trust-on-first-use).
    store.post("room-claimed", b"squatter", token="not-the-derived-token")
    client = RelayClient(url)
    with pytest.raises(SyncError, match="token"):
        client.post("room-claimed", b"mine")


def test_localdir_mailbox_holds_only_ciphertext(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    a = make_vault("A")
    b = make_vault("B", passphrase="pw-b")
    issue = a.document.add_issue(category="mold", room="bath", title=SENTINEL, issue_id="i1")
    photo = make_jpeg("unique-source.jpg", with_location=True)
    image_bytes = photo.read_bytes()
    capture(a, photo, issue_id=issue, tsa=local_tsa)

    mbox_dir = tmp_path / "mbox"
    transport = LocalDirTransport(mbox_dir)
    sync(a, b.identity.public(), transport, channel="room")

    # The on-disk mailbox holds only base64 of sealed blobs: assert no plaintext marker
    # survives in either the raw file bytes or any base64-decoded line.
    raw = b"".join(p.read_bytes() for p in mbox_dir.glob("*"))
    decoded = b"".join(base64.b64decode(line) for line in raw.splitlines() if line.strip())
    assert raw and decoded
    for marker in _no_content_markers(a, image_bytes):
        assert marker not in raw
        assert marker not in decoded


# --- metadata-resistant transport (EXP-12) ------------------------------------


def test_padding_transport_round_trips_a_full_sync(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    """Wrapping a transport in padding + cover traffic must not break real delivery."""
    a = make_vault("A")
    b = make_vault("B", passphrase="pw-b")
    _seed(a, make_jpeg, local_tsa)
    inner = LocalDirTransport(tmp_path / "mbox")
    ta = PaddingTransport(inner, block_size=4096, batch_size=4)
    tb = PaddingTransport(inner, block_size=4096, batch_size=4)
    sync(a, b.identity.public(), ta, channel="room")
    result = sync(b, a.identity.public(), tb, channel="room")

    # The real message survives the padding/decoy round-trip; decoys are dropped silently.
    assert result.captures_imported == 1
    assert [i.issue_id for i in b.document.issues()] == ["i1"]
    assert b.custody.verify().ok

    # Idempotent even through padding: re-importing changes nothing.
    again = import_messages(b, tb.fetch("room"))
    assert again.captures_imported == 0


def test_padding_transport_emits_uniform_block_sized_cover_batch(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    """One real post must leave the relay a full batch of identical-size blobs."""
    a = make_vault("A")
    b = make_vault("B", passphrase="pw-b")
    _seed(a, make_jpeg, local_tsa)
    inner = LocalDirTransport(tmp_path / "mbox")
    transport = PaddingTransport(inner, block_size=4096, batch_size=4)
    sync(a, b.identity.public(), transport, channel="room")

    # What the relay actually stored: read the raw framed blobs via the inner transport.
    raw_blobs = inner.fetch("room")
    # Exactly batch_size blobs left the sender (1 real + 3 decoys) — the relay cannot tell
    # from the count how many were real.
    assert len(raw_blobs) == 4
    # Every blob in the flush is padded to one identical, block-aligned size, so neither
    # size nor position distinguishes the real message from its decoys.
    sizes = {len(blob) for blob in raw_blobs}
    assert len(sizes) == 1
    assert next(iter(sizes)) % 4096 == 0


def test_padding_transport_drops_decoys_on_import(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    """A channel of mostly decoys imports exactly the one real message, no more."""
    a = make_vault("A")
    b = make_vault("B", passphrase="pw-b")
    _seed(a, make_jpeg, local_tsa)
    inner = LocalDirTransport(tmp_path / "mbox")
    # A large batch means many decoys accompany the single real message.
    transport = PaddingTransport(inner, block_size=4096, batch_size=8)
    sync(a, b.identity.public(), transport, channel="room")
    assert len(inner.fetch("room")) == 8  # 1 real + 7 decoys on the wire

    tb = PaddingTransport(inner, block_size=4096, batch_size=8)
    result = import_messages(b, tb.fetch("room"))
    assert result.messages_merged == 1
    assert result.captures_imported == 1


def test_padding_transport_batches_multiple_posts_when_not_auto_flushing(
    make_vault: Callable[..., Vault],
    tmp_path: Path,
) -> None:
    """auto_flush=False buffers posts until one flush emits a single padded batch."""
    inner = LocalDirTransport(tmp_path / "mbox")
    transport = PaddingTransport(inner, block_size=1024, batch_size=4, auto_flush=False)
    transport.post("room", b"one")
    transport.post("room", b"two")
    # Nothing has left the sender yet: buffered, not posted.
    assert inner.fetch("room") == []

    transport.flush("room")
    raw_blobs = inner.fetch("room")
    # Two real + two decoys, all one block, emitted together in a single batch.
    assert len(raw_blobs) == 4
    assert {len(blob) for blob in raw_blobs} == {1024}
    # Both real payloads are recoverable (order is shuffled, so compare as a set).
    recovered = {transport._unframe(blob) for blob in raw_blobs}
    assert {b"one", b"two"} <= recovered


def test_padding_transport_passes_through_unframed_blobs(tmp_path: Path) -> None:
    """A channel that also carries plain (unpadded) blobs still delivers them."""
    inner = LocalDirTransport(tmp_path / "mbox")
    inner.post("room", b"legacy-unframed-message")
    transport = PaddingTransport(inner, block_size=1024, batch_size=2)
    assert b"legacy-unframed-message" in transport.fetch("room")
