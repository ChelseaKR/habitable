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
from habitable.sync import LocalDirTransport, RelayClient, import_messages, sync
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
