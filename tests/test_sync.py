# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Peer-to-peer sync over a directory and over the relay."""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from habitable.capture import capture
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


def test_relay_sync_is_end_to_end_encrypted(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    relay_url: tuple[str, RelayStore],
) -> None:
    url, store = relay_url
    a = make_vault("A")
    b = make_vault("B", passphrase="pw-b")
    _seed(a, make_jpeg, local_tsa)
    client = RelayClient(url)
    sync(a, b.identity.public(), client, channel="room-relay")
    result = sync(b, a.identity.public(), client, channel="room-relay")

    assert result.captures_imported == 1
    assert b.custody.verify().ok
    # The relay only ever held ciphertext: a unique plaintext sentinel never appears.
    for blob in store.fetch("room-relay"):
        assert SENTINEL.encode() not in blob
    assert store.metrics()["posted"] >= 2
