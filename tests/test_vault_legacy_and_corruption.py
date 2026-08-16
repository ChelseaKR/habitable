# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Fail-closed and legacy-migration paths in the encrypted store.

These are the branches `vault.py` takes when what it reads back off disk is not
what it wrote: a corrupt record, a truncated migration, a peer entry whose
identity does not match its own key. They were the largest untested region of
the module that holds evidence at rest, and the reason `vault.py` sat below the
documented per-module coverage floor (issue #183). Every case here asserts the
same thing: the vault refuses, by name, rather than carrying on with a record it
cannot vouch for.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from habitable.canonical import canonical_json
from habitable.crypto import Identity
from habitable.errors import VaultError
from habitable.vault import Vault, human_bytes

_PASSPHRASE = "test-passphrase"


def _rewrite_blob(vault: Vault, name: str, payload: object) -> None:
    """Replace one encrypted blob with well-formed ciphertext over bad plaintext.

    The point is to exercise the *decoder*, not the AEAD: the bytes decrypt
    cleanly and then fail the record's own shape checks.
    """
    plaintext = canonical_json(payload)  # type: ignore[arg-type]
    (vault.path / name).write_bytes(vault._dek.encrypt(plaintext, aad=name.encode()))


class TestNodeIdMigration:
    """FIX-01: a pre-FIX-01 vault kept a passphrase-derived node_id in plaintext."""

    def test_a_legacy_plaintext_node_id_is_moved_into_the_encrypted_store(
        self, make_vault: Callable[..., Vault]
    ) -> None:
        vault = make_vault()
        vault.save()
        node_id = vault.document.clock.node_id
        # Reconstruct the pre-FIX-01 shape: no encrypted blob, a plaintext line.
        (vault.path / "node.enc").unlink()
        config = vault.path / "config.toml"
        # Top-level key, as pre-FIX-01 wrote it -- appending would land it inside
        # whichever table happens to be last.
        config.write_text(
            f'node_id = "{node_id}"\n' + config.read_text(encoding="utf-8"), encoding="utf-8"
        )

        reopened = Vault.open(vault.path, _PASSPHRASE)

        # The value is carried over unchanged, so already-exported ids stay stable.
        assert reopened.document.clock.node_id == node_id
        assert (vault.path / "node.enc").exists()
        # ...and the plaintext, passphrase-derived value is gone from config.toml.
        assert "node_id" not in config.read_text(encoding="utf-8")

    def test_a_vault_with_neither_an_encrypted_nor_a_legacy_node_id_refuses_to_open(
        self, make_vault: Callable[..., Vault]
    ) -> None:
        vault = make_vault()
        vault.save()
        (vault.path / "node.enc").unlink()

        with pytest.raises(VaultError, match="no device node identity"):
            Vault.open(vault.path, _PASSPHRASE)

    def test_a_node_record_that_is_not_an_object_refuses_to_open(
        self, make_vault: Callable[..., Vault]
    ) -> None:
        vault = make_vault()
        vault.save()
        _rewrite_blob(vault, "node.enc", ["not", "an", "object"])

        with pytest.raises(VaultError, match="corrupt node identity record"):
            Vault.open(vault.path, _PASSPHRASE)


class TestPeerHaveRecord:
    def test_a_vault_predating_the_peer_have_record_opens_with_no_known_inventory(
        self, make_vault: Callable[..., Vault]
    ) -> None:
        """FIX-02 is additive: a vault without the file falls back to sending everything."""
        vault = make_vault()
        vault.record_peer_captures("peer-fingerprint", ["cap-1"])
        vault.save()
        (vault.path / "peer_have.enc").unlink()

        reopened = Vault.open(vault.path, _PASSPHRASE)
        assert reopened.known_peer_captures("peer-fingerprint") == frozenset()

    def test_a_peer_have_record_that_is_not_an_object_refuses_to_open(
        self, make_vault: Callable[..., Vault]
    ) -> None:
        vault = make_vault()
        vault.save()
        _rewrite_blob(vault, "peer_have.enc", ["not", "an", "object"])

        with pytest.raises(VaultError, match="corrupt peer-have record"):
            Vault.open(vault.path, _PASSPHRASE)

    def test_a_peer_have_entry_that_is_not_a_list_refuses_to_open(
        self, make_vault: Callable[..., Vault]
    ) -> None:
        vault = make_vault()
        vault.save()
        _rewrite_blob(vault, "peer_have.enc", {"peer-fingerprint": "cap-1"})

        with pytest.raises(VaultError, match="corrupt peer-have record"):
            Vault.open(vault.path, _PASSPHRASE)


class TestSyncSecurityRecord:
    def test_a_sync_security_record_that_is_not_an_object_refuses_to_open(
        self, make_vault: Callable[..., Vault]
    ) -> None:
        vault = make_vault()
        vault.save()
        _rewrite_blob(vault, "sync_security.enc", ["not", "an", "object"])

        with pytest.raises(VaultError, match="corrupt sync security record"):
            Vault.open(vault.path, _PASSPHRASE)

    def test_a_peer_whose_identity_bytes_do_not_decode_refuses_to_open(
        self, make_vault: Callable[..., Vault]
    ) -> None:
        vault = make_vault("A")
        make_vault("B", passphrase="pw-b")  # same case: the fixture pairs them
        vault.save()
        peers = _decode_sync_security(vault)
        assert peers, "fixture vault has no authorized peer to corrupt"
        fingerprint = next(iter(peers))
        peers[fingerprint]["identity"] = "not-a-public-identity"
        _rewrite_blob(vault, "sync_security.enc", peers)

        with pytest.raises(VaultError, match="corrupt sync peer identity"):
            Vault.open(vault.path, _PASSPHRASE)

    def test_a_peer_filed_under_a_fingerprint_that_is_not_its_own_refuses_to_open(
        self, make_vault: Callable[..., Vault]
    ) -> None:
        """The record's key must be derivable from the record's own key material."""
        vault = make_vault("A")
        make_vault("B", passphrase="pw-b")  # same case: the fixture pairs them
        vault.save()
        peers = _decode_sync_security(vault)
        assert peers
        fingerprint = next(iter(peers))
        record = peers.pop(fingerprint)
        # Same authorization, filed under a different, real fingerprint.
        peers[Identity.generate().public().fingerprint] = record
        _rewrite_blob(vault, "sync_security.enc", peers)

        with pytest.raises(VaultError, match="fingerprint does not match its identity"):
            Vault.open(vault.path, _PASSPHRASE)


def _decode_sync_security(vault: Vault) -> dict[str, dict[str, object]]:
    import json

    from habitable.vault import _read_blob

    raw = json.loads(_read_blob(vault.path, vault._dek, "sync_security.enc"))
    assert isinstance(raw, dict)
    return raw


def test_a_building_label_given_at_creation_is_stored_as_case_metadata(
    tmp_path: Path,
) -> None:
    vault = Vault.create(tmp_path / "v", _PASSPHRASE, case_id="c1", unit="4B", building="Elm St")
    assert vault.document.get_meta("building") == "Elm St"
    assert Vault.open(vault.path, _PASSPHRASE).document.get_meta("building") == "Elm St"


def test_human_bytes_keeps_scaling_past_terabytes() -> None:
    assert human_bytes(512) == "512 bytes"
    assert human_bytes(6_100_000) == "6.1 MB"
    assert human_bytes(2_500_000_000_000_000) == "2.5 PB"
