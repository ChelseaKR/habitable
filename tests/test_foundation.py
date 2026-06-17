# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Foundation: clock, canonical hashing, config, and crypto."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from habitable.canonical import canonical_json, sha256_bytes, sha256_file
from habitable.clock import HLCTimestamp, HybridLogicalClock
from habitable.config import Config, default_config_toml
from habitable.crypto import (
    Identity,
    PublicIdentity,
    SymmetricKey,
    create_keyfile,
    export_recovery_blob,
    import_recovery_blob,
    open_keyfile,
    open_sealed,
    rotate_passphrase,
    seal_to,
    sign,
    verify,
)
from habitable.errors import ConfigError, CryptoError


class TestClock:
    def test_now_is_strictly_increasing(self) -> None:
        clock = HybridLogicalClock("n", time_source=lambda: 100)  # constant wall time
        stamps = [clock.now() for _ in range(50)]
        assert stamps == sorted(stamps)
        assert len(set(stamps)) == 50  # counter keeps them unique

    def test_encode_decode_round_trip(self) -> None:
        ts = HLCTimestamp(123, 4, "node-x")
        assert HLCTimestamp.decode(ts.encode()) == ts

    def test_update_advances_past_remote(self) -> None:
        clock = HybridLogicalClock("a", time_source=lambda: 10)
        remote = HLCTimestamp(1000, 7, "b")
        issued = clock.update(remote)
        assert issued.wall_ms == 1000
        assert issued > remote

    def test_total_order(self) -> None:
        assert HLCTimestamp(1, 0, "a") < HLCTimestamp(1, 0, "b")
        assert HLCTimestamp(1, 0, "z") < HLCTimestamp(1, 1, "a")
        assert HLCTimestamp(1, 9, "z") < HLCTimestamp(2, 0, "a")


class TestCanonical:
    def test_key_order_is_stable(self) -> None:
        assert canonical_json({"b": 1, "a": 2}) == canonical_json({"a": 2, "b": 1})

    def test_known_sha256(self) -> None:
        assert sha256_bytes(b"") == hashlib.sha256(b"").hexdigest()
        assert sha256_bytes(b"abc").startswith("ba7816bf")

    def test_sha256_file(self, tmp_path: Path) -> None:
        f = tmp_path / "x.bin"
        f.write_bytes(b"hello world")
        assert sha256_file(f) == sha256_bytes(b"hello world")

    def test_nan_rejected(self) -> None:
        with pytest.raises(ValueError, match="Out of range"):
            canonical_json(float("nan"))


class TestConfig:
    def test_default_has_rfc3161_authorities(self) -> None:
        config = Config.default("node-1")
        assert config.timestamp_authorities
        assert all(a.kind == "rfc3161" for a in config.timestamp_authorities)
        assert config.sharing.strip_location is True

    def test_toml_round_trip(self, tmp_path: Path) -> None:
        path = tmp_path / "config.toml"
        path.write_text(default_config_toml("node-7", language="es"), encoding="utf-8")
        config = Config.from_toml(path)
        assert config.node_id == "node-7"
        assert config.language == "es"
        assert len(config.timestamp_authorities) >= 1

    def test_rejects_future_schema(self) -> None:
        with pytest.raises(ConfigError, match="newer"):
            Config.from_mapping({"node_id": "n", "schema_version": 999})

    def test_rejects_bad_tsa_kind(self) -> None:
        with pytest.raises(ConfigError, match="kind"):
            Config.from_mapping(
                {"node_id": "n", "timestamp_authorities": [{"name": "x", "kind": "bogus"}]}
            )


class TestCrypto:
    def test_keyfile_lifecycle(self) -> None:
        keyfile, dek = create_keyfile("pw")
        blob = dek.encrypt(b"secret", aad=b"ctx")
        assert open_keyfile(keyfile, "pw").decrypt(blob, aad=b"ctx") == b"secret"

    def test_wrong_passphrase_rejected(self) -> None:
        keyfile, _ = create_keyfile("pw")
        with pytest.raises(CryptoError):
            open_keyfile(keyfile, "WRONG")

    def test_wrong_aad_rejected(self) -> None:
        keyfile, dek = create_keyfile("pw")
        blob = dek.encrypt(b"secret", aad=b"ctx")
        with pytest.raises(CryptoError):
            open_keyfile(keyfile, "pw").decrypt(blob, aad=b"other")

    def test_passphrase_rotation_keeps_data(self) -> None:
        keyfile, dek = create_keyfile("old")
        blob = dek.encrypt(b"secret", aad=b"ctx")
        rotated = rotate_passphrase(keyfile, "old", "new")
        assert open_keyfile(rotated, "new").decrypt(blob, aad=b"ctx") == b"secret"
        with pytest.raises(CryptoError):
            open_keyfile(rotated, "old")

    def test_recovery_backup(self) -> None:
        _, dek = create_keyfile("pw")
        blob = dek.encrypt(b"secret", aad=b"ctx")
        recovery = export_recovery_blob(dek, "recovery words")
        recovered = import_recovery_blob(recovery, "recovery words")
        assert recovered.decrypt(blob, aad=b"ctx") == b"secret"

    def test_sign_and_verify(self) -> None:
        identity = Identity.generate()
        pub = identity.public()
        sig = sign(identity, b"message")
        assert verify(pub.sign_public, b"message", sig)
        assert not verify(pub.sign_public, b"tampered", sig)

    def test_sealed_box_round_trip_and_isolation(self) -> None:
        alice, bob = Identity.generate(), Identity.generate()
        box = seal_to(bob.public(), b"for bob")
        assert open_sealed(bob, box) == b"for bob"
        with pytest.raises(CryptoError):
            open_sealed(alice, box)

    def test_identity_serialization_and_fingerprint(self) -> None:
        identity = Identity.generate()
        restored = Identity.deserialize(identity.serialize())
        assert restored.public().fingerprint == identity.public().fingerprint
        assert PublicIdentity.decode(identity.public().encode()) == identity.public()


# One AEAD key for the property test — scrypt key-wrapping is covered above; here
# we exercise encrypt/decrypt over many payloads without re-deriving a key per example.
_RT_KEY = SymmetricKey.generate()


@given(st.binary(max_size=2048))
def test_symmetric_round_trip(payload: bytes) -> None:
    assert _RT_KEY.decrypt(_RT_KEY.encrypt(payload, aad=b"a"), aad=b"a") == payload
