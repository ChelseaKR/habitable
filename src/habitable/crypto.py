# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Cryptography: encryption at rest, device identity, and end-to-end sync sealing.

The promise habitable makes is that no operator can read a union's data, so the
data is encrypted on the device and stays encrypted in transit. This module is
the one place that promise is implemented, kept small and auditable on purpose.

Design
------
* **At rest.** A random 32-byte *data encryption key* (DEK) encrypts every vault
  blob with ChaCha20-Poly1305 (AEAD: confidentiality + integrity). The DEK is
  itself wrapped under a *key-encryption key* (KEK) derived from the user's
  passphrase with scrypt. This indirection makes passphrase rotation and
  encrypted recovery backups cheap — the bulk data never has to be re-encrypted.
* **Identity.** Each device holds an Ed25519 signing key (signs custody entries,
  sync messages, and packets) and an X25519 key-agreement key (receives sealed
  sync deltas). The pair has a short fingerprint peers verify out of band.
* **In transit.** :func:`seal_to` is an ECIES-style sealed box (ephemeral X25519
  → HKDF → ChaCha20-Poly1305) so a delta can be encrypted to a peer's public key
  with forward-secrecy for the sender.

Every authentication failure surfaces as :class:`~habitable.errors.CryptoError`
rather than a bare library exception.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .errors import CryptoError

__all__ = [
    "KDF_PROFILES",
    "KEYFILE_VERSION",
    "Identity",
    "KdfParams",
    "PublicIdentity",
    "SymmetricKey",
    "create_keyfile",
    "export_recovery_blob",
    "harden_keyfile",
    "import_recovery_blob",
    "open_keyfile",
    "open_sealed",
    "rotate_passphrase",
    "seal_to",
    "sign",
    "verify",
]

KEYFILE_VERSION = 1
_NONCE_BYTES = 12
_KEY_BYTES = 32
_DEK_AAD = b"habitable-dek-wrap-v1"
_SEALEDBOX_INFO = b"habitable-sealedbox-v1"

# Named scrypt cost profiles (N; r/p stay fixed). "standard" is what `create_keyfile`
# uses -- tuned for an interactive unlock on a low-end phone. `key harden` re-wraps the
# DEK under a stronger profile chosen here; see docs/crypto-spec.md sec 3.1 for the
# rationale and a bump procedure (FIX-08).
KDF_PROFILES: dict[str, int] = {
    "standard": 2**15,  # ~32 MiB -- the original default, adequate but not future-proof
    "hardened": 2**17,  # ~128 MiB -- OWASP's current scrypt-minimum recommendation
    "paranoid": 2**20,  # ~1 GiB -- for a device that can spare the time and memory
}


@dataclass(frozen=True, slots=True)
class KdfParams:
    """scrypt parameters. Defaults target an interactive unlock on a phone."""

    salt: bytes
    n: int = KDF_PROFILES["standard"]
    r: int = 8
    p: int = 1
    length: int = _KEY_BYTES

    def derive(self, passphrase: bytes) -> bytes:
        """Derive a key-encryption key from a passphrase."""
        kdf = Scrypt(salt=self.salt, length=self.length, n=self.n, r=self.r, p=self.p)
        return kdf.derive(passphrase)

    def to_dict(self) -> dict[str, object]:
        return {
            "name": "scrypt",
            "salt": _b64e(self.salt),
            "n": self.n,
            "r": self.r,
            "p": self.p,
            "length": self.length,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, object]) -> KdfParams:
        if raw.get("name") != "scrypt":
            raise CryptoError(f"unsupported KDF: {raw.get('name')!r}")
        return cls(
            salt=_b64d(_as_str(raw, "salt")),
            n=_as_int(raw, "n"),
            r=_as_int(raw, "r"),
            p=_as_int(raw, "p"),
            length=_as_int(raw, "length"),
        )

    @classmethod
    def for_profile(cls, profile: str, *, salt: bytes) -> KdfParams:
        """Cost parameters for a named entry in :data:`KDF_PROFILES`."""
        try:
            n = KDF_PROFILES[profile]
        except KeyError:
            known = ", ".join(sorted(KDF_PROFILES))
            raise CryptoError(f"unknown KDF profile {profile!r}; known: {known}") from None
        return cls(salt=salt, n=n)


class SymmetricKey:
    """An authenticated-encryption key (the DEK). Bytes are never exposed."""

    __slots__ = ("_aead", "_key")

    def __init__(self, key: bytes) -> None:
        if len(key) != _KEY_BYTES:
            raise CryptoError(f"symmetric key must be {_KEY_BYTES} bytes")
        self._key = key
        self._aead = ChaCha20Poly1305(key)

    @classmethod
    def generate(cls) -> SymmetricKey:
        return cls(ChaCha20Poly1305.generate_key())

    def encrypt(self, plaintext: bytes, *, aad: bytes = b"") -> bytes:
        """Encrypt, returning ``nonce || ciphertext``. ``aad`` is authenticated."""
        nonce = os.urandom(_NONCE_BYTES)
        return nonce + self._aead.encrypt(nonce, plaintext, aad)

    def decrypt(self, blob: bytes, *, aad: bytes = b"") -> bytes:
        """Reverse :meth:`encrypt`; raises :class:`CryptoError` on tamper/wrong key."""
        if len(blob) < _NONCE_BYTES:
            raise CryptoError("ciphertext too short")
        nonce, ct = blob[:_NONCE_BYTES], blob[_NONCE_BYTES:]
        try:
            return self._aead.decrypt(nonce, ct, aad)
        except InvalidTag as exc:
            raise CryptoError("decryption failed (wrong key or tampered data)") from exc

    def _raw(self) -> bytes:
        return self._key


# --- keyfile: wrap/unwrap the DEK under a passphrase-derived KEK ---------------


def create_keyfile(passphrase: str) -> tuple[str, SymmetricKey]:
    """Create a fresh vault key and a keyfile (JSON string) that protects it."""
    dek = SymmetricKey.generate()
    params = KdfParams(salt=os.urandom(16))
    keyfile = _wrap_dek(dek, passphrase, params)
    return keyfile, dek


def open_keyfile(keyfile: str, passphrase: str) -> SymmetricKey:
    """Recover the vault key from a keyfile and passphrase."""
    doc = _load_keyfile(keyfile)
    params = KdfParams.from_dict(_as_dict(doc, "kdf"))
    kek = SymmetricKey(params.derive(passphrase.encode("utf-8")))
    dek_bytes = kek.decrypt(_b64d(_as_str(doc, "wrapped_dek")), aad=_DEK_AAD)
    return SymmetricKey(dek_bytes)


def rotate_passphrase(keyfile: str, old_passphrase: str, new_passphrase: str) -> str:
    """Re-wrap the same DEK under a new passphrase (no bulk re-encryption)."""
    dek = open_keyfile(keyfile, old_passphrase)
    return _wrap_dek(dek, new_passphrase, KdfParams(salt=os.urandom(16)))


def harden_keyfile(dek: SymmetricKey, passphrase: str, *, profile: str = "hardened") -> str:
    """Re-wrap ``dek`` under ``passphrase`` at a stronger named KDF cost profile.

    This is the ``key harden`` remedy for FIX-08: KDF parameters that were adequate
    when a vault was created but are light today. Same passphrase, same DEK, just a
    costlier re-derivation on unlock going forward -- no bulk re-encryption (see
    ``Vault.rotate_dek`` for that). Raises :class:`CryptoError` for an unknown
    ``profile``.
    """
    return _wrap_dek(dek, passphrase, KdfParams.for_profile(profile, salt=os.urandom(16)))


def export_recovery_blob(dek: SymmetricKey, recovery_passphrase: str) -> str:
    """Export the vault key under an independent recovery passphrase (a backup)."""
    return _wrap_dek(dek, recovery_passphrase, KdfParams(salt=os.urandom(16)))


def import_recovery_blob(blob: str, recovery_passphrase: str) -> SymmetricKey:
    """Recover the vault key from a recovery backup made by :func:`export_recovery_blob`."""
    return open_keyfile(blob, recovery_passphrase)


def _wrap_dek(dek: SymmetricKey, passphrase: str, params: KdfParams) -> str:
    kek = SymmetricKey(params.derive(passphrase.encode("utf-8")))
    wrapped = kek.encrypt(dek._raw(), aad=_DEK_AAD)
    doc = {
        "habitable_keyfile_version": KEYFILE_VERSION,
        "aead": "chacha20poly1305",
        "kdf": params.to_dict(),
        "wrapped_dek": _b64e(wrapped),
    }
    return json.dumps(doc, indent=2, sort_keys=True)


def _load_keyfile(keyfile: str) -> dict[str, object]:
    try:
        doc = json.loads(keyfile)
    except json.JSONDecodeError as exc:
        raise CryptoError("keyfile is not valid JSON") from exc
    if not isinstance(doc, dict):
        raise CryptoError("keyfile must be a JSON object")
    version = doc.get("habitable_keyfile_version")
    if version != KEYFILE_VERSION:
        raise CryptoError(f"unsupported keyfile version: {version!r}")
    return doc


# --- device identity ----------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PublicIdentity:
    """A peer's public keys: Ed25519 (verify) and X25519 (seal to)."""

    sign_public: bytes  # 32 raw bytes
    box_public: bytes  # 32 raw bytes

    @property
    def fingerprint(self) -> str:
        """Short, human-verifiable fingerprint (peers compare this out of band)."""
        digest = hashes.Hash(hashes.SHA256())
        digest.update(self.sign_public + self.box_public)
        hex_fp = digest.finalize().hex()
        return "-".join(hex_fp[i : i + 4] for i in range(0, 16, 4))

    def encode(self) -> str:
        return _b64e(self.sign_public + self.box_public)

    @classmethod
    def decode(cls, raw: str) -> PublicIdentity:
        data = _b64d(raw)
        if len(data) != 64:
            raise CryptoError("public identity must be 64 bytes")
        return cls(sign_public=data[:32], box_public=data[32:])


@dataclass(frozen=True, slots=True)
class Identity:
    """A device's private signing + key-agreement identity."""

    _sign_private: bytes  # 32 raw bytes (Ed25519 seed)
    _box_private: bytes  # 32 raw bytes (X25519 private)

    @classmethod
    def generate(cls) -> Identity:
        sign_key = Ed25519PrivateKey.generate()
        box_key = X25519PrivateKey.generate()
        return cls(
            _sign_private=sign_key.private_bytes_raw(),
            _box_private=box_key.private_bytes_raw(),
        )

    def public(self) -> PublicIdentity:
        sign_pub = Ed25519PrivateKey.from_private_bytes(self._sign_private).public_key()
        box_pub = X25519PrivateKey.from_private_bytes(self._box_private).public_key()
        return PublicIdentity(
            sign_public=sign_pub.public_bytes(Encoding.Raw, PublicFormat.Raw),
            box_public=box_pub.public_bytes(Encoding.Raw, PublicFormat.Raw),
        )

    def serialize(self) -> bytes:
        """Raw 64 bytes (sign seed || box private), to be stored encrypted."""
        return self._sign_private + self._box_private

    @classmethod
    def deserialize(cls, data: bytes) -> Identity:
        if len(data) != 64:
            raise CryptoError("serialized identity must be 64 bytes")
        return cls(_sign_private=data[:32], _box_private=data[32:])

    def sign(self, message: bytes) -> bytes:
        return Ed25519PrivateKey.from_private_bytes(self._sign_private).sign(message)

    def box_private_key(self) -> X25519PrivateKey:
        return X25519PrivateKey.from_private_bytes(self._box_private)


def sign(identity: Identity, message: bytes) -> bytes:
    """Ed25519-sign ``message`` with the device identity."""
    return identity.sign(message)


def verify(sign_public: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an Ed25519 signature; returns ``False`` rather than raising."""
    try:
        Ed25519PublicKey.from_public_bytes(sign_public).verify(signature, message)
    except Exception:
        # Any failure (bad signature, malformed key) means "not verified".
        return False
    return True


# --- sealed box (encrypt-to-public-key) ---------------------------------------


def seal_to(recipient: PublicIdentity, plaintext: bytes) -> bytes:
    """Encrypt ``plaintext`` to a recipient's X25519 public key (anonymous sender)."""
    ephemeral = X25519PrivateKey.generate()
    eph_pub = ephemeral.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    recipient_pub = X25519PublicKey.from_public_bytes(recipient.box_public)
    shared = ephemeral.exchange(recipient_pub)
    key = _derive_box_key(shared, eph_pub, recipient.box_public)
    nonce = os.urandom(_NONCE_BYTES)
    ct = ChaCha20Poly1305(key).encrypt(nonce, plaintext, eph_pub)
    return eph_pub + nonce + ct


def open_sealed(identity: Identity, box: bytes) -> bytes:
    """Decrypt a sealed box addressed to this device."""
    if len(box) < 32 + _NONCE_BYTES:
        raise CryptoError("sealed box too short")
    eph_pub, nonce, ct = box[:32], box[32 : 32 + _NONCE_BYTES], box[32 + _NONCE_BYTES :]
    box_private = identity.box_private_key()
    recipient_pub = box_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    shared = box_private.exchange(X25519PublicKey.from_public_bytes(eph_pub))
    key = _derive_box_key(shared, eph_pub, recipient_pub)
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, ct, eph_pub)
    except InvalidTag as exc:
        raise CryptoError("sealed box failed to open (not for us or tampered)") from exc


def _derive_box_key(shared: bytes, eph_pub: bytes, recipient_pub: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=_KEY_BYTES,
        salt=None,
        info=_SEALEDBOX_INFO + eph_pub + recipient_pub,
    )
    return hkdf.derive(shared)


# --- small helpers ------------------------------------------------------------


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(text: str) -> bytes:
    try:
        # binascii.Error (raised on malformed input) is a subclass of ValueError.
        return base64.b64decode(text, validate=True)
    except ValueError as exc:
        raise CryptoError("invalid base64 in key material") from exc


def _as_str(raw: dict[str, object], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str):
        raise CryptoError(f"expected string for {key!r}")
    return value


def _as_int(raw: dict[str, object], key: str) -> int:
    value = raw.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise CryptoError(f"expected integer for {key!r}")
    return value


def _as_dict(raw: dict[str, object], key: str) -> dict[str, object]:
    value = raw.get(key)
    if not isinstance(value, dict):
        raise CryptoError(f"expected object for {key!r}")
    return value
