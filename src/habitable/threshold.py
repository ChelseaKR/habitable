# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Threshold (M-of-N) social custody of a vault's recovery key (EXP-11).

The problem this solves is stated at length in
[`docs/key-custody-playbook.md`](../../docs/key-custody-playbook.md): a union
needs recovery backups to survive a dropped phone, but one person holding every
family's recovery blob *is* the honeypot the whole project exists to avoid. The
plain ``key backup`` / ``key restore`` commands can only approximate distributed
trust by social convention (blob held by A, passphrase by B). This module makes
it cryptographic: the recovery key is split into ``N`` shares handed to ``N``
stewards, and *any* ``M`` of them — but no fewer — can reconstruct it. No single
custodian can, so no single custodian is worth attacking.

Construction
------------
* A fresh random 256-bit **recovery secret** wraps the vault's data-encryption
  key (DEK) with ChaCha20-Poly1305 into a **recovery bundle** (a small JSON
  blob). The bundle is not itself sensitive: it is useless without the secret.
* The recovery secret is split with **Shamir's Secret Sharing over GF(2⁸)**
  (the AES field, reduction polynomial ``0x11b``). Each of the ``secret``'s
  bytes is an independent degree ``M-1`` polynomial evaluated at the share's
  x-coordinate; ``M`` points recover the constant term (the secret byte) by
  Lagrange interpolation at ``x = 0``. Information-theoretically, ``M-1`` shares
  reveal *nothing* about the secret.
* Every share carries the bundle's ``bundle_id`` (a digest of the wrapped DEK),
  so shares from different bundles cannot be silently mixed, and reconstruction
  is checked against the bundle: a wrong or corrupt share set surfaces as a
  :class:`~habitable.errors.CryptoError`, never a garbage key.

The primitive is implemented here (Python has no threshold scheme in
``cryptography``); everything else routes through the audited primitives in
:mod:`habitable.crypto`.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from collections.abc import Sequence
from dataclasses import dataclass

from .crypto import SymmetricKey
from .errors import CryptoError

__all__ = [
    "RECOVERY_BUNDLE_VERSION",
    "SHARE_VERSION",
    "Share",
    "combine_secret",
    "create_recovery_bundle",
    "recover_dek",
    "split_secret",
]

RECOVERY_BUNDLE_VERSION = 1
SHARE_VERSION = 1

_SCHEME = "shamir-gf256"
_THRESHOLD_AAD = b"habitable-threshold-recovery-wrap-v1"
_SECRET_BYTES = 32
_MAX_SHARES = 255  # x-coordinates are non-zero bytes in GF(2⁸): 1..255


# --- GF(2⁸) arithmetic (AES field, reduction polynomial x⁸+x⁴+x³+x+1 = 0x11b) --


def _build_gf_tables() -> tuple[list[int], list[int]]:
    """Exp/log tables for GF(2⁸) using the generator 0x03."""
    exp = [0] * 512
    log = [0] * 256
    x = 1
    for i in range(255):
        exp[i] = x
        log[x] = i
        # multiply x by the generator 3 = (x + 1): x*3 = x*2 ^ x
        x ^= _xtime(x)
    for i in range(255, 512):
        exp[i] = exp[i - 255]
    return exp, log


def _xtime(a: int) -> int:
    """Multiply by 2 in GF(2⁸)."""
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


_GF_EXP, _GF_LOG = _build_gf_tables()


def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _GF_EXP[_GF_LOG[a] + _GF_LOG[b]]


def _gf_inv(a: int) -> int:
    if a == 0:
        raise CryptoError("GF(2^8) inverse of zero is undefined")
    return _GF_EXP[255 - _GF_LOG[a]]


# --- low-level Shamir over byte strings ---------------------------------------


def split_secret(secret: bytes, threshold: int, count: int) -> list[tuple[int, bytes]]:
    """Split ``secret`` into ``count`` shares, any ``threshold`` of which recover it.

    Returns ``(x, y)`` pairs where ``x`` is the share's distinct non-zero
    x-coordinate and ``y`` has one byte per secret byte.
    """
    if not 2 <= threshold <= count:
        raise CryptoError(f"threshold must satisfy 2 <= M <= N (got M={threshold}, N={count})")
    if count > _MAX_SHARES:
        raise CryptoError(f"at most {_MAX_SHARES} shares are supported (got {count})")
    if not secret:
        raise CryptoError("cannot split an empty secret")

    # One degree M-1 polynomial per secret byte, with the byte as the constant
    # term and fixed random higher coefficients. Every share evaluates the *same*
    # polynomials at its own x-coordinate — the coefficients must not vary by
    # share, or the points would not lie on a common curve.
    polys = [[s, *os.urandom(threshold - 1)] for s in secret]
    shares: list[tuple[int, bytes]] = []
    for x in range(1, count + 1):
        y = bytes(_eval_poly(coeffs, x) for coeffs in polys)
        shares.append((x, y))
    return shares


def combine_secret(parts: Sequence[tuple[int, bytes]]) -> bytes:
    """Reconstruct a secret from ``(x, y)`` shares via Lagrange interpolation at 0."""
    if len(parts) < 2:
        raise CryptoError("need at least two shares to reconstruct a secret")
    xs = [x for x, _ in parts]
    if any(not isinstance(x, int) or isinstance(x, bool) or not 1 <= x <= _MAX_SHARES for x in xs):
        raise CryptoError(f"share x-coordinates must be integers in 1..{_MAX_SHARES}")
    if len(set(xs)) != len(xs):
        raise CryptoError("duplicate share x-coordinates; each share must be distinct")
    length = len(parts[0][1])
    if any(len(y) != length for _, y in parts):
        raise CryptoError("shares disagree on secret length; they are not from one bundle")

    secret = bytearray(length)
    for j in range(length):
        acc = 0
        for x_i, y_i in parts:
            # Lagrange basis L_i(0) = prod_{m != i} x_m / (x_m - x_i); in GF(2⁸)
            # subtraction is XOR, so (x_m - x_i) == (x_m ^ x_i).
            num = 1
            den = 1
            for x_m, _ in parts:
                if x_m == x_i:
                    continue
                num = _gf_mul(num, x_m)
                den = _gf_mul(den, x_m ^ x_i)
            basis = _gf_mul(num, _gf_inv(den))
            acc ^= _gf_mul(y_i[j], basis)
        secret[j] = acc
    return bytes(secret)


def _eval_poly(coeffs: Sequence[int], x: int) -> int:
    """Evaluate a GF(2⁸) polynomial (Horner) at ``x``."""
    acc = 0
    for c in reversed(coeffs):
        acc = _gf_mul(acc, x) ^ c
    return acc


# --- share and bundle documents -----------------------------------------------


@dataclass(frozen=True, slots=True)
class Share:
    """One steward's share of a vault's recovery secret."""

    index: int
    y: bytes
    threshold: int
    count: int
    bundle_id: str
    steward: str = ""
    version: int = SHARE_VERSION
    scheme: str = _SCHEME

    def to_json(self) -> str:
        doc = {
            "habitable_share_version": self.version,
            "scheme": self.scheme,
            "threshold": self.threshold,
            "shares": self.count,
            "index": self.index,
            "steward": self.steward,
            "bundle_id": self.bundle_id,
            "y": _b64e(self.y),
        }
        return json.dumps(doc, indent=2, sort_keys=True)

    @classmethod
    def from_json(cls, text: str) -> Share:
        doc = _load(text, "share")
        if doc.get("habitable_share_version") != SHARE_VERSION:
            raise CryptoError(f"unsupported share version: {doc.get('habitable_share_version')!r}")
        if doc.get("scheme") != _SCHEME:
            raise CryptoError(f"unsupported share scheme: {doc.get('scheme')!r}")
        return cls(
            index=_as_int(doc, "index"),
            y=_b64d(_as_str(doc, "y")),
            threshold=_as_int(doc, "threshold"),
            count=_as_int(doc, "shares"),
            bundle_id=_as_str(doc, "bundle_id"),
            steward=_as_str(doc, "steward") if isinstance(doc.get("steward"), str) else "",
        )


def create_recovery_bundle(
    dek: SymmetricKey, threshold: int, stewards: Sequence[str]
) -> tuple[str, list[str]]:
    """Wrap ``dek`` under a fresh secret and split that secret among ``stewards``.

    Returns ``(bundle_json, [share_json, ...])`` — one share per steward, any
    ``threshold`` of which recover the DEK together with the bundle. Distribute
    each share to its steward and keep them apart; the bundle itself is not
    secret but is useless without ``threshold`` shares.
    """
    count = len(stewards)
    if not 2 <= threshold <= count:
        raise CryptoError(
            f"threshold must satisfy 2 <= M <= N stewards (got M={threshold}, N={count})"
        )

    recovery_secret = os.urandom(_SECRET_BYTES)
    kek = SymmetricKey(recovery_secret)
    wrapped = kek.encrypt(dek._raw(), aad=_THRESHOLD_AAD)
    bundle_id = hashlib.sha256(wrapped).hexdigest()[:16]

    bundle = {
        "habitable_recovery_bundle_version": RECOVERY_BUNDLE_VERSION,
        "aead": "chacha20poly1305",
        "scheme": _SCHEME,
        "threshold": threshold,
        "shares": count,
        "bundle_id": bundle_id,
        "wrapped_dek": _b64e(wrapped),
    }

    raw_shares = split_secret(recovery_secret, threshold, count)
    share_docs = [
        Share(
            index=x,
            y=y,
            threshold=threshold,
            count=count,
            bundle_id=bundle_id,
            steward=stewards[i],
        ).to_json()
        for i, (x, y) in enumerate(raw_shares)
    ]
    return json.dumps(bundle, indent=2, sort_keys=True), share_docs


def recover_dek(bundle_json: str, share_jsons: Sequence[str]) -> SymmetricKey:
    """Reconstruct the DEK from a recovery bundle and a quorum of shares."""
    bundle = _load(bundle_json, "recovery bundle")
    if bundle.get("habitable_recovery_bundle_version") != RECOVERY_BUNDLE_VERSION:
        raise CryptoError(
            f"unsupported bundle version: {bundle.get('habitable_recovery_bundle_version')!r}"
        )
    if bundle.get("scheme") != _SCHEME:
        raise CryptoError(f"unsupported bundle scheme: {bundle.get('scheme')!r}")
    threshold = _as_int(bundle, "threshold")
    bundle_id = _as_str(bundle, "bundle_id")
    wrapped = _b64d(_as_str(bundle, "wrapped_dek"))

    shares = [Share.from_json(text) for text in share_jsons]
    for s in shares:
        if s.bundle_id != bundle_id:
            raise CryptoError(
                "a share does not belong to this recovery bundle (bundle_id mismatch)"
            )
    # De-duplicate by index so an accidentally repeated share is not double-counted.
    unique: dict[int, Share] = {}
    for s in shares:
        unique.setdefault(s.index, s)
    quorum = list(unique.values())
    if len(quorum) < threshold:
        raise CryptoError(
            f"need at least {threshold} distinct shares to recover; got {len(quorum)}"
        )

    recovery_secret = combine_secret([(s.index, s.y) for s in quorum])
    kek = SymmetricKey(recovery_secret)
    dek_bytes = kek.decrypt(wrapped, aad=_THRESHOLD_AAD)
    return SymmetricKey(dek_bytes)


# --- small JSON helpers (mirroring habitable.crypto) --------------------------


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(text: str) -> bytes:
    try:
        return base64.b64decode(text, validate=True)
    except ValueError as exc:
        raise CryptoError("invalid base64 in share material") from exc


def _load(text: str, what: str) -> dict[str, object]:
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CryptoError(f"{what} is not valid JSON") from exc
    if not isinstance(doc, dict):
        raise CryptoError(f"{what} must be a JSON object")
    return doc


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
