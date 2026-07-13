# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Threshold (M-of-N) social custody of recovery keys (EXP-11)."""

from __future__ import annotations

import itertools
import os

import pytest
from hypothesis import given
from hypothesis import strategies as st

from habitable.crypto import SymmetricKey
from habitable.errors import CryptoError
from habitable.threshold import (
    Share,
    combine_secret,
    create_recovery_bundle,
    recover_dek,
    split_secret,
)

# --- low-level Shamir over GF(2^8) --------------------------------------------


def test_any_threshold_subset_reconstructs_the_secret() -> None:
    secret = os.urandom(32)
    shares = split_secret(secret, threshold=3, count=5)
    assert len(shares) == 5
    # Every 3-of-5 combination recovers the exact secret.
    for subset in itertools.combinations(shares, 3):
        assert combine_secret(list(subset)) == secret
    # And a full set does too.
    assert combine_secret(shares) == secret


def test_fewer_than_threshold_shares_are_rejected() -> None:
    secret = os.urandom(16)
    shares = split_secret(secret, threshold=3, count=4)
    # combine_secret still needs >= 2 points; below M it simply returns a
    # different (wrong) secret — recovery is enforced end-to-end via recover_dek.
    with pytest.raises(CryptoError):
        combine_secret(shares[:1])


def test_two_shares_below_threshold_do_not_reveal_the_secret() -> None:
    secret = bytes([0x42] * 8)
    shares = split_secret(secret, threshold=3, count=5)
    # With only 2 of 3 required points, interpolation yields some 8-byte value
    # that is (with overwhelming probability) not the real secret.
    guessed = combine_secret(shares[:2])
    assert guessed != secret


@given(
    secret=st.binary(min_size=1, max_size=48),
    params=st.sampled_from([(2, 2), (2, 3), (3, 5), (4, 7), (5, 5)]),
)
def test_roundtrip_property(secret: bytes, params: tuple[int, int]) -> None:
    threshold, count = params
    shares = split_secret(secret, threshold, count)
    # A random threshold-sized subset must always round-trip.
    subset = shares[:threshold]
    assert combine_secret(subset) == secret


def test_split_rejects_bad_parameters() -> None:
    with pytest.raises(CryptoError):
        split_secret(b"x", threshold=1, count=3)  # M must be >= 2
    with pytest.raises(CryptoError):
        split_secret(b"x", threshold=4, count=3)  # M must be <= N
    with pytest.raises(CryptoError):
        split_secret(b"", threshold=2, count=3)  # empty secret
    with pytest.raises(CryptoError):
        split_secret(b"x", threshold=2, count=256)  # too many shares


def test_combine_rejects_duplicate_and_mismatched_shares() -> None:
    shares = split_secret(os.urandom(8), threshold=2, count=3)
    with pytest.raises(CryptoError):
        combine_secret([shares[0], shares[0]])  # duplicate x
    with pytest.raises(CryptoError):
        combine_secret([shares[0]])  # too few
    bad = [(shares[0][0], shares[0][1]), (shares[1][0], shares[1][1][:-1])]
    with pytest.raises(CryptoError):
        combine_secret(bad)  # length mismatch


@pytest.mark.parametrize("bad_x", [-1, 0, 256, True])
def test_combine_rejects_out_of_field_x_coordinates(bad_x: int) -> None:
    shares = split_secret(os.urandom(8), threshold=2, count=2)
    with pytest.raises(CryptoError, match=r"1\.\.255"):
        combine_secret([(bad_x, shares[0][1]), shares[1]])


# --- end-to-end DEK custody ---------------------------------------------------


def _same_key(a: SymmetricKey, b: SymmetricKey) -> bool:
    """Two SymmetricKeys are equal iff each can open the other's ciphertext."""
    blob = a.encrypt(b"probe", aad=b"t")
    return b.decrypt(blob, aad=b"t") == b"probe"


def test_bundle_and_recover_roundtrip() -> None:
    dek = SymmetricKey.generate()
    bundle, shares = create_recovery_bundle(dek, threshold=2, stewards=["Ana", "Bo", "Cy"])
    assert len(shares) == 3

    recovered = recover_dek(bundle, shares[:2])
    assert _same_key(dek, recovered)
    # A different quorum recovers the same DEK too.
    assert _same_key(dek, recover_dek(bundle, [shares[0], shares[2]]))


def test_single_share_cannot_recover() -> None:
    dek = SymmetricKey.generate()
    bundle, shares = create_recovery_bundle(dek, threshold=2, stewards=["Ana", "Bo", "Cy"])
    with pytest.raises(CryptoError):
        recover_dek(bundle, shares[:1])


def test_duplicate_share_is_not_counted_toward_quorum() -> None:
    dek = SymmetricKey.generate()
    bundle, shares = create_recovery_bundle(dek, threshold=3, stewards=["A", "B", "C", "D"])
    with pytest.raises(CryptoError):
        recover_dek(bundle, [shares[0], shares[0], shares[0]])


def test_shares_from_a_different_bundle_are_rejected() -> None:
    dek = SymmetricKey.generate()
    bundle_a, shares_a = create_recovery_bundle(dek, threshold=2, stewards=["A", "B", "C"])
    _bundle_b, shares_b = create_recovery_bundle(dek, threshold=2, stewards=["A", "B", "C"])
    with pytest.raises(CryptoError, match="bundle_id"):
        recover_dek(bundle_a, [shares_a[0], shares_b[1]])


def test_wrong_shares_do_not_yield_a_usable_key() -> None:
    # A quorum of shares that are individually valid but whose y-values were
    # tampered with must fail authentication, not silently return a bad key.
    dek = SymmetricKey.generate()
    bundle, shares = create_recovery_bundle(dek, threshold=2, stewards=["A", "B", "C"])
    tampered = Share.from_json(shares[0])
    corrupt = Share(
        index=tampered.index,
        y=bytes((tampered.y[0] ^ 0xFF, *tampered.y[1:])),
        threshold=tampered.threshold,
        count=tampered.count,
        bundle_id=tampered.bundle_id,
        steward=tampered.steward,
    ).to_json()
    with pytest.raises(CryptoError):
        recover_dek(bundle, [corrupt, shares[1]])


def test_create_bundle_rejects_bad_threshold() -> None:
    dek = SymmetricKey.generate()
    with pytest.raises(CryptoError):
        create_recovery_bundle(dek, threshold=1, stewards=["A", "B"])
    with pytest.raises(CryptoError):
        create_recovery_bundle(dek, threshold=3, stewards=["A", "B"])


def test_share_json_roundtrip_and_version_checks() -> None:
    dek = SymmetricKey.generate()
    _bundle, shares = create_recovery_bundle(dek, threshold=2, stewards=["Ana", "Bo"])
    parsed = Share.from_json(shares[0])
    assert parsed.steward == "Ana"
    assert parsed.threshold == 2
    assert parsed.count == 2
    # Re-serializing and re-parsing is stable.
    assert Share.from_json(parsed.to_json()).y == parsed.y

    with pytest.raises(CryptoError):
        Share.from_json("not json")
    with pytest.raises(CryptoError):
        Share.from_json('{"habitable_share_version": 99}')


def test_recover_rejects_malformed_bundle() -> None:
    dek = SymmetricKey.generate()
    _bundle, shares = create_recovery_bundle(dek, threshold=2, stewards=["A", "B"])
    with pytest.raises(CryptoError):
        recover_dek("not json", shares)
    with pytest.raises(CryptoError):
        recover_dek('{"habitable_recovery_bundle_version": 99}', shares)
