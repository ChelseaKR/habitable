# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Property-based invariants for the assurance-critical core.

`tests/test_verify_fuzz.py` property-hardens the *packet verifier* against hostile
input. This module extends the same discipline inward, to the four primitives every
packet's proof actually rests on — the primitive-level targets named in
`docs/productionization.md` §E17 ("Expand property-based testing"):

1. **Canonical JSON** — round-trip, key-order independence, byte stability, and
   the whitespace/sort rules every hash and signature in habitable depends on.
2. **Chain of custody** — append/verify invariants: no accepted reordering,
   insertion, interior deletion, or hashed-field mutation; hostile records and
   signatures answered with exactly one named error (`CustodyError`); plus an
   honest, executable statement of the one edit the chain alone *cannot* see
   (suffix truncation, which is why the head hash is committed separately).
3. **Sealed boxes and vault AEAD** — round-trips, and exactly one named error
   (`CryptoError`) for every hostile input, never a bare library exception.
4. **Timestamp tokens** — parse/verify invariants: only `TimestampError` on
   hostile input, and no accepted mutation of a dev token. For RFC 3161, whose
   CMS wrapper legitimately carries bytes outside the signature, the invariant is
   exercised **both with a synthetic certificate anchor configured and without
   one**, and is stated as what actually holds: mutation can never move the
   attested ``gen_time`` or ``digest``, and can never *manufacture* trust. Trust
   is losable — editing the embedded certificate breaks the anchor match and
   drops `trusted_chain` to `False`, a fail-closed direction that is pinned
   executably rather than claimed away.

Everything here is offline and synthetic: the local RFC 3161 issuer and the dev
TSA, never a network authority and never real tenant data.
"""

from __future__ import annotations

import base64
import json
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import Certificate
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from habitable.canonical import _CHUNK, JSONValue, canonical_json, sha256_bytes, sha256_file
from habitable.crypto import Identity, SymmetricKey, open_sealed, seal_to
from habitable.errors import CryptoError, CustodyError, TimestampError
from habitable.evidence import GENESIS_PREV_HASH, CustodyAction, CustodyEntry, CustodyLog
from habitable.tsa import (
    DevTSA,
    LocalRfc3161TSA,
    TimestampInfo,
    TimestampToken,
    retimestamp,
    verify_archive_chain,
    verify_token,
)

# The same fixed instant `tests/conftest.py` uses, so anything printed by a failing
# example is reproducible. Declared locally because `tests/` is not a package.
FIXED_EPOCH_SECONDS = 1_767_312_000

# Hypothesis forbids function-scoped fixtures inside `@given`, so file-backed
# properties write into one module-scoped scratch directory.
_SCRATCH = Path(tempfile.mkdtemp(prefix="habitable-props-"))

# =============================================================================
# 1. Canonical JSON: the same logical content must always produce the same bytes
# =============================================================================

_KEY = st.text(alphabet="abcABC_0é", max_size=6)
_LEAF: st.SearchStrategy[JSONValue] = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(2**53), max_value=2**53),
    st.floats(allow_nan=False, allow_infinity=False),
    st.text(max_size=12),
)


def _extend(children: st.SearchStrategy[JSONValue]) -> st.SearchStrategy[JSONValue]:
    return cast(
        "st.SearchStrategy[JSONValue]",
        st.lists(children, max_size=3) | st.dictionaries(_KEY, children, max_size=3),
    )


_JSON: st.SearchStrategy[JSONValue] = st.recursive(_LEAF, _extend, max_leaves=8)


def _reordered(value: JSONValue) -> JSONValue:
    """Rebuild every mapping with its keys inserted in the opposite order."""
    if isinstance(value, dict):
        return {key: _reordered(value[key]) for key in sorted(value, reverse=True)}
    if isinstance(value, list):
        return [_reordered(item) for item in value]
    return value


def _outside_strings(encoded: bytes) -> bytes:
    """Drop every JSON string literal, leaving only structural bytes."""
    out = bytearray()
    in_string = False
    escaped = False
    for byte in encoded:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:  # backslash
                escaped = True
            elif byte == 0x22:  # closing quote
                in_string = False
        elif byte == 0x22:  # opening quote
            in_string = True
        else:
            out.append(byte)
    return bytes(out)


def _key_orders(encoded: bytes) -> list[list[str]]:
    """Every object's key order, exactly as it appears in ``encoded``."""
    orders: list[list[str]] = []

    def hook(pairs: list[tuple[str, JSONValue]]) -> dict[str, JSONValue]:
        orders.append([key for key, _ in pairs])
        return dict(pairs)

    json.loads(encoded, object_pairs_hook=hook)
    return orders


class TestCanonicalJson:
    """Hashing and signing are only meaningful if the bytes are reproducible."""

    @settings(max_examples=200, deadline=None)
    @given(value=_JSON)
    def test_round_trips_through_json(self, value: JSONValue) -> None:
        assert json.loads(canonical_json(value)) == value

    @settings(max_examples=200, deadline=None)
    @given(value=_JSON)
    def test_encoding_is_idempotent(self, value: JSONValue) -> None:
        encoded = canonical_json(value)
        assert canonical_json(json.loads(encoded)) == encoded

    @settings(max_examples=200, deadline=None)
    @given(value=_JSON)
    def test_key_insertion_order_cannot_change_the_bytes_or_digest(self, value: JSONValue) -> None:
        encoded = canonical_json(value)
        assert canonical_json(_reordered(value)) == encoded
        assert sha256_bytes(canonical_json(_reordered(value))) == sha256_bytes(encoded)

    @settings(max_examples=200, deadline=None)
    @given(value=_JSON)
    def test_every_object_is_key_sorted(self, value: JSONValue) -> None:
        for order in _key_orders(canonical_json(value)):
            assert order == sorted(order)

    @settings(max_examples=200, deadline=None)
    @given(value=_JSON)
    def test_no_insignificant_whitespace(self, value: JSONValue) -> None:
        structural = _outside_strings(canonical_json(value))
        assert not set(structural) & {0x20, 0x09, 0x0A, 0x0D}

    @settings(max_examples=100, deadline=None)
    @given(
        text=st.text(alphabet=st.characters(min_codepoint=0xA1, max_codepoint=0x2FF), max_size=8)
    )
    def test_non_ascii_is_emitted_as_utf8_not_escaped(self, text: str) -> None:
        encoded = canonical_json(text)
        assert b"\\u" not in encoded
        assert text.encode("utf-8") in encoded

    @pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
    def test_non_finite_floats_are_refused(self, bad: float) -> None:
        with pytest.raises(ValueError, match="Out of range"):
            canonical_json(bad)

    @settings(max_examples=50, deadline=None)
    @given(payload=st.binary(max_size=2048))
    def test_file_and_byte_digests_agree(self, payload: bytes) -> None:
        path = _SCRATCH / "payload.bin"
        path.write_bytes(payload)
        assert sha256_file(path) == sha256_bytes(payload)

    @pytest.mark.parametrize("size", [_CHUNK - 1, _CHUNK, _CHUNK + 1])
    def test_streaming_digest_holds_across_the_chunk_boundary(self, size: int) -> None:
        """`sha256_file` reads in fixed chunks; the seam must not change the digest."""
        payload = (bytes(range(256)) * (size // 256 + 1))[:size]
        path = _SCRATCH / f"chunk-{size}.bin"
        path.write_bytes(payload)
        assert sha256_file(path) == sha256_bytes(payload)


# =============================================================================
# 2. Chain of custody: append-only, hash-linked, and tamper-evident
# =============================================================================

_ACTIONS = st.sampled_from([action.value for action in CustodyAction])
_ITEMS = st.sampled_from(["cap-1", "cap-2", "cap-3"])
_ACTORS = st.sampled_from(["organizer", "tenant", "device-a"])
_DETAILS = st.dictionaries(
    st.sampled_from(["content_hash", "media_type", "tsa"]),
    st.text(alphabet="abc0123", max_size=5),
    max_size=3,
)
_OPS = st.lists(st.tuples(_ACTIONS, _ITEMS, _ACTORS, _DETAILS), min_size=1, max_size=8)

_HASHED_FIELDS = ("seq", "action", "item_id", "hlc", "actor_commitment", "prev_hash", "details")
_SIGNER = Identity.generate()

# Positions into a per-example collection are drawn from the collection's own range
# (`st.sampled_from`, via `st.data()` where the length is only known inside the
# example) rather than from an unbounded integer reduced with `%`: the same
# bounded-draw discipline `tests/test_verify_fuzz.py` uses for byte offsets, so
# Hypothesis can shrink and report the index it actually used.

type _Op = tuple[str, str, str, dict[str, str]]


def _build(ops: Sequence[_Op], *, sign: bool = False) -> CustodyLog:
    log = CustodyLog()
    for index, (action, item_id, actor, details) in enumerate(ops):
        log.append(
            action,
            item_id,
            actor=actor,
            hlc=f"{index:06d}-node",
            details=details,
            identity=_SIGNER if sign else None,
        )
    return log


def _mutate(entry: CustodyEntry, field: str) -> CustodyEntry:
    """Alter exactly one of the fields the entry hash commits to."""
    if field == "seq":
        return replace(entry, seq=entry.seq + 1)
    if field == "details":
        return replace(entry, details={**entry.details, "injected": "x"})
    if field == "action":
        return replace(entry, action=entry.action + "!")
    if field == "item_id":
        return replace(entry, item_id=entry.item_id + "!")
    if field == "hlc":
        return replace(entry, hlc=entry.hlc + "!")
    if field == "actor_commitment":
        return replace(entry, actor_commitment=entry.actor_commitment + "!")
    return replace(entry, prev_hash=entry.prev_hash + "!")


class TestCustodyChain:
    """Insertion, deletion, reordering, and edits must all break the chain."""

    @settings(max_examples=60, deadline=None)
    @given(ops=_OPS)
    def test_intact_chain_verifies_and_summarizes_every_item(self, ops: Sequence[_Op]) -> None:
        log = _build(ops)
        result = log.verify()
        assert result.ok
        assert result.length == len(ops)
        assert result.head_hash == log.entries[-1].entry_hash == log.head_hash
        assert log.entries[0].prev_hash == GENESIS_PREV_HASH
        assert sum(summary.entries for summary in result.items.values()) == len(ops)

    @settings(max_examples=60, deadline=None)
    @given(ops=_OPS)
    def test_exported_chain_verifies_standalone_without_any_identity(
        self, ops: Sequence[_Op]
    ) -> None:
        log = _build(ops, sign=True)
        records = log.to_export_records()
        for record in records:
            assert set(record) == {
                "seq",
                "action",
                "item_id",
                "hlc",
                "actor_commitment",
                "details",
                "prev_hash",
                "entry_hash",
            }
        rebuilt = CustodyLog.from_records(records)
        assert rebuilt.verify().ok
        assert rebuilt.head_hash == log.head_hash
        # The vault form keeps what the export drops.
        assert all(record["actor"] for record in log.to_vault_records())

    @settings(max_examples=120, deadline=None)
    @given(ops=_OPS, data=st.data(), field=st.sampled_from(_HASHED_FIELDS))
    def test_no_hashed_field_can_be_edited_undetected(
        self, ops: Sequence[_Op], data: st.DataObject, field: str
    ) -> None:
        log = _build(ops)
        entries = list(log.entries)
        target = data.draw(st.sampled_from(range(len(entries))), label="entry")
        entries[target] = _mutate(entries[target], field)
        with pytest.raises(CustodyError):
            CustodyLog(entries).verify()

    @settings(max_examples=120, deadline=None)
    @given(ops=_OPS, data=st.data())
    def test_forged_entry_hash_is_rejected(self, ops: Sequence[_Op], data: st.DataObject) -> None:
        log = _build(ops)
        entries = list(log.entries)
        target = data.draw(st.sampled_from(range(len(entries))), label="entry")
        entries[target] = replace(entries[target], entry_hash=sha256_bytes(b"forged"))
        with pytest.raises(CustodyError):
            CustodyLog(entries).verify()

    @settings(max_examples=120, deadline=None)
    @given(ops=_OPS, data=st.data())
    def test_reordering_two_entries_is_rejected(
        self, ops: Sequence[_Op], data: st.DataObject
    ) -> None:
        entries = list(_build(ops).entries)
        assume(len(entries) >= 2)
        i = data.draw(st.sampled_from(range(len(entries))), label="left")
        # Drawn from the complement, so no example is ever discarded for i == j.
        j = data.draw(st.sampled_from([k for k in range(len(entries)) if k != i]), label="right")
        entries[i], entries[j] = entries[j], entries[i]
        with pytest.raises(CustodyError):
            CustodyLog(entries).verify()

    @settings(max_examples=120, deadline=None)
    @given(ops=_OPS, data=st.data())
    def test_interior_deletion_is_rejected(self, ops: Sequence[_Op], data: st.DataObject) -> None:
        entries = list(_build(ops).entries)
        assume(len(entries) >= 2)
        # Never the tail: see the truncation limit below.
        target = data.draw(st.sampled_from(range(len(entries) - 1)), label="entry")
        del entries[target]
        with pytest.raises(CustodyError):
            CustodyLog(entries).verify()

    @settings(max_examples=120, deadline=None)
    @given(ops=_OPS, data=st.data())
    def test_replaying_an_entry_is_rejected(self, ops: Sequence[_Op], data: st.DataObject) -> None:
        entries = list(_build(ops).entries)
        target = data.draw(st.sampled_from(range(len(entries))), label="entry")
        entries.insert(target, entries[target])
        with pytest.raises(CustodyError):
            CustodyLog(entries).verify()

    @settings(max_examples=60, deadline=None)
    @given(ops=_OPS)
    def test_suffix_truncation_is_invisible_to_the_chain_but_moves_the_head(
        self, ops: Sequence[_Op]
    ) -> None:
        """The honest limit: a hash-linked chain proves a *prefix*, not completeness.

        Dropping trailing entries leaves a chain that still verifies — which is
        precisely why the head hash is committed outside the chain (in the signed
        bundle, and in the sync proof summary). This pins that boundary so it can
        never be quietly mistaken for a completeness proof.
        """
        log = _build(ops)
        assume(len(log) >= 2)
        truncated = CustodyLog(list(log.entries[:-1]))
        assert truncated.verify().ok
        assert truncated.head_hash != log.head_hash

    @settings(max_examples=40, deadline=None)
    @given(ops=_OPS, data=st.data())
    def test_signed_entries_verify_and_a_forged_signature_is_rejected(
        self, ops: Sequence[_Op], data: st.DataObject
    ) -> None:
        log = _build(ops, sign=True)
        keys = {entry.actor_commitment: _SIGNER.public().sign_public for entry in log.entries}
        result = log.verify(signer_keys=keys)
        assert result.signatures_checked == len(ops)

        entries = list(log.entries)
        target = data.draw(st.sampled_from(range(len(entries))), label="entry")
        raw = bytearray(base64.b64decode(entries[target].signature))
        raw[0] ^= 0xFF
        entries[target] = replace(
            entries[target], signature=base64.b64encode(bytes(raw)).decode("ascii")
        )
        with pytest.raises(CustodyError):
            CustodyLog(entries).verify(signer_keys=keys)

    @settings(max_examples=200, deadline=None)
    @given(ops=_OPS, data=st.data(), signature=st.text(max_size=12))
    def test_hostile_signatures_raise_only_custodyerror(
        self, ops: Sequence[_Op], data: st.DataObject, signature: str
    ) -> None:
        """An arbitrary `signature` string must never escape as a library exception.

        A stored or imported entry's base64 `signature` is hostile input in exactly
        the way a token's `token_b64` is: `base64.b64decode` raises `binascii.Error`
        on a bad alphabet or bad padding, and `CustodyLog.verify` may only ever
        raise `CustodyError`.
        """
        log = _build(ops, sign=True)
        keys = {entry.actor_commitment: _SIGNER.public().sign_public for entry in log.entries}
        entries = list(log.entries)
        target = data.draw(st.sampled_from(range(len(entries))), label="entry")
        entries[target] = replace(entries[target], signature=signature)
        try:
            CustodyLog(entries).verify(signer_keys=keys)
        except CustodyError:
            return
        except Exception as exc:  # a non-habitable exception type is the failure
            raise AssertionError(f"verify leaked {type(exc).__name__}: {exc}") from exc
        # Only the empty signature is a legitimate accept: it means "unsigned".
        assert signature == ""

    @settings(max_examples=200, deadline=None)
    @given(
        records=st.lists(
            st.dictionaries(
                st.sampled_from(
                    ["seq", "action", "item_id", "hlc", "actor_commitment", "details", "prev_hash"]
                ),
                st.one_of(st.text(max_size=6), st.integers(), st.none(), st.booleans()),
                max_size=7,
            ),
            max_size=3,
        )
    )
    def test_hostile_records_raise_only_custodyerror(
        self, records: Sequence[Mapping[str, JSONValue]]
    ) -> None:
        """Imported chains are hostile input: rebuild + verify may only raise `CustodyError`."""
        try:
            CustodyLog.from_records(records).verify()
        except CustodyError:
            return
        except Exception as exc:  # a non-habitable exception type is the failure
            raise AssertionError(f"from_records/verify leaked {type(exc).__name__}: {exc}") from exc
        # The only accepted input is the empty chain; anything else lacks `entry_hash`.
        assert not records

    @settings(max_examples=60, deadline=None)
    @given(ops=_OPS)
    def test_hlc_mapped_proof_relinks_into_a_chain_that_still_verifies(
        self, ops: Sequence[_Op]
    ) -> None:
        log = _build(ops)
        proof = log.integrity_proof(hlc_map=lambda hlc: sha256_bytes(f"opaque:{hlc}".encode()))
        entries = cast("list[Mapping[str, JSONValue]]", proof["entries"])
        rebuilt = CustodyLog.from_records(entries)
        assert rebuilt.verify().ok
        assert rebuilt.head_hash == proof["head_hash"]
        assert proof["length"] == len(ops)
        original_hlcs = {entry.hlc for entry in log.entries}
        assert not original_hlcs & {cast("str", record["hlc"]) for record in entries}

    @settings(max_examples=60, deadline=None)
    @given(ops=_OPS)
    def test_integrity_proof_refuses_to_describe_a_broken_chain(self, ops: Sequence[_Op]) -> None:
        entries = list(_build(ops).entries)
        entries[-1] = replace(entries[-1], item_id=entries[-1].item_id + "!")
        with pytest.raises(CustodyError):
            CustodyLog(entries).integrity_proof()


# =============================================================================
# 3. Sealed boxes and vault AEAD: one named error, never a library traceback
# =============================================================================

_RECIPIENT = Identity.generate()
_STRANGER = Identity.generate()


class TestSealedBox:
    """Hostile bytes arrive from a relay, a courier file, or a pairing code."""

    @settings(max_examples=100, deadline=None)
    @given(plaintext=st.binary(max_size=512))
    def test_round_trips_to_the_addressed_device_only(self, plaintext: bytes) -> None:
        box = seal_to(_RECIPIENT.public(), plaintext)
        assert open_sealed(_RECIPIENT, box) == plaintext
        with pytest.raises(CryptoError):
            open_sealed(_STRANGER, box)

    @settings(max_examples=50, deadline=None)
    @given(plaintext=st.binary(max_size=64))
    def test_sealing_is_never_deterministic(self, plaintext: bytes) -> None:
        assert seal_to(_RECIPIENT.public(), plaintext) != seal_to(_RECIPIENT.public(), plaintext)

    @settings(max_examples=150, deadline=None)
    @given(
        plaintext=st.binary(max_size=64),
        data=st.data(),
        value=st.integers(min_value=0, max_value=255),
    )
    def test_any_single_byte_change_fails_closed(
        self, plaintext: bytes, data: st.DataObject, value: int
    ) -> None:
        box = bytearray(seal_to(_RECIPIENT.public(), plaintext))
        index = data.draw(st.sampled_from(range(len(box))), label="byte")
        box[index] = value if box[index] != value else value ^ 0xFF
        with pytest.raises(CryptoError):
            open_sealed(_RECIPIENT, bytes(box))

    @settings(max_examples=200, deadline=None)
    @given(box=st.binary(max_size=128))
    def test_arbitrary_bytes_raise_only_cryptoerror(self, box: bytes) -> None:
        """Includes degenerate keys (all-zero ephemeral point), which X25519 refuses."""
        try:
            open_sealed(_RECIPIENT, box)
        except CryptoError:
            return
        except Exception as exc:  # a non-habitable exception type is the failure
            raise AssertionError(f"open_sealed leaked {type(exc).__name__}: {exc}") from exc
        raise AssertionError("open_sealed accepted arbitrary bytes")

    @pytest.mark.parametrize("box", [b"", b"\x00" * 43, b"\x00" * 44, b"\x00" * 96])
    def test_degenerate_ephemeral_keys_are_named_rejections(self, box: bytes) -> None:
        with pytest.raises(CryptoError):
            open_sealed(_RECIPIENT, box)


_KEY_A = SymmetricKey.generate()
_KEY_B = SymmetricKey.generate()


class TestVaultAead:
    """The at-rest layer: authenticated, key-bound, and context-bound."""

    @settings(max_examples=100, deadline=None)
    @given(plaintext=st.binary(max_size=512), aad=st.binary(max_size=16))
    def test_round_trips_under_the_same_key_and_context(self, plaintext: bytes, aad: bytes) -> None:
        assert _KEY_A.decrypt(_KEY_A.encrypt(plaintext, aad=aad), aad=aad) == plaintext

    @settings(max_examples=100, deadline=None)
    @given(plaintext=st.binary(max_size=64), aad=st.binary(max_size=8))
    def test_wrong_key_or_wrong_context_fails_closed(self, plaintext: bytes, aad: bytes) -> None:
        blob = _KEY_A.encrypt(plaintext, aad=aad)
        with pytest.raises(CryptoError):
            _KEY_B.decrypt(blob, aad=aad)
        with pytest.raises(CryptoError):
            _KEY_A.decrypt(blob, aad=aad + b"\x00")

    @settings(max_examples=200, deadline=None)
    @given(blob=st.binary(max_size=128))
    def test_arbitrary_ciphertext_raises_only_cryptoerror(self, blob: bytes) -> None:
        try:
            _KEY_A.decrypt(blob)
        except CryptoError:
            return
        except Exception as exc:  # a non-habitable exception type is the failure
            raise AssertionError(f"decrypt leaked {type(exc).__name__}: {exc}") from exc
        raise AssertionError("decrypt accepted arbitrary ciphertext")


# =============================================================================
# 4. Timestamp tokens: parse and verify without ever leaking a traceback
# =============================================================================

_DIGEST = sha256_bytes(b"synthetic-evidence-bytes")
_OTHER_DIGEST = sha256_bytes(b"different-synthetic-bytes")
_DEV_TSA = DevTSA("prop-dev-tsa", time_source=lambda: FIXED_EPOCH_SECONDS)
_RFC_TSA = LocalRfc3161TSA("prop-rfc3161", time_source=lambda: FIXED_EPOCH_SECONDS)
_DEV_TOKEN = _DEV_TSA.stamp(_DIGEST)
_RFC_TOKEN = _RFC_TSA.stamp(_DIGEST)

# A second synthetic authority, so "anchor configured, but not *this* token's
# authority" is a distinct, exercised condition rather than an untested one.
_OTHER_RFC_TSA = LocalRfc3161TSA("prop-rfc3161-other", time_source=lambda: FIXED_EPOCH_SECONDS)
_OWN_ANCHOR = [_RFC_TSA.certificate]
_FOREIGN_ANCHOR = [_OTHER_RFC_TSA.certificate]

_RFC_BASELINE = verify_token(_RFC_TOKEN, _DIGEST)
_RFC_ANCHORED_BASELINE = verify_token(_RFC_TOKEN, _DIGEST, trusted_certs=_OWN_ANCHOR)

# Byte offsets are drawn from the token's real length, the way `test_verify_fuzz.py`
# draws them from `len(_BUNDLE) - 1`.
_DEV_BYTE = st.integers(min_value=0, max_value=len(_DEV_TOKEN.data) - 1)
_RFC_BYTE = st.integers(min_value=0, max_value=len(_RFC_TOKEN.data) - 1)
_VALUE = st.integers(min_value=0, max_value=255)


def _mutated(token: TimestampToken, index: int, value: int) -> TimestampToken:
    data = bytearray(token.data)
    data[index] = value if data[index] != value else value ^ 0xFF
    return replace(token, data=bytes(data))


def _attestation_must_hold(
    token: TimestampToken,
    baseline: TimestampInfo,
    *,
    trusted_certs: list[Certificate] | None,
) -> TimestampInfo | None:
    """Either a named rejection, or the pristine token's attested time and digest.

    Returns the accepted :class:`TimestampInfo` (or ``None`` on a rejection) so the
    caller can assert the trust-verdict invariant that applies to its own anchor.
    """
    try:
        info = verify_token(token, _DIGEST, trusted_certs=trusted_certs)
    except TimestampError:
        return None
    except Exception as exc:  # a non-habitable exception type is the failure
        raise AssertionError(f"verify_token leaked {type(exc).__name__}: {exc}") from exc
    assert (info.gen_time, info.digest_hex) == (baseline.gen_time, baseline.digest_hex)
    return info


class TestTimestampTokenParsing:
    @settings(max_examples=100, deadline=None)
    @given(kind=st.text(max_size=8), name=st.text(max_size=8), data=st.binary(max_size=128))
    def test_record_round_trip(self, kind: str, name: str, data: bytes) -> None:
        token = TimestampToken(kind=kind, tsa_name=name, data=data)
        assert TimestampToken.from_dict(token.to_dict()) == token

    @settings(max_examples=200, deadline=None)
    @given(
        raw=st.dictionaries(
            st.sampled_from(["kind", "tsa_name", "token_b64", "extra"]),
            st.one_of(st.text(max_size=10), st.integers(), st.none(), st.booleans()),
            max_size=4,
        )
    )
    def test_malformed_records_raise_only_timestamperror(self, raw: Mapping[str, object]) -> None:
        try:
            TimestampToken.from_dict(raw)
        except TimestampError:
            return
        except Exception as exc:  # a non-habitable exception type is the failure
            raise AssertionError(f"from_dict leaked {type(exc).__name__}: {exc}") from exc

    @pytest.mark.parametrize("token_b64", ["!", "a", "AB", "===", "AA=A", "ab cd"])
    def test_non_alphabet_base64_is_a_named_rejection(self, token_b64: str) -> None:
        with pytest.raises(TimestampError, match="malformed timestamp token record"):
            TimestampToken.from_dict({"kind": "dev", "tsa_name": "x", "token_b64": token_b64})


class TestDevTokenVerification:
    """Every byte of a dev token is inside its signed canonical document."""

    def test_pristine_token_verifies_and_is_never_called_trusted(self) -> None:
        info = verify_token(_DEV_TOKEN, _DIGEST)
        assert info.digest_hex == _DIGEST
        assert info.trusted_chain is False

    @settings(max_examples=250, deadline=None)
    @given(position=_DEV_BYTE, value=_VALUE)
    def test_no_byte_mutation_is_ever_accepted(self, position: int, value: int) -> None:
        with pytest.raises(TimestampError):
            verify_token(_mutated(_DEV_TOKEN, position, value), _DIGEST)

    @settings(max_examples=250, deadline=None)
    @given(data=st.binary(max_size=192))
    def test_arbitrary_token_bytes_raise_only_timestamperror(self, data: bytes) -> None:
        token = TimestampToken(kind="dev", tsa_name="x", data=data)
        try:
            verify_token(token, _DIGEST)
        except TimestampError:
            return
        except Exception as exc:  # a non-habitable exception type is the failure
            raise AssertionError(f"verify_token leaked {type(exc).__name__}: {exc}") from exc
        raise AssertionError("verify_token accepted arbitrary dev-token bytes")

    def test_a_token_never_verifies_against_other_content(self) -> None:
        with pytest.raises(TimestampError, match="digest does not match"):
            verify_token(_DEV_TOKEN, _OTHER_DIGEST)

    @settings(max_examples=50, deadline=None)
    @given(kind=st.text(max_size=8).filter(lambda k: k not in {"dev", "rfc3161"}))
    def test_unknown_kinds_are_refused(self, kind: str) -> None:
        with pytest.raises(TimestampError, match="unknown token kind"):
            verify_token(replace(_DEV_TOKEN, kind=kind), _DIGEST)


class TestRfc3161TokenVerification:
    """A CMS wrapper legitimately carries bytes outside the signature.

    So the invariant is not "every byte is load-bearing". The properties below are
    exercised across the three trust conditions habitable actually ships — **no
    anchor**, **this token's own anchor**, and **some other authority's anchor**;
    each property names the conditions it asserts — and together they pin:

    * the attested ``gen_time`` and ``digest`` can never move;
    * trust can never be *manufactured*: no mutation makes an unanchored or
      foreign-anchored token report ``trusted_chain is True``;
    * trust *can* be lost — editing the embedded certificate breaks the anchor
      match while leaving the CMS signature over TSTInfo verifiable, so an anchored
      ``True`` can become ``False``. That is the fail-closed direction, and
      `test_a_certificate_edit_drops_trust_without_moving_the_attestation` pins it
      executably rather than claiming it away.
    """

    def test_pristine_token_is_trusted_only_under_its_own_anchor(self) -> None:
        assert _RFC_BASELINE.digest_hex == _DIGEST
        assert _RFC_BASELINE.trusted_chain is False
        assert _RFC_ANCHORED_BASELINE.trusted_chain is True
        assert _RFC_ANCHORED_BASELINE.digest_hex == _DIGEST
        foreign = verify_token(_RFC_TOKEN, _DIGEST, trusted_certs=_FOREIGN_ANCHOR)
        assert foreign.trusted_chain is False

    @settings(max_examples=250, deadline=None)
    @given(position=_RFC_BYTE, value=_VALUE)
    def test_mutation_never_moves_the_attested_time_or_digest(
        self, position: int, value: int
    ) -> None:
        """With no anchor and with a real one — the condition the claim rests on."""
        token = _mutated(_RFC_TOKEN, position, value)
        _attestation_must_hold(token, _RFC_BASELINE, trusted_certs=None)
        _attestation_must_hold(token, _RFC_ANCHORED_BASELINE, trusted_certs=_OWN_ANCHOR)

    @settings(max_examples=250, deadline=None)
    @given(position=_RFC_BYTE, value=_VALUE)
    def test_mutation_can_never_manufacture_trust(self, position: int, value: int) -> None:
        """The direction that matters: an untrusted token can never be edited trusted."""
        token = _mutated(_RFC_TOKEN, position, value)
        for anchor in (None, _FOREIGN_ANCHOR):
            info = _attestation_must_hold(token, _RFC_BASELINE, trusted_certs=anchor)
            if info is not None:
                assert info.trusted_chain is False

    def test_a_certificate_edit_drops_trust_without_moving_the_attestation(self) -> None:
        """The honest limit under an anchor: an anchored verdict is losable.

        The last byte of the embedded certificate's DER is the last byte of the
        certificate's *own* signature. Editing it leaves the CMS signature over
        TSTInfo verifiable (the signing public key is in the unchanged `tbs`
        portion), but the certificate no longer matches the anchor by fingerprint
        and no longer verifies against a trusted issuer — so `trusted_chain` drops
        to `False` while the attested time and digest stand.
        """
        cert_der = _RFC_TSA.certificate.public_bytes(serialization.Encoding.DER)
        start = _RFC_TOKEN.data.find(cert_der)
        assert start >= 0, "an RFC 3161 token must embed its signing certificate"
        edited = _mutated(_RFC_TOKEN, start + len(cert_der) - 1, 0x00)
        info = verify_token(edited, _DIGEST, trusted_certs=_OWN_ANCHOR)
        assert info.trusted_chain is False
        assert _RFC_ANCHORED_BASELINE.trusted_chain is True
        assert (info.gen_time, info.digest_hex) == (
            _RFC_ANCHORED_BASELINE.gen_time,
            _RFC_ANCHORED_BASELINE.digest_hex,
        )

    @settings(max_examples=250, deadline=None)
    @given(data=st.binary(max_size=192))
    def test_arbitrary_der_raises_only_timestamperror(self, data: bytes) -> None:
        token = TimestampToken(kind="rfc3161", tsa_name="x", data=data)
        for anchor in (None, _OWN_ANCHOR, _FOREIGN_ANCHOR):
            try:
                verify_token(token, _DIGEST, trusted_certs=anchor)
            except TimestampError:
                continue
            except Exception as exc:  # a non-habitable exception type is the failure
                raise AssertionError(f"verify_token leaked {type(exc).__name__}: {exc}") from exc
            raise AssertionError("verify_token accepted arbitrary RFC 3161 bytes")

    def test_a_token_never_verifies_against_other_content(self) -> None:
        for anchor in (None, _OWN_ANCHOR):
            with pytest.raises(TimestampError):
                verify_token(_RFC_TOKEN, _OTHER_DIGEST, trusted_certs=anchor)


_ARCHIVES = [retimestamp(_RFC_TOKEN, _RFC_TSA)]
_ARCHIVES.append(retimestamp(_ARCHIVES[0], _RFC_TSA))
_ARCHIVES.append(retimestamp(_ARCHIVES[1], _RFC_TSA))

# Every (link, byte offset) a mutation could land on, drawn directly rather than
# reduced from an unbounded integer: the links differ in length, so a shared bound
# would either overrun the short ones or never reach the tail of the long ones.
_ARCHIVE_SITES = [
    (link, position)
    for link, archive in enumerate(_ARCHIVES)
    for position in range(len(archive.data))
]


class TestArchiveChain:
    """Re-timestamping must carry a proof forward without letting a link move."""

    @pytest.mark.parametrize("depth", [1, 2, 3])
    def test_chain_of_any_depth_verifies_in_order(self, depth: int) -> None:
        infos = verify_archive_chain(_DIGEST, _RFC_TOKEN, _ARCHIVES[:depth])
        assert len(infos) == depth + 1
        assert infos[0].digest_hex == _DIGEST

    @settings(max_examples=150, deadline=None)
    @given(site=st.sampled_from(_ARCHIVE_SITES), value=_VALUE)
    def test_a_mutated_link_can_never_extend_the_chain(
        self, site: tuple[int, int], value: int
    ) -> None:
        link, position = site
        archives = list(_ARCHIVES)
        archives[link] = _mutated(archives[link], position, value)
        try:
            verify_archive_chain(_DIGEST, _RFC_TOKEN, archives)
        except TimestampError:
            return
        except Exception as exc:  # a non-habitable exception type is the failure
            raise AssertionError(f"archive chain leaked {type(exc).__name__}: {exc}") from exc
        # An accepted mutation must have landed outside every signed field; with no
        # anchor configured — the condition asserted here — the attested chain must
        # then be identical to the pristine one, field for field.
        assert verify_archive_chain(_DIGEST, _RFC_TOKEN, archives) == verify_archive_chain(
            _DIGEST, _RFC_TOKEN, _ARCHIVES
        )

    @settings(max_examples=150, deadline=None)
    @given(site=st.sampled_from(_ARCHIVE_SITES), value=_VALUE)
    def test_a_mutated_link_can_never_manufacture_trust(
        self, site: tuple[int, int], value: int
    ) -> None:
        """Same sweep with an anchor for a *different* authority: trust stays False."""
        link, position = site
        archives = list(_ARCHIVES)
        archives[link] = _mutated(archives[link], position, value)
        try:
            infos = verify_archive_chain(
                _DIGEST, _RFC_TOKEN, archives, trusted_certs=_FOREIGN_ANCHOR
            )
        except TimestampError:
            return
        except Exception as exc:  # a non-habitable exception type is the failure
            raise AssertionError(f"archive chain leaked {type(exc).__name__}: {exc}") from exc
        assert not any(info.trusted_chain for info in infos)

    def test_dropping_a_link_breaks_the_chain(self) -> None:
        with pytest.raises(TimestampError):
            verify_archive_chain(_DIGEST, _RFC_TOKEN, [_ARCHIVES[1], _ARCHIVES[2]])

    def test_reordering_links_breaks_the_chain(self) -> None:
        with pytest.raises(TimestampError):
            verify_archive_chain(_DIGEST, _RFC_TOKEN, [_ARCHIVES[1], _ARCHIVES[0], _ARCHIVES[2]])
