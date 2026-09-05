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

5. **Sequences, not single shots** — E17's remaining half (issue #257): a
   `RuleBasedStateMachine` over a real packet, applying meaning-preserving
   operations (archive re-timestamp, append a custody event, re-sign) and
   unrepairable ones (media edits, retargeted digests, forged archive links,
   stripped tokens, rewritten timeline text, reordered custody) in any order,
   and checking a model after every step. The four sets of targets
   above generate one hostile input and assert one verdict; they cannot, in
   principle, find the defect where each operation is individually sound and the
   composition is not — which is the shape #163 and #204 both had.

Everything here is offline and synthetic: the local RFC 3161 issuer and the dev
TSA, never a network authority and never real tenant data.
"""

from __future__ import annotations

import base64
import json
import shutil
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import Certificate
from hypothesis import assume, given, settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, invariant, precondition, rule

from habitable.canonical import _CHUNK, JSONValue, canonical_json, sha256_bytes, sha256_file
from habitable.crypto import Identity, SymmetricKey, open_sealed, seal_to
from habitable.errors import CryptoError, CustodyError, TimestampError, VerificationError
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
from habitable.verify import SUPPORTED_PACKET_VERSION, VerificationReport, verify_packet

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


# =============================================================================
# 5. A stateful machine: the defects a single-shot target structurally cannot find
# =============================================================================

_GOLDEN_PACKET = Path(__file__).resolve().parent / "golden" / f"packet-v{SUPPORTED_PACKET_VERSION}"
_PRISTINE_BYTES = (_GOLDEN_PACKET / "bundle.json").read_bytes()
_PRISTINE_BUNDLE: dict[str, Any] = json.loads(_PRISTINE_BYTES)
_PRISTINE_HEAD: str = _PRISTINE_BUNDLE["custody_proof"]["head_hash"]
_PRISTINE_CUSTODY: list[Any] = _PRISTINE_BUNDLE["custody_proof"]["entries"]
_PRISTINE_MEDIA = {
    path.name: path.read_bytes() for path in sorted((_GOLDEN_PACKET / "media").iterdir())
}

# The key the golden packet was really signed with, held out of band the way a
# recipient who has seen a previous packet from this producer would hold it.
_PINNED_PRODUCER_KEY: str = json.loads(
    (_GOLDEN_PACKET / "bundle.sig.json").read_text(encoding="utf-8")
)["sign_public"]

# Bounded draws over the fixture's own shape, as everywhere else in this module:
# an index into a collection comes from that collection's range, never from an
# unbounded integer reduced with `%`, so a failing example shrinks to the index
# it actually used.
_ITEM_INDEX = st.sampled_from(range(len(_PRISTINE_BUNDLE["items"])))
_TIMELINE_INDEX = st.sampled_from(range(len(_PRISTINE_BUNDLE["timeline"])))
_MEDIA_NAMES = sorted(path.name for path in (_GOLDEN_PACKET / "media").iterdir())
_MEDIA_NAME = st.sampled_from(_MEDIA_NAMES)
_MEDIA_BYTE = st.integers(
    min_value=0,
    max_value=min((_GOLDEN_PACKET / "media" / name).stat().st_size for name in _MEDIA_NAMES) - 1,
)

# The machine's own authority. It can mint real RFC 3161 tokens, so it can do
# both halves of the archival story: extend a proof forward honestly, and forge
# a link over bytes no authority ever saw.
_MACHINE_TSA = LocalRfc3161TSA("prop-stateful", time_source=lambda: FIXED_EPOCH_SECONDS)

# The five contradictions the machine can commit, drawn as one value rather than
# spread over five rules; `contradict_something_a_proof_already_fixed` says why.
_CONTRADICTIONS = st.sampled_from(
    [
        "shared media",
        "an item's digest",
        "an item's timestamp token",
        "a timeline entry's text",
        "the custody order",
    ]
)


def test_the_exported_bundle_is_already_canonical() -> None:
    """Re-encoding the golden bundle must return the exported bytes.

    This was a rule inside the machine below, and it was the wrong shape for one:
    it changed nothing, so a third of the machine's steps went on re-asserting a
    property of a *fixture*, in states where it had already been asserted seven
    times. It is a property of the export, it is true or false before the machine
    starts, and one assertion states it.

    Why it matters: if the exported bytes were not canonical, every hash and
    signature over them would be a claim about one particular serialisation
    rather than about the content -- and a recipient who re-encoded before
    hashing, as any independent implementation might, would get a different
    answer and no way to tell which of them was wrong.
    """
    assert canonical_json(_PRISTINE_BUNDLE) == _PRISTINE_BYTES


class HostilePacketSequences(RuleBasedStateMachine):
    """Sequences of operations on a real packet, checked against a model after each.

    The single-shot targets above and in `tests/test_verify_fuzz.py` generate one
    hostile input and assert one verdict. They cannot, in principle, find the
    defect where every operation is individually sound and the *composition* is
    not — which is the shape of this project's two most serious findings so far:
    the `have` manifest validated one line after the CRDT merge (#163), and an
    anchor check that never consulted certificate validity (#204). Both needed a
    sequence: a state reached legitimately, then an operation that was fine in
    isolation.

    So this machine holds a working copy of the newest golden packet and applies
    operations to it. Three kinds:

    * **Meaning-preserving** — extend an item's archive-timestamp chain
      (RFC 4998), append a later custody event, re-sign. None of these change
      what the packet asserts about the evidence.
    * **Unrepairable** — flip a byte of shared media, retarget an item's digest,
      attach an archive link over bytes no authority stamped, strip an item's
      token, rewrite a timeline entry's text under its own commitment, reorder
      the custody chain. Each contradicts something a *timestamp authority*, a
      media digest, or a custody-bound commitment already fixed, so no amount of
      producer-side repair can make it verify again.
    * **The honest limit** — truncate the custody chain. A hash-linked chain
      proves a prefix, so the shortened chain still verifies standalone; the
      head hash moves, which is exactly why it is committed separately.

    Every bundle-editing rule draws whether to re-sign -- all but the truncation
    below, which always does, and says why -- because that is the composition
    that matters: re-signing is individually sound (a packet's signature carries
    its own verifying key, FIX-05), and the model asserts it can never launder a
    contradiction. When a tampered packet has a *valid* signature, the invariant
    additionally demands that `signature_ok` really is True — otherwise the
    rejection would be the signature's doing and the anchor checks would be
    getting credit for work they did not do.

    Each step is verified twice, under both trust policies the verifier offers:
    open (the signature is self-attesting) and with the producer key pinned. That
    is where the limit and its mitigation are pinned together — an operation the
    open policy tolerates because the producer could legitimately have done it is
    exactly one the pin refuses.
    """

    def __init__(self) -> None:
        super().__init__()
        self.packet = _SCRATCH / "stateful-packet"
        if self.packet.exists():
            shutil.rmtree(self.packet)
        shutil.copytree(_GOLDEN_PACKET, self.packet)
        #: A field inside the bundle was made to contradict something a timestamp
        #: authority or a custody-bound commitment already fixed. Held as history
        #: rather than derived, because no rule here can put such a field back --
        #: the read-back checks below cover everything that *can* be undone.
        self.unrepairable = False
        #: `bundle.sig.json` now carries a key the original producer never used.
        self.producer_key_replaced = False
        #: The bundle bytes the signature on disk actually covers. Not a boolean
        #: "is the signature stale": appending a custody entry and then dropping
        #: it again restores the exported bytes exactly, and the *original*
        #: signature is valid over them once more. This machine found that
        #: two-step composition in its own model on its first run -- which is
        #: precisely the class of thing it exists to find, so it is recorded
        #: here rather than quietly repaired.
        self.signed_bytes = _PRISTINE_BYTES
        #: the custody chain no longer walks, so it cannot be rebuilt or extended.
        self.custody_broken = False
        #: archive links added so far. Every link is re-verified on every later
        #: step, so an uncapped chain makes the machine's cost quadratic in the
        #: step count for no new coverage -- `TestArchiveChain` above already
        #: sweeps depth 1..3 exhaustively. Three is enough to interleave an
        #: honest link, a forged one, and a repair.
        self.archive_links = 0

    # --- reading and writing the working packet ------------------------------

    def _read(self) -> dict[str, Any]:
        return cast("dict[str, Any]", json.loads((self.packet / "bundle.json").read_bytes()))

    def _write(self, bundle: Mapping[str, Any], *, resign: bool) -> None:
        (self.packet / "bundle.json").write_bytes(canonical_json(cast("JSONValue", bundle)))
        if resign:
            self._resign()

    # --- what is true of the packet right now, read back rather than remembered

    def _bundle_bytes(self) -> bytes:
        return (self.packet / "bundle.json").read_bytes()

    def _signature_is_fresh(self) -> bool:
        return self.signed_bytes == self._bundle_bytes()

    def _bundle_is_the_exported_one(self) -> bool:
        return self._bundle_bytes() == _PRISTINE_BYTES

    def _media_is_the_exported_media(self) -> bool:
        return all(
            (self.packet / "media" / name).read_bytes() == payload
            for name, payload in _PRISTINE_MEDIA.items()
        )

    def _exported_custody_is_still_a_prefix(self) -> bool:
        """Whether every entry the producer exported is still there, in order.

        Not a length comparison: dropping three entries and appending three more
        leaves the length alone while the exported chain is gone, and appending
        one then dropping it leaves a longer chain that is nonetheless exactly
        what was exported.
        """
        entries: list[Any] = self._read()["custody_proof"]["entries"]
        return bool(entries[: len(_PRISTINE_CUSTODY)] == _PRISTINE_CUSTODY)

    def _contradicted(self) -> bool:
        return self.unrepairable or not self._media_is_the_exported_media()

    def _resign(self) -> None:
        """Sign the bundle on disk with a freshly generated producer key.

        This is the whole of FIX-05 in four lines: `signature_ok` takes its
        verifying key from the signature file itself, so anyone who rewrites a
        bundle can also re-sign it. The open policy therefore cannot tell this
        from the real producer, and is not asked to; the pinned policy can, and
        this machine asserts it always does.
        """
        digest = sha256_bytes((self.packet / "bundle.json").read_bytes())
        identity = Identity.generate()
        public = identity.public()
        record: dict[str, JSONValue] = {
            "bundle_sha256": digest,
            "producer_fingerprint": public.fingerprint,
            "sign_public": base64.b64encode(public.sign_public).decode("ascii"),
            "signature": base64.b64encode(identity.sign(digest.encode("ascii"))).decode("ascii"),
        }
        (self.packet / "bundle.sig.json").write_bytes(canonical_json(record))
        self.producer_key_replaced = True
        self.signed_bytes = self._bundle_bytes()

    # --- meaning-preserving operations ---------------------------------------

    @rule(index=_ITEM_INDEX, forged=st.booleans(), resign=st.booleans())
    @precondition(lambda self: self.archive_links < 3)
    def add_an_archive_link(self, index: int, forged: bool, resign: bool) -> None:
        """RFC 4998 archival, told honestly or dishonestly on one draw.

        Honest: stamp the newest token so the proof outlives the key that made
        it. Forged: attach a real token, from a real authority, over bytes that
        are not this token -- the operation that looks identical in a listing and
        proves nothing about the chain it claims to extend.

        One rule rather than two because each mints an RSA signature and leaves
        behind a link every later step re-verifies, and as two rules of six they
        took a fifth of the machine's steps -- for a pair of operations
        `TestArchiveChain` above already sweeps exhaustively at depths one to
        three. What is wanted here is the composition, an honest link and a
        forged one and a repair in some order, and one drawn boolean expresses
        that as well as two rules did.
        """
        bundle = self._read()
        item = bundle["items"][index]
        links = list(item.get("archive_timestamps") or [])
        if forged:
            links.append(_MACHINE_TSA.stamp(sha256_bytes(b"bytes no link ever carried")).to_dict())
        else:
            newest = links[-1] if links else item.get("timestamp")
            if newest is None:  # the token was stripped; there is nothing to carry forward
                return
            links.append(retimestamp(TimestampToken.from_dict(newest), _MACHINE_TSA).to_dict())
        item["archive_timestamps"] = links
        self.archive_links += 1
        self._write(bundle, resign=resign)
        self.unrepairable = self.unrepairable or forged

    @rule(resign=st.booleans())
    def append_a_later_custody_event(self, resign: bool) -> None:
        """Handling did not stop when the packet was exported; the chain can grow.

        Guarded from the inside rather than by a `@precondition`, and so is the
        truncation rule below. Hypothesis picks a rule by filtering a
        `sampled_from` over all of them, gives up after a bounded number of
        rejections, and throws the whole example away when it does: with four of
        the six rules this machine had gated that way, 12 of 42 generated
        examples were being discarded as "unable to satisfy". A step that returns
        early once the chain is broken costs one step; a discarded example costs
        eight of them.
        """
        if self.custody_broken:
            return  # the chain no longer walks, so it cannot be extended
        bundle = self._read()
        log = CustodyLog.from_records(bundle["custody_proof"]["entries"])
        log.append(
            CustodyAction.VIEWED,
            "cap-stateful-machine",
            actor="reviewer",
            hlc=f"{len(log):06d}-machine",
        )
        bundle["custody_proof"] = log.integrity_proof()
        self._write(bundle, resign=resign)

    @rule()
    def resign_with_a_fresh_producer_key(self) -> None:
        self._resign()

    # --- operations no re-signing can repair ---------------------------------

    @rule(
        contradiction=_CONTRADICTIONS,
        index=_ITEM_INDEX,
        digest_field=st.sampled_from(["content_hash", "shared_hash"]),
        entry=_TIMELINE_INDEX,
        media=_MEDIA_NAME,
        position=_MEDIA_BYTE,
        value=_VALUE,
        resign=st.booleans(),
    )
    def contradict_something_a_proof_already_fixed(
        self,
        contradiction: str,
        index: int,
        digest_field: str,
        entry: int,
        media: str,
        position: int,
        value: int,
        resign: bool,
    ) -> None:
        """Do one of five things no producer-side repair can undo.

        One rule with a drawn operation, not five rules, and the reason is a
        budget one. ``unrepairable`` is an absorbing state: once it is set, every
        later step asserts the same easy branch of the invariant ("still not
        accepted"), so a second contradiction on top of the first buys nothing.
        As five separate rules these were five of eleven draws, and the machine
        spent 56% of its invariant checks inside that absorbing state -- while
        the one branch nothing else in this repository covers, the custody
        truncation limit below, was reached in 2% of them. Collapsing them to one
        draw leaves every operation reachable, in the same combinations, and
        moves the budget to the steps where acceptance is still in doubt.

        Each operation contradicts something a *timestamp authority*, a media
        digest, or a custody-bound commitment has already fixed:

        * **shared media** -- flip a byte of a file an item's ``shared_hash``
          covers.
        * **an item's digest** -- point a signed item at content the authority's
          token never covered.
        * **an item's timestamp token** -- strip the anchor; removing it is not a
          way to pass, because an unanchored item is not a verified one.
        * **a timeline entry's text** -- change what the tenant said happened,
          leaving the commitment that bound the old text behind.
        * **the custody order** -- swap two entries, which breaks the hash chain
          rather than rewriting it.
        """
        if contradiction == "shared media":
            path = self.packet / "media" / media
            raw = bytearray(path.read_bytes())
            raw[position] = value if raw[position] != value else value ^ 0xFF
            path.write_bytes(bytes(raw))
            self.unrepairable = True
            return

        bundle = self._read()
        if contradiction == "an item's digest":
            bundle["items"][index][digest_field] = sha256_bytes(
                f"substituted:{digest_field}:{index}".encode()
            )
        elif contradiction == "an item's timestamp token":
            if "timestamp" not in bundle["items"][index]:
                return  # already stripped; there is nothing left to remove
            del bundle["items"][index]["timestamp"]
        elif contradiction == "a timeline entry's text":
            record = bundle["timeline"][entry]
            record["text"] = f"{record.get('text', '')} (rewritten after the fact)"
        elif contradiction == "the custody order":
            entries = bundle["custody_proof"]["entries"]
            if len(entries) < 2 or self.custody_broken:
                return
            entries[0], entries[1] = entries[1], entries[0]
            self.custody_broken = True
        else:  # a label with no branch would silently do nothing, which is the
            # defect class this whole module exists to catch.
            raise AssertionError(f"no operation implements the contradiction {contradiction!r}")
        self._write(bundle, resign=resign)
        self.unrepairable = True

    # --- the honest limit ----------------------------------------------------

    @rule()
    def truncate_the_custody_chain(self) -> None:
        """Drop the newest entry, and re-sign: the prefix still verifies, and the head moves.

        This is the limit `test_suffix_truncation_is_invisible_to_the_chain_but_
        moves_the_head` pins on a bare chain, carried up to a whole packet. The
        verifier may still accept — until enough is gone that some other signed
        structure loses the entry that bound it — and that is not a defect, it is
        why the head hash is committed outside the chain and why a recipient who
        pinned the producer key is told about it. The invariant below asserts both
        halves: the head always moves, and the pinned policy always refuses.
        """
        if self.custody_broken:
            return  # a chain that no longer walks has no verifiable prefix to keep
        bundle = self._read()
        records = bundle["custody_proof"]["entries"]
        if len(records) < 2:
            return
        shortened = CustodyLog.from_records(records[:-1])
        assert shortened.verify().ok, "a truncated prefix must still verify on its own"
        proof = shortened.integrity_proof()
        assert proof["head_hash"] != bundle["custody_proof"]["head_hash"], (
            "dropping an entry left the head hash unchanged, so the separately "
            "committed head would no longer detect truncation at all"
        )
        bundle["custody_proof"] = proof
        # Always re-signed, unlike every other edit here, and for two reasons.
        # A truncation the signature already refuses is not the limit this rule
        # exists to state -- "a bundle edited after signing must not verify" is
        # asserted by every other rule's unsigned draw. And an unparameterised
        # rule is one hypothesis reaches far more often: with a `resign` draw
        # this rule took 7.4% of steps and its branch of the invariant 2.3% of
        # checks, which is not enough to call a limit pinned.
        self._write(bundle, resign=True)

    # --- the model -----------------------------------------------------------

    def _verdict(self, *, pin: str | None) -> tuple[bool, VerificationReport | None]:
        """Accepted-or-not under one trust policy, and never a leaked exception."""
        try:
            report = verify_packet(self.packet, expected_producer_key=pin)
        except VerificationError:
            return False, None
        except Exception as exc:  # a non-habitable exception type is the failure
            raise AssertionError(f"verify_packet leaked {type(exc).__name__}: {exc}") from exc
        accepted = (
            report.structurally_intact
            and report.signature_ok
            and report.custody_ok
            and bool(report.items)
            and report.cryptographically_verified_items == len(report.items)
        )
        return accepted, report

    @invariant()
    def the_verifier_never_contradicts_the_model(self) -> None:
        """Acceptance is a function of what was done, not of the order it was done in.

        "Accepted" is the predicate `tests/test_golden.py` uses for a packet with
        no trust root supplied: structurally intact, signature and custody good,
        and every item cryptographically verified. Deliberately *not*
        `report.ok` — that is `evidence_ready`, which also requires a trusted
        anchor the golden corpus does not ship, so it is False for a pristine
        packet too and would make "never accepted a tampered packet" vacuously
        true for every state this machine can reach.
        """
        open_accepted, open_report = self._verdict(pin=None)
        pinned_accepted, _ = self._verdict(pin=_PINNED_PRODUCER_KEY)

        if self._contradicted():
            assert not open_accepted, (
                "the verifier accepted a packet contradicting something a timestamp "
                "authority, a media digest, or a custody-bound commitment already "
                f"fixed, after: {self._state()}"
            )
            if self._signature_is_fresh():
                assert open_report is not None and open_report.signature_ok, (
                    "the rejection came from the signature, not from the anchor "
                    "checks — a re-signed packet must be refused on its content"
                )
        elif not self._signature_is_fresh():
            assert not open_accepted, "a bundle edited after signing must not verify"
            assert open_report is not None and not open_report.signature_ok
        elif not self._exported_custody_is_still_a_prefix():
            # The prefix limit: acceptance is genuinely not determined here — it
            # depends on whether a dropped entry still bound something else — but
            # the head a recipient pinned or a seal covered always moves.
            assert self._read()["custody_proof"]["head_hash"] != _PRISTINE_HEAD, (
                "custody entries were dropped without moving the declared head hash"
            )
        else:
            assert open_accepted, (
                f"meaning-preserving operations lost an accepted packet, after: {self._state()}"
            )

        # The pin is the recipient-side answer to every producer-side rewrite:
        # it refuses anything whose bytes or whose signing key are not the ones
        # the producer actually exported, the truncation above included.
        untouched = (
            not self._contradicted()
            and self._bundle_is_the_exported_one()
            and not self.producer_key_replaced
        )
        assert pinned_accepted is untouched, (
            f"with the producer key pinned, accepted={pinned_accepted} but the packet "
            f"was {'untouched' if untouched else 'rewritten'}, after: {self._state()}"
        )

    def _state(self) -> str:
        return (
            f"contradicted={self._contradicted()} "
            f"bundle_is_exported={self._bundle_is_the_exported_one()} "
            f"signature_fresh={self._signature_is_fresh()} "
            f"producer_key_replaced={self.producer_key_replaced} "
            f"custody_broken={self.custody_broken} "
            f"exported_custody_prefix={self._exported_custody_is_still_a_prefix()}"
        )


# Budget. Every step verifies the whole packet twice — once per trust policy —
# so the cost is `max_examples x stateful_step_count x 2` verifications, and the
# archive-link cap above keeps each of those from growing with the step count.
# Eight steps stays: it is the shortest sequence that can interleave a tamper, a
# repair and a second tamper, which is the shape this machine exists to find.
#
# Twenty-four examples rather than thirty, because a step is not a fixed price.
# Verifying a packet that is already contradicted is *cheap* — a mismatched media
# digest short-circuits the item checks that dominate the profile — so the more
# of its budget the machine spends in states where acceptance is still in doubt,
# the more each step costs. That is the trade this rule set was rebalanced to
# make, and it was measured rather than assumed. Interleaved runs of the old rule
# set at 30 x 8 against this one at 24 x 8: 5.66s vs 4.47s per run, and the
# custody-truncation branch of the invariant — the tightest claim here, and the
# only one nothing else in this repository covers — reached 2.9% of checks (7.7
# per run) before and 15.5% (33.7 per run) after. Cheaper *and* four times the
# coverage of the branch that needed it.
#
# Hunt with a raised count and `--hypothesis-seed=random` locally, not in the
# merge gate.
HostilePacketSequences.TestCase.settings = settings(
    max_examples=24, stateful_step_count=8, deadline=None
)
TestHostilePacketSequences = HostilePacketSequences.TestCase
