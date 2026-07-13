# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Trusted timestamping: dev TSA and real RFC 3161, with tamper detection."""

from __future__ import annotations

import datetime

import pytest
from asn1crypto import cms, tsp

from habitable.canonical import sha256_bytes
from habitable.errors import TimestampError
from habitable.tsa import DevTSA, LocalRfc3161TSA, TimestampToken, verify_token

DIGEST = sha256_bytes(b"the original photo bytes")


class TestDevTSA:
    def test_stamp_and_verify(self, dev_tsa: DevTSA) -> None:
        info = verify_token(dev_tsa.stamp(DIGEST), DIGEST)
        assert info.gen_time == "2026-01-02T00:00:00Z"
        assert info.trusted_chain is False  # dev TSA is never a trusted chain

    def test_wrong_digest_rejected(self, dev_tsa: DevTSA) -> None:
        token = dev_tsa.stamp(DIGEST)
        with pytest.raises(TimestampError):
            verify_token(token, sha256_bytes(b"different"))

    def test_signature_tamper_rejected(self, dev_tsa: DevTSA) -> None:
        token = dev_tsa.stamp(DIGEST)
        bad = TimestampToken("dev", "x", token.data.replace(b'"digest"', b'"DIGEST"'))
        with pytest.raises(TimestampError):
            verify_token(bad, DIGEST)


class TestRfc3161:
    def test_issue_and_verify_offline(self, local_tsa: LocalRfc3161TSA) -> None:
        info = verify_token(local_tsa.stamp(DIGEST), DIGEST)
        assert info.gen_time == "2026-01-02T00:00:00Z"
        assert info.kind == "rfc3161"
        assert info.trusted_chain is False  # no roots supplied

    def test_trusted_when_authority_cert_pinned(self, local_tsa: LocalRfc3161TSA) -> None:
        info = verify_token(local_tsa.stamp(DIGEST), DIGEST, trusted_certs=[local_tsa.certificate])
        assert info.trusted_chain is True

    def test_token_serialization_round_trip(self, local_tsa: LocalRfc3161TSA) -> None:
        token = local_tsa.stamp(DIGEST)
        restored = TimestampToken.from_dict(token.to_dict())
        assert verify_token(restored, DIGEST).gen_time == "2026-01-02T00:00:00Z"

    def test_gentime_rewind_detected(self, local_tsa: LocalRfc3161TSA) -> None:
        token = local_tsa.stamp(DIGEST)
        content_info = cms.ContentInfo.load(token.data)
        signed = content_info["content"]
        tst = tsp.TSTInfo.load(bytes(signed["encap_content_info"]["content"].contents))
        tst["gen_time"] = datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC)  # backdate
        signed["encap_content_info"]["content"] = tst
        forged = TimestampToken("rfc3161", "x", bytes(content_info.dump(force=True)))
        with pytest.raises(TimestampError):
            verify_token(forged, DIGEST)

    def test_truncation_detected(self, local_tsa: LocalRfc3161TSA) -> None:
        token = local_tsa.stamp(DIGEST)
        with pytest.raises(TimestampError):
            verify_token(TimestampToken("rfc3161", "x", token.data[:-25]), DIGEST)

    def test_missing_signer_is_reported_as_timestamp_error(
        self, local_tsa: LocalRfc3161TSA
    ) -> None:
        token = local_tsa.stamp(DIGEST)
        content_info = cms.ContentInfo.load(token.data)
        content_info["content"]["signer_infos"] = cms.SignerInfos([])
        malformed = TimestampToken("rfc3161", "x", content_info.dump(force=True))
        with pytest.raises(TimestampError, match="exactly one signer"):
            verify_token(malformed, DIGEST)


def test_unknown_token_kind() -> None:
    with pytest.raises(TimestampError, match="unknown token kind"):
        verify_token(TimestampToken("magic", "x", b"{}"), DIGEST)
