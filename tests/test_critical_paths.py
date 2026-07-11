# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Edge-path tests for the evidence-integrity core (crypto, vault, tsa, verify).

These pin the rejection and failure branches of the four modules that carry the
per-module coverage floor (CODE-QUALITY-STANDARD: security/crypto-critical paths
hold >=95% branch coverage, above the 85% baseline). The floor is enforced by the
scoped ``coverage report --fail-under=95`` step in ``make cov`` (and therefore in
CI via ``make verify``).
"""

from __future__ import annotations

import base64
import json
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from asn1crypto import algos, cms, tsp
from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from habitable.canonical import JSONValue, canonical_json, sha256_bytes
from habitable.crypto import (
    Identity,
    KdfParams,
    PublicIdentity,
    SymmetricKey,
    create_keyfile,
    open_keyfile,
    open_sealed,
)
from habitable.errors import (
    CryptoError,
    FixityError,
    TimestampError,
    VaultError,
    VerificationError,
)
from habitable.tsa import (
    LocalRfc3161TSA,
    Rfc3161HttpTSA,
    TimestampToken,
    verify_token,
)
from habitable.vault import Vault
from habitable.verify import verify_packet

if TYPE_CHECKING:
    from collections.abc import Callable

DIGEST = sha256_bytes(b"the original photo bytes")


# --- crypto: every malformed input is a CryptoError, never a crash -------------


class TestCryptoRejections:
    def test_unsupported_kdf_rejected(self) -> None:
        raw: dict[str, object] = {"name": "argon2"}
        with pytest.raises(CryptoError, match="unsupported KDF"):
            KdfParams.from_dict(raw)

    def test_symmetric_key_length_enforced(self) -> None:
        with pytest.raises(CryptoError, match="32 bytes"):
            SymmetricKey(b"short")

    def test_ciphertext_shorter_than_a_nonce_rejected(self) -> None:
        with pytest.raises(CryptoError, match="too short"):
            SymmetricKey.generate().decrypt(b"tiny")

    def test_public_identity_must_be_64_bytes(self) -> None:
        encoded = base64.b64encode(b"way-too-short").decode("ascii")
        with pytest.raises(CryptoError, match="64 bytes"):
            PublicIdentity.decode(encoded)

    def test_public_identity_rejects_bad_base64(self) -> None:
        with pytest.raises(CryptoError, match="base64"):
            PublicIdentity.decode("!!! not base64 !!!")

    def test_identity_deserialize_must_be_64_bytes(self) -> None:
        with pytest.raises(CryptoError, match="64 bytes"):
            Identity.deserialize(b"short")

    def test_sealed_box_too_short(self) -> None:
        with pytest.raises(CryptoError, match="too short"):
            open_sealed(Identity.generate(), b"tiny")


class TestKeyfileRejections:
    def test_keyfile_must_be_json(self) -> None:
        with pytest.raises(CryptoError, match="not valid JSON"):
            open_keyfile("definitely not json", "pw")

    def test_keyfile_must_be_an_object(self) -> None:
        with pytest.raises(CryptoError, match="JSON object"):
            open_keyfile("[]", "pw")

    @staticmethod
    def _tampered(mutate: Callable[[dict[str, object]], None]) -> str:
        keyfile, _ = create_keyfile("pw")
        doc: dict[str, object] = json.loads(keyfile)
        mutate(doc)
        return json.dumps(doc)

    def test_unknown_version_rejected(self) -> None:
        tampered = self._tampered(lambda d: d.__setitem__("habitable_keyfile_version", 99))
        with pytest.raises(CryptoError, match="unsupported keyfile version"):
            open_keyfile(tampered, "pw")

    def test_kdf_must_be_an_object(self) -> None:
        tampered = self._tampered(lambda d: d.__setitem__("kdf", "scrypt"))
        with pytest.raises(CryptoError, match="expected object"):
            open_keyfile(tampered, "pw")

    def test_kdf_salt_must_be_a_string(self) -> None:
        def mutate(doc: dict[str, object]) -> None:
            kdf = doc["kdf"]
            assert isinstance(kdf, dict)
            kdf["salt"] = 12345

        with pytest.raises(CryptoError, match="expected string"):
            open_keyfile(self._tampered(mutate), "pw")

    def test_kdf_cost_must_be_an_integer(self) -> None:
        def mutate(doc: dict[str, object]) -> None:
            kdf = doc["kdf"]
            assert isinstance(kdf, dict)
            kdf["n"] = "expensive"

        with pytest.raises(CryptoError, match="expected integer"):
            open_keyfile(self._tampered(mutate), "pw")


# --- vault: fixity failures and corrupt records surface as errors --------------


class TestVaultCriticalPaths:
    def test_seal_original_detects_source_change(
        self, make_vault: Callable[..., Vault], tmp_path: Path
    ) -> None:
        vault = make_vault("v-seal")
        source = tmp_path / "original.bin"
        source.write_bytes(b"actual bytes")
        with pytest.raises(FixityError, match="changed during capture"):
            vault.seal_original("cap-1", source, sha256_bytes(b"promised bytes"))

    def test_store_original_bytes_checks_hash(self, make_vault: Callable[..., Vault]) -> None:
        vault = make_vault("v-store")
        with pytest.raises(FixityError, match="do not match"):
            vault.store_original_bytes("cap-1", b"data", sha256_bytes(b"other"))

    def test_read_original_missing_is_an_error(self, make_vault: Callable[..., Vault]) -> None:
        vault = make_vault("v-missing")
        with pytest.raises(VaultError, match="missing"):
            vault.read_original("cap-none", sha256_bytes(b"data"))

    def test_read_original_reverifies_fixity(self, make_vault: Callable[..., Vault]) -> None:
        vault = make_vault("v-fixity")
        content_hash = sha256_bytes(b"data")
        name = vault.store_original_bytes("cap-1", b"data", content_hash)
        # A validly-encrypted substitution under the same AAD must still fail the
        # fixity re-check on read: decryption alone is not proof of integrity.
        aad = f"original:cap-1:{content_hash}".encode()
        (vault.path / "originals" / name).write_bytes(vault._dek.encrypt(b"swapped", aad=aad))
        with pytest.raises(FixityError, match="failed fixity"):
            vault.read_original("cap-1", content_hash)

    def test_get_token_absent_returns_none(self, make_vault: Callable[..., Vault]) -> None:
        assert make_vault("v-token").get_token("cap-none") is None

    def test_corrupt_token_records_raise(self, make_vault: Callable[..., Vault]) -> None:
        primary = make_vault("v-corrupt-primary")
        (primary.path / "tokens" / "cap-1.json").write_text("[]", encoding="utf-8")
        with pytest.raises(VaultError, match="corrupt token record"):
            Vault.open(primary.path, "test-passphrase")

        additional = make_vault("v-corrupt-additional")
        (additional.path / "tokens" / "cap-2.additional.json").write_text("[{}]", encoding="utf-8")
        with pytest.raises(VaultError, match="corrupt additional-token record"):
            Vault.open(additional.path, "test-passphrase")

        archive = make_vault("v-corrupt-archive")
        (archive.path / "tokens" / "cap-3.archive.json").write_text("[{}]", encoding="utf-8")
        with pytest.raises(VaultError, match="corrupt archive-token record"):
            Vault.open(archive.path, "test-passphrase")

    def test_open_with_missing_blob_raises(
        self, make_vault: Callable[..., Vault], tmp_path: Path
    ) -> None:
        vault = make_vault("v-blob")
        (vault.path / "identity.enc").unlink()
        with pytest.raises(VaultError, match="vault file missing"):
            Vault.open(vault.path, "test-passphrase")

    def test_open_with_corrupt_case_state_raises(self, make_vault: Callable[..., Vault]) -> None:
        vault = make_vault("v-case")
        vault._write_blob("case.enc", canonical_json([]))
        with pytest.raises(VaultError, match="corrupt case state"):
            Vault.open(vault.path, "test-passphrase")

    def test_open_with_corrupt_custody_raises(self, make_vault: Callable[..., Vault]) -> None:
        vault = make_vault("v-custody")
        vault._write_blob("custody.enc", canonical_json({"not": "a list"}))
        with pytest.raises(VaultError, match="expected a JSON array"):
            Vault.open(vault.path, "test-passphrase")
        vault._write_blob("custody.enc", canonical_json([1, 2]))
        with pytest.raises(VaultError, match="expected a JSON object record"):
            Vault.open(vault.path, "test-passphrase")


# --- tsa: malformed tokens, HTTP client, and chain-of-trust edges ---------------


class TestDevTokenRejections:
    def test_token_record_must_be_well_formed(self) -> None:
        with pytest.raises(TimestampError, match="malformed timestamp token record"):
            TimestampToken.from_dict({})

    def test_dev_token_must_be_json(self) -> None:
        with pytest.raises(TimestampError, match="not valid JSON"):
            verify_token(TimestampToken("dev", "t", b"not json"), DIGEST)

    def test_dev_token_must_be_an_object(self) -> None:
        with pytest.raises(TimestampError, match="must be an object"):
            verify_token(TimestampToken("dev", "t", canonical_json([])), DIGEST)

    def test_dev_token_missing_signature(self) -> None:
        with pytest.raises(TimestampError, match="missing signature"):
            verify_token(TimestampToken("dev", "t", canonical_json({})), DIGEST)

    def test_dev_token_missing_pubkey(self) -> None:
        doc: dict[str, JSONValue] = {"sig": base64.b64encode(b"x").decode("ascii")}
        with pytest.raises(TimestampError, match="missing pubkey"):
            verify_token(TimestampToken("dev", "t", canonical_json(doc)), DIGEST)

    def test_dev_token_missing_gen_time(self) -> None:
        # A validly-signed dev token with no gen_time is still rejected.
        identity = Identity.generate()
        pub = base64.b64encode(identity.public().sign_public).decode("ascii")
        payload: dict[str, JSONValue] = {
            "kind": "dev",
            "tsa_name": "t",
            "digest": DIGEST,
            "alg": "ed25519",
            "pubkey": pub,
        }
        signature = identity.sign(canonical_json(payload))
        doc: dict[str, JSONValue] = {
            **payload,
            "sig": base64.b64encode(signature).decode("ascii"),
        }
        with pytest.raises(TimestampError, match="missing gen_time"):
            verify_token(TimestampToken("dev", "t", canonical_json(doc)), DIGEST)


class _FakeHttpResponse:
    """Minimal stand-in for the urlopen context manager."""

    def __init__(self, body: bytes) -> None:
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> _FakeHttpResponse:
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None


def _serve(monkeypatch: pytest.MonkeyPatch, body: bytes) -> None:
    def fake_urlopen(request: urllib.request.Request, timeout: float = 0.0) -> _FakeHttpResponse:
        assert request.get_header("Content-type") == "application/timestamp-query"
        return _FakeHttpResponse(body)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)


class TestHttpTSA:
    def test_round_trip_against_a_granted_response(
        self, monkeypatch: pytest.MonkeyPatch, local_tsa: LocalRfc3161TSA
    ) -> None:
        real = local_tsa.stamp(DIGEST)
        response = tsp.TimeStampResp(
            {
                "status": tsp.PKIStatusInfo({"status": 0}),
                "time_stamp_token": cms.ContentInfo.load(real.data),
            }
        )
        _serve(monkeypatch, bytes(response.dump()))
        token = Rfc3161HttpTSA("fake-tsa", "https://tsa.example/stamp").stamp(DIGEST)
        info = verify_token(token, DIGEST, trusted_certs=[local_tsa.certificate])
        assert info.kind == "rfc3161"
        assert info.trusted_chain is True

    def test_non_http_url_refused(self) -> None:
        client = Rfc3161HttpTSA("bad", "file:///etc/passwd")
        with pytest.raises(TimestampError, match="non-HTTP"):
            client.stamp(DIGEST)

    def test_network_failure_is_a_timestamp_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def explode(request: urllib.request.Request, timeout: float = 0.0) -> None:
            raise OSError("connection refused")

        monkeypatch.setattr(urllib.request, "urlopen", explode)
        client = Rfc3161HttpTSA("down", "https://tsa.example/stamp")
        with pytest.raises(TimestampError, match="failed"):
            client.stamp(DIGEST)

    def test_rejected_status_is_surfaced(
        self, monkeypatch: pytest.MonkeyPatch, local_tsa: LocalRfc3161TSA
    ) -> None:
        # Even if a rejection carries a (stray) token, the status must win.
        response = tsp.TimeStampResp(
            {
                "status": tsp.PKIStatusInfo({"status": 2}),
                "time_stamp_token": cms.ContentInfo.load(local_tsa.stamp(DIGEST).data),
            }
        )
        _serve(monkeypatch, bytes(response.dump()))
        client = Rfc3161HttpTSA("rejecting", "https://tsa.example/stamp")
        with pytest.raises(TimestampError, match="rejected"):
            client.stamp(DIGEST)

    def test_garbage_response_is_a_parse_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _serve(monkeypatch, b"this is not ASN.1")
        client = Rfc3161HttpTSA("garbled", "https://tsa.example/stamp")
        with pytest.raises(TimestampError, match="could not parse"):
            client.stamp(DIGEST)


def _forge(token: TimestampToken, content_info: object) -> TimestampToken:
    der = bytes(content_info.dump(force=True))  # type: ignore[attr-defined]
    return TimestampToken(kind="rfc3161", tsa_name=token.tsa_name, data=der)


class TestRfc3161Tampering:
    def test_not_cms_signed_data(self) -> None:
        plain = cms.ContentInfo({"content_type": "data", "content": b"hello"})
        token = TimestampToken("rfc3161", "t", bytes(plain.dump()))
        with pytest.raises(TimestampError, match="not CMS SignedData"):
            verify_token(token, DIGEST)

    def test_wrong_encapsulated_content(self, local_tsa: LocalRfc3161TSA) -> None:
        token = local_tsa.stamp(DIGEST)
        content_info = cms.ContentInfo.load(token.data)
        content_info["content"]["encap_content_info"] = cms.EncapsulatedContentInfo(
            {"content_type": "data", "content": cms.ParsableOctetString(b"x")}
        )
        with pytest.raises(TimestampError, match="does not encapsulate TSTInfo"):
            verify_token(_forge(token, content_info), DIGEST)

    def test_imprint_must_be_sha256(self, local_tsa: LocalRfc3161TSA) -> None:
        token = local_tsa.stamp(DIGEST)
        content_info = cms.ContentInfo.load(token.data)
        signed = content_info["content"]
        tst = tsp.TSTInfo.load(bytes(signed["encap_content_info"]["content"].contents))
        tst["message_imprint"]["hash_algorithm"] = algos.DigestAlgorithm({"algorithm": "sha1"})
        signed["encap_content_info"]["content"] = tst
        with pytest.raises(TimestampError, match="not SHA-256"):
            verify_token(_forge(token, content_info), DIGEST)

    def test_signer_certificate_must_be_present(self, local_tsa: LocalRfc3161TSA) -> None:
        token = local_tsa.stamp(DIGEST)
        content_info = cms.ContentInfo.load(token.data)
        signer = content_info["content"]["signer_infos"][0]
        # Point the signer identifier at a serial the embedded certs don't carry.
        signer["sid"].chosen["serial_number"] = 424242
        with pytest.raises(TimestampError, match="signing certificate"):
            verify_token(_forge(token, content_info), DIGEST)

    def test_signed_attributes_are_required(self, local_tsa: LocalRfc3161TSA) -> None:
        token = local_tsa.stamp(DIGEST)
        content_info = cms.ContentInfo.load(token.data)
        signer = content_info["content"]["signer_infos"][0]
        signer["signed_attrs"] = cms.CMSAttributes([])
        with pytest.raises(TimestampError, match="no signed attributes"):
            verify_token(_forge(token, content_info), DIGEST)

    def test_unsupported_message_digest_algorithm(self, local_tsa: LocalRfc3161TSA) -> None:
        token = local_tsa.stamp(DIGEST)
        content_info = cms.ContentInfo.load(token.data)
        signer = content_info["content"]["signer_infos"][0]
        signer["digest_algorithm"] = algos.DigestAlgorithm({"algorithm": "md5"})
        with pytest.raises(TimestampError, match="unsupported digest algorithm"):
            verify_token(_forge(token, content_info), DIGEST)

    def test_signature_hash_falls_back_to_digest_algorithm(
        self, local_tsa: LocalRfc3161TSA
    ) -> None:
        # md5_rsa advertises an unsupported hash; verification must fall back to
        # the signer's digest algorithm (SHA-256) and still validate the token.
        token = local_tsa.stamp(DIGEST)
        content_info = cms.ContentInfo.load(token.data)
        signer = content_info["content"]["signer_infos"][0]
        signer["signature_algorithm"] = algos.SignedDigestAlgorithm({"algorithm": "md5_rsa"})
        info = verify_token(_forge(token, content_info), DIGEST)
        assert info.kind == "rfc3161"

    def test_unsupported_signature_algorithm(self, local_tsa: LocalRfc3161TSA) -> None:
        token = local_tsa.stamp(DIGEST)
        content_info = cms.ContentInfo.load(token.data)
        signer = content_info["content"]["signer_infos"][0]
        # ECDSA algorithm identifier over an RSA key: no valid verification path.
        signer["signature_algorithm"] = algos.SignedDigestAlgorithm({"algorithm": "sha256_ecdsa"})
        with pytest.raises(TimestampError, match="unsupported signature algorithm"):
            verify_token(_forge(token, content_info), DIGEST)

    def test_tampered_signature_bytes_rejected(self, local_tsa: LocalRfc3161TSA) -> None:
        token = local_tsa.stamp(DIGEST)
        content_info = cms.ContentInfo.load(token.data)
        signer = content_info["content"]["signer_infos"][0]
        signer["signature"] = b"\x00" * 256
        with pytest.raises(TimestampError, match="signature is invalid"):
            verify_token(_forge(token, content_info), DIGEST)


def _self_signed(
    common_name: str, key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey
) -> crypto_x509.Certificate:
    name = crypto_x509.Name([crypto_x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(tz=UTC)
    return (
        crypto_x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(crypto_x509.random_serial_number())
        .not_valid_before(now.replace(year=now.year - 1))
        .not_valid_after(now.replace(year=now.year + 5))
        .sign(key, crypto_hashes.SHA256())
    )


class TestCertificateChain:
    def test_issuer_signed_chain_is_trusted(self) -> None:
        from habitable.tsa import _issue_token

        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca_cert = _self_signed("test-root", ca_key)
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(tz=UTC)
        leaf_cert = (
            crypto_x509.CertificateBuilder()
            .subject_name(
                crypto_x509.Name([crypto_x509.NameAttribute(NameOID.COMMON_NAME, "leaf-tsa")])
            )
            .issuer_name(ca_cert.subject)
            .public_key(leaf_key.public_key())
            .serial_number(crypto_x509.random_serial_number())
            .not_valid_before(now.replace(year=now.year - 1))
            .not_valid_after(now.replace(year=now.year + 5))
            .sign(ca_key, crypto_hashes.SHA256())
        )
        der = _issue_token(DIGEST, private_key=leaf_key, certificate=leaf_cert, gen_time=now)
        token = TimestampToken(kind="rfc3161", tsa_name="leaf-tsa", data=der)

        # Trusting the issuing CA (not the leaf itself) chains the token.
        assert verify_token(token, DIGEST, trusted_certs=[ca_cert]).trusted_chain is True

        # An unrelated RSA root does not vouch for the leaf.
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        other_cert = _self_signed("unrelated-root", other_key)
        assert verify_token(token, DIGEST, trusted_certs=[other_cert]).trusted_chain is False

        # A non-RSA trusted certificate can never RSA-vouch for this leaf.
        ec_cert = _self_signed("ec-root", ec.generate_private_key(ec.SECP256R1()))
        assert verify_token(token, DIGEST, trusted_certs=[ec_cert]).trusted_chain is False


# --- verify: hostile packet inputs are clean rejections, never crashes ---------


class TestPacketRejections:
    def test_missing_bundle_is_an_error(self, tmp_path: Path) -> None:
        with pytest.raises(VerificationError, match=r"no bundle\.json"):
            verify_packet(tmp_path)

    def test_bundle_must_be_valid_json(self, tmp_path: Path) -> None:
        (tmp_path / "bundle.json").write_bytes(b"{nope")
        with pytest.raises(VerificationError, match="not valid JSON"):
            verify_packet(tmp_path)

    def test_bundle_must_be_an_object(self, tmp_path: Path) -> None:
        (tmp_path / "bundle.json").write_text("[]", encoding="utf-8")
        with pytest.raises(VerificationError, match="JSON object"):
            verify_packet(tmp_path)

    @staticmethod
    def _write_bundle(packet_dir: Path, bundle: dict[str, JSONValue]) -> bytes:
        raw = json.dumps(bundle).encode("utf-8")
        (packet_dir / "bundle.json").write_bytes(raw)
        return raw

    def test_malformed_items_and_missing_signature(self, tmp_path: Path) -> None:
        self._write_bundle(
            tmp_path,
            {
                "packet_version": 1,
                "custody_proof": {"entries": [], "head_hash": ""},
                "items": [
                    123,  # not an object: recorded as a problem, not a crash
                    {
                        "capture_id": "cap-1",
                        "content_hash": DIGEST,
                        # a non-object additional timestamp is skipped
                        "additional_timestamps": [5],
                    },
                ],
            },
        )
        report = verify_packet(tmp_path)
        assert "malformed item in bundle" in report.problems
        assert report.signature_ok is False  # no bundle.sig.json at all
        assert report.ok is False
        [verdict] = report.items
        assert verdict.timestamp_verified is False
        assert "awaiting timestamp" in verdict.notes

    def test_signature_file_edge_cases(self, tmp_path: Path) -> None:
        bundle_bytes = self._write_bundle(
            tmp_path,
            {"packet_version": 1, "custody_proof": {"entries": [], "head_hash": ""}, "items": []},
        )
        sig_path = tmp_path / "bundle.sig.json"

        sig_path.write_text("{invalid", encoding="utf-8")
        assert verify_packet(tmp_path).signature_ok is False

        sig_path.write_text("[]", encoding="utf-8")
        assert verify_packet(tmp_path).signature_ok is False

        doc: dict[str, JSONValue] = {
            "bundle_sha256": sha256_bytes(bundle_bytes),
            "sign_public": 42,  # wrong type: rejected before any signature math
            "signature": "AA==",
        }
        sig_path.write_text(json.dumps(doc), encoding="utf-8")
        assert verify_packet(tmp_path).signature_ok is False

    def test_trusted_additional_timestamp_counts(
        self, tmp_path: Path, local_tsa: LocalRfc3161TSA
    ) -> None:
        extra = local_tsa.stamp(DIGEST)
        extra_record: dict[str, JSONValue] = dict(extra.to_dict())
        self._write_bundle(
            tmp_path,
            {
                "packet_version": 1,
                "custody_proof": {"entries": [], "head_hash": ""},
                "items": [
                    {
                        "capture_id": "cap-1",
                        "content_hash": DIGEST,
                        "additional_timestamps": [extra_record],
                    }
                ],
            },
        )
        report = verify_packet(tmp_path, trusted_certs=[local_tsa.certificate])
        [verdict] = report.items
        assert verdict.timestamp_verified is True
        assert verdict.tsa_name == local_tsa.name
        assert verdict.verified_authorities == (local_tsa.name,)
