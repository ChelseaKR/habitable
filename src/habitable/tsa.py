# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Trusted timestamping: proving content existed no later than a point in time.

A trusted timestamp is what turns "the tenant says this photo is from January"
into "an independent authority attests this exact content existed by 02 Jan." It
proves an *upper bound* on creation — the file cannot have been fabricated or
edited afterwards without detection — and the authority only ever sees a hash,
never the photo.

This module provides:

* :class:`Rfc3161HttpTSA` — the production path: a real RFC 3161 client that POSTs
  a hash to a public timestamp authority and stores the signed token.
* :class:`LocalRfc3161TSA` — issues *real* RFC 3161 tokens from a self-signed
  authority, so the standard code path is exercised fully offline (tests, demos).
* :class:`DevTSA` — a tiny Ed25519 "authority" for offline use where even a local
  X.509 TSA is overkill. Clearly **non-production**; tokens say so.
* :func:`verify_token` — validates a token against an expected digest, checking the
  signature and (for RFC 3161) the certificate, and returns when the content
  provably existed.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol, runtime_checkable

from asn1crypto import algos, cms, tsp
from asn1crypto import x509 as asn1_x509
from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID

from .canonical import JSONValue, canonical_json, sha256_bytes
from .crypto import Identity, verify
from .errors import TimestampError

__all__ = [
    "DevTSA",
    "LocalRfc3161TSA",
    "Rfc3161HttpTSA",
    "TimestampAuthority",
    "TimestampInfo",
    "TimestampToken",
    "TokenKind",
    "retimestamp",
    "verify_archive_chain",
    "verify_token",
]

_ID_CT_TST_INFO = "tst_info"
_SHA256 = "sha256"

# RFC 3161 tokens in the wild use a range of digests; verification must follow the
# token's own algorithms rather than assuming SHA-256.
_CRYPTO_HASH: dict[str, type[crypto_hashes.HashAlgorithm]] = {
    "sha1": crypto_hashes.SHA1,
    "sha224": crypto_hashes.SHA224,
    "sha256": crypto_hashes.SHA256,
    "sha384": crypto_hashes.SHA384,
    "sha512": crypto_hashes.SHA512,
}


def _digest(data: bytes, algo_name: str) -> bytes:
    if algo_name not in _CRYPTO_HASH:
        raise TimestampError(f"unsupported digest algorithm: {algo_name!r}")
    return hashlib.new(algo_name, data).digest()


def _crypto_hash(algo_name: str) -> crypto_hashes.HashAlgorithm:
    cls = _CRYPTO_HASH.get(algo_name)
    if cls is None:
        raise TimestampError(f"unsupported signature hash algorithm: {algo_name!r}")
    return cls()


class TokenKind(StrEnum):
    RFC3161 = "rfc3161"
    DEV = "dev"


@dataclass(frozen=True, slots=True)
class TimestampToken:
    """An opaque, storable timestamp token plus the authority that issued it."""

    kind: str
    tsa_name: str
    data: bytes  # DER (rfc3161) or canonical JSON (dev)

    def to_dict(self) -> dict[str, str]:
        import base64

        return {
            "kind": self.kind,
            "tsa_name": self.tsa_name,
            "token_b64": base64.b64encode(self.data).decode("ascii"),
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, object]) -> TimestampToken:
        import base64

        kind = raw.get("kind")
        name = raw.get("tsa_name")
        token_b64 = raw.get("token_b64")
        if not isinstance(kind, str) or not isinstance(name, str) or not isinstance(token_b64, str):
            raise TimestampError("malformed timestamp token record")
        return cls(kind=kind, tsa_name=name, data=base64.b64decode(token_b64))


@dataclass(frozen=True, slots=True)
class TimestampInfo:
    """The result of verifying a token: when the content provably existed."""

    kind: str
    tsa_name: str
    gen_time: str  # ISO 8601 UTC
    digest_hex: str
    trusted_chain: bool
    note: str = ""


@runtime_checkable
class TimestampAuthority(Protocol):
    """Anything that can stamp a digest. Swappable per config."""

    name: str
    kind: str

    def stamp(self, digest_hex: str) -> TimestampToken: ...


# --- development TSA (Ed25519, non-production) ---------------------------------


class DevTSA:
    """A minimal, offline, **non-production** timestamp authority.

    Signs ``(digest, time)`` with an Ed25519 key. Tokens are self-describing and
    are always reported as an untrusted chain, because the "authority" is just a
    local key — fine for tests and demos, never for real evidence.
    """

    kind = TokenKind.DEV.value

    def __init__(
        self,
        name: str = "dev-tsa",
        *,
        identity: Identity | None = None,
        time_source: object = None,
    ) -> None:
        self.name = name
        self._identity = identity or Identity.generate()
        # time_source returns epoch seconds; default to the real clock.
        self._time_source = time_source

    def _now_epoch(self) -> int:
        if callable(self._time_source):
            return int(self._time_source())
        return int(datetime.now(tz=UTC).timestamp())

    def stamp(self, digest_hex: str) -> TimestampToken:
        gen_time = datetime.fromtimestamp(self._now_epoch(), tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        import base64

        pub = self._identity.public().sign_public
        payload: dict[str, JSONValue] = {
            "kind": TokenKind.DEV.value,
            "tsa_name": self.name,
            "gen_time": gen_time,
            "digest": digest_hex,
            "alg": "ed25519",
            "pubkey": base64.b64encode(pub).decode("ascii"),
        }
        signature = self._identity.sign(canonical_json(payload))
        doc: dict[str, JSONValue] = {**payload, "sig": base64.b64encode(signature).decode("ascii")}
        return TimestampToken(
            kind=TokenKind.DEV.value,
            tsa_name=self.name,
            data=canonical_json(doc),
        )


def _verify_dev_token(token: TimestampToken, digest_hex: str) -> TimestampInfo:
    import base64

    try:
        doc = json.loads(token.data)
    except json.JSONDecodeError as exc:
        raise TimestampError("dev token is not valid JSON") from exc
    if not isinstance(doc, dict):
        raise TimestampError("dev token must be an object")
    sig = doc.pop("sig", None)
    if not isinstance(sig, str):
        raise TimestampError("dev token missing signature")
    pub_b64 = doc.get("pubkey")
    if not isinstance(pub_b64, str):
        raise TimestampError("dev token missing pubkey")
    pub = base64.b64decode(pub_b64)
    if not verify(pub, canonical_json(doc), base64.b64decode(sig)):
        raise TimestampError("dev token signature is invalid")
    if doc.get("digest") != digest_hex:
        raise TimestampError("dev token digest does not match the content")
    gen_time = doc.get("gen_time")
    if not isinstance(gen_time, str):
        raise TimestampError("dev token missing gen_time")
    return TimestampInfo(
        kind=TokenKind.DEV.value,
        tsa_name=str(doc.get("tsa_name", "dev-tsa")),
        gen_time=gen_time,
        digest_hex=digest_hex,
        trusted_chain=False,
        note="non-production dev TSA (local key, no trusted certificate chain)",
    )


# --- RFC 3161 issuance and verification ---------------------------------------


def _build_request(digest_hex: str) -> bytes:
    request = tsp.TimeStampReq(
        {
            "version": 1,
            "message_imprint": tsp.MessageImprint(
                {
                    "hash_algorithm": algos.DigestAlgorithm({"algorithm": _SHA256}),
                    "hashed_message": bytes.fromhex(digest_hex),
                }
            ),
            "nonce": secrets.randbits(64),
            "cert_req": True,
        }
    )
    return bytes(request.dump())


def _issue_token(
    digest_hex: str,
    *,
    private_key: rsa.RSAPrivateKey,
    certificate: crypto_x509.Certificate,
    gen_time: datetime,
    policy_oid: str = "1.3.6.1.4.1.99999.1",
) -> bytes:
    """Issue a real RFC 3161 timestamp token (CMS SignedData over TSTInfo)."""
    tst_info = tsp.TSTInfo(
        {
            "version": 1,
            "policy": policy_oid,
            "message_imprint": tsp.MessageImprint(
                {
                    "hash_algorithm": algos.DigestAlgorithm({"algorithm": _SHA256}),
                    "hashed_message": bytes.fromhex(digest_hex),
                }
            ),
            "serial_number": secrets.randbits(64),
            "gen_time": gen_time,
            "ordering": False,
        }
    )
    content = tst_info.dump()
    asn1_cert = asn1_x509.Certificate.load(certificate.public_bytes(serialization.Encoding.DER))
    signed_attrs = cms.CMSAttributes(
        [
            cms.CMSAttribute({"type": "content_type", "values": [_ID_CT_TST_INFO]}),
            cms.CMSAttribute({"type": "message_digest", "values": [sha256_raw(content)]}),
            cms.CMSAttribute(
                {
                    "type": "signing_time",
                    "values": [cms.Time({"utc_time": gen_time})],
                }
            ),
        ]
    )
    signature = private_key.sign(signed_attrs.dump(), padding.PKCS1v15(), crypto_hashes.SHA256())
    signer_info = cms.SignerInfo(
        {
            "version": "v1",
            "sid": cms.SignerIdentifier(
                {
                    "issuer_and_serial_number": cms.IssuerAndSerialNumber(
                        {
                            "issuer": asn1_cert.issuer,
                            "serial_number": asn1_cert.serial_number,
                        }
                    )
                }
            ),
            "digest_algorithm": algos.DigestAlgorithm({"algorithm": _SHA256}),
            "signed_attrs": signed_attrs,
            "signature_algorithm": algos.SignedDigestAlgorithm({"algorithm": "sha256_rsa"}),
            "signature": signature,
        }
    )
    signed_data = cms.SignedData(
        {
            "version": "v3",
            "digest_algorithms": [algos.DigestAlgorithm({"algorithm": _SHA256})],
            "encap_content_info": cms.EncapsulatedContentInfo(
                {"content_type": _ID_CT_TST_INFO, "content": tst_info}
            ),
            "certificates": [asn1_cert],
            "signer_infos": [signer_info],
        }
    )
    token = cms.ContentInfo({"content_type": "signed_data", "content": signed_data})
    return bytes(token.dump())


def _self_signed_tsa(name: str) -> tuple[rsa.RSAPrivateKey, crypto_x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = crypto_x509.Name([crypto_x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(tz=UTC)
    cert = (
        crypto_x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(crypto_x509.random_serial_number())
        .not_valid_before(now.replace(year=now.year - 1))
        .not_valid_after(now.replace(year=now.year + 10))
        .add_extension(
            crypto_x509.ExtendedKeyUsage([crypto_x509.oid.ExtendedKeyUsageOID.TIME_STAMPING]),
            critical=True,
        )
        .sign(key, crypto_hashes.SHA256())
    )
    return key, cert


class LocalRfc3161TSA:
    """Issues real RFC 3161 tokens from a self-signed authority (offline/testing)."""

    kind = TokenKind.RFC3161.value

    def __init__(self, name: str = "local-rfc3161", *, time_source: object = None) -> None:
        self.name = name
        self._key, self._cert = _self_signed_tsa(name)
        self._time_source = time_source

    @property
    def certificate(self) -> crypto_x509.Certificate:
        return self._cert

    def _gen_time(self) -> datetime:
        if callable(self._time_source):
            return datetime.fromtimestamp(int(self._time_source()), tz=UTC)
        return datetime.now(tz=UTC)

    def stamp(self, digest_hex: str) -> TimestampToken:
        der = _issue_token(
            digest_hex,
            private_key=self._key,
            certificate=self._cert,
            gen_time=self._gen_time(),
        )
        return TimestampToken(kind=TokenKind.RFC3161.value, tsa_name=self.name, data=der)


class Rfc3161HttpTSA:
    """Production RFC 3161 client: POST a hash to a public authority over HTTP."""

    kind = TokenKind.RFC3161.value

    def __init__(self, name: str, url: str, *, timeout: float = 15.0) -> None:
        self.name = name
        self.url = url
        self.timeout = timeout

    def stamp(self, digest_hex: str) -> TimestampToken:
        request_der = _build_request(digest_hex)
        http_request = urllib.request.Request(  # noqa: S310 - scheme validated below
            self.url,
            data=request_der,
            headers={
                "Content-Type": "application/timestamp-query",
                "Accept": "application/timestamp-reply",
            },
            method="POST",
        )
        if not self.url.lower().startswith(("http://", "https://")):
            raise TimestampError(f"refusing non-HTTP timestamp URL: {self.url!r}")
        try:
            with urllib.request.urlopen(http_request, timeout=self.timeout) as response:  # noqa: S310
                body = response.read()
        except (OSError, ValueError) as exc:
            raise TimestampError(f"timestamp request to {self.name} failed: {exc}") from exc
        token_der = _extract_token_from_response(body)
        return TimestampToken(kind=TokenKind.RFC3161.value, tsa_name=self.name, data=token_der)


def _extract_token_from_response(body: bytes) -> bytes:
    try:
        response = tsp.TimeStampResp.load(body)
        # asn1crypto renders PKIStatus as its name (e.g. "granted"), not an int;
        # accept granted / granted-with-mods in either rendering.
        status = response["status"]["status"].native
        granted = {0, 1, "granted", "granted_with_mods", "grantedWithMods"}
        if status not in granted:
            raise TimestampError(f"timestamp authority rejected the request (status {status!r})")
        return bytes(response["time_stamp_token"].dump())
    except TimestampError:
        raise
    except Exception as exc:  # malformed ASN.1 from a server
        raise TimestampError(f"could not parse timestamp response: {exc}") from exc


def _verify_rfc3161_token(
    token: TimestampToken,
    digest_hex: str,
    *,
    trusted_certs: list[crypto_x509.Certificate] | None,
) -> TimestampInfo:
    try:
        content_info = cms.ContentInfo.load(token.data)
        if content_info["content_type"].native != "signed_data":
            raise TimestampError("token is not CMS SignedData")
        signed_data = content_info["content"]
        encap = signed_data["encap_content_info"]
        if encap["content_type"].native != _ID_CT_TST_INFO:
            raise TimestampError("token does not encapsulate TSTInfo")
        content_der = bytes(encap["content"].contents)
        tst_info = tsp.TSTInfo.load(content_der)
    except TimestampError:
        raise
    except Exception as exc:
        raise TimestampError(f"malformed RFC 3161 token: {exc}") from exc

    imprint = tst_info["message_imprint"]
    if imprint["hash_algorithm"]["algorithm"].native != _SHA256:
        raise TimestampError("token imprint is not SHA-256")
    if imprint["hashed_message"].native != bytes.fromhex(digest_hex):
        raise TimestampError("token imprint does not match the content digest")

    signer_info = signed_data["signer_infos"][0]
    signer_cert = _find_signer_cert(signed_data, signer_info)
    if signer_cert is None:
        raise TimestampError("token does not contain its signing certificate")

    _verify_signed_attrs(content_der, signer_info, signer_cert)
    trusted = _verify_cert_chain(signer_cert, trusted_certs)

    gen_time = tst_info["gen_time"].native
    if not isinstance(gen_time, datetime):
        raise TimestampError("token has no genTime")
    note = "" if trusted else "signature valid; signing certificate not chained to a trusted root"
    return TimestampInfo(
        kind=TokenKind.RFC3161.value,
        tsa_name=token.tsa_name,
        gen_time=gen_time.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        digest_hex=digest_hex,
        trusted_chain=trusted,
        note=note,
    )


def _find_signer_cert(
    signed_data: cms.SignedData, signer_info: cms.SignerInfo
) -> crypto_x509.Certificate | None:
    sid = signer_info["sid"].chosen
    want_serial = sid["serial_number"].native
    want_issuer = sid["issuer"]
    for choice in signed_data["certificates"]:
        cert = choice.chosen
        if cert.serial_number == want_serial and cert.issuer == want_issuer:
            return crypto_x509.load_der_x509_certificate(cert.dump())
    return None


def _verify_signed_attrs(
    content_der: bytes,
    signer_info: cms.SignerInfo,
    signer_cert: crypto_x509.Certificate,
) -> None:
    signed_attrs = signer_info["signed_attrs"]
    if not signed_attrs:
        raise TimestampError("token signer has no signed attributes")
    digest_algo = signer_info["digest_algorithm"]["algorithm"].native
    found_digest: bytes | None = None
    for attr in signed_attrs:
        if attr["type"].native == "message_digest":
            found_digest = attr["values"][0].native
    if found_digest != _digest(content_der, digest_algo):
        raise TimestampError("signed message-digest attribute does not match TSTInfo")
    data_to_verify = signed_attrs.untag().dump()
    signature = signer_info["signature"].native
    public_key = signer_cert.public_key()
    # Follow the token's own signature algorithm + hash — public TSAs use both RSA
    # (e.g. DigiCert) and ECDSA (e.g. FreeTSA), with SHA-256/384/512.
    sig_alg = signer_info["signature_algorithm"]
    try:
        sig_hash = _crypto_hash(sig_alg.hash_algo)
    except ValueError, KeyError, TimestampError:
        sig_hash = _crypto_hash(digest_algo)
    signature_algo = sig_alg.signature_algo
    try:
        if signature_algo == "rsassa_pkcs1v15" and isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, data_to_verify, padding.PKCS1v15(), sig_hash)
        elif signature_algo == "ecdsa" and isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, data_to_verify, ec.ECDSA(sig_hash))
        else:
            raise TimestampError(
                f"unsupported signature algorithm: {signature_algo} with this key type"
            )
    except TimestampError:
        raise
    except Exception as exc:
        raise TimestampError("token signature is invalid") from exc


def _verify_cert_chain(
    signer_cert: crypto_x509.Certificate,
    trusted_certs: list[crypto_x509.Certificate] | None,
) -> bool:
    if not trusted_certs:
        return False
    signer_fp = signer_cert.fingerprint(crypto_hashes.SHA256())
    for trusted in trusted_certs:
        # A pinned authority certificate (matched by fingerprint) is trusted.
        if trusted.fingerprint(crypto_hashes.SHA256()) == signer_fp:
            return True
        # Otherwise the signer must be signed by a trusted issuer.
        if _issuer_signed(trusted, signer_cert):
            return True
    return False


def _issuer_signed(issuer: crypto_x509.Certificate, cert: crypto_x509.Certificate) -> bool:
    """Whether ``cert`` carries a valid RSA signature from ``issuer``."""
    public_key = issuer.public_key()
    algorithm = cert.signature_hash_algorithm
    if not isinstance(public_key, rsa.RSAPublicKey) or algorithm is None:
        return False
    try:
        public_key.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), algorithm)
    except Exception:
        return False
    return True


# --- dispatch + helpers -------------------------------------------------------


def verify_token(
    token: TimestampToken,
    digest_hex: str,
    *,
    trusted_certs: list[crypto_x509.Certificate] | None = None,
) -> TimestampInfo:
    """Verify a token against ``digest_hex`` and return when content existed."""
    if token.kind == TokenKind.DEV.value:
        return _verify_dev_token(token, digest_hex)
    if token.kind == TokenKind.RFC3161.value:
        return _verify_rfc3161_token(token, digest_hex, trusted_certs=trusted_certs)
    raise TimestampError(f"unknown token kind: {token.kind!r}")


def retimestamp(existing: TimestampToken, tsa: TimestampAuthority) -> TimestampToken:
    """Produce an *archive* timestamp over an existing token.

    Re-timestamping a token before its authority's certificate (or hash
    algorithm) ages out keeps the proof verifiable into the future: the new token
    attests that the old token — and therefore the content it covered — existed by
    the new time, anchored by an authority that is still trusted. Chains
    arbitrarily deep (RFC 4998-style).
    """
    return tsa.stamp(sha256_bytes(existing.data))


def verify_archive_chain(
    content_hash: str,
    primary: TimestampToken,
    archives: list[TimestampToken],
    *,
    trusted_certs: list[crypto_x509.Certificate] | None = None,
) -> list[TimestampInfo]:
    """Verify a primary token over the content, then each archive over the prior token.

    Returns each link's :class:`TimestampInfo`, earliest first; raises
    :class:`TimestampError` on the first broken link. The content's provable
    existence is anchored at ``result[0].gen_time``; later links carry that proof
    forward in time.
    """
    infos = [verify_token(primary, content_hash, trusted_certs=trusted_certs)]
    previous = primary
    for archive in archives:
        infos.append(
            verify_token(archive, sha256_bytes(previous.data), trusted_certs=trusted_certs)
        )
        previous = archive
    return infos


def sha256_raw(data: bytes) -> bytes:
    """Raw (non-hex) SHA-256, used for CMS message-digest attributes."""
    import hashlib

    return hashlib.sha256(data).digest()
