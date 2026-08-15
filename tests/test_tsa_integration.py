# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Integration: stamp and verify against real public RFC 3161 authorities.

The default suite only exercises the local issuer / dev TSA. This proves the
production path (`Rfc3161HttpTSA`) end to end against ≥1 public authority, and
asserts that only a SHA-256 digest — never content — leaves the device. It is
marked ``integration`` (excluded from `make verify`) and skips cleanly when a TSA
is unreachable, so it is a monitoring signal, not a flaky gate. Run with
`make integration` or the scheduled CI workflow.
"""

from __future__ import annotations

import urllib.error
import urllib.request

import pytest
from cryptography import x509

from habitable.canonical import sha256_bytes
from habitable.errors import TimestampError
from habitable.tsa import Rfc3161HttpTSA, verify_token

pytestmark = pytest.mark.integration

# Free, public RFC 3161 authorities. We only ever send a hash.
_PUBLIC_TSAS = [
    ("freetsa", "https://freetsa.org/tsr"),
    ("digicert", "http://timestamp.digicert.com"),
]


@pytest.mark.parametrize(("name", "url"), _PUBLIC_TSAS)
def test_public_tsa_round_trip(name: str, url: str) -> None:
    digest = sha256_bytes(b"habitable integration probe - synthetic, not real evidence")
    tsa = Rfc3161HttpTSA(name, url, timeout=20.0)
    try:
        token = tsa.stamp(digest)
    except (TimestampError, urllib.error.URLError, OSError) as exc:
        pytest.skip(f"{name} unreachable ({exc}); integration check is best-effort")

    # The token verifies against the digest we sent (signature + imprint + genTime).
    info = verify_token(token, digest)
    assert info.kind == "rfc3161"
    assert info.digest_hex == digest
    assert info.gen_time  # an actual time was returned

    # A token must NOT verify against a different digest.
    with pytest.raises(TimestampError):
        verify_token(token, sha256_bytes(b"different content"))


def test_a_live_freetsa_token_anchors_to_freetsas_published_root() -> None:
    """The join, live: stamp at a real authority, anchor to that authority's
    published certificate (issue #159 item 1).

    Until this existed, a green integration run said nothing about trust — it
    proved a token could be *obtained* and called ``verify_token`` with no
    anchor at all, while every anchor assertion in the suite used a certificate
    this repository minted.

    The offline half of this — a committed token plus the same published
    certificates — is ``tests/test_tsa_real_authority.py``, which is what
    actually gates ``make verify``. This test is the freshness signal: it fails
    if FreeTSA rotates to a chain shape the one-hop anchor rule cannot follow
    (see ``habitable.tsa.ANCHOR_RULE``), which is exactly the change that would
    silently invalidate the fixture's premise.
    """
    digest = sha256_bytes(b"habitable anchor probe - synthetic, not real evidence")
    tsa = Rfc3161HttpTSA("freetsa", "https://freetsa.org/tsr", timeout=20.0)
    try:
        token = tsa.stamp(digest)
        published_root = urllib.request.urlopen(
            "https://freetsa.org/files/cacert.pem", timeout=20.0
        ).read()
    except (TimestampError, urllib.error.URLError, OSError) as exc:
        pytest.skip(f"freetsa unreachable ({exc}); integration check is best-effort")

    anchors = x509.load_pem_x509_certificates(published_root)
    info = verify_token(token, digest, trusted_certs=anchors)

    assert info.trusted_chain is True, (
        "a live FreeTSA token no longer anchors to FreeTSA's published root; "
        "check whether the authority's chain shape changed"
    )
    assert info.note == ""
    assert verify_token(token, digest).trusted_chain is False
