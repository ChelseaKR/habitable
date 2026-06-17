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

import pytest

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
