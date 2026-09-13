# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Integration: stamp and verify against real public RFC 3161 authorities.

The default suite only exercises the local issuer / dev TSA. This proves the
production path (`Rfc3161HttpTSA`) end to end against ≥1 public authority, and
asserts that only a SHA-256 digest — never content — leaves the device. It is
marked ``integration`` (excluded from `make verify`). Run with `make integration`
or the scheduled CI workflow.

A SINGLE authority being unreachable is a vendor outage, not a defect here, so
that case still skips. ZERO authorities answering is not a pass: until
``test_at_least_one_public_authority_answered`` existed, every authority could
fail to answer and this module reported ``3 skipped``, exit 0, under a job named
"stamp + verify against real public RFC 3161 authorities" — the docstring above
claimed the ≥1 the code never enforced. Measured on 2026-09-13 by pointing both
URLs at ``.invalid`` hosts: 3 skipped, exit 0, green.

Every run prints how many authorities were actually reached out of how many are
configured, whether it passes or fails, so a green run states what it examined
instead of implying it examined everything.
"""

from __future__ import annotations

import urllib.error
import urllib.request

import pytest
from cryptography import x509

from habitable.canonical import sha256_bytes
from habitable.errors import TimestampError
from habitable.tsa import Rfc3161HttpTSA, TimestampToken, verify_token

pytestmark = pytest.mark.integration

# Free, public RFC 3161 authorities. We only ever send a hash.
_PUBLIC_TSAS = [
    ("freetsa", "https://freetsa.org/tsr"),
    ("digicert", "http://timestamp.digicert.com"),
]


PROBE_DIGEST = sha256_bytes(b"habitable integration probe - synthetic, not real evidence")


@pytest.fixture(scope="module")
def public_tsa_probe() -> dict[str, tuple[TimestampToken | None, str]]:
    """Stamp once at every configured authority; record the token or the error.

    Module-scoped so the count below and the per-authority assertions read the
    SAME attempt. If each test probed on its own, the floor would be counting a
    different set of network calls than the one the assertions ran against, and
    "reached 2 of 2" could be printed by a run in which neither round trip was
    the one that was verified.
    """
    results: dict[str, tuple[TimestampToken | None, str]] = {}
    for name, url in _PUBLIC_TSAS:
        try:
            results[name] = (Rfc3161HttpTSA(name, url, timeout=20.0).stamp(PROBE_DIGEST), "")
        except (TimestampError, urllib.error.URLError, OSError) as exc:
            results[name] = (None, f"{type(exc).__name__}: {exc}")
    return results


def test_at_least_one_public_authority_answered(
    public_tsa_probe: dict[str, tuple[TimestampToken | None, str]],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The floor: zero authorities reached is a failure, not three clean skips.

    This is the only assertion in this module that a total outage can reach. The
    per-authority tests skip, by design, so without this the scheduled workflow
    is green in exactly the state it exists to detect: nothing answered.
    """
    reached = sorted(n for n, (token, _) in public_tsa_probe.items() if token is not None)
    with capsys.disabled():
        print(
            f"\n  public RFC 3161 authorities reached: "
            f"{len(reached)} of {len(_PUBLIC_TSAS)}"
            + (f" ({', '.join(reached)})" if reached else "")
        )
    assert reached, (
        "no configured public RFC 3161 authority answered, so this run verified "
        "the production timestamping path against nothing:\n"
        + "\n".join(f"  - {n}: {err}" for n, (_, err) in sorted(public_tsa_probe.items()))
    )


@pytest.mark.parametrize(("name", "url"), _PUBLIC_TSAS)
def test_public_tsa_round_trip(
    name: str, url: str, public_tsa_probe: dict[str, tuple[TimestampToken | None, str]]
) -> None:
    digest = PROBE_DIGEST
    token, err = public_tsa_probe[name]
    if token is None:
        pytest.skip(f"{name} unreachable ({err}); a single authority is best-effort")

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
        pytest.skip(
            f"freetsa unreachable ({exc}); this freshness signal is best-effort, and "
            "the floor above is what refuses a run that reached nothing"
        )

    anchors = x509.load_pem_x509_certificates(published_root)
    info = verify_token(token, digest, trusted_certs=anchors)

    assert info.trusted_chain is True, (
        "a live FreeTSA token no longer anchors to FreeTSA's published root; "
        "check whether the authority's chain shape changed"
    )
    assert info.note == ""
    assert verify_token(token, digest).trusted_chain is False
