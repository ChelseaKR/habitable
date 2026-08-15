<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Golden fixture: a real public authority's token and its published certificates

Issue [#159](https://github.com/ChelseaKR/habitable/issues/159): every trust
anchor in the test suite was one this repository generated. The production path
was proven to *produce* a token from a real authority (`tests/test_tsa_integration.py`,
network-only) and separately proven to *anchor* a token from an authority we
wrote — the join was asserted nowhere.

This fixture is that join, frozen so it runs offline, in every `make verify`,
forever. `tests/test_tsa_real_authority.py` loads it.

## What is here

| File | What it is |
| --- | --- |
| `token.tsr` | A real RFC 3161 token issued by FreeTSA, DER, exactly as returned. |
| `freetsa-cacert.pem` | FreeTSA's published root CA certificate, fetched from the authority, not derived from the token. |
| `freetsa-responder.pem` | FreeTSA's published TSA responder certificate, likewise. |

Certificates are public artefacts and carry no private key material. The token
is a signature over a hash, and the hash is of a fixed synthetic string — no
tenant data, no real evidence, was involved in producing it.

## Provenance — re-derivable, not trust-me

- Retrieved **2026-08-14**.
- Certificates: `https://freetsa.org/files/cacert.pem` and
  `https://freetsa.org/files/tsa.crt` (the latter saved here as
  `freetsa-responder.pem`).
- Token: requested from `https://freetsa.org/tsr` with
  `habitable.tsa.Rfc3161HttpTSA`, over the SHA-256 of the exact bytes

  ```
  habitable golden real-authority fixture v1 - synthetic, never evidence
  ```

  i.e. digest `ae97f95eea6593ee54566a900b361501b3ad28cc26b773116eeafc0106288169`,
  which the test recomputes from those bytes rather than hard-coding — if the
  committed token ever stops matching, the test fails rather than adapting.
- Attested `genTime`: 2026-08-14T18:07:04Z.

## Why FreeTSA specifically, and what this fixture does *not* prove

FreeTSA issues its responder certificate **directly** from the root published at
the URL above, so its published root is exactly one hop from the token's signer
— which is what `habitable.tsa`'s anchor rule checks (see `ANCHOR_RULE`).

DigiCert, measured the same day, issues its responder through an intermediate:
its published root is two hops away and therefore does **not** chain under this
rule, while its timestamping CA certificate does. That is a real limit of the
anchor check, not of this fixture, and it is stated in `ANCHOR_RULE`,
`docs/embedding-the-verifier.md`, and `docs/verifier-decision-table.md` §5
rather than papered over here. This fixture proves the join for a directly
issued authority; it does not prove path building, because there is none.

## If this fixture ever fails

It should not expire: the anchor check does not consult certificate validity
periods (again, see `ANCHOR_RULE`), and both certificates run to 2040/2041
regardless. A failure means the verification path changed — investigate the
change, do not refresh the fixture to make it pass.
