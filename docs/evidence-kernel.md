<!-- SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0 -->
# The habitable evidence kernel

> **What this is.** The reusable, local-first *tamper-evidence kernel* extracted from
> habitable as a stable, embeddable public surface — `habitable.kernel`. It is the hardest,
> most valuable part of the tool (a correct, fail-closed, RFC 3161-backed, custody-linked
> evidence spine with an independent verifier) packaged so **other civic tools can adopt it
> without copying code**. Realizes **EXP-13** in
> [`docs/ideation/02-large-scale-fixes.md`](ideation/02-large-scale-fixes.md).
>
> **You may redistribute this.** Everything the kernel exposes is offered under **Apache-2.0**
> as an additional permission (GPLv3 §7) — see [`NOTICE`](../NOTICE). A wage-theft documenter,
> an environmental-hazard logger, or any "prove this record wasn't altered after the fact" tool
> can embed the kernel and ship it without the AGPL reaching their own code.

## Why a kernel

A "prove this record is intact" primitive is exactly what many civic tools need and few get
right: canonical bytes so the same content always hashes the same, streaming content fixity,
an append-only hash-linked chain of custody, RFC 3161 trusted timestamps, Ed25519 signatures,
and a verifier that **fails closed** (a malformed or newer-than-supported input yields "not
intact", never a wrong "intact"). habitable already isolates this subset behind a narrow import
boundary and a permissive license. The kernel names that subset, versions it, and pins its wire
formats with a language-independent golden corpus so a *second* tool can cross-check the *same*
bytes rather than reinvent them.

## The public surface

```python
from habitable.kernel import (
    # canonical serialization + hashing
    canonical_json, sha256_bytes, sha256_file, HASH_ALGORITHM,
    # chain of custody
    CustodyLog, CustodyEntry, CustodyAction, CustodyVerification,
    ItemCustodySummary, content_hash, fixity_ok, verify_fixity, GENESIS_PREV_HASH,
    # trusted timestamping (RFC 3161)
    TimestampToken, TimestampInfo, TimestampAuthority, TokenKind,
    verify_token, verify_archive_chain,
    # signatures / identity (verification half)
    verify_signature, PublicIdentity,
    # packet verification
    verify_packet, VerificationReport, ItemVerdict, SUPPORTED_PACKET_VERSION,
    # kernel identity
    KERNEL_NAME, KERNEL_API_VERSION,
)
```

`import habitable.kernel` pulls in **only** this verification subset — no relay, sync, CLI,
app, capture, or vault code — enforced in a fresh process by
[`tests/test_kernel_golden.py`](../tests/test_kernel_golden.py) (mirroring the verifier guard in
[`tests/test_guards.py`](../tests/test_guards.py)). Runtime dependencies are just
[`cryptography`](https://cryptography.io) and [`asn1crypto`](https://github.com/wbond/asn1crypto).

### Install

```console
$ pip install "habitable[kernel]"     # kernel + its two runtime deps, nothing else
```

The `kernel` extra in [`pyproject.toml`](../pyproject.toml) is the minimal install for adopters
that only want the evidence spine. (It is the same minimal runtime as the older `verify` extra;
`kernel` is the forward name for the whole embeddable surface, not just packet verification.)

## The three layers

| Layer | Names | Guarantee |
| --- | --- | --- |
| **Canonical + hashing** | `canonical_json`, `sha256_bytes`, `sha256_file` | UTF-8, sorted keys, tight separators, no NaN/Infinity — same logical content ⇒ same bytes ⇒ same hash, on any machine, forever. |
| **Chain of custody** | `CustodyLog`, `CustodyEntry`, `content_hash`, `verify_fixity` | Append-only, hash-linked entries; `entry_hash = sha256(canonical_json(public_payload))`; identity/PII is never hashed or exported (see [`threat-model.md`](threat-model.md) §4). |
| **Timestamps + signatures + packet** | `verify_token`, `verify_archive_chain`, `verify_signature`, `verify_packet` | RFC 3161 token verification (optionally chained to roots you trust), Ed25519 signature checks, and the whole-packet **fail-closed** verdict (`VerificationReport`). |

For the packet-level embedding recipe (the 20-line verifier, reading a `VerificationReport`,
asserting trusted TSA roots), see [`embedding-the-verifier.md`](embedding-the-verifier.md); this
document is the wider kernel it sits inside.

## Semver contract

`KERNEL_API_VERSION` is **semantic versioning for the kernel — the names above and the wire
formats they produce — independent of the habitable application version** in `pyproject.toml`.
The current value is `1.0.0`.

Within a major version:

- Names in `habitable.kernel.__all__` are **not removed** and keep their meaning; new names may
  be **added** (a minor bump).
- The **wire formats are frozen** byte-for-byte: `canonical_json` output, `sha256_bytes` output,
  and the custody entry-hash rule. These are pinned by the golden corpus below, so an accidental
  change fails the test suite rather than silently breaking adopters.
- The packet format carries its **own** compatibility gate, `packet_version` (accepted range
  `1..SUPPORTED_PACKET_VERSION`); every version ever emitted keeps verifying, guarded by the
  committed golden-*packet* corpus in [`tests/golden/`](../tests/golden/).

A change that would break any of the above is a **major** `KERNEL_API_VERSION` bump with a
migration note in [`CHANGELOG.md`](../CHANGELOG.md), and the golden corpus is regenerated in the
same commit.

## The golden corpus (cross-checking two verifiers)

[`tests/golden/kernel/vectors.json`](../tests/golden/kernel/vectors.json) is a **language-
independent** set of test vectors for the pure primitives:

- **`canonical_json`** — each case gives an input value, its exact canonical UTF-8 string, and its
  SHA-256. Any reimplementation (Python, Rust, Go, a court's audit script) can load the file and
  confirm it produces the same bytes and hash.
- **`custody_chain`** — each case gives a fully materialized chain (`records`) plus its expected
  `head_hash` and length. An adopter confirms it walks the chain to the same head and recomputes
  each `entry_hash` from the entry's public payload.

[`tests/test_kernel_golden.py`](../tests/test_kernel_golden.py) is habitable's own run of that
cross-check — the executable form of the EXP-13 excellence bar: *two tools' verifiers cross-check
the same corpus.* A second adopter runs the identical file; if both agree, the two tools are
byte-compatible without sharing a line of code.

Regenerate the corpus only on an intentional, documented format change:

```console
$ python scripts/gen_kernel_corpus.py      # writes tests/golden/kernel/vectors.json
```

Never edit the JSON by hand — it is derived from the live kernel so it cannot drift from the code.

## What is shipped here vs. a standalone package

This document, `habitable.kernel`, the `kernel` extra, and the golden corpus make the kernel a
**consumable in-repo library today**: another tool in the same workspace, or a vendored copy of
the subset, adopts it immediately, and the cross-check corpus is live.

Publishing the kernel as its *own* PyPI distribution / separate repository (its own release
cadence and issue tracker) is a deliberate, owner-only step — a published library is a real
maintenance commitment for a single maintainer and, per EXP-13's own risk note, is "only worth it
if a second adopter is real." When that second adopter exists, the split is mechanical because the
boundary, license, contract, and corpus are already in place:

1. move `canonical.py`, `crypto.py`, `errors.py`, `evidence.py`, `tsa.py`, `verify.py`, `kernel.py`
   and `tests/golden/kernel/` + `tests/test_kernel_golden.py` into a new `evidence-kernel` package;
2. ship it under Apache-2.0 with `KERNEL_API_VERSION` as its release version;
3. make habitable depend on it and re-export `habitable.kernel` from it for continuity.

Until then the kernel lives here, fully specified and independently verifiable, and nothing about
adopting it requires the split to have happened.
