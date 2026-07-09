<!-- SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0 -->
# Embedding the habitable verifier

> **Audience.** Courts, legal-aid groups, opposing parties, and civic/legal-aid tool integrators
> (persona P-23) who want to confirm a habitable packet from their own software. Realizes backlog
> **E-27** (embedding cookbook) and complements **E-26/R-51** (the
> [bundle schema](packet-bundle.schema.json)).
>
> **You may redistribute this.** The verification subset is offered under **Apache-2.0** as an
> additional permission (GPLv3 §7) — see [`NOTICE`](../NOTICE) and the SPDX headers. You can embed and
> ship verification in your own product without the AGPL reaching your code. (Merely *running* the
> verifier never triggers copyleft regardless.)

> **Adopting the whole evidence spine, not just the packet verifier?** See
> [`evidence-kernel.md`](evidence-kernel.md) — the reusable, semver-contracted kernel
> (`habitable.kernel`: canonical + custody + timestamps + signatures + verify) with a
> language-independent golden corpus for cross-checking two implementations. This page is the
> packet-verification recipe that sits inside it.

## What "the verifier subset" is

The independently-licensed subset is `habitable.verify` plus the pure modules it imports:
`habitable.canonical`, `habitable.crypto`, `habitable.evidence`, and `habitable.tsa`. It pulls no
AGPL-only or heavy modules — `import habitable.verify` brings in only this subset, and a guard test
in `tests/test_guards.py` keeps it that way. Runtime dependencies are
[`cryptography`](https://cryptography.io) and [`asn1crypto`](https://github.com/wbond/asn1crypto).

**Python support.** The subset uses only standard, parenthesized exception syntax and runs on any
maintained Python 3 (it does not require the 3.14 features the full app targets). If you vendor the
source, keep multi-type `except (A, B):` parenthesized so it parses on older interpreters.

## The 20-line version

```python
from pathlib import Path
from habitable.verify import verify_packet

report = verify_packet(Path("4B-packet"))          # a packet directory (has bundle.json)

print(report.summary())                            # one-line human verdict
if report.ok:
    print("packet intact")
else:
    if not report.signature_ok:
        print("- bundle signature did not verify")
    if not report.custody_ok:
        print("- chain of custody is broken")
    for problem in report.problems:
        print(f"- {problem}")
    for item in report.items:
        if not item.ok:
            print(f"- item {item.capture_id}: {', '.join(item.notes)}")

raise SystemExit(0 if report.ok else 1)
```

`verify_packet(packet_dir, *, trusted_certs=None)` returns a `VerificationReport`. It **fails
closed**: a malformed or newer-than-supported packet yields `report.ok == False` (not a wrong
"intact"). Two pre-structural conditions — a missing `bundle.json` or bytes that aren't valid JSON —
raise `VerificationError`; wrap the call if you treat those as "could not verify":

```python
from habitable.errors import VerificationError
try:
    report = verify_packet(packet_dir)
    ok = report.ok
except VerificationError as exc:
    ok = False                                     # nothing to verify / unreadable bundle
    print(f"could not verify: {exc}")
```

## Reading the report

`VerificationReport` (frozen dataclass):

| Field / property | Meaning |
| --- | --- |
| `ok` | overall verdict (see [decision table §0](verifier-decision-table.md#0-what-intact-means)) |
| `signature_ok` | producer signature over the bundle bytes verified |
| `custody_ok` | chain walks cleanly and the declared head matches |
| `custody_length` | number of custody entries |
| `items` | tuple of `ItemVerdict` |
| `problems` | tuple of structural/version problems (empty when clean) |
| `verified_items` | count of items with `ok == True` |
| `summary()` | a single human-readable line |

`ItemVerdict` (per media item): `capture_id`, `content_hash`, `timestamp_verified`, `gen_time`,
`tsa_name`, `shared_media_ok`, `custody_binding_ok`, `original_fixity_ok` (`True`/`False`/`None`),
`verified_authorities` (tuple of every TSA whose token verified — one per authority when redundant
timestamps are used), `notes` (tuple of strings), and `ok`. The `notes` carry the human reasons (e.g. `awaiting
timestamp`, `shared media does not match its recorded hash`).

## Asserting trusted timestamp roots

Without `trusted_certs`, a structurally valid RFC 3161 token still verifies but is flagged "authority
not chained to a trusted root." To require the token chain to a TSA root *you* trust, pass loaded
certificates:

```python
from cryptography import x509
roots = [x509.load_pem_x509_certificate(Path(p).read_bytes())
         for p in ("freetsa-root.pem", "digicert-root.pem")]
report = verify_packet(packet_dir, trusted_certs=roots)
```

Then a token whose authority does not chain to one of `roots` will carry the not-chained note (the
item can still be `ok` on the other checks; decide your own policy on whether to require a trusted
chain).

From the command line, the same anchoring is available without writing code:

```console
$ habitable verify 4B-packet --trusted-cert freetsa-root.pem --trusted-cert digicert-root.pem
$ habitable verify 4B-packet --json          # structured report (per-item verdicts + notes)
```

## Verifying the bundle against the published schema (optional)

You can additionally validate structure against [`packet-bundle.schema.json`](packet-bundle.schema.json)
(JSON Schema 2020-12). Schema validation is **not** a substitute for `verify_packet` — it checks
shape, not signatures, hashes, timestamps, or custody — but it is a cheap first gate for an ingest
pipeline:

```python
import json, jsonschema           # your dependency, not habitable's
schema = json.load(open("packet-bundle.schema.json"))
jsonschema.validate(json.load(open(packet_dir / "bundle.json")), schema)
```

## Stability contract (what you can rely on)

- **`packet_version`** gates compatibility. This verifier accepts versions
  `1..SUPPORTED_PACKET_VERSION` and rejects newer ones cleanly. Every version ever emitted keeps
  verifying — guarded by the committed golden-packet corpus in `tests/`.
- The **bundle/field shapes** in [`bundle-schema.md`](bundle-schema.md) are additive within a major
  `packet_version`; a breaking change is a major bump with a migration note (semver on the packet
  format and verification protocol, independent of the package version — see
  [`CHANGELOG.md`](../CHANGELOG.md) and [`ROADMAP.md`](../ROADMAP.md)).
- For a no-dependency, hand cross-check (OpenSSL + sha256sum + any Ed25519 lib), see
  [verifier-decision-table §5](verifier-decision-table.md#5-independent-cross-check-without-habitable-r-31).

If you embed the verifier, please watch [`SECURITY.md`](../SECURITY.md) for advisories on the
verification protocol.
