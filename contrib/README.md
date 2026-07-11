<!-- SPDX-License-Identifier: Apache-2.0 -->
# `contrib/` — reference integrations (Apache-2.0)

Small, dependency-light integrations meant to be **copied into a downstream system**. Unlike the
rest of the repository (AGPL-3.0), everything in this directory is offered under **Apache-2.0** and
builds only on the habitable *verification subset*, so an integrator inherits no copyleft
obligation. See [`../NOTICE`](../NOTICE) and [`../docs/embedding-the-verifier.md`](../docs/embedding-the-verifier.md).

## `bagit_packet_adapter.py` — exact packet transfer

Creates and validates a strict [BagIt 1.0](https://www.rfc-editor.org/rfc/rfc8493.html) directory
containing an exact, Habitable-verified packet under `data/packet/`. SHA-256 payload and tag
manifests detect transfer corruption; the adapter rejects unsafe filesystem objects, path escapes,
and case/Unicode ambiguities, then publishes through a single rename to a new destination.

```console
$ python contrib/bagit_packet_adapter.py create 4B-packet 4B-transfer.bag
$ python contrib/bagit_packet_adapter.py validate 4B-transfer.bag
$ habitable verify 4B-transfer.bag/data/packet --trusted-cert independently-trusted-tsa.pem
```

BagIt does not protect against an active attacker and does not replace Habitable signature,
custody, timestamp, or authority-trust verification. See the full [profile, usage, security
boundary, and RFC choices](bagit-packet-adapter.md).

## `legal_aid_importer.py` — importer + signed evidence receipt

Realizes roadmap **EXP-10**. It lets a legal-aid case-management system ingest and independently
re-verify a habitable evidence packet, and produce a **signed, machine-readable receipt** to store
next to the case file and re-check later without re-running the whole verifier.

### The 20-line version

```python
import sys
sys.path.insert(0, "contrib")          # or vendor the single file into your tree

from cryptography import x509
from legal_aid_importer import import_packet, sign_receipt, verify_receipt, generate_signing_key

# 1. Verify with an authority certificate your organisation independently trusts.
root = x509.load_pem_x509_certificate(open("tsa-root.pem", "rb").read())
result = import_packet(
    "4B-packet", trusted_certs=[root], now="2026-01-02T00:10:00Z"
)
print(result.report.summary())
receipt = result.receipt               # a plain dict you can store as JSON

# 2. Seal it with your organisation's signing key so the stored record is tamper-evident.
private_seed, public_key = generate_signing_key()      # keep the seed secret; publish the key
envelope = sign_receipt(receipt, private_seed)

# 3. Later, re-check a stored receipt — no packet directory required.
check = verify_receipt(envelope, expected_public=public_key)
assert check.ok                        # digest + signature verify, and the key is one you pinned
```

From the command line:

```console
$ python contrib/legal_aid_importer.py 4B-packet --trusted-cert tsa-root.pem --now 2026-01-02T00:10:00Z
$ python contrib/legal_aid_importer.py 4B-packet --trusted-cert tsa-root.pem --sign-key org-ed25519.seed
```

The exit code is `0` only when the packet is technically evidence-ready, `1` when it is not, and
`2` for pre-verification input/trust-certificate errors. Without `--trusted-cert`, a packet may be
structurally intact and its timestamp signatures mechanically valid, but authority trust,
evidence readiness, and `ok` fail closed. Development timestamps can never become trusted.

### The receipt

A receipt is a plain JSON object. It **binds the verdict to the packet's identity** — the SHA-256 of
the exact `bundle.json` bytes — so a relying party can independently re-hash the packet's
`bundle.json` and confirm the receipt is about *this* packet:

```jsonc
{
  "receipt_type": "habitable.evidence-receipt",
  "receipt_version": 2,
  "importer": "habitable-contrib-importer/2",
  "packet_schema": "https://chelseakr.github.io/habitable/schema/packet-bundle-v1.schema.json",
  "supported_packet_version": 2,
  "verified_at": "2026-01-02T00:10:00Z",      // present only when you pass `now`
  "packet": {
    "bundle_sha256": "58345801…",             // the packet's identity
    "packet_version": 1,
    "case_id": "golden-4B",
    "unit": "4B",
    "producer_fingerprint": "e0f9-20ab-0253-70f3"
  },
  "verdict": {
    "ok": true, "status": "evidence_ready", "structurally_intact": true,
    "timestamp_authority_trusted": true, "evidence_ready": true,
    "signature_ok": true, "custody_ok": true, "custody_length": 5,
    "items_total": 1, "items_verified": 1,
    "items_cryptographically_verified": 1, "items_trusted_timestamp": 1,
    "problems": [], "summary": "integrity: intact; timestamp authority: trusted …"
  },
  "items": [
    { "capture_id": "cap-…", "content_hash": "80ff…", "structurally_intact": true,
      "cryptographically_verified": true, "timestamp_present": true,
      "timestamp_kind": "rfc3161", "timestamp_verified": true,
      "timestamp_authority_trusted": true, "evidence_ready": true,
      "gen_time": "2026-01-02T00:00:00Z", "tsa_name": "golden-tsa",
      "verified_authorities": ["golden-tsa"], "trusted_authorities": ["golden-tsa"],
      "shared_media_ok": true,
      "custody_binding_ok": true, "original_fixity_ok": null, "ok": true, "notes": [] }
  ]
}
```

`sign_receipt` wraps it in an envelope carrying `receipt_sha256` (the SHA-256 of the receipt's
canonical bytes), the signer's `sign_public`, and an Ed25519 `signature` over that digest. Editing a
stored receipt after signing changes the digest and fails `verify_receipt`.

### Stability contract

- **`receipt_version`** and **`packet_schema`** name the exact contract a receipt was produced
  against. A store should refuse a receipt whose `receipt_version` major it does not understand
  rather than mis-read a future format. The packet format itself is versioned by `packet_version`
  (accepted `1..supported_packet_version`; newer is rejected, not mis-verified).
- Receipt version 2 separates structural integrity, mechanical timestamp verification,
  timestamp-authority trust, and evidence readiness. Its legacy `ok` field is a fail-closed alias
  for `evidence_ready`; version 1 consumers must migrate rather than infer old semantics.
- The receipt canonicalises with the same encoder the packet signature relies on
  (`habitable.canonical.canonical_json`: UTF-8, sorted keys, tight separators), so its digest is
  reproducible across machines and Python versions.
- Like the verifier subset, this module uses only portable, parenthesized exception syntax and runs
  on any maintained Python 3 — its only third-party runtime dependency is
  [`cryptography`](https://cryptography.io).

Cross-tested against the committed golden-packet corpus in
[`../tests/test_contrib_importer.py`](../tests/test_contrib_importer.py), which runs in the normal
CI gate.
