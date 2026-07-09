<!-- SPDX-License-Identifier: Apache-2.0 -->
# `contrib/` — reference integrations (Apache-2.0)

Small, dependency-light integrations meant to be **copied into a downstream system**. Unlike the
rest of the repository (AGPL-3.0), everything in this directory is offered under **Apache-2.0** and
builds only on the habitable *verification subset*, so an integrator inherits no copyleft
obligation. See [`../NOTICE`](../NOTICE) and [`../docs/embedding-the-verifier.md`](../docs/embedding-the-verifier.md).

## `legal_aid_importer.py` — importer + signed evidence receipt

Realizes roadmap **EXP-10**. It lets a legal-aid case-management system ingest and independently
re-verify a habitable evidence packet, and produce a **signed, machine-readable receipt** to store
next to the case file and re-check later without re-running the whole verifier.

### The 20-line version

```python
import sys
sys.path.insert(0, "contrib")          # or vendor the single file into your tree

from legal_aid_importer import import_packet, sign_receipt, verify_receipt, generate_signing_key

# 1. Verify a packet and build a receipt (fails closed like the verifier).
result = import_packet("4B-packet", now="2026-01-02T00:10:00Z")
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
$ python contrib/legal_aid_importer.py 4B-packet --now 2026-01-02T00:10:00Z            # prints receipt JSON
$ python contrib/legal_aid_importer.py 4B-packet --sign-key org-ed25519.seed           # prints signed envelope
```

The exit code is `0` when the packet verifies intact, `1` when it does not, `2` when there is
nothing to verify (no `bundle.json` / unreadable bundle).

### The receipt

A receipt is a plain JSON object. It **binds the verdict to the packet's identity** — the SHA-256 of
the exact `bundle.json` bytes — so a relying party can independently re-hash the packet's
`bundle.json` and confirm the receipt is about *this* packet:

```jsonc
{
  "receipt_type": "habitable.evidence-receipt",
  "receipt_version": 1,
  "importer": "habitable-contrib-importer/1",
  "packet_schema": "https://chelseakr.github.io/habitable/schema/packet-bundle-v1.schema.json",
  "supported_packet_version": 1,
  "verified_at": "2026-01-02T00:10:00Z",      // present only when you pass `now`
  "packet": {
    "bundle_sha256": "58345801…",             // the packet's identity
    "packet_version": 1,
    "case_id": "golden-4B",
    "unit": "4B",
    "producer_fingerprint": "e0f9-20ab-0253-70f3"
  },
  "verdict": {
    "ok": true, "signature_ok": true, "custody_ok": true,
    "custody_length": 5, "items_total": 1, "items_verified": 1,
    "problems": [], "summary": "1/1 items verify …"
  },
  "items": [
    { "capture_id": "cap-…", "content_hash": "80ff…", "timestamp_verified": true,
      "gen_time": "2026-01-02T00:00:00Z", "tsa_name": "golden-tsa",
      "verified_authorities": ["golden-tsa"], "shared_media_ok": true,
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
- The receipt canonicalises with the same encoder the packet signature relies on
  (`habitable.canonical.canonical_json`: UTF-8, sorted keys, tight separators), so its digest is
  reproducible across machines and Python versions.
- Like the verifier subset, this module uses only portable, parenthesized exception syntax and runs
  on any maintained Python 3 — its only third-party runtime dependency is
  [`cryptography`](https://cryptography.io).

Cross-tested against the committed golden-packet corpus in
[`../tests/test_contrib_importer.py`](../tests/test_contrib_importer.py), which runs in the normal
CI gate.
