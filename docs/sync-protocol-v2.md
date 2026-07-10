<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Authenticated sync protocol v2

This document specifies the security-relevant wire fields. Canonical encoding
means UTF-8 JSON with sorted keys and no insignificant whitespace, as implemented
by `canonical_json`.

## 1. Pairing

`sync-pair-create` produces one line beginning `habitable-pairing-v1.`. The
suffix is URL-safe base64 of an X25519 sealed box addressed to one recipient.
The sealed plaintext contains:

```text
envelope = { issuer, payload_b64, signature_b64 }

payload = {
  protocol: "habitable-pairing-v1",
  case_id,
  pairing_id,       # 128 random bits, hex
  issuer,           # complete Ed25519 + X25519 public identity
  recipient,        # complete expected recipient identity
  key_b64           # 256 random pairing-key bits
}
```

The issuer signs the canonical payload. Acceptance opens the box, verifies that
signature, requires the local identity to equal `recipient`, requires the open
vault's `case_id`, and stores the exact issuer identity plus pairing id/key in
`sync_security.enc`. A fingerprint collision is not enough: later lookups compare
the complete encoded identity.

The line can be copied manually, carried as a `.hpair` file, or used as the
payload of an ordinary QR encoder. The QR/courier is not trusted with plaintext;
the material is already sealed. Humans must still compare the issuer fingerprint
over a trusted channel.

## 2. Sync message

The inner payload contains `protocol`, `message_id`, `case_id`, `recipient`,
`state`, `state_sha256`, `have`, `captures`, `custody_proof`, and `receipts`.

Each capture carries its content hash, optional original bytes, primary RFC 3161
token, every independent additional token, and the ordered archive-token chain.
The first/original-bearing transfer carries the sender's complete custody proof.
After a peer confirms the original, it retains that proof encrypted locally and
metadata-only deltas carry an empty valid proof instead of uploading the entire
chain again. An omitted original is accepted only if the recipient actually has
that sealed capture.

The outer envelope contains the complete sender identity, pairing id, canonical
inner bytes, an Ed25519 signature, and HMAC-SHA256 over those same inner bytes.
The envelope is then sealed to the recipient. The signature preserves durable
sender attribution; the HMAC proves possession of the out-of-band pairing
material; the sealed box provides confidentiality and recipient authentication.

## 3. Import order and fail-closed rules

Before merging CRDT state or writing an original, import verifies:

1. sealed-box authentication;
2. exact sender allowlist match and pairing id;
3. envelope signature and pairing HMAC;
4. protocol, recipient, message id, outer case, state case, and state digest;
5. complete signed per-field provenance for every known author or legacy attestor;
6. source custody chain and each transferred original's content-hash binding;
7. original SHA-256 fixity;
8. primary, additional, and archive timestamp material; and
9. every embedded receipt against a message actually sent to that peer.

Any failure aborts that message before merge. Unknown peers, unknown signed-field
authors/attestors, unsigned mutable fields, wrong-case state, stale pairings,
malformed timestamps, and missing originals all fail closed.

## 4. Replay and receipts

Accepted message ids are persisted in `sync_security.enc`. Re-delivery is
reported and skipped without re-merging state, appending custody, or rewriting
evidence.

After import, the recipient signs a receipt binding the case id, exact message
id/digest, original sender and importer identities, every capture id/content
hash, and the custody head after import. The receipt rides in the recipient's
next delta. The original sender accepts it only if the digest matches a message
recorded as sent to that exact peer.

A receipt proves cryptographic acceptance by a device key. It does not prove
that a particular human reviewed the contents or constitute legal service.

## 5. Compatibility

Vaults created before v2 open with an empty authorization list. Case data and
unsigned legacy LWW registers remain readable locally. Before their first v2
export, the current device signs each unchanged legacy value/timestamp as a
migration attestation; this is explicitly distinct from original authorship.
V1 messages, unsigned mutable fields on import, and implicit public-id trust are
rejected. Pair once, then continue with v2.
