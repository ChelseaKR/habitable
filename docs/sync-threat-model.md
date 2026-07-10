<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Sync threat model and trust boundaries

This is the sync-specific companion to the project-wide
[`threat-model.md`](threat-model.md). It describes implemented controls, not a
claim of external audit.

## Assets and adversaries

The protocol protects case state, originals, timestamp material, custody
history, and participant identities from a malicious relay or courier. It also
protects integrity against an unknown device that knows a room name or recipient
public id, a peer sending a wrong-case delta, replayed files, and post-signature
message tampering.

An explicitly paired peer is trusted to contribute CRDT edits. Per-field
provenance makes the current writer attributable; it does not prevent a paired
peer's later HLC write from winning. A compromised paired endpoint therefore
remains a serious integrity threat.

## Boundary table

| Boundary | Attacker capability | Implemented control | Residual risk |
| --- | --- | --- | --- |
| QR/file/courier during pairing | Read, replace, replay material | Invitation is issuer-signed, recipient-sealed, identity- and case-bound; stale replacement fails | A user who skips fingerprint confirmation can intentionally pair the wrong key |
| Relay or USB stick | Observe size/timing; drop, duplicate, reorder, corrupt blobs | Recipient sealed box, signature, pairing HMAC, random replay id | Availability and traffic metadata are not hidden; padding only reduces size/count leakage |
| Unknown device with recipient public id | Seal arbitrary data to recipient | Exact encrypted allowlist and pairing-key proof required | A compromised allowlisted key is authorized until explicitly re-paired |
| Paired peer using wrong vault | Send validly authenticated data for another case | Pairing, message, and CRDT state independently bind `case_id` | Reusing one case label for unrelated matters is operational error |
| Replayed valid delta | Re-deliver old ciphertext indefinitely | Persisted message-id set; replay is reported and has no state/custody effect | Local rollback of the encrypted replay database can re-enable an old delta |
| Malicious paired peer | Edit CRDT fields, forge another actor, or strip provenance as “legacy” | New writes are signed as authored; legacy values are signed as migration attestations before export; unsigned mutable imports and unknown signers fail | An authorized peer may sign harmful edits as itself; provenance must remain reviewable |
| Recipient denying delivery | Claim a message never arrived | Next reply carries a signed receipt for the exact message and capture hashes | A receipt proves a device key accepted it, not that a human read it |
| Device compromise | Read keys and unlocked vault | At-rest encryption only while locked | Malware or unlocked access defeats pairing and message protections |

## Security invariants

- No network or file transport is an authorization source.
- Fingerprints are display aids; complete identities are compared in code.
- Authorization and replay state are encrypted local policy, never remote CRDT
  state.
- Timestamp tokens are verified before storage, including archive order.
- Imported source custody is verified, retained, and hash-bound into the local
  import custody entry.
- A validation failure cannot partially merge the message's CRDT state.

## Explicit non-claims

This protocol has not received independent cryptographic review. It does not
provide anonymity, endpoint security, proof of human identity, prevention of
edits by an authorized peer, or recall after disclosure. Signed receipts are not
legal service-of-process receipts.
