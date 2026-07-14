<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# ADR-0009: Require authenticated, case-bound pairing for sync protocol v2

- **Status:** Accepted
- **Date:** 2026-07-10
- **Decider:** Project maintainer

## Context

The original sync envelope was encrypted to a recipient and signed by whatever
sender key appeared inside it. That protected confidentiality and detected byte
tampering, but it did not answer the authorization question: *was this exact
sender expected for this exact case?* Imports also made case checking optional,
accepted the same message repeatedly, transferred only the primary timestamp,
and produced no signed acknowledgement that a peer accepted a delta.

PR #53 proposed signing mutable CRDT fields. That is useful attribution, but a
field signature alone does not authorize a device, bind a relationship to a
case, authenticate key exchange, prevent replay, or acknowledge receipt.

## Decision

Sync protocol v2 requires an explicitly paired peer stored in the encrypted
vault. Pairing material is bound to the issuer, recipient, and `case_id`, signed
by the issuer, sealed to the recipient, and carries a random 256-bit key for
authenticating subsequent messages.

Every message binds the exact recipient, case, state digest, random message id,
complete sender identity, pairing id, custody proof, timestamps, and receipts.
The canonical inner bytes are Ed25519-signed and HMAC-SHA256-authenticated with
the pairing key before the envelope is sealed to the recipient. Import accepts
only the complete identity in the local allowlist, always checks both message
and state `case_id`, and records message ids so replay cannot mutate state.

Mutable LWW fields also carry PR #53's actor/signature provenance stamp. Import
verifies each attributed author or migration attestor against the local device
or an explicitly paired identity. Legacy unsigned registers remain readable
locally; before first v2 export the current device signs their unchanged
value/timestamp as `attested_legacy` (not original authorship). V2 import rejects
unsigned mutable registers, so a hostile peer cannot strip provenance and call
the result legacy. All new local writes are signed as `authored`.

## Options considered

| Option | Assessment |
| --- | --- |
| Keep signed envelopes only | Low migration cost, but authenticates an arbitrary key rather than an authorized peer. Rejected. |
| Trust on first use | Convenient, but the first hostile delta permanently pins the attacker. Rejected. |
| Per-field signatures only (PR #53) | Preserves attribution after merge, but leaves pairing, case binding, replay, and receipts unresolved. Incorporated, not sufficient alone. |
| Explicit signed-and-sealed pairing plus v2 messages | Adds one ceremony step and local state, but makes the trust decision explicit and testable. Chosen. |

## Consequences

- Existing vault contents open normally, but no legacy peer is silently trusted.
  Peers must pair before the next sync or share.
- Protocol-v1 messages fail closed. There is no insecure compatibility switch.
- Re-pairing is explicit; stale pairing material cannot roll a newer key back.
- Replay ids, receipts, source-custody proofs, and allowlists are encrypted local
  policy state and never CRDT-merged.
- A user must still verify the displayed fingerprint out of band. Pairing cannot
  prove the human standing behind a key.
- This supersedes PR #53 as the sync authorization design while retaining its
  signed-field provenance capability.

## Follow-up

- External security review remains required before production claims.
- A visual QR encoder/scanner may wrap the existing one-line `.hpair` material;
  it must not change the protocol or bypass fingerprint confirmation.
