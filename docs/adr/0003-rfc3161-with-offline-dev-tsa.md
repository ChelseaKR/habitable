# 3. RFC 3161 trusted timestamps with an offline dev TSA and a deferred queue

Status: Accepted (2026-06-17)

## Context

A bare JPEG with editable EXIF is weak evidence; a date a landlord's lawyer will
contest. A *trusted timestamp* turns "the tenant says this photo is from January"
into "an independent authority attests this exact content existed by then." That
attestation requires a network call to a timestamp authority — but the realities
of this tool pull against the network:

- **Capture happens offline**, in an apartment, often with no connectivity at the
  moment the evidence is created. Capture must never block waiting for a network.
- **The authority must not see the photo.** Privacy is non-negotiable; the
  authority may see a hash and nothing more.
- **The proof must be independently verifiable** by a skeptic — a court or an
  opposing party — using only the packet, without trusting this project.

We also need the standard timestamping path to be fully exercisable offline, in
tests and demos, without depending on a live public authority.

## Decision

Hash and seal at capture, **instantly and fully offline** (`src/habitable/capture.py`):
the original bytes are SHA-256 hashed, sealed immutably, and a signed chain-of-custody
entry is appended before any network is touched. Obtaining the trusted timestamp is a
separate, deferred step:

- If an authority is reachable, request an **RFC 3161** token over the hash
  immediately. If not, queue the request (a deferred-timestamp queue) and show the
  item as *awaiting-timestamp* until connectivity lets the token be fetched and
  attached (`resolve_deferred`).
- Support **multiple authorities** (`TimestampAuthority` is a pluggable protocol),
  so the proof need not rest on a single party.
- Ship two non-network issuers so the standard path runs offline
  (`src/habitable/tsa.py`):
  - `LocalRfc3161TSA` — a self-signed authority that issues **real** RFC 3161 tokens
    (CMS `SignedData` over `TSTInfo`), so the production code path and the verifier
    are exercised end to end with no network.
  - `DevTSA` — a tiny Ed25519 "authority" for cases where even a local X.509 TSA is
    overkill. It is **clearly non-production**: its tokens are self-describing, always
    report an untrusted chain, and carry a note saying so.

## Consequences

- Capture never blocks on the network. Evidence is created the instant the shutter
  fires; the timestamp catches up when the device is online.
- The semantics are honest about what a timestamp proves: an RFC 3161 token bounds
  *when* content existed (an upper bound on creation), not *who* created it or
  *what* it depicts — and offline, the only claim until resolution is "awaiting
  timestamp," surfaced plainly rather than hidden.
- The dev TSA must **never** be mistaken for production. We mitigate by making its
  tokens self-identifying, forcing `trusted_chain = False`, and attaching an explicit
  non-production note; reviewers and verification output should treat a dev token as
  unverified-for-evidence. This is a standing risk to watch as the project matures.
- Verification (`src/habitable/verify.py`, `verify_token`) validates the full chain
  of an RFC 3161 token: the CMS signature over the signed attributes, the signing
  certificate (chained to a trusted root when trusted certs are supplied, otherwise
  reported as untrusted), the message-imprint binding to the content digest, and the
  `genTime`. The verifier is part of the Apache-2.0 verification subset so a third
  party can embed it.
