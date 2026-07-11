# 8. Separate packet integrity, timestamp-authority trust, and evidence readiness

Status: Accepted (2026-07-09)

## Context

The verifier historically exposed one `ok` boolean. Per-item `timestamp_verified`
became true when a timestamp token's signature and content imprint verified, even
when its signing certificate did not chain to a caller-supplied trusted root.
`ItemVerdict.ok`, `VerificationReport.ok`, the CLI exit code, and human summaries
then treated that state as a successful packet verification.

That collapsed three different questions:

1. Are the signed bundle, custody chain, and included media structurally intact?
2. Does each timestamp token validate to an authority certificate the recipient
   independently trusts?
3. Has the packet passed both checks and included timestamp coverage for every item?

The collapse was especially unsafe for `DevTSA`: its self-authenticating development
token correctly returned `trusted_chain = False`, but the packet still returned
`ok = True`. An unanchored RFC 3161 token had the same ambiguity. Human-readable HTML
and PDF exports also described any attached token as "trusted" or "verified" even
though rendering performs no cryptographic verification and has no recipient trust
store.

## Decision

Expose and preserve three independent claims:

- `structurally_intact`: packet format, producer signature, custody chain, shared
  media hashes/bindings, and any embedded-original fixity all pass. Timestamp
  presence and authority trust do not redefine byte integrity.
- `timestamp_authority_trusted`: every evidence item has at least one valid timestamp
  token whose authority chains to a certificate supplied by the verifier caller.
  Token signatures can validate while this remains false.
- `evidence_ready`: the packet is structurally intact, contains at least one evidence
  item, and every item has a valid, authority-trusted timestamp. This is a technical
  workflow state, not a legal opinion or admissibility decision.

Per-item verdicts expose the same separation plus:

- `timestamp_present`: distinguishes awaiting timestamps from attached-but-invalid
  tokens;
- `timestamp_kind`: lets human output distinguish development from RFC 3161 tokens;
- `timestamp_verified`: the existing mechanical signature/imprint result;
- `cryptographically_verified`: the historical integrity-plus-valid-token check,
  explicitly named and independent of authority trust;
- `trusted_authorities` alongside the existing `verified_authorities`.

The legacy `ok` JSON/Python field is retained for shape compatibility but tightened
to be an alias of `evidence_ready`. `verified_items` is likewise the number of
evidence-ready items. Callers that intentionally need the old mechanical result must
migrate to `cryptographically_verified` / `cryptographically_verified_items`.

`habitable verify` returns zero only for `evidence_ready`. It accepts `--lang en|es`,
defaults to the packet language, and reports the three claims separately. Without
`--trusted-cert`, valid RFC 3161 tokens remain mechanically verified but authority
trust and evidence readiness fail closed. `DevTSA` always remains untrusted regardless
of supplied certificates.

Generated HTML and PDF views make no verification verdict. They report only token
presence and the authority name recorded in the bundle, mark development tokens as
untrusted, and instruct recipients to verify with an independently trusted
certificate. English and Spanish use one shared source of trust-status copy so the
renderers cannot drift.

## Consequences

- Existing scripts that treated `ok = True` without supplying a trust root will now
  receive `ok = False` and CLI exit status 1. This is an intentional fail-closed
  behavior change; the machine fields remain present.
- The Apache-licensed legal-aid evidence receipt advances to version 2 and records all
  three claims. Its CLI accepts repeatable `--trusted-cert` arguments; receipt version 1
  consumers must migrate because the meaning of `ok` is intentionally stricter.
- A signed empty packet may be `structurally_intact` but is never `evidence_ready`.
- A missing timestamp can coexist with intact structure. An invalid attached token is
  reported separately and never receives the calm "awaiting" state.
- Trust roots are recipient policy, not packet data. Habitable does not silently use
  the certificate embedded in a token as its own trust anchor.
- "Evidence-ready" means these technical checks passed. It does not establish who
  captured media, the truth of a depicted condition, admissibility, or a legal result.
