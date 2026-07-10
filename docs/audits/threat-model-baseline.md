# Threat-model baseline — frozen for external review

> **Status: alpha / concept stage.** Freezing the threat model is a precondition for
> the external security and cryptographic review (productionization task 1.1), not a
> claim that the review has happened. The alpha caveat in the
> [README](../../README.md) and the [threat model](../threat-model.md) stays until
> that review, a lawyer's read on the framing, a recorded screen-reader pass, and a
> pilot are all done.

This is the **baseline** an external reviewer is handed: a specific, content-pinned
version of [`docs/threat-model.md`](../threat-model.md), a maintainer re-review of it,
and the explicit list of residual risks the reviewer is asked to confirm or refute
independently. The point of freezing is that the reviewer and the maintainer are
talking about the *same* document, and that any later change to it is detectable
rather than silent — the project's own "verify, don't trust" discipline applied to
its own security narrative.

## Baseline B1

| Field | Value |
| --- | --- |
| Baseline id | **B1** |
| Frozen on | 2026-06-17 |
| Frozen document | [`docs/threat-model.md`](../threat-model.md) |
| Document SHA-256 | `809e0a433018f415705e7af18ca3198a67a5ad9293f1ba6a1042333239fcb71f` |
| Companion ACR (SHA-256) | `60a41477f156993e7121085e2f9e94c7ae99e86683070e15b4d9fa0ae15e5331` |
| Package version | `habitable 0.1.0` |
| Git tag | `threat-model-baseline-B1` (annotated; points at the freeze commit) |

Confirm the frozen document has not drifted from this baseline:

```sh
test "$(shasum -a 256 docs/threat-model.md | awk '{print $1}')" \
  = 809e0a433018f415705e7af18ca3198a67a5ad9293f1ba6a1042333239fcb71f \
  && echo "threat model matches baseline B1" || echo "DRIFTED — re-review and cut a new baseline"
```

## Maintainer re-review (2026-06-17)

The threat model was re-walked section by section against the code as it stands at
the freeze commit. Findings:

- **§1 Adversary (retaliating landlord + lawyer; device seizure; subpoena of third
  parties; contesting the evidence).** Still the right adversary and still correctly
  scoped. Out-of-scope adversaries (state-level, targeted device exploit, capable
  forensic lab) remain explicitly excluded — unchanged.
- **§2 Assets (tenant identity/location, case contents, evidence integrity,
  organizer identities).** Unchanged and complete.
- **§3 Trust boundaries.** Matches the implementation: the device holds the only
  plaintext (`vault.py`); the relay stores ciphertext sealed to recipient keys and
  keeps only aggregate passthrough counts (`relay.py`, `sync.py`); the RFC 3161
  authority sees only a SHA-256 imprint (`tsa.py`).
- **§4 What is protected.** Reconciled with shipped code. **Two mitigations named in
  the model are now implemented rather than designed:** passphrase rotation and the
  independent-passphrase recovery blob (`vault.rotate_passphrase` /
  `export_recovery` / `restore_keyfile`; `crypto.export_recovery_blob`), and the
  custody-identity minimization on export (`evidence.public_payload` / `redacted` /
  `integrity_proof`). **One mitigation has been added since the model was first
  written and is now folded into §4/§6:** archive (re-)timestamping
  (`tsa.retimestamp` / `verify_archive_chain`, `capture.retimestamp_all`), which
  keeps an existence proof durable past an authority's certificate or hash algorithm
  aging out, anchored at the primary token's time. No protection claim in §4
  overstates the code.
- **§5 What is NOT protected.** Every stated limit still holds and none has silently
  been "fixed" into a false promise. The hostile-keyholder limit on local custody,
  relay metadata exposure, the duress-state's limits against coercion/forensics, the
  no-recovery consequence of lost keys, the non-production dev TSA, no admissibility
  guarantee, and endpoint-compromise defeating everything — all still accurate.
- **§6 Mitigations and residual risk.** The table matches the current mitigations;
  the archive-timestamping addition strengthens the "evidence altered after capture"
  row's mitigation without changing its residual risk (a hostile keyholder can still
  rewrite the local chain before any external anchor exists).
- **§7 Summary.** Accurate.

**Net:** the threat model is consistent with the code at the freeze commit. The
re-review surfaced no overstated protection and no newly-unprotected gap; it folded
in archive re-timestamping and confirmed that two previously-designed mitigations are
now implemented. The document is fit to be the baseline for external review.

## Residual risks handed to the external reviewer

These are the project's own statements of what it does **not** protect. The external
review (task 1.1) and the independent threat-model review (task 2.4) are asked to
confirm each is stated honestly and completely, and to surface any the project has
missed:

1. **Hostile keyholder can rewrite the local custody chain** before any external
   anchor (a counterpart holding the head hash, or a timestamp over it) exists.
   Custody is tamper-*evident*, not tamper-*proof*, against the device owner.
2. **Relay connection metadata** (who syncs with whom, when, roughly how much) is
   visible to any relay, including a no-log one. No traffic-analysis resistance.
   Only pure peer-to-peer sync removes the party.
3. **Duress-safe state is harm reduction, not a safe** — it does not withstand a
   coercing adversary who compels the real passphrase or a forensic adversary who
   images storage at rest.
4. **Lost keys with no recovery blob and no surviving peer = permanent data loss**,
   by design; there is no operator-side recovery.
5. **A timestamp proves *when*, never *who* or *what*.** Tamper-evidence and a
   timestamp strengthen a true record; they do not manufacture a case.
6. **Endpoint compromise defeats the cryptography.** Confidentiality at rest assumes
   a locked vault on a clean device; malware/keylogger/screen-recorder on an unlocked
   device defeats it.
7. **No admissibility guarantee.** Whether a court or agency admits a packet, and
   what weight it carries, is a legal question outside the tool.

## What "frozen" means

- This baseline is **immutable once tagged.** Substantive changes to the threat model
  do not edit B1 — they produce a **new baseline (B2, …)** in this file with a fresh
  document hash, re-review, and tag, so the review trail is append-only.
- Per [`governance.md`](../governance.md), a change touching the hard rules or the
  threat model is recorded as an ADR; a baseline cut references the relevant ADR.
- Per [`README.md`](../../README.md) audit-as-artifact discipline, the threat model is
  re-reviewed each release that could affect it, and a release that changes it cuts a
  new baseline here.

## Post-freeze erratum — 2026-07-09 (not part of B1)

B1 item 3 and its maintainer re-review incorrectly described a duress-safe state as an
implemented mitigation. No such code existed at the freeze and none exists now. The frozen
text remains above as an audit artifact rather than being silently rewritten; reviewers must
treat that statement as a finding, not a current capability. The corrected current state is
recorded in the [capability ledger](../capabilities.md), [threat model](../threat-model.md),
and [ADR 0007](../adr/0007-limits-first-distress-decoy-vault-model.md).
