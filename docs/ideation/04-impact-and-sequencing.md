<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Impact, effort, and sequencing (2026-07-01)

Ties [`02-large-scale-fixes.md`](02-large-scale-fixes.md) (`FIX-01`…`FIX-14`) and
[`03-expansions.md`](03-expansions.md) (`EXP-01`…`EXP-15`) into one prioritized view.
This sequence deliberately goes **beyond** [`ROADMAP.md`](../../ROADMAP.md)'s workstreams
A–D and the `R-##`/`E-##` backlog; it does not re-order them. Impact is judged by
harm-reduction and evidentiary value under the retaliation threat model; effort as in the
prior files. These are ideas for evaluation, not commitments.

## Impact × effort matrix

| Impact ↓ / Effort → | S | M | L | XL |
| --- | --- | --- | --- | --- |
| **High** | FIX-14 (doc part), FIX-06, FIX-09 | FIX-03, FIX-12, EXP-03, EXP-09 | **FIX-01**, FIX-02, FIX-05, FIX-07, EXP-01, EXP-05, EXP-06, EXP-08, EXP-15 | EXP-11, EXP-13 |
| **Medium** | FIX-13 | FIX-08, FIX-11, EXP-02, EXP-04, EXP-10 | FIX-04*, EXP-07 | EXP-12, EXP-14 |
| **Low** | — | FIX-10 | — | — |

\* FIX-04 is Medium-impact in the common pure-P2P case but High-impact for any union that
depends on a relay for async sync.

Notes on the two headline items:
- **FIX-01** is the highest-priority item overall despite its L effort — it is a
  confidentiality break of a *stated* guarantee, exploitable by the literal modelled
  adversary (opposing counsel holding a court packet). It should be treated as a security
  fix, not a feature.
- **EXP-01** (external anchoring) is the highest-value expansion because it closes the one
  gap the threat model itself flags as its sharpest (`§5`, hostile keyholder).

## Dependency notes

- **The format-migration cluster: `FIX-01` + `FIX-05` + `FIX-10`.** All three change
  `bundle.json` bytes/ids and force one `packet_version` bump and one golden-corpus update
  (`tests/golden/packet-v1`, `verify.SUPPORTED_PACKET_VERSION`). Do them together to
  amortize a single migration and a single external-review round.
- **`FIX-08` pairs with `FIX-01`.** Hardening scrypt is moot while the plaintext
  `node_id` remains a cheaper passphrase oracle; land `FIX-01` first, then `FIX-08`.
- **`FIX-06` pairs with a Wi-Fi-only option (roadmap R-19).** Adding redundant offline
  timestamps must not silently cost a metered-data tenant.
- **`FIX-02` interacts with `FIX-04`.** Delta sync and relay hardening both touch the
  message/transport path; sequence delta sync first, then harden the relay around the new
  message shape.
- **`EXP-05` depends on `FIX-05` and the decision table.** A zero-install verifier is only
  as trustworthy as the authenticity model it checks; ship `FIX-05` and pin the in-browser
  verifier to `docs/verifier-decision-table.md` + the golden corpus.
- **`EXP-11` depends on `FIX-08`** (KDF/key lifecycle) and the external crypto review.
- **`EXP-15` depends on `FIX-14`** shipping the honest-docs correction first.
- **`EXP-07` completes `FIX-11`** (the honest-refusal short-term fix precedes the full
  pipeline).
- **`FIX-07`, `EXP-08` share the CRDT/property-test guardrail** (`tests/test_model.py`,
  `tests/test_sync.py`) — neither may break merge commutativity/idempotency.

## Suggested Now / Next / Later (beyond the roadmap)

### Now — security and honesty debt that a pilot or audit will otherwise expose

1. **`FIX-14` (doc reconciliation, S).** Correct every "duress-safe state" claim to
   "planned, not implemented" today — the cheapest, most urgent honesty fix.
2. **`FIX-01` (L) as a security fix.** Sever the passphrase→`node_id`→plaintext/packet
   leak; treat as the top engineering priority. Batch its format migration with `FIX-05`
   and `FIX-10`.
3. **`FIX-03` (M).** Authenticate the app server and stop `docs/mobile.md` recommending an
   unauthenticated `0.0.0.0` bind.
4. **`FIX-09` (S–M) and `FIX-06` (S–M).** Two small, high-trust wins: no silently-degraded
   packets, and redundancy for the most at-risk (offline) captures.

### Next — structural robustness and the biggest evidentiary lever

5. **`FIX-05` (L)** — packet authenticity bound to the custody chain (with the `FIX-01`
   migration).
6. **`EXP-01` (L)** — external anchoring; closes the threat model's sharpest §5 gap.
7. **`FIX-02` (L)** then **`FIX-04` (M)** — delta sync, then eviction-proof/durable relay
   rooms.
8. **`FIX-12` (M)** — real pluralization/locale formatting, before onboarding more
   languages (roadmap B / R-47).
9. **`EXP-05` (L)** — the zero-install recipient verifier (the research pass's #1 expansion
   gap, E-15), now with a trustworthy authenticity model.

### Later — capability breadth and transformative bets

10. **`FIX-07` (L)** — CRDT per-field provenance; **`EXP-08` (L)** — the on-device campaign
    engine.
11. **`EXP-03`/`EXP-04`/`EXP-09` (M)** — evidence-strength feedback, threading, and
    instrument corroboration; **`EXP-06` (L)** — jurisdiction-native exports.
12. **The XL bets — `EXP-11`, `EXP-12`, `EXP-13`, `EXP-14`** — threshold custody,
    metadata-resistant transport, the extractable evidence kernel, and the opt-in
    aggregate commons — each gated on external review and a real second stakeholder.

## Items requiring a human / legal / SME / real-data gate

Per the portfolio ethos — **defer and report honestly, never fake** — these cannot be
completed by an engineer alone and must be marked as blocked on a real person, real money,
or a real-world event. This complements the `execution-log.md` "not executable by an agent
(👤)" list and the v1.0 gate.

| Item | Gate | Why it cannot be self-served |
| --- | --- | --- |
| `FIX-01`, `FIX-05`, `FIX-08`, `EXP-11`, `EXP-12`, `EXP-14` | **External cryptographic / security review** | These change or add crypto and privacy-critical behaviour; the project's own principle is that such changes are audited, not self-certified (roadmap A; v1.0 gate). |
| `EXP-06`, and any jurisdiction mapping | **Licensed attorney (per state)** | Code→citation mappings and form semantics must be vetted by a lawyer in that jurisdiction; CA-only scope must stay explicit (R-34). |
| `EXP-07`, `EXP-09`, `EXP-05` accessibility | **Recorded assistive-technology pass** | Video captions/transcripts, chart text-equivalents, and the in-browser verifier must be confirmed usable with AT, which automation (axe) cannot certify (roadmap B; v1.0 gate). |
| `EXP-08`, `EXP-15`, `FIX-03`, `FIX-14` | **Real tenant-union / legal-aid pilot** | Campaign workflows, coercion-resistance, LAN exposure, and safety claims must be validated against real field conditions and real risk before they are trusted (roadmap D; v1.0 gate; pilot currently deferred pending a real CA organization). |
| Any anchoring/publishing option in `EXP-01`, the commons in `EXP-14` | **Policy / community decision** | Whether and how to publish even hash-only or aggregate data is a governance choice for the unions served, not an engineering default (roadmap D governance). |
| `EXP-13` (kernel extraction), `EXP-11` at scale | **Sustainability / bus-factor decision** | Publishing a reusable library or a threshold-custody scheme is a long-term maintenance commitment; only justified with a real second adopter and a shared-governance step (R-44; roadmap D). |

Everything above the gate line in **Now** (`FIX-14` docs, `FIX-01` engineering, `FIX-03`,
`FIX-06`, `FIX-09`) is buildable and testable by a maintainer against the existing
`make verify` + a11y gates — but `FIX-01`, being crypto-adjacent, should still pass under
the eventual external review before the "alpha — do not rely on this" caveat is removed.
