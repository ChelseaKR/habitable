<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# ADR 0014: Move-out condition and deposit-dispute record

- Status: Accepted
- Date: 2026-08-26

## Context

`docs/novel-use-cases-plan.md`'s *Beyond the current portfolio* table ranks a
**move-out condition and deposit-dispute record** (#11) as value 5, fit 5,
confidence 4, effort M, decided **"Now: solo-buildable, no partner gate — same
class as #1/#2."** `ROADMAP.md`'s v0.5 row names it as one of the two
solo-buildable product-expansion items, and the plan's own *Next* section says
the next 1–2 solo-buildable ideas should go through the full definition of done:
ADR, tests, i18n parity, a11y, threat-model delta, CHANGELOG.

The plan also sizes it precisely, and that sizing is the reason it is next:

> #11 reuses `before_of`/`after_of` plus a new `expense_receipt`-adjacent
> artifact type for the itemized deduction (already in `ARTIFACT_TYPES`'s
> neighborhood — a `deduction_itemization` type and a `deduction_for`
> relationship are the only additions)

The tenant job is concrete. A tenant moves out, the landlord withholds some or
all of the deposit and sends an itemized statement of deductions, and the tenant
wants to put that statement next to what the unit actually looked like when they
moved in and when they left. Today they can record the photographs and they can
seal the statement as `other_document`, but nothing says *what that document is*
or *which condition it charges against*: the connection lives only in the
tenant's head, or in a free-text note a recipient has no reason to trust.

This is squarely inside the fit filter: it documents housing conditions, stays on
the tenant's device, verifies independently, needs no account or telemetry, and
is expressible as evidence plus relationships plus presentation. The thing it
must **not** become is an arbiter — the filter excludes "automated judgments
about truth," and "this deduction is unfair" or "this is normal wear and tear"
are exactly that.

## Decision

1. **One new artifact type, `deduction_itemization`.** The landlord's itemized
   deduction statement becomes a first-class document rather than an untyped
   `other_document`. It enters the unchanged capture pipeline: hashed, sealed,
   custody-bound, RFC 3161 timestamped or deferred, synced, exported, verified.
   Its `issuer` remains an assertion, exactly as for every other artifact — the
   packet distinguishes producer integrity from issuer authenticity, and sealing
   a landlord's letter proves the tenant held those bytes, never that the
   landlord sent them.
2. **One new relationship type, `deduction_for`,** with the same endpoint shape
   as `repair_claim_for`: from an `artifact` (or the `timeline` entry recording
   its arrival) to an `issue` or a `capture`. Both types record *somebody else's
   claim about a documented condition*, so both point from the claim at the
   condition. `deduction_for` therefore cannot connect two documents, and carries
   no counter-assertion of its own; a tenant's rebuttal is a separate record
   joined with the existing `supports`.
3. **One new profile, `move_out_deposit`,** `maintainer_reviewed` per the plan's
   recorded "no partner gate" classification, jurisdiction `generic`, reading
   order `move_in_condition → move_out_condition → deduction_claim →
   tenant_records → proof_limits`, and two disclosures that travel with every
   export:
   - "An itemized deduction is the landlord's assertion; recording it here
     neither accepts nor rebuts it."
   - "Condition records do not establish wear and tear, damage, cost, or what a
     deposit is owed."
4. **No expiry.** The profile carries no jurisdiction-specific guidance, so it
   has nothing to go stale; `expires_at` stays empty, like the other ten. ADR
   0012's mechanism is for the jurisdiction profiles that will carry dated
   review windows, not for this one.
5. **No new protocol surface.** `packet_version` stays 4, the profile schema
   stays 1, the artifact and relationship schemas stay 1. The two new terms are
   additional values in existing vocabularies.
6. **The verifier's duplicated vocabulary is pinned to the registry by a test.**
   `verify.py` restates `ARTIFACT_TYPES`, `RELATIONSHIP_TYPES`, and
   `RELATIONSHIP_ENDPOINT_KINDS` rather than importing `habitable.usecases`,
   because the Apache-2.0 verifier subset must stay standalone. That
   independence was unguarded: nothing held the two copies equal, so a term
   added on one side only would let a vault seal evidence its own verifier then
   rejects. `tests/test_guards.py::test_verifier_vocabulary_mirrors_the_use_case_registry`
   now fails on any drift, in either direction, including an endpoint pair
   loosened on one side. The browser app's `<option>` lists get the same
   treatment in `tests/test_usecases.py`.

## Options considered

| Option | Assessment |
| --- | --- |
| Do nothing; let tenants use `other_document` and a free-text note | Rejected: it is what exists today, and it is precisely the untyped state the N1/N2 primitives were built to replace. A recipient reading the packet cannot tell an itemized deduction from any other attachment, and the link to the charged condition is unverifiable prose. |
| Add a `deposit_deduction` **amount** field and total the deductions | Rejected: arithmetic over a landlord's asserted line items invites reading the total as an established debt, and the displacement-expense profile already learned this ("Arithmetic totals do not establish reimbursement eligibility"). The itemization is evidence of what was claimed; the tool has no business computing from it. |
| Let `deduction_for` point document-to-document, so a deduction can be linked to the receipt that rebuts it | Rejected: that pairing asserts a rebuttal *relationship the tool cannot verify*. `supports` already lets the tenant attach their own receipt to the condition, leaving the reader to draw the conclusion. |
| A `wear_and_tear` or `disputed` flag on the deduction | Rejected outright: a legal conclusion, and the fit filter's "automated judgments about truth" exclusion. The tenant's position belongs in their own recorded statement, not in a field the packet presents as a finding. |
| Import the vocabulary into `verify.py` instead of restating it and testing parity | Rejected: it would put `habitable.usecases` inside the Apache-2.0 verifier subset that legal-aid embedders vendor, which `tests/test_guards.py::test_verifier_imports_stay_within_apache_subset` exists to prevent. A test is the right place to pay for the duplication. |
| Ship jurisdiction letter-framing growth (candidate #12) first | Rejected for *this* change: #12 is filed as issue #207 and labelled **good first issue**. Contributor growth is an open roadmap exit criterion (workstream D) with the newcomer inventory deliberately stocked; consuming a reserved onboarding issue to save a maintainer an afternoon is a bad trade. #11 is higher-value on the plan's own scoring anyway. |

## Consequences

- **Old packets keep verifying, unchanged.** Nothing about the existing corpus
  moves; the golden packets are untouched and still pass.
- **The compatibility direction that does change is forward, and is stated
  rather than papered over:** a packet containing a `deduction_itemization`
  artifact or a `deduction_for` relationship will be rejected by a verifier
  built before this change, which knows neither term. That is the fail-closed
  direction (an old verifier refuses rather than mis-reports), it is the same
  behavior any earlier vocabulary addition had, and it is why the vocabulary
  lives in a versioned bundle whose schema is published in
  `docs/packet-bundle.schema.json`.
- **Threat-model delta: none.** No new external surface, no new network path, no
  new key material, no change to what is encrypted or to what a relay can see.
  The new artifact type follows the identical seal/custody/timestamp path as
  every other document, and the new relationship is validated and
  commitment-bound exactly as the other nine are.
- **Rollback/migration:** none needed in the vault (the two terms are additive
  values, and a case that never uses them is byte-identical to before). A
  revert would strand any packet already exported with the new terms, so the
  backout is "leave the vocabulary in place," not "remove it."
- **ISO 25010:** functional appropriateness (a recorded tenant job the tool
  could not previously express), and analysability (the drift guard turns an
  invisible duplication into a failing test).
- **What this does not do:** it does not tell a tenant whether a deduction is
  lawful, whether damage exceeds wear and tear, what a deposit is worth, or
  whether they will prevail. `docs/capabilities.md`'s "Independent
  legal/court/inspector fitness" row is unchanged and still reads *externally
  unvalidated*.

## Action items

- [x] `deduction_itemization` artifact type and `deduction_for` relationship
      type, in the registry and in the verifier's restatement of it.
- [x] `move_out_deposit` profile with neutral sections and two disclosures.
- [x] Browser app `<option>` entries and EN/ES labels at parity.
- [x] Published bundle JSON Schema enums updated.
- [x] Registry/verifier and registry/app vocabulary drift guards.
- [x] End-to-end test: seal, relate, export, verify, with the disclosures
      asserted in the rendered handoff.
- [x] Fail-closed tests: forbidden endpoints refused locally, and a forged
      deduction rejected by a recipient's verifier.
- [ ] A named legal-aid reviewer read of the deposit vocabulary. Not a
      precondition for this profile (the plan classifies it as no-partner-gate,
      and it asserts nothing about law), but it belongs in the same recruitment
      queue as the six `external_review_required` profiles.
