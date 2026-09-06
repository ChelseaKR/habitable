<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# ADR 0010: Profile-driven evidence workflows

**Status:** Accepted
**Date:** 2026-07-23
**Deciders:** Project maintainer

## Context

The post-roadmap opportunity plan names ten housing workflows, but their shared
technical needs are much smaller: reviewed vocabulary, document-like evidence,
explicit relationships, recipient-oriented presentation, and consented local
aggregation. Implementing each workflow as a separate case schema would multiply
protocol, migration, accessibility, and verifier risk.

The existing case is a state-based CRDT with immutable grow logs for captures
and timeline entries. Packets preserve old-version verification, and the project
must not turn presentation profiles into legal rules or remote mutable content.

## Decision

1. Add a versioned, built-in `UseCaseProfile` registry. Profiles declare prompts,
   vocabulary, presentation order, disclosures, and review state only. A profile
   never constrains what the case can hold: see the clarification below.
2. Add two append-only CRDT logs:
   - `Artifact` for sealed document-like evidence;
   - `EvidenceRelationship` for explicit typed links between captures,
     artifacts, timeline entries, and issues.
3. Bind artifacts and relationships into the existing signed custody chain.
4. Carry both logs through authenticated sync and packet v4. Keep packet v1–v3
   verification unchanged.
5. Generate recipient handoff manifests from signed bundle facts. A manifest can
   reorder or summarize facts but cannot suppress disclosures or alter verdicts.
6. Extend local aggregate exports with a profile/question identifier and the
   existing household-threshold protections.
7. Profiles needing legal, medical, jurisdiction, accessibility, or partner
   review remain marked `external_review_required`. Implementation availability
   is not a claim that the workflow is reviewed or fit for a real matter.

### Clarification, 2026-09-06 — "declare", not "constrain" (issue #277, finding 1)

Decision 1 originally said profiles "define … vocabulary", and a reviewer
reasonably read that as a constraint. It is not one, and deliberately so.
`artifact_types` and `relationship_types` are a *declaration*: they say which
document and link types this workflow is about, they travel in the exported
bundle so a recipient can see what the workflow claimed to be for, and they are
enforced nowhere. `model.add_artifact` validates against the global
`ARTIFACT_TYPES`; the app offers all thirteen document types whichever profile
is selected, which
`tests/test_usecases.py::test_browser_app_offers_exactly_the_registry_vocabulary`
requires.

Making the declaration binding was considered and refused. A profile is
presentation and prompting policy, chosen for a workflow the tenant is *starting*
— and the landlord decides what arrives afterwards. A tenant who picked "Repair
notice and delivery ledger" and is then handed a clinician's letter must be able
to record it. Refusing the record, or making them abandon the profile to file it,
would let a presentation choice decide what evidence exists, which is exactly the
line decision 1's "only" was written to hold. The failure would also land at the
worst moment: on the person, mid-case, holding the document.

So the declaration constrains nothing, and the word here is "declare". What a
profile may still do with its vocabulary is *prompt* — order it, suggest it, name
it in a handoff manifest — because none of that removes a record from a tenant's
reach.

## Options considered

### Separate schema per workflow

| Dimension | Assessment |
| --- | --- |
| Complexity | Very high |
| Compatibility risk | Very high |
| Workflow flexibility | High |
| Maintenance | Poor for a small project |

Pros: every workflow can be deeply specialized.
Cons: ten migrations, ten verifier surfaces, duplicated rendering, and likely
semantic drift.

### Free-form tags on existing captures

| Dimension | Assessment |
| --- | --- |
| Complexity | Low |
| Compatibility risk | Low |
| Verifiability | Weak |
| Recipient clarity | Weak |

Pros: minimal code.
Cons: document provenance and relationships remain implicit; typos and inference
replace reviewed semantics.

### Shared immutable primitives plus profiles

| Dimension | Assessment |
| --- | --- |
| Complexity | Medium |
| Compatibility risk | Bounded by packet v4 and case schema v3 |
| Verifiability | Strong |
| Maintenance | One shared implementation |

Pros: one evidence model, one verifier path, reusable accessibility and tests,
and honest experimental gating.
Cons: profiles cannot encode every jurisdiction-specific workflow and require
careful generic language.

## Consequences

- Case schema v3 and packet v4 are required.
- Sync v2 can carry the new case state additively, but source-byte transfer and
  receipt summaries must explicitly include artifact ids and hashes.
- Old readers reject newer case state rather than silently discarding logs.
- Old packet goldens remain verifier fixtures.
- Profiles are shipped code and therefore reviewed like any other claim surface;
  their `review_state` is signed into packets.
- Selective disclosure is still blocked. Handoff manifests are presentation over
  the packet's declared complete scope, not scoped custody views.

## Action items

- [x] Define the built-in profile registry and review states.
- [x] Add artifact and relationship CRDT logs.
- [x] Add custody, sync, packet-v4, verifier, CLI, and app support.
- [x] Add handoff manifests and local pattern-summary support.
- [x] Add compatibility, hostile-input, accessibility, and migration tests.
