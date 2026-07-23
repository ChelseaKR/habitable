<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Novel use cases — implementation plan

**Planning date:** 2026-07-22
**Planning horizon:** Now / Next / Later; sequencing is intentional, dates are not
promises.
**Product boundary:** tenant-owned habitability evidence, not a generic evidence
cloud and not legal advice.

**Implementation status (2026-07-23):** the shared N0–N4 primitives and all ten
profile surfaces are implemented in case schema v3 / packet v4, including CLI,
localhost app, encrypted sync, verifier, accessible HTML, fixed-question local
aggregation, and partner capsules. “External review required” profiles remain
synthetic-evaluation surfaces only; the named human/partner gates below are still
open and cannot be completed by code.

This plan identifies new user jobs that reuse Habitable's strongest primitives:
offline capture, an encrypted local vault, an attributable timeline, independent
timestamps, complete-custody verification, direct peer sync, deliberate
disclosure, and recipient-readable packets. It does not assume demand; each
medium/large build has a partner or usability gate before implementation.

## Fit filter

A use case belongs in the application only when all answers are yes:

1. Does it help a tenant or tenant organization document, communicate, inspect,
   or remediate unsafe housing?
2. Can the useful record stay on devices controlled by the people affected?
3. Can a recipient independently verify integrity without trusting Habitable?
4. Can the feature avoid accounts, telemetry, central plaintext, legal outcome
   promises, and automated judgments about truth?
5. Can it be expressed as evidence, chronology, relationships, presentation, or
   consented aggregation without weakening old packet verification?

Ideas that fail this filter—public intake databases, cloud backup operated by the
project, landlord risk scores, automated legal advice, covert surveillance, fake
photo detection, or guaranteed admissibility—remain out of scope.

## Prioritized portfolio

Scores are relative: value and fit are 1–5 (higher is better); effort is
engineering plus review, from S to XL. Confidence is deliberately lower where
the need has not been tested with a real partner.

| Rank | Use case | Primary user job | Value | Fit | Confidence | Effort | Decision |
| ---: | --- | --- | ---: | ---: | ---: | --- | --- |
| 1 | Repair notice + delivery ledger | Show what was reported, how it was delivered, and what happened next | 5 | 5 | 4 | M | **Now: validate and build a narrow artifact path** |
| 2 | Before/after repair comparison | Show progression or whether a claimed repair changed the documented condition | 5 | 5 | 4 | M | **Now: prototype on existing captures** |
| 3 | Inspector handoff profile | Give an inspector a short condition-first view without changing proof semantics | 5 | 5 | 3 | M | **Next: partner-gated** |
| 4 | Heat, water, smoke, and outage diary | Join observations, sensor readings, notices, and service restoration on one timeline | 4 | 5 | 4 | M | **Next: profile over existing evidence types** |
| 5 | Reasonable-accommodation request record | Preserve request, supporting artifacts, delivery, response, and follow-up | 4 | 4 | 2 | M | **Next: legal/accessibility review first** |
| 6 | Public-housing inspection remediation trail | Track finding → repair deadline → tenant observation → reinspection | 4 | 5 | 2 | L | **Next: housing-authority partner first** |
| 7 | Health corroboration handoff | Let a tenant attach a clinician letter or symptom diary without turning Habitable into a medical record system | 4 | 4 | 2 | L | **Later: privacy and partner review** |
| 8 | Temporary displacement and expense log | Preserve relocation, hotel, transport, food, property-loss, and return events after an unsafe-unit event | 4 | 4 | 3 | M | **Later: evidence profile, no reimbursement promise** |
| 9 | Building pattern map | Show repeated condition categories and recurrence across consenting units without exposing household records | 5 | 5 | 3 | L | **Later: extend the local commons carefully** |
| 10 | Partner evidence capsule | Embed a small signed Habitable proof inside an existing legal-aid, organizing, or safety tool | 4 | 5 | 3 | L | **Later: adopter-gated kernel work** |

## Foundation sequence

Build shared primitives once, in this order, instead of adding ten bespoke
workflows.

### N0 — Versioned use-case profiles

Add a `UseCaseProfile` presentation/configuration layer with:

- stable profile id and schema version;
- reviewed issue categories and timeline event choices;
- required/optional evidence prompts;
- recipient-oriented section order and labels;
- disclosure additions;
- locale catalogs, reviewer, jurisdiction, reviewed date, and expiry date;
- no cryptographic or verifier behavior changes.

Profiles must never contain legal deadline calculators, remedy promises, or
mutable remote content. Unknown profiles render neutrally. Packets sign the
profile id/version used for presentation while the underlying facts remain in
the stable bundle schema.

Acceptance:

- generic packets remain byte/meaning compatible;
- one profile cannot hide signed facts;
- EN/ES parity and 320 px expansion checks pass;
- an expired jurisdiction profile warns and falls back instead of silently
  presenting stale guidance.

### N1 — Corroborating artifact records

Introduce a first-class `Artifact` record for documents such as repair letters,
delivery receipts, inspection reports, clinician letters, hotel receipts, and
utility notices.

Minimum fields:

- opaque id, issue id, artifact type, neutral title;
- reported creation/receipt date and recorded-at time;
- source assertion and optional issuer label;
- sealed content hash, media type, and optional accessible description;
- links to timeline entries and predecessor/successor artifacts;
- custody binding and timestamp state.

The artifact follows the existing capture pipeline. “Issuer” is an assertion
unless separately signed by that issuer. OCR, if later added, must be local,
optional, and clearly labelled as a convenience transcription.

Acceptance:

- PDFs/images/text documents seal, timestamp/defer, sync, export, and verify;
- malformed/oversized documents fail within bounded resources;
- packet disclosure distinguishes producer integrity from issuer authenticity;
- an artifact can be omitted only through the future reviewed scoped-view
  protocol, not by truncating custody.

### N2 — Explicit evidence relationships

Add signed relationship records rather than inferring meaning from dates:

- `documents_condition`;
- `sent_via`;
- `delivery_receipt_for`;
- `response_to`;
- `before_of` / `after_of`;
- `inspection_finding_for`;
- `repair_claim_for`;
- `expense_caused_by`.

Relationships carry no legal conclusion. The verifier checks endpoint existence,
allowed type pairs, scope membership, and semantic commitment. The Evidence Atlas
renders them with an accessible table equivalent.

Acceptance:

- dangling, cyclic where forbidden, cross-issue, or type-invalid links fail
  closed;
- old packets remain valid;
- relationships survive merge in any order;
- screen-reader and keyboard paths expose the same relationship meaning as the
  visual atlas.

### N3 — Handoff profiles

Create recipient views as signed presentation manifests over the same complete
packet:

- tenant/organizer review;
- inspector condition roll-up;
- legal-aid chronology and exhibit index;
- clinician corroboration request;
- disaster-assistance expense appendix.

This is presentation, not certification. Each manifest states what it includes,
what it omits from the presentation, and that the signed bundle is the source of
truth. It does not restore selective disclosure; a complete packet may present a
short view while still carrying the complete declared scope.

Acceptance:

- every displayed fact traces to a signed bundle path;
- the profile cannot alter a verdict or suppress a disclosure;
- HTML is the accessible reference rendering;
- PDF remains a print convenience unless the PDF/UA gate is met.

### N4 — Consented local aggregation

Extend the existing commons only after a pilot defines a concrete organizing
question. Contributions must be generated on-device from explicit categories,
coarsened time/place buckets, and a per-export consent step. Keep distinct-
household thresholds, suppression, contribution receipts, and no network
transmission.

Never aggregate narrative text, media, exact addresses, device ids, exact times,
rare free-text categories, or small-cell intersections.

Acceptance:

- property tests prove every published cell meets the household threshold;
- differencing tests cover repeated exports and overlapping cohorts;
- a withdrawal/refresh model is documented honestly—published aggregates cannot
  be remotely revoked;
- a real organizer can answer the validated question without opening household
  vaults.

## Use-case delivery plans

### 1. Repair notice + delivery ledger

**Outcome:** a tenant can connect a documented condition to a repair request,
delivery evidence, landlord response or silence, and later repair/recurrence.

Implementation:

1. Validate the exact event/artifact vocabulary with one legal-aid reviewer;
   preserve neutral terms.
2. Land N1 for letters, email exports, portal receipts, and postal receipts.
3. Land the N2 notice/delivery/response relationships.
4. Add a guided app path: choose issue → add/send-copy record → add delivery
   proof → add response → review gaps.
5. Render an exhibit index and relationship chain in HTML/PDF.
6. Add importer examples, not live provider integrations, until an adopter owns
   the data-processing boundary.

Tests/gates: offline capture, duplicate receipt, wrong-issue link, modified
document, deferred timestamp, sync convergence, EN/ES copy, keyboard/axe, packet
golden and recipient cold-read.

### 2. Before/after repair comparison

**Outcome:** pair two or more observations without claiming that the later image
proves repair quality.

Implementation:

1. Add `before_of`/`after_of` relationships with order and same-issue checks.
2. Add an app pairing flow and side-by-side/stacked accessible rendering.
3. Show reported dates, recorded dates, timestamp state, hashes, and source
   assertions separately.
4. Add optional local image alignment only as a visual aid; never synthesize or
   modify evidentiary originals.
5. Export a comparison sheet whose disclosure says “documents change between
   these records; does not establish cause, completeness, or code compliance.”

Tests/gates: swapped pair, missing endpoint, same file twice, cross-issue pair,
metadata policy, visual reflow, alt text, and independent packet verification.

### 3. Inspector handoff profile

**Outcome:** an inspector can move room → condition → chronology → supporting
artifact quickly.

Implementation:

1. Observe one inspector or code-enforcement reviewer using a synthetic packet.
2. Define N0/N3 labels from that workflow; do not import local code citations
   until a qualified owner accepts maintenance.
3. Add room/condition filtering, an inspection-contact sheet, and stable exhibit
   anchors.
4. Permit inspector findings/reports as N1 artifacts with asserted issuer
   metadata.
5. Record profile review date and jurisdiction; expire stale profiles visibly.

Success: the reviewer finds every supplied condition and its latest support in
under two minutes and correctly states what the packet does not prove.

### 4. Utility and environmental outage diary

**Outcome:** document heat, water, electricity, smoke, moisture, or temperature
events over time using observations plus optional instrument files.

Implementation:

1. Ship a generic, non-code-compliance N0 profile.
2. Reuse sensor CSV, media, recurrence, impact, and notice events.
3. Add bounded local summaries (min/max/interval coverage) with raw readings
   preserved and summary derivation committed.
4. Flag clock gaps, device/source assertions, and calibration unknowns.
5. Never transform a threshold crossing into a legal violation claim.

Tests/gates: timezone/clock ambiguity, gaps, duplicate readings, extreme values,
CSV formula safety, large-file bounds, summary reproducibility and packet
verification.

### 5. Accommodation request record

**Outcome:** preserve a tenant-controlled chronology of a request and response
without diagnosing disability or recommending legal strategy.

Before build: accessibility researcher, disability-rights legal reviewer, and
privacy threat review must approve the minimum data model.

Implementation constraints:

- no diagnosis field, eligibility score, or required medical upload;
- user-controlled neutral labels and high-sensitivity warning;
- clinician/supporting letters are optional N1 artifacts;
- a dedicated disclosure explains that technical integrity does not establish
  disability, entitlement, receipt, or compliance;
- whole-case export remains the only disclosure scope until scoped views pass
  review.

### 6. Public-housing remediation trail

**Outcome:** connect an official inspection finding to repairs, tenant
observations, reinspection, and unresolved recurrence.

Partner gate: one housing-authority/advocacy reviewer must supply the real
synthetic workflow and own source freshness. Implementation uses N0–N3; agency
status is always “reported/imported,” never live-scraped or silently refreshed.

### 7. Health corroboration handoff

**Outcome:** give a clinician or advocate a narrow request/checklist and preserve
what the tenant chooses to bring back.

Boundary: Habitable does not become a health record, collect from providers, or
infer causation. The plan needs a HIPAA/privacy analysis even if Habitable itself
is not acting as a covered entity. Build only with a clinic/legal partner and the
future reviewed scoped-view protocol.

### 8. Temporary displacement and expense log

**Outcome:** organize receipts and events following an unsafe-unit evacuation or
temporary relocation.

Use N1 artifacts and N2 causation-as-assertion links. Add totals as reproducible
local arithmetic with currency/locale rules, not reimbursement eligibility.
Packet language must distinguish arithmetic from entitlement.

### 9. Building pattern map

**Outcome:** let a union answer a validated question such as “how many consenting
households reported no heat this week?” without creating a case database.

Build on N4. Start with a single fixed question, high threshold, coarse week and
building-level buckets, and no public upload. Defer maps, cross-building joins,
and repeated longitudinal releases until differencing risk is reviewed.

### 10. Partner evidence capsule

**Outcome:** another civic tool can create or verify a small Habitable-compatible
evidence object without adopting the entire app.

Implementation:

1. Secure a named adopter and write the minimum API contract together.
2. Keep kernel versioning independent from packet/app versions.
3. Add golden vectors for artifact and relationship records.
4. Provide one import/export adapter and a conformance CLI.
5. Do not promise protocol stability beyond the documented surface or ship a
   hosted verification service.

## Now / Next / Later

### Now

- Run synthetic partner tests for repair notice/delivery and before/after views.
- Specify N0, N1, and N2 in ADRs; prototype without changing emitted packet
  versions.
- Complete external roadmap gates already prepared by the review hub.
- Keep 20% capacity for scoped-view protocol/security work and 10% for
  unplanned safety fixes.

### Next

- Implement N0–N2 behind versioned schemas and feature flags.
- Ship the repair/delivery and comparison vertical slices through app, CLI,
  sync, packet, verifier, HTML, tests, and docs.
- Pilot the inspector and utility/outage profiles using synthetic data.
- Decide the supported desktop/mobile target from observed pilot constraints.

### Later

- Add N3 handoff profiles and N4 aggregation after review evidence exists.
- Consider accommodation, public-housing, health, displacement, and partner
  capsule work only with named maintainers/partners.
- Expand jurisdictions and languages only with dated owners and expiry policy.

## Cross-cutting Definition of Done

Every use case must:

- work offline for capture and fail clearly when a network-only step waits;
- preserve encrypted-at-rest and authenticated peer-sync boundaries;
- emit no telemetry and require no Habitable account;
- version every changed schema/protocol and keep old goldens verifying;
- bind new semantic records into custody and validate them independently;
- disclose what is asserted, observed, timestamped, issuer-authenticated, and
  unknown as separate facts;
- pass ruff, strict mypy, coverage floors, hostile-input tests, i18n parity,
  keyboard/reflow/axe gates, link/claim checks, and reproducible builds;
- include a threat-model delta, migration/backout plan, and public claim update;
- complete the named human/legal/accessibility review when the feature depends
  on it.

## Measurement without surveillance

Success evidence comes from artifacts and opt-in studies, never product
analytics:

- task completion and comprehension in bounded synthetic sessions;
- reviewer findings closed;
- packets independently verified;
- old-version compatibility and hostile-input gates green;
- partner adoption commitments and written pilot outcomes;
- languages/jurisdictions with named maintainers and current review dates;
- recovery, install, and update drills completed on named hardware.

The first decision checkpoint is not “how many features shipped.” It is whether a
real reviewer can use the repair/delivery or comparison slice, understand its
limits, and prefer it to an ordinary folder of files.
