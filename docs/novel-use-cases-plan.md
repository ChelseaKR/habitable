<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Novel use cases — implementation plan

**Planning date:** 2026-07-22
**Planning horizon:** Now / Next / Later; sequencing is intentional, dates are not
promises.
**Product boundary:** tenant-owned habitability evidence, not a generic evidence
cloud and not legal advice.

**Implementation status (2026-07-23, reconciled 2026-08-22, extended
2026-08-26):** the shared N0–N4 primitives and all eleven profile surfaces —
the original ten, plus `move_out_deposit` (candidate #11, ADR 0014) — are
implemented in case schema v3 / packet v4, including CLI, localhost app, encrypted sync, verifier, accessible
HTML, fixed-question local aggregation, and partner capsules. “External review
required” profiles remain synthetic-evaluation surfaces only; the named
human/partner gates below are still open and cannot be completed by code. The
`Now / Next / Later` section below was left describing this as unbuilt work
after it shipped; it is corrected in place. Profile review-expiry enforcement
(ADR 0012) shipped 2026-08-22 and the move-out/deposit-dispute record
(candidate #11, ADR 0014) shipped 2026-08-26;
[Beyond the current portfolio](#beyond-the-current-portfolio--year-2-and-year-3-candidates)
names the rest of the scored candidate set.

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
  presenting stale guidance. **Shipped 2026-08-22:** selection refuses an
  already-expired profile, export falls back to none and records why if one
  expires after selection, and the CLI/app flag expiry before it forces that
  fallback (`docs/adr/0012-profile-review-expiry-enforcement.md`). None of the
  ten profiles below sets an expiry yet; this is enforced infrastructure for
  the jurisdiction/community profiles in
  [Beyond the current portfolio](#beyond-the-current-portfolio--year-2-and-year-3-candidates).

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
allowed type pairs, scope membership, and semantic commitment. The Repair Trail
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
coarsened time/place buckets, and a recorded consent step. Keep distinct-
household thresholds, suppression, contribution receipts, and no network
transmission.

**What "consent step" means here, as built.** This plan originally said *a
per-export consent step*. That is not what exists and, for a batch export an
organizer runs over several unlocked vaults, it is not something the tool can
honestly capture: nobody is prompted at export time. What `habitable pattern`
enforces instead is a **standing, per-case, per-question consent record**, held
in that household's own vault:

- `habitable consent record --vault <v>` writes a signed, hybrid-logical-clock
  timestamped register into the case document, carrying the same authorship
  provenance `habitable provenance` prints for any other mutable field. It
  merges to paired devices like any other case fact.
- `habitable consent record --vault <v> --withdraw` records a withdrawal. A
  withdrawal is a write, not a delete: "never recorded" and "recorded, then
  withdrawn" stay distinguishable.
- `habitable pattern` reads the record out of each vault and **refuses the whole
  export** if any offered case has no record or a recorded withdrawal. A case is
  never silently dropped, because a silently smaller cohort still publishes.
- The distinct-household token used for thresholding is derived from the consent
  record's own provenance, so it cannot be produced for a case without one. It
  is never emitted.
- The emitted `consent` block states `explicit_per_export: false`, names the
  mechanism, and reports how many cases had a record. Earlier versions of this
  format asserted `explicit_per_export: true` from a hash of the export
  command's own arguments; that field is kept, with the opposite value, so a
  reader who saw the old file sees the correction rather than a silent removal.

Making per-export consent real would need a prompt on each household's own
device at export time, which the current batch-over-unlocked-vaults shape does
not have. That is a design change, not a bug fix, and it is not scheduled.

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

## Beyond the current portfolio — Year 2 and Year 3 candidates

**Added 2026-08-22**, as part of reconciling this plan with `ROADMAP.md` and
`docs/productionization.md` into one multiyear picture (`ROADMAP.md`,
workstream E). The ten use cases above are implemented; this section is the
*next* portfolio, scored the same way and passed through the same
[fit filter](#fit-filter). None of this is committed work — it is a ranked set
of candidates for the roadmap's v0.3–v2.x horizons, sized so a solo/volunteer
effort can actually plan against it.

| Rank | Use case | Primary user job | Value | Fit | Confidence | Effort | Decision |
| ---: | --- | --- | ---: | ---: | ---: | --- | --- |
| 11 | Move-out condition & deposit-dispute record | Pair documented move-in/move-out condition with an itemized deduction to dispute a withheld security deposit | 5 | 5 | 4 | M | **Shipped 2026-08-26** as the `move_out_deposit` profile (ADR 0014) |
| 12 | Jurisdiction template growth | Add a second/third `letter.py` jurisdiction framing beyond `generic`/`us_habitability`, dated and expiry-tracked | 4 | 5 | 4 | S–M | **Now: solo-buildable — ADR 0012 makes this safely growable for the first time. Filed as issue #207 and labelled *good first issue*: left for a newcomer on purpose, since a sustained outside contributor is an open workstream-D exit criterion** |
| 13 | Joint multi-tenant case bundle | Let an organizer present several already-signed individual packets as one navigable building-wide submission, without merging custody chains | 4 | 5 | 3 | M | **Shipped 2026-08-27** as `habitable joint` (ADR 0015), to this plan's own sizing: a digest-bound table of contents, no merged custody chain, `packet_version` unchanged |
| 14 | Protected-activity and landlord-action timeline | Juxtapose a tenant's protected activity (complaint filed, union joined) and a landlord's later action on one neutral chronology | 5 | 3 | 2 | M | **Later: framing decision (ADR) before any code — see caution below** |

Sequencing notes:

**Status (2026-08-26):** #12's stated precondition — "dated and expiry-tracked",
resting on ADR 0012 — did not actually hold for `letter.py`, whose
`LetterProfile` carried no review metadata of any kind. That mechanism now
exists (ADR 0013): built-in framings are dated, an expired framing falls back,
and union-supplied `[letter]` local-law wording carries review dates whose lapse
withholds the wording from the letter. The remaining half of #12 — an actual
second/third jurisdiction framing — is blocked on a named legal reviewer by
design, per this plan's own fit filter and the "Later" line below.

- **#11 and #12** need no new primitive: #11 reuses `before_of`/`after_of` plus
  a new `expense_receipt`-adjacent artifact type for the itemized deduction
  (already in `ARTIFACT_TYPES`'s neighborhood — a `deduction_itemization` type
  and a `deduction_for` relationship are the only additions); #12 reuses
  `letter.py`'s existing `LetterProfile` registry pattern. Both are natural
  first picks for the *Now* row above precisely because they cost no new
  protocol surface. **#11 shipped 2026-08-26 exactly to that sizing** — the two
  named additions and nothing else, `packet_version` unchanged at 4 (ADR 0014).
  Building it surfaced one thing this plan had not: `verify.py` restates the
  artifact/relationship vocabulary rather than importing it, to keep the
  Apache-2.0 subset standalone, and nothing held the two copies equal. Any
  future vocabulary addition — #13's included — must update both sides, and a
  drift guard now fails the gate if one is forgotten.
- **#13 shipped 2026-08-27 (ADR 0015) as exactly that safe version.** It is
  presentation over facts that already exist and verify independently, and it
  creates no merged-custody artifact, which would have reopened the
  scoped/rehashed-custody-view gate workstream A is still closing. Each row
  binds its member by that packet's own `bundle.json` SHA-256, and
  `habitable joint check` re-derives every recorded claim from the packets, so
  the index is never a trust root. Building it surfaced the half this plan's
  phrase "a signed table of contents" had left unexamined: the members are
  signed, the table of contents is not, and *whose* signature it should carry is
  a decision rather than an implementation. ADR 0015 deferred it explicitly and
  named the two candidate mechanisms; **ADR 0016 (2026-08-27) settled it** by
  applying ADR 0011's authority seal to the index, which needs no organizer
  identity and therefore names nobody. The index still carries no signature of
  its own; what it carries is a token proving *this list, at this time*, which
  is what a dropped member defeats and a digest cannot catch.
- **#14 is flagged, not queued, on purpose.** "Retaliation" is a legal
  conclusion, and the fit filter explicitly excludes "automated judgments
  about truth" and "landlord risk scores." A neutral two-column chronology
  (what the tenant did, what the landlord did, both already-recorded facts)
  stays inside the filter; anything that scores, flags, or labels the
  juxtaposition as retaliation does not. This needs a maintainer decision
  recorded as an ADR — not a feature branch — before implementation starts,
  specifically choosing the non-inference framing and rejecting the
  scoring/labeling version outright rather than leaving it ambiguous.

## Multiyear sequencing (2026 to 2029)

**Added 2026-08-27.** The table above scores *what* is worth building. This one
orders it, and separates the two kinds of item that the scores cannot tell
apart: work an engineer can finish alone, and work that is finished by a person
who has not been found yet. Mixing them produces a plan that looks stalled when
it is actually waiting, or one that quietly drops the waiting items because they
never move. The horizons are `ROADMAP.md`'s and will slip; the ordering and the
gate column are the parts that matter.

| Phase | Horizon | What | Gate |
| ---: | --- | --- | --- |
| 1 | 2026 H2 | **Joint multi-tenant submission index** (#13): a digest-bound table of contents over N already-signed packets, merging no custody chain | None. Shipped 2026-08-27, ADR 0015 |
| 2 | 2026 H2 | **Authenticate the joint index** | None. Shipped 2026-08-27, ADR 0016: an RFC 3161 seal over the finished index, chosen over an organizer signing key because it needs no identity, which ADR 0011 had already declined to invent |
| 3 | 2026 H2 | **Extend the ADR 0011 authority seal to the multi-packet surfaces it named as unfinished** | None. Shipped 2026-08-27: `campaign export` seals each unit packet with that unit's own configured authority under that unit's own metered-link policy. ADR 0011 had already made the decision; this applied it, so it needed no ADR of its own |
| 4 | when a newcomer takes it | **Jurisdiction letter framing growth** (#12) | Doubly gated, and deliberately so: it is reserved as good first issue #207 because a sustained outside contributor is an open workstream-D exit criterion, and any framing it adds is blocked on a **named legal reviewer**. ADR 0013 built the dating and expiry mechanism; writing a `reviewer`/`reviewed_at` pair for a review nobody performed would be a false claim, which is the whole reason the field exists |
| 5 | after its framing ADR | **Protected-activity and landlord-action chronology** (#14) | A **maintainer decision**, recorded as an ADR, that must precede any code: choose the neutral two-column chronology and reject the scoring or labelling version outright. It is not an implementation question. "Retaliation" is a legal conclusion, and this plan's fit filter excludes automated judgments about truth and landlord risk scores |
| 6 | as partners arrive | **Promote each `external_review_required` profile to `maintainer_reviewed`** | A **named reviewer or partner per profile**, recorded with a date. Six profiles, six separate people. `docs/recruitment/` holds the briefs; the gate is a partnership problem, not an engineering one |
| 7 | 2027 to 2028 | **Versioned scoped and rehashed custody views**, restoring issue-scoped and date-scoped exports and issue-subset shares | An **independent cryptographic review** before the CLI and app selectors can be re-enabled, per workstream A. The protocol design is engineering; shipping it behind a self-review is not an option this project takes |
| 8 | ~2028 | **The v1.0 trust gate**, when the alpha caveat comes off | Four external outcomes, none of them a commit: an independent security and cryptographic review, a recorded human NVDA and VoiceOver pass, at least one completed tenant-union or legal-aid pilot with written outcomes, and a lawyer's read of the "not legal advice" framing |

Phases 1 to 3 are the whole of what a solo effort can finish on its own from
this portfolio, and as of 2026-08-27 all three are done. Everything after them
is waiting on a named person, and saying so plainly is the point of the table:
an item in phases 4 to 8 that appears to be making progress without its gate
having been met is a warning, not an achievement.

## Now / Next / Later

**Reconciled 2026-08-22** — the sections below described this as unbuilt work;
it is not. The N0–N4 foundation and all eleven profiles have been implemented
end to end (CLI, app, sync, packet v4, verifier, accessible HTML, i18n) — ten
since 2026-07-23 and `move_out_deposit` since 2026-08-26 — confirmed against
current code (`src/habitable/usecases.py`,
`artifact.py`, `handoff.py`, `patterns.py`, `capsule.py`), not merely asserted.
Four profiles (`repair_delivery`, `repair_comparison`, `utility_outage`,
`displacement_expense`) are `maintainer_reviewed` and require no further
engineering to use as shipped. Six (`inspector_handoff`,
`accommodation_request`, `public_housing_remediation`,
`health_corroboration`, `building_pattern`, `partner_capsule`) remain
`external_review_required` — implemented and synthetic-evaluation-tested, but
gated on a named human reviewer/partner per use case, exactly as designed; that
gate is a *decision*, not a to-do list an engineer can clear alone. What
follows is honest present-tense status, not a build plan.

### Now

- Recruit the named reviewer/partner for each of the six
  `external_review_required` profiles (see `docs/recruitment/`); this is the
  actual remaining work for the current ten, and it is a partnership problem,
  not an implementation one.
- Complete external roadmap gates already prepared by the review hub (security/
  crypto audit, recorded AT pass, tenant-union pilot — see `ROADMAP.md`'s v1.0
  gate); these block the alpha caveat regardless of use-case count.
- Ship the genuinely new, solo-buildable expansion items from
  [Beyond the current portfolio](#beyond-the-current-portfolio--year-2-and-year-3-candidates).
  Three are done: profile review-expiry enforcement (ADR 0012, 2026-08-22), the
  move-out/deposit-dispute record (#11, ADR 0014, 2026-08-26), and the joint
  multi-tenant submission index (#13, ADR 0015 and ADR 0016, 2026-08-27). Of the
  remainder,
  #12 is deliberately reserved for a first-time contributor (issue #207), and
  #14 is blocked on its own framing ADR. That leaves no solo-buildable
  use-case candidate open: what is left in this portfolio is people-gated, and
  the multiyear sequencing table above says so by name.
- Keep 20% capacity for scoped-view protocol/security work and 10% for
  unplanned safety fixes, unchanged from the original plan.

### Next

- Nothing in this portfolio is left that a solo effort can finish alone. Phases
  1 to 3 of the sequencing table are done; phases 4 to 8 are each waiting on a
  named person, and the honest next step is recruitment, not code. Jurisdiction
  template growth (#12) in particular stays available to a newcomer rather than
  being absorbed by the maintainer, and would still need a named legal reviewer
  after they finished.
- As each `external_review_required` profile clears its named gate, promote it
  to `maintainer_reviewed` in an ADR-recorded decision and update
  `docs/capabilities.md`.
- Decide the supported desktop/mobile target from observed pilot constraints
  (unchanged — no pilot has run yet).

### Later

- Only take on a *new* partner-gated use case (health, public-housing,
  accommodation-adjacent ideas beyond the current six) with a named
  maintainer/partner attached before implementation starts, per the fit
  filter above.
- Expand jurisdictions and languages only with dated owners and expiry policy
  — now enforceable rather than aspirational (ADR 0012).

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
