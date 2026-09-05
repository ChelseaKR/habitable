<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# ADR 0019: The building-pattern question must be one the record can answer, and retiring a question retires its consent

- Status: Accepted
- Date: 2026-09-05

## Context

`habitable pattern` exists to publish exactly one number. An organizer runs it
over vaults they can already unlock, it reduces each case on-device to
`(building, category, ISO week)`, applies the commons household threshold, and
writes a file the union decides — separately, by hand — whether to publish. It
is the most carefully fenced output this project produces: a standing
per-household consent record read out of each vault, a whole-export refusal when
one is missing, `DEFAULT_K = 5` suppression, and a `consent` block in the file
that states what the mechanism *is not* because an earlier version of the format
claimed the opposite (issue #182).

Issue #276 reports that all of that machinery has been gating a number that is
structurally always zero.

### What the code actually did

Four facts, each checked in the tree, decide this ADR.

1. **The cohort filter named a category nothing stores.**
   `patterns.build_no_heat_weekly_summary` kept only observations where
   `item.category == "no_heat"`.
2. **`no_heat` has not been storable through a supported path since #206.**
   `cli.py` declares `--category` with
   `choices=(*ISSUE_CATEGORIES, *ISSUE_CATEGORY_ALIASES)`, and
   `ISSUE_CATEGORIES` holds `heat`. #240 then made `no_heat` an accepted
   *alias*: `_cmd_issue` resolves it through `ISSUE_CATEGORY_ALIASES` and stores
   `heat`, printing `recording --category no_heat as heat`. The app is the same
   — `appserver.add_issue` folds case and runs the same alias lookup, and the
   Condition datalist in `app/index.html` offers `heat`.
3. **Every writer of the literal `no_heat` in the repository was a test**
   calling `CaseDocument.add_issue` directly, which is deliberately unvalidated
   so grandfathered vaults keep loading. `tests/test_patterns.py` was green
   because it seeded the one value the product cannot produce.
4. **Consent is keyed by question id.** `record_consent` writes
   `pattern_consent:<question_id>` into the household's own document, and
   `_cmd_pattern` refuses the entire export when that key is absent from any
   vault it was handed.

Facts 1–3 together mean the published aggregate has been empty for every export
produced since #206. Fact 4 is what makes fixing it delicate.

### Why an empty answer is worse than an error

The output is a consent-gated, suppressed, k-anonymous count an organizer takes
into a landlord meeting or a code complaint. An empty answer does not read as a
malfunction. It reads as *"no household reported this, this week"* — which is a
finding. A tenant union could act on it, or decide not to act because of it. The
command even exits `0` and prints `0 published cell(s), 3 case(s) with a
recorded consent record`, which is a sentence describing a healthy run.

### What the record can express

The vocabulary's finest grain is `heat`. #240 settled that it stays six members
plus `other`, on the ground that every packet template and letter framing must
know how to present each member, and that `other` with a label costs nothing.
`heat` therefore covers no heat at all, heat that is inadequate, and heat a
household cannot control, without distinguishing them — and there is no other
stored field that does. Severity is habitable's own operational vocabulary for
sorting a tenant's record and carries no statutory or diagnostic meaning; title
and description are free text the commons is forbidden to read.

**So the question as worded cannot be answered from what habitable stores.**
That is the finding, and everything below follows from it.

## Decision

**1. The question is reworded to the condition the record holds, and the file
says what the category does not distinguish.**

The prompt becomes *"In each building and ISO week, how many households that
recorded consent to this question reported a heat condition?"*, the cohort
filters on `heat`, and `PatternQuestion` gains a `scope_note` published beside
the prompt:

> habitable records every heat problem under one condition category. This counts
> no heat at all, inadequate heat, and heat a household cannot control as the
> same condition, because the record does not distinguish them. It is not a
> count of households with no heat.

The caveat travels *in the file* rather than in a reviewer brief. A brief
reaches whoever reads the brief; the export reaches a council staffer. This is
the same discipline that keeps `explicit_per_export: false` in the payload
instead of dropping a field that was once wrong.

**2. `no_heat` is not promoted to a seventh category.** It was rejected in #240
for a reason that has not changed: a member of `ISSUE_CATEGORIES` is a thing
every packet template, letter framing, app surface and translation must know how
to present. Adding one to make a single aggregate finer is a vocabulary decision
taken for an aggregate's convenience, and it would also split every existing
`heat` record from every new `no_heat` one — buying precision going forward by
making the past incomparable. If a review (#264) comes back saying organizers
need "no heat at all" as a distinct condition, that is a vocabulary change with
its own ADR, its own template work, and its own migration; it is not this fix.

**3. No heuristic over severity, title, or description.** Reading "no heat" out
of a title would mean the published number depends on how a stressed person
phrased a note at 11pm, and it would be a *narrowing* inference — excluding
households from a count they consented to be in, on evidence the record does not
support. Rejected without qualification.

**4. `question_id` is retired, and the stored consent does not come with it.**

This is the load-bearing decision. `consenting_households_no_heat_by_week`
becomes `consenting_households_heat_condition_by_week`, which orphans every
household's stored consent record. The obvious alternative — keep the id, change
only the prompt — was available, keeps every campaign running, and is wrong.

The cohort genuinely broadens. A household whose heat is inadequate rather than
absent was, under the old sentence, outside the count; under the new one they
are inside it. Keeping the key stable while the sentence under it widens means
the export claims a consent for a question nobody was asked. That is #182 again,
committed more quietly: the difference between *the tool asserts consent it does
not have* and *the tool reuses consent given for something else* is not one a
household would recognise. And an id that keeps the word `no_heat` while
counting `heat` is the same defect this ADR exists to fix, one layer down —
habitable would have replaced a lying prompt with a lying key.

The failure direction is safe and loud. A vault with no record for the new
question makes `pattern` refuse the whole export and `consent show` print *not
recorded*; nothing publishes half a cohort under a heading claiming consent.
Against that, the cost is bounded, though not as absolutely as a first draft of
this ADR claimed. Since #206 the **CLI** cannot store `no_heat`: `--category`
rejected it outright, and now normalises it to `heat`. The **app** is a different
story — its Condition field is free text and always has been, and until the
normalisation added alongside this work `appserver.add_issue` stored whatever was
typed. A household who typed `no_heat` into the app, exactly, would have been
counted. So the honest statement is that a campaign conducted through the CLI
cannot have had a non-empty export, and a campaign conducted through the app
could have, if a member happened to type the underscored form rather than
choosing from the six offered words.

That does not change the decision — reusing an answer given to a narrower
sentence is the #182 failure whether one household or none is affected — but it
does mean this migration may cost a real number rather than provably costing
nothing, and a union should be told that rather than reassured. What each
household is asked to do is answer, for the first time, the question that will
actually be asked about them.

To keep that refusal from looking like a bug, `SUPERSEDED_QUESTION_IDS` names
the retired id, `superseded_consent_ids()` reports which retired records a case
still holds, and the `ConsentMissingError` says so in a sentence a person reads.
The record is reported, never honoured; no code path treats it as consent.

**5. Spellings the vocabulary knows to be one condition are folded at
aggregation, not by rewriting the vault.** `commons.canonical_category()` folds
case and surrounding space for the *lookup* and resolves a recognised member or
documented synonym to that member, carrying anything else through as the tenant
wrote it — deliberately the same rule `appserver.add_issue` applies at entry, so
the commons never invents a mapping the product would refuse to store. Nothing
rewrites a stored value; #240's promise holds.

Without this, the fix would newly orphan the households it is meant to serve. A
vault holding a free-text `no_heat` from before #206 is exactly the case the
issue describes, and grouping on the raw string would leave it uncounted in its
own building's heat total. Worse, a split cell is measured against `k` twice: a
building where five households reported heat can publish nothing at all because
three said `heat` and two said `no_heat`. Suppression exists to stop a household
being identified, not to hide a building's condition behind a spelling.

**6. Two guards pin the facts, so this cannot rot silently.**
`test_the_question_names_a_category_the_vocabulary_can_actually_store` asserts
the question's category is a member of `ISSUE_CATEGORIES` and is its own
canonical form — with no vault, fixture, or consent record, so it fails the
moment the question and the vocabulary drift again.
`test_the_counted_category_is_one_the_cli_stores` builds three households
through `init`, `issue`, `capture`, `consent record` and `pattern` and requires
a published cell; nothing about the stored category is asserted by the test
rather than produced by the product. Against the pre-#276 filter it fails with
`0 published cell(s)`.

## Migration note: stored consent for the retired question

**What changed.** `habitable pattern` used to ask *"how many households that
recorded consent to this question reported no heat?"* and count issues stored
under the category `no_heat`. No supported path has stored that category since
the condition vocabulary was constrained: `habitable issue --category no_heat`
is accepted but recorded as `heat`, and the app stores `heat`. The question is
now *"how many households that recorded consent to this question reported a heat
condition?"* and counts `heat`, which covers no heat at all, inadequate heat,
and heat that cannot be controlled, without separating them.

**What it means for stored consent.** Consent is recorded per question, under
the key `pattern_consent:<question_id>` in each household's own vault. The
question id changed from `consenting_households_no_heat_by_week` to
`consenting_households_heat_condition_by_week`, so **every consent record
written before this release stops counting.** It is not deleted, not migrated,
and not read as consent to the new question. The new question includes
households the old one did not, and reusing an answer given to a narrower
sentence would make the export claim a consent nobody gave.

**What you will see.** `habitable pattern` refuses the whole export, naming the
first vault without a record, and writes no file. `habitable consent show`
prints `consent: not recorded` for a household that consented before this
release. If that household still holds the old record, the refusal says so and
names the retired question, so it is clear this is a migration rather than a
neighbour who changed their mind.

**What to do.** On each household's own device, run:

```
habitable consent record --vault <their vault>
```

The command prints the new prompt before it writes, so the household sees the
question they are answering. `habitable consent record --withdraw` still records
a withdrawal, and a withdrawal remains distinguishable from never having
answered. There is no bulk path and there is deliberately not going to be one:
the point of the record is that each household made it.

**What is not affected.** Issues, captures, timeline entries, custody, packets,
letters, and sync are untouched — nothing else reads this meta key. No stored
category is rewritten. Aggregates already published cannot be recalled, by this
change or any other; that was true before and is restated because a union
re-consenting may reasonably ask.

**Why this was not made silent.** Keeping the old key and changing only the
prompt would have kept every campaign running and cost nothing visible. It would
also have widened the question under a consent record given for a narrower one,
which is the failure #182 recorded — an export asserting a consent it did not
have. Refusing until each household answers again is the loud version of the
same situation, and the loud version is the one that can be corrected.

## Consequences

- **Easier/safer.** The question habitable asks is one its data can answer, and
  a suite that seeded an impossible value now exercises the CLI end to end. A
  structural guard fails on the next drift between the question and the
  vocabulary, without needing anyone to notice a building of zeroes. Two
  spellings of one condition no longer split a cell — and no longer suppress
  both halves.
- **Costs.** Every household that had recorded consent must record it again, and
  a union mid-campaign meets a refusal before it meets this note. The published
  aggregate is coarser than the question it replaces: it cannot say how many
  households had *no* heat, only how many reported a heat condition, and a
  reader who wants the finer number will not get it from this tool. The pattern
  export's `schema_version` moves to 3 (the `question` block gains `scope_note`
  and `supersedes`; the `consent` block gains `superseded_records_honoured`), so
  a consumer that pinned the question id sees a different one.
- **Follow-up.** (a) `docs/recruitment/profile-building-pattern.md` still tells a
  reviewer to check the `no_heat`/`heat` mismatch with the maintainer before
  running anything; that warning is now spent and the brief should ask the
  reworded question instead (#264). (b) The Python symbols
  `NO_HEAT_WEEKLY_QUESTION` and `build_no_heat_weekly_summary` survive as
  aliases in `patterns.py` because `cli.py` imports them, and `habitable pattern
  --help` still says "no-heat weekly summary"; both are renames inside `cli.py`
  and were out of scope for this change. (c) `docs/commons.md` quotes the
  `provenance.aggregation` string, which now also states that synonym spellings
  are folded before counting.

## References

- Issues #276 (this defect), #206 (constrained the vocabulary), #240 (added the
  aliases and settled the six members), #264 (the `building_pattern` reviewer
  brief), #182 (the export that claimed a consent nobody gave)
- `src/habitable/patterns.py`, `src/habitable/commons.py`,
  `src/habitable/model.py` (`ISSUE_CATEGORIES`, `ISSUE_CATEGORY_ALIASES`)
- [`docs/commons.md`](../commons.md) — the invariant argument for why the
  commons is not telemetry, and the withdrawal model
- ADR 0008 (separate integrity, timestamp trust, and readiness) — the precedent
  for keeping distinct claims distinct rather than collapsing them
- ADR 0017 (append-only change log) — the precedent for refusing the cheap
  version of a fix because it would ship a silent change
