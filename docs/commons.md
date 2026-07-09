# The opt-in aggregate housing-conditions commons (EXP-14)

> **Status: alpha / concept stage.** This documents a deliberately-constrained,
> opt-in feature and the argument for *why it is not telemetry*. It is not a
> promise about any legal or advocacy outcome. Read it alongside
> [`privacy.md`](privacy.md) and the "Requests we should decline" analysis in
> [`research/synthetic-personas-feedback.md`](research/synthetic-personas-feedback.md).

## The problem this squares

Funders (persona P-21) and organizers want **population-level** evidence — "how much
mold is there across this landlord's buildings?" — but habitable's founding invariants
are **no telemetry, ever**, **no server-side personal data**, and **no central case
store**. Those two pulls look irreconcilable, and the wrong resolution — background
"anonymous usage stats" — is explicitly on the decline list.

The commons is the *only* reconciliation we accept, and only because it is reshaped
until it fits every invariant: a union can **choose** to compute a coarse, k-anonymous,
building-level summary **on its own device** and then **decide, as a separate manual
act, whether to publish the resulting file**. Nothing is automatic, nothing is
per-person, and nothing is transmitted by the tool.

## What it is

`habitable commons` reads one or more case vaults the organizer can already open,
reduces each case **on-device** to nothing more than `(building label, issue category,
coarse time period)` tuples, aggregates them, suppresses anything that could point at a
single household, and writes a JSON file. That's it. See
[`../src/habitable/commons.py`](../src/habitable/commons.py).

```
habitable commons \
  --vault case-4B --vault case-5A --vault case-2C \
  --out mold-report.json --k 5 --period month
```

The output is a self-describing file: a `provenance` block travels with the numbers so a
recipient can read the constraints they were produced under without trusting the
sender's prose.

```json
{
  "kind": "habitable/commons",
  "schema_version": 1,
  "provenance": {
    "opt_in": true,
    "on_device": true,
    "telemetry": false,
    "network_transmission": false,
    "k_anonymity_threshold": 5,
    "aggregation": "counts grouped by building label, issue category, and coarsened time period; cells backed by fewer than k distinct households are suppressed, not rounded",
    "excludes": "case ids, unit labels, rooms, titles, descriptions, severity, photos, hashes, timestamp tokens, actors, and device identity"
  },
  "period_granularity": "month",
  "contributing_cases": 12,
  "suppressed_cells": 3,
  "cells": [
    { "building_label": "1200 Elm", "category": "mold", "period": "2026-01", "issue_count": 9, "household_count": 6 }
  ]
}
```

## The invariant argument — why this is not telemetry

Each hard rule, and how the design meets it:

| Invariant | How the commons stays inside it |
| --- | --- |
| **No telemetry, ever** | There is no background collection and no automatic run. The summary exists only because a human typed `habitable commons`. The module has **no network capability at all** — it imports only the standard library and the local case model, so it *cannot* open a socket or make a request even if misused. A test (`test_module_imports_nothing_network_capable`) enforces this structurally. |
| **No server-side personal data / no central store** | The tool never sends the file anywhere. Publication is a separate, deliberate act the union performs by hand (email it, post it, hand it to a reporter — or not). The project runs no endpoint that receives it. |
| **Aggregate-only, never per-person** | A case is reduced on-device to `(building, category, period)` before it is ever counted. No case id, unit label, room, title, description, severity, photo, hash, timestamp token, actor, or device identity is carried forward. A test asserts a sensitive case id never appears anywhere in the output. |
| **k-anonymous** | A cell is emitted only when it is backed by **at least `k` distinct households**. Cells below the threshold are *suppressed*, not rounded, so no published number reflects fewer than `k` households. The threshold counts distinct households, not issue rows, so one prolific household filing ten reports cannot clear a cell on its own. `k` may never be set below `MIN_K = 3`; the tool errors rather than silently weaken the guarantee. |
| **De-identified building label** | The building label is a **union-chosen coarse label**, entered deliberately at `habitable init --building`, never an address the tool derives from photo GPS or any other case content. Because every published cell is backed by ≥ `k` households, a building label reveals a *building's* condition, never an identifiable person's. |

## Residual risks we do **not** claim to eliminate

Honesty is the point of this project, so the limits are stated plainly:

- **Complementary / small-population inference.** Cell suppression is the documented
  baseline, but it is not perfect. In a very small building, the *combination* of a
  published cell and a suppressed one can narrow inference. A union publishing about a
  building with only a handful of households should raise `--k` and think about whether
  to publish at all. The tool makes the safe choice easy (suppress by default) but
  cannot make the judgment for the union.
- **Building label is chosen, not sanitized.** If a union types a hyper-specific label,
  that is the union's disclosure to make. The tool does not invent labels and does not
  read them from evidence, but it also cannot stop a human from choosing a revealing one.
- **The union is the controller.** Once the file is published, it is out of the tool's
  hands. This is by design — there is no operator who can recall, correlate, or leak it,
  because no operator ever held it.
- **Synthetic, not audited-in-the-field.** Like the rest of the alpha, the privacy model
  here should get **external review before any real release**, exactly as the ideation
  entry (EXP-14) requires.

## When to decline it

If a proposed use cannot meet **all** of opt-in, on-device, aggregate-only, k-anonymous,
and manually-published, the correct answer is to decline it and say so — the same
discipline the [decline table](research/synthetic-personas-feedback.md#requests-we-should-decline-invariant-conflicts)
applies to every other tempting-but-invariant-breaking request. A "live impact
dashboard the funder can watch" is that request, and it stays declined; this opt-in,
publish-by-hand summary is the honest alternative.
