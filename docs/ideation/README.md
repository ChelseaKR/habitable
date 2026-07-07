<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Ideation — large-scale fixes and expansions

> **Drafted 2026-07-01.** This folder is a *next-layer* ideation pass for habitable:
> deep, structural fixes and larger expansions that go **beyond** what the existing
> planning documents already contain. It is deliberately separate from the roadmap so
> that speculative, large-scale thinking never gets mistaken for a commitment.

## What this is

An honest, grounded exploration of where habitable could go if resources allowed —
written after reading the actual source (`src/habitable/*.py`), the app
(`app/app.js`, `app/index.html`), the relay, the CI gates, and every planning doc.
Every idea here cites real files and real behaviour. Where something is uncertain
(because the agent read code, not ran it), that is stated plainly.

## What this is **not**

- **Not a commitment.** These are ideas for evaluation. Some are large; several need
  human, legal, or funding gates that an engineer cannot cross alone (see
  [`04-impact-and-sequencing.md`](04-impact-and-sequencing.md)).
- **Not a restatement of existing plans.** [`ROADMAP.md`](../../ROADMAP.md) (the build
  spec, workstreams A–D and the v1.0 gate) and
  [`docs/research/synthetic-personas-feedback.md`](../research/synthetic-personas-feedback.md)
  (the 2026-06-30 synthetic-stakeholder pass, backlog IDs `R-##`/`E-##`) already
  hold a large backlog. This folder **references** those items by ID when it builds on
  them and otherwise proposes only net-new material.

## How this relates to the existing roadmap and research

| Document | Role | This folder's relationship |
| --- | --- | --- |
| [`ROADMAP.md`](../../ROADMAP.md) | The committed plan (workstreams A–D, v1.0 gate) | We do not re-plan A–D; we surface fixes/expansions the roadmap does not name. |
| [`docs/research/synthetic-personas-feedback.md`](../research/synthetic-personas-feedback.md) | Synthetic user research → `R-##`/`E-##` backlog | We cross-reference by ID and go past it; several findings here are things *no* synthetic persona surfaced. |
| [`docs/research/execution-log.md`](../research/execution-log.md) | Honest ledger of what the research pass shipped | We note where an item is "spec-written, code-deferred" so we do not double-count. |
| [`docs/threat-model.md`](../threat-model.md) | Adversary model, §5 admitted limits | Several ideas here directly target the §5 residual-risk list. |

## Index

1. [`01-deep-dive.md`](01-deep-dive.md) — current-state assessment from a direct read
   of the code: architecture, what is genuinely strong, structural debt actually
   observed, and habitable's strategic position in the portfolio.
2. [`02-large-scale-fixes.md`](02-large-scale-fixes.md) — 14 deep structural fixes
   (`FIX-01`…`FIX-14`) across architecture, cryptography, correctness, privacy,
   security, accessibility, and operability. Includes the highest-severity finding of
   this pass.
3. [`03-expansions.md`](03-expansions.md) — 15 expansions (`EXP-01`…`EXP-15`) across
   three horizons: H1 deepen the core, H2 adjacent capabilities, H3 transformative bets.
4. [`04-impact-and-sequencing.md`](04-impact-and-sequencing.md) — an impact×effort
   matrix over every `FIX`/`EXP` ID, dependency notes, a Now/Next/Later sequence that
   goes beyond the roadmap, and a clearly separated list of items that require
   human/legal/SME/real-data gates.

## The ethos these ideas must honour

Everything here is shaped by the same invariants the product holds itself to:
honesty-as-a-feature ("what this proves / does not prove"), mandatory tamper-evidence,
no server-side personal data, no telemetry, retaliation as the threat model, and
EN/ES bilingual + accessibility equity as non-negotiable. An idea that would violate an
invariant is either reshaped to fit or explicitly declined — the same discipline
`synthetic-personas-feedback.md` applies in its "Requests we should decline" table.
