<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# ADR 0013: Dated, expiring jurisdiction framing for the repair-request letter

- Status: Accepted
- Date: 2026-08-26

## Context

`ROADMAP.md` (workstream E) and `docs/novel-use-cases-plan.md` ("Beyond the
current portfolio", candidate #12) queue **jurisdiction template growth** as one
of two solo-buildable *Now* items, and both documents state the precondition the
same way: jurisdictions may be expanded "only with dated owners and expiry
policy — now enforceable rather than aspirational (ADR 0012)."

That precondition was not actually true for the letter. ADR 0012's expiry
machinery lives entirely on `UseCaseProfile` in `usecases.py`. The letter
generator's `LetterProfile` had **no review metadata at all**: no reviewer, no
review date, no expiry, and nothing that could enforce one.

The gap matters more here than anywhere else in the project, because of where
the letter goes. `docs/letter-generator.md` designates `[letter] header`/`footer`
in `config.toml` as the home for a **locally verified statutory citation**:

> The `header`/`footer` are the right place to put a **locally-verified**
> statutory citation; the generator itself will never invent one.

That is the correct division of labour — habitable must not invent law — but it
leaves the one string in this project that can silently stop being true sitting
in an undated field. A statute is amended; a local ordinance is repealed; a
2026-verified citation is wrong by 2028. Meanwhile the letter is, by the
project's own description, "the one document that leaves the tenant's control and
lands in a landlord's — and possibly a court's — hands," and it goes out **under
the tenant's name**. A tenant can be handed a lapsed legal claim by a tool that
had no way to know the claim had lapsed.

Everything else habitable emits is dated, versioned, or verifiable. This was not.

## Decision

1. **`LetterProfile` gains `reviewer`/`reviewed_at`/`expires_at`**, mirroring
   `UseCaseProfile`. A jurisdiction framing cannot be added without recording who
   stood behind it and when.
2. **`letter.framing_expired(profile, *, today=None)`** — a pure predicate, the
   letter-side twin of `usecases.profile_expired`, with identical semantics: no
   `expires_at` never expires; comparison is by calendar date, so a framing
   expires at the *start* of its named day; `today` is injectable so the decision
   is reproducible under test.
3. **Neither built-in framing sets `expires_at`, deliberately.** An expiry exists
   to stop stale *specifics* going out unread. `generic` and `us_habitability`
   name no statute, no deadline, and no remedy — there are no specifics to go
   stale — and expiring them would only mean `habitable letter` stops producing
   the safe fallback framing on a date, taking the conservative default away from
   a tenant to punish a maintainer. Both are now dated (`reviewed_at`), and the
   mechanical half of that review is `test_jurisdiction_profiles_and_fallback`,
   which fails the build on a `§` or `U.S.C` in any reader-visible field.
4. **`[letter]` gains a local-law review block** — `local_law_reviewer`,
   `local_law_reviewed_at`, `local_law_expires_at` — dating the union's own
   `header`/`footer` wording. `letter.review_local_law(template, *, today=None)`
   classifies it into exactly four states: `absent`, `undated`, `current`,
   `expired`.
5. **Expired wording is withheld, and the withholding is never silent.**
   `build_letter` sets `header`/`footer` to `""` when the review has lapsed, so
   the landlord's copy simply does not carry it; both renderers read those two
   fields and nothing else, so HTML and PDF cannot disagree about what was
   withheld. `habitable letter` then prints, in the requested language, what was
   dropped and what to do about it.
6. **Undated wording is used and reported, not refused.** It is still the union's
   own considered text, and refusing it would break every config written before
   these fields existed. The operator is told that nothing can tell them when it
   stopped being true.
7. **Review dates are strictly `YYYY-MM-DD`**, validated in
   `LetterTemplate.__post_init__` so a programmatically constructed template
   cannot smuggle in a value either. `date.fromisoformat` alone accepts
   `20260826` and full timestamps; a value that parses in one place but not
   another is how a date meant to expire quietly never does. The digit class is
   written `[0-9]`, not `\d`, because `\d` matches every Unicode decimal digit —
   a fullwidth `２０２６` would pass the pattern and then raise deep inside the
   date parser instead of being named as a bad config value.
8. **`today` is never derived from `options.date`.** The letter's date is
   caller-controlled; if the expiry check read it, anyone could resurrect lapsed
   legal wording by backdating the letter.

## Options considered

| Option | Assessment |
| --- | --- |
| Refuse to generate the letter when local-law wording has expired | Rejected: same reasoning as ADR 0012's export fallback. The *evidence* is not stale and the tenant's need for a repair-request letter is immediate. Refusing the whole document over presentation metadata leaves a tenant with nothing, for a reason they cannot fix without a fresh legal review. Falling back to wording that claims less is strictly safer. |
| Keep expired wording but append a warning inside the letter | Rejected: the letter is adversarial correspondence. A paragraph saying "the citation above may no longer be accurate" is worse than omitting the citation — it hands the landlord's representative the impeachment for free, on the tenant's own document. |
| Refuse undated wording outright | Rejected for now: it would break every existing config the moment this shipped, punishing unions who did the verification work before there was a field to record it in. Revisit if a future major version can carry the migration. |
| Add a third built-in jurisdiction framing in the same change | **Deliberately not done.** See "What this does not do" below. |
| Date the built-ins with an expiry too | Rejected: see decision 3. |

## What this does not do

This ADR builds the *mechanism* candidate #12 named as its precondition. It does
**not** add a new jurisdiction framing, and that omission is a decision, not an
unfinished edge.

Writing a `california` or `nyc` framing means making jurisdiction-specific legal
claims. This project's rule is that it "will never invent one," the built-ins
"make no claim about a specific statute or code section," and the roadmap's own
"Later" line permits expanding jurisdictions "only with dated owners." A
maintainer adding hedged-but-specific legal framing for a jurisdiction they have
not had reviewed would be doing exactly what every one of those sentences
forbids — and would now also have to type a `reviewed_at` date and a
`reviewer` name asserting a review that did not happen.

The mechanism is therefore the honest half to ship alone: it exists *before* the
first dated framing is added rather than after, which is the same sequencing
ADR 0012 chose. Adding a real jurisdiction framing stays blocked on a named
reviewer, and that gate is recorded in `docs/capabilities.md`.

## Consequences

- No packet, bundle, or verification change whatsoever. The letter is
  correspondence, not proof; `verify.py` is untouched and no packet version
  moves. `CONFIG_SCHEMA_VERSION` stays 1: the three fields are additive and
  optional, and every config written before this change keeps loading.
- `RepairLetter` gains `profile_key`, `framing_reviewed_at`,
  `framing_expired_fallback`, and `local_law`, plus `local_law_limitation` and
  `framing_limitation` properties that mirror the existing
  `language_limitation` pattern: operator-facing prose, never letter body.
- Three new CLI message keys in both shipped locales, so the notes reach a
  Spanish-configured union in Spanish even though the letter itself stays
  English (issue #161's rule is unchanged).
- `framing_expired` ships inert — no built-in sets an expiry — and is verified
  against a synthetic expired framing, exactly as ADR 0012 verified its
  predicate before a real expiring profile existed.

## Action items

- [x] `LetterProfile` review metadata; both built-ins dated.
- [x] `letter.framing_expired` predicate and generic fallback in `build_letter`.
- [x] `[letter]` local-law review block, with strict `YYYY-MM-DD` validation.
- [x] `letter.review_local_law` and the four-state classification.
- [x] Withhold expired wording from both renderings; report it in the CLI.
- [x] EN/ES CLI messages for expired framing, expired wording, undated wording.
- [x] Tests, including a backdating test that fails if `today` is ever derived
      from the caller-controlled letter date.
- [ ] A reviewed jurisdiction framing (blocked on a named legal reviewer; see
      "What this does not do").
