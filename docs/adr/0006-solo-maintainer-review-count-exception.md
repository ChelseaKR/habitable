# 6. Required PR review count is 0, by explicit waiver, not a silent gap

- Status: Accepted. The "no bypass actor" clause is **superseded 2026-08-28**;
  see "Superseding note" at the end. The review-count decision itself stands.
- Date: 2026-07-05

## Context

The code-quality and CI/CD standards call for branch protection requiring at
least one approving review before merge (CQ-37/38, CICD-11..16). habitable
today has one active maintainer. A hard `required_approving_review_count: 1`
on a solo-maintained repo does not add a second pair of eyes — it either
deadlocks every PR (nobody else can approve) or forces the maintainer to add a
bypass actor for themselves, which is functionally identical to having no
review requirement, except now it is *hidden* inside a bypass-actor exception
instead of stated as policy.

The audit (2026-07-05, CQ/CICD family) is correct that "documented intent, not
enforced" is a real defect distinct from "enforced." The wrong fix is to
pretend a review gate exists when it cannot, in practice, gate anything.

## Decision

`.github/rulesets/main-branch.json`'s `pull_request` rule sets
`required_approving_review_count: 0` **explicitly**. Pull requests themselves,
current-branch status checks, review-thread resolution, no force-push, and no
deletion are enforced with **no bypass actor**, including for the repository
owner. *(That last clause was reversed on 2026-08-28 — see the superseding note
below. Everything else in this section stands.)*

`require_code_owner_review` is deliberately `false` while the sole CODEOWNER is
also the author of every maintainer PR. GitHub treats code-owner review as an
independent approval requirement even when the general approval count is zero;
turning it on now would deadlock every change, not add a second pair of eyes.
When a second maintainer joins, this ADR requires enabling code-owner review and
raising the approval count together.

This is a **dated, explicit waiver**, not an absent gate: the ruleset artifact
records the real posture (zero-review, solo-maintainer) instead of a
branch-protection setting that claims "1 review required" while the only
human who can approve is also the only human who can push.

## Consequences

- All currently configured AUTO-checkable merge gates are enforced without
  exception, including against the maintainer; required checks must be rerun
  against current `main` before merge.
- The moment a second regular contributor joins, this ADR is superseded: bump
  `required_approving_review_count` to 1 and set
  `require_code_owner_review` to `true` in
  `.github/rulesets/main-branch.json` and re-apply the ruleset. That is the
  trigger condition — not a calendar date.
- Until then, the review-count control is scored as an honest, recorded
  exception (per the standard's own waiver mechanism) rather than a silent
  FAIL or a misleading PASS.

## Superseding note — 2026-08-28: the owner's bypass is deliberate

The "no bypass actor, including for the repository owner" clause above is
withdrawn. It is not a stricter gate; it is a hazard, and the hazard has already
fired.

`bypass_actors` on `.github/rulesets/main-branch.json` now holds exactly the
repository owner's standing bypass (`RepositoryRole` 5,
`bypass_mode: always`), deliberately and permanently: an agent once applied a
ruleset with no bypass and locked the owner out of their own repository, and
restoring access took a sweep across eighteen repositories. An empty list there
is not a tighter policy, it is the lockout.

The reasoning in **Context** above is still right about the *risk* — an admin
bypass does hand the merge gate's off-switch to the person most likely to be in
a hurry at 2am. It was wrong about which risk is larger. It also framed the
choice as review-count-versus-hidden-exception, when the actual failure was
recoverability: a solo maintainer with no bypass has no way back into their own
repository when a ruleset is applied wrongly, and no second maintainer to let
them in.

What that changes, and what it does not:

- Every AUTO-checkable merge gate still runs on every pull request, and every
  change since 2026-07-11 has gone through one. A standing bypass is a recovery
  path, not a merge policy, and using it routinely would be a defect in
  practice rather than in configuration.
- The waiver this ADR exists for — `required_approving_review_count: 0` while
  there is one active maintainer, with `require_code_owner_review` false — is
  unaffected, and its trigger condition (a second regular contributor) is
  unchanged.
- The `v*` tag ruleset (`.github/rulesets/release-tags.json`, live ruleset
  `18815834`) really does carry no bypass actor, and keeps none: a released tag
  must not be movable by anyone, owner included. The two rulesets differ on
  purpose. Do not harmonise them in either direction.
- `tests/test_release_workflow.py` asserts the owner's bypass on the committed
  branch ruleset and on the live one **independently**, rather than comparing
  the two to each other, because comparing them would report conformance on the
  day both were emptied together — the incident recurring with a green tick on
  it.

If you are reading this because the empty list looked more secure and you were
about to restore it: re-applying a ruleset file that omits the owner's bypass is
how the lockout happens. Do not.
