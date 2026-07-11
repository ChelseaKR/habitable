# 6. Required PR review count is 0, by explicit waiver, not a silent gap

- Status: Accepted
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
owner.

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
