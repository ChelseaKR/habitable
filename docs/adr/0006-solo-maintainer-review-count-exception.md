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
`required_approving_review_count: 0` **explicitly**, with
`require_code_owner_review: true` and `dismiss_stale_reviews_on_push: true`
left on (so the moment a second maintainer/CODEOWNER exists, those
requirements immediately become meaningful without any further ruleset edit).
Every other applicable rule — linear history, required signatures, the full
required-status-checks list, no force-push, no deletion — is enforced with
**no bypass actor**, including for the repository owner.

This is a **dated, explicit waiver**, not an absent gate: the ruleset artifact
records the real posture (zero-review, solo-maintainer) instead of a
branch-protection setting that claims "1 review required" while the only
human who can approve is also the only human who can push.

## Consequences

- All AUTO-checkable gates (status checks, linear history, tag/commit
  signing) are enforced without exception, including against the maintainer.
- The moment a second regular contributor joins, this ADR is superseded: bump
  `required_approving_review_count` to 1 in
  `.github/rulesets/main-branch.json` and re-apply the ruleset. That is the
  trigger condition — not a calendar date.
- Until then, the review-count control is scored as an honest, recorded
  exception (per the standard's own waiver mechanism) rather than a silent
  FAIL or a misleading PASS.
