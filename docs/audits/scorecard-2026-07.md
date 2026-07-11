<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# OpenSSF Scorecard — first dated report (2026-07)

**Run date:** 2026-07-05. **Tool:** `scorecard` CLI v5.5.0
(commit `c395761df6afe1a69e476bc60a013a94bcbc153f`), run locally against the
public repo `github.com/ChelseaKR/habitable` (read-only GitHub API calls — the
same checks `.github/workflows/scorecard.yml` runs weekly going forward).

**Aggregate score: 5.5 / 10.**

> **Post-baseline deployment update (2026-07-11):** repository branch protection is
> active, and repository ruleset `18815834` now protects `v*` tags from update or
> deletion and requires signatures. The table below remains the unedited 2026-07-05
> measurement. Signed-Releases cannot improve until a new release is actually cut
> with a signed tag; the existing v0.1.0/v0.2.0 tags remain unsigned historical facts.

This is the honest number for the state of `main` **before** this remediation
pass's changes are committed and pushed — per P1-5's own instruction ("expect
Branch-Protection/Signed-Releases to score red until P1-2/P0-3 land — commit
the honest number"), this snapshot is recorded now rather than waited on, so
there is a real baseline instead of a guessed one.

| Check | Score | Reason |
|---|---|---|
| Binary-Artifacts | 10/10 | no binaries in the repo |
| Branch-Protection | 3/10 | not maximal on `main` (classic protection only; the P1-2 ruleset artifact is drafted but **not yet applied** — that's a `gh api` write action this pass deliberately left for the maintainer) |
| CI-Tests | 10/10 | 7/7 recent merged PRs checked by CI |
| CII-Best-Practices | 0/10 | no OpenSSF Best Practices badge pursued yet (not attempted this pass) |
| Code-Review | 0/10 | 0/23 changesets had an approving review — expected and correctly scored for a solo maintainer; see ADR 0006 |
| Contributors | 3/10 | one contributing org/person |
| Dangerous-Workflow | 10/10 | no dangerous workflow patterns |
| Dependency-Update-Tool | 10/10 | Renovate detected |
| Fuzzing | 0/10 | the in-repo Hypothesis property/fuzz tests (`test_verify_fuzz.py`) aren't OSS-Fuzz-integrated, which is what this check looks for — not attempted this pass |
| License | 10/10 | license file detected |
| Maintained | 0/10 | repo created within the last 90 days — an artifact of project age, not activity |
| Packaging | ? | At the 2026-07-05 run, no published-package workflow was detected. Post-run update (2026-07-09): the tag workflow is now wired for PyPI Trusted Publishing; one-time registry setup and evidence of a successful publish remain open. |
| Pinned-Dependencies | 10/10 | all GitHub Actions + deps pinned by SHA/lock |
| SAST | 10/10 | CodeQL runs on all commits |
| Security-Policy | 10/10 | `SECURITY.md` detected |
| Signed-Releases | 0/10 | no release has a signed tag yet (P0-3's gap; the release-job guard added this pass will enforce it going forward, but the *existing* v0.1.0/v0.2.0 tags predate it and stay unsigned) |
| Token-Permissions | 0/10 (pre-fix) | flagged `release.yml`'s workflow-level `contents: write`; **fixed this pass** (moved to job-level, P3/CICD-04) — expect this to improve on the next run |
| Vulnerabilities | 10/10 | 0 known vulnerabilities |

## What changes this number, and when to re-run

This pass adds (uncommitted, pending the maintainer's review and push):
secret scanning (closes nothing on *this* checklist directly, but is Tier-1),
a signed-tag release guard (Signed-Releases will only improve once a release
is actually cut with a signed tag under the new guard), a drafted-but-unapplied
branch ruleset (`.github/rulesets/`), job-level workflow permissions (should
fix Token-Permissions), and a Scorecard workflow itself (feeds future runs).

**Re-run after:** the stronger proposed main-branch ruleset is reconciled with the
active branch protection and the next release is cut with a signed tag. The tag
protection half of this original action was applied on 2026-07-11; until a signed
release exists, a re-run still cannot improve Signed-Releases.

## Why record a "bad" number at all

Because the alternative — waiting to publish a Scorecard report until the
number looks good — is exactly the misrepresented-conformance pattern this
audit exists to catch. 5.5/10 with a dated, itemized reason per row is more
trustworthy than a badge with no history behind it.
