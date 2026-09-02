# Open pull request triage — 2026-08-28

Read-only triage of every open pull request against `origin/main` at
`1c4d0a0 feat(joint): present several signed packets as one submission, merging nothing (#221)`.

Nothing in this report was merged, closed, commented on, labelled, re-run or
otherwise modified. The only write is this file.

## Counts

The queue holds **nine** open pull requests, not eight: #225, #224, #223, #222,
#218, #217, #216, #213, #209.

| Group | Count | PRs |
| --- | --- | --- |
| Mergeable now, no further work | 1 | #225 |
| Green, blocked only on an owner decision about a CodeQL alert | 2 | #223, #222 |
| Behind, mechanical branch update then green | 3 | #217, #216, #209 |
| Behind, and genuinely fails once updated | 1 | #218 |
| Conflicting, needs rebase plus real rework | 1 | #224 |
| Rework or close: the gate it adds cannot fail | 1 | #213 |

Of those nine, **#222 is fully contained in #223** and adds nothing once #223
lands, so the queue is really eight distinct changes.

## Per-PR table

| PR | Base | Real merge state | CI classification | Recommendation |
| --- | --- | --- | --- | --- |
| **#225** record the owner's standing bypass in the committed main ruleset | `main` | `CLEAN` / `MERGEABLE`; `merge-tree` exit 0 | All ten required contexts SUCCESS. The extra non-required `CodeQL` check-run is **NEUTRAL** and its reason is *"1 configuration present on `refs/heads/main` was not found: `.github/workflows/codeql.yml:analyze`"* — an **absent baseline**, not a defect in the PR | **Merge first.** It records a bypass that already exists live; it removes nothing |
| **#224** audit: eight issues, and eight guards that could not fail | `main` | `DIRTY` / `CONFLICTING`. `git merge-tree --write-tree --messages origin/main origin/bugfix/sweep-2026-08-28` exits 1 with conflicts in exactly `src/habitable/cli.py` and `tests/test_guards.py` | **Absent.** Zero check-runs, zero statuses and zero workflow runs exist for head SHA `3007c0d`, and `gh run list --branch bugfix/sweep-2026-08-28` is empty. GitHub cannot build `refs/pull/224/merge` while the PR conflicts, so no `pull_request` workflow was ever created. Not starved, not failing — never triggered | **Rebase, then rework.** See the `ew_disrepair` section and the changelog section below. Do not merge as-is |
| **#223** feat(campaign): seal each unit packet with that unit's own authority | `main` | `BLOCKED` / `MERGEABLE`. `merge-tree` exit 0 against current `origin/main`. The block is **not** a check: the ruleset sets `required_review_thread_resolution: true` and there is one unresolved CodeQL review thread | All ten required contexts SUCCESS. The non-required `CodeQL` check-run is **FAILURE**: one high alert, `py/clear-text-logging-sensitive-data`, at `src/habitable/cli.py:1466` | **Merge after the owner adjudicates the CodeQL alert** (see below). Nothing else stands in the way |
| **#222** feat(joint): seal the list of packets, not just the packets in it | `main` | `BLOCKED` / `MERGEABLE`, same unresolved-thread cause. `merge-tree` exit 0 | Same single high alert, at `cli.py:1466` | **Close as superseded by #223**, or merge it first and accept the redundancy. It contributes nothing after #223 |
| **#218** bump docker/setup-buildx-action 4.2.0 → 4.3.0 | `main` | `BEHIND` / `MERGEABLE`. `merge-tree` exit 0 — it will not conflict | **Genuine failure, and the PR's own.** `lint · types · tests` ran all steps in 3m29s and failed at the gate step: `tests/test_reproducible_build.py::test_relay_reproducibility_gate_is_wired_to_merge_and_release` — `ValueError: substring not found` on `container_workflow.index(setup_buildx)`. `_SETUP_BUILDX_SHA` is pinned in the test and Dependabot changed only the workflows | **Merge after** updating `_SETUP_BUILDX_SHA` in `tests/test_reproducible_build.py:22` to `37fe631027851001ddb9b187196cc803df7f5f0e`. The failing test is doing its job: it caught an incomplete bump |
| **#217** bump the codeql-action group (3 updates) | `main` | `BEHIND` / `MERGEABLE`. `merge-tree` exit 0 | All required contexts SUCCESS. `CodeQL` NEUTRAL for the same absent-baseline reason as #225. No test pins the codeql-action SHA (only `_SETUP_BUILDX_SHA` exists) | **Update branch and merge** |
| **#216** bump the python-dependencies group (3 updates) | `main` | `BEHIND` / `MERGEABLE`. `merge-tree` exit 0 | All required contexts SUCCESS — but they ran against a base three commits stale | **Update branch and merge early.** It raises `ruff` 0.16.3 → 0.16.4, which is the binary `make lint` runs. Landing it before the rest means every later PR is linted by the version `main` will actually use |
| **#213** feat(i18n): add pseudo-locale text expansion verification gate (#208) | `main` | `BEHIND` / `MERGEABLE`. Fork PR (`ffjh567/habitable`); `merge-tree` against `origin/pr-213` exits 0 | All required contexts SUCCESS — **vacuously.** Nothing in the repo executes the file it adds | **Rework or close.** It verifies nothing (see below) |
| **#209** docs(contributing): point good-first-issues.md at the newly filed issues | `main` | `BEHIND` / `MERGEABLE`. `merge-tree` exit 0 | All required contexts SUCCESS | **Update branch and merge.** A five-line documentation note, no risk |

## The stack: a cumulative snapshot, not a dependency chain

Neither #222 nor #223 has the other as its base. **Both are based on `main`**, and
their merge base with `origin/main` is `1c4d0a0` in both cases. So **no PR in this
queue would auto-close if some other PR's base branch were merged and deleted** —
there is no base-branch stack here at all.

What there is instead is a cumulative snapshot:

```
origin/main  1c4d0a0
     |
     +-- #222  feat/joint-index-authority-seal
     |         19dd51a  feat(joint): seal the list of packets ...
     |         patch-id 4bed4968d784138f111d0936cc4f0b058527f035
     |
     +-- #223  feat/campaign-export-seal
               e1dc8b1  feat(joint): seal the list of packets ...   <-- SAME patch-id
               060c508  feat(campaign): seal each unit packet ...
               d5e88ce  docs(plan): rewrap the sequencing table ...

    #223 is a rebased SUPERSET of #222.
```

Verified three ways:

- `git patch-id --stable` gives `4bed4968…` for both `19dd51a` (#222) and
  `e1dc8b1` (#223).
- `git range-diff` reports `1: 19dd51a = 1: e1dc8b1`, with #223 carrying two
  extra commits.
- Merging #223 into `main` produces a tree in which #222's own files —
  `src/habitable/joint.py`, `src/habitable/i18n.py`, `tests/test_joint.py` — are
  **byte-identical** to #222's head. The only remaining differences are #223's
  additions that #222 lacks.

`git merge-base --is-ancestor origin/feat/joint-index-authority-seal origin/feat/campaign-export-seal`
returns false, because the commits were rebased rather than chained.

**Consequence.** The ruleset allows `merge`, `squash` and `rebase`. If #223 is
squash-merged, GitHub will not auto-close #222: it will sit open showing a diff
that has become empty in substance. Close it by hand.

The PR bodies describe a linear "Phase 2 of 8 / Phase 3 of 8, stacked on #221"
chain. #221 has already landed (`1c4d0a0`), and both branches were rebased onto
it, so the prose is now describing a shape the git history no longer has.

## The dominant defect: guards that pass without checking anything

### #213 is the whole defect, not a case of it

`scripts/check_pseudo_locale.py` is the only file the PR adds, and its entry
point is:

```python
def main() -> int:
    en_bundle = _load(_EN)
    pseudo_bundle = generate_pseudo_locale(en_bundle)
    print(f"Successfully generated {len(pseudo_bundle)} pseudo-localized keys.")
    return 0
```

There is no comparison, no threshold, no failure branch and no exit path other
than `0`. The PR title says "verification gate"; nothing is verified. Beyond
that:

- **Nothing runs it.** It is referenced nowhere in `Makefile`, `.github/`,
  `pyproject.toml`, `tests/`, or any other script.
- **Nothing lints it.** `make lint` runs `ruff` over
  `src tests scripts/check_doc_links.py scripts/check_reproducible_build.py` —
  an explicit two-script allowlist. A newly added script is outside it.
- **Nothing type-checks it.** `[tool.mypy] files = ["src", "tests"]`.
- Consequently its unused `_flatten` import and its post-`sys.path` import
  ordering are never reported by anything.
- **The real check already exists on `main`:**
  `tests/test_app_i18n.py::test_pseudo_locale_expansion_fits_compact_ui`
  already asserts that every bundle string pseudo-expands within a width cap.

Its green CI is the strongest evidence against it: the checks are green because
no gate in this repository can see the file.

### #218's red CI is the opposite case, and is good news

`test_relay_reproducibility_gate_is_wired_to_merge_and_release` pins
`_SETUP_BUILDX_SHA` and asserts the action appears before `make relay-repro` in
both `container-scan.yml` and `release.yml`. Dependabot changed the workflows and
not the constant, so the assertion raised `ValueError: substring not found`. That
is a guard catching a genuinely incomplete change. Fix the constant, do not
weaken the test.

### `c7e3553` has NOT landed on `main`

The briefing states that `c7e3553 test: repair guards that pass without checking
anything` just landed on `main`, and that heavy overlap with #224 is likely.
**Both halves are wrong.**

```
$ git merge-base --is-ancestor c7e3553 origin/main   # NO
$ git merge-base --is-ancestor 3007c0d origin/main   # NO
$ git branch -a --contains c7e3553
* bugfix/sweep-2026-08-28
  remotes/origin/bugfix/sweep-2026-08-28
```

`c7e3553` and `3007c0d` exist only on **#224's own head branch**. They are the
PR, not a precursor to it. There is therefore **no overlap to subtract**: every
guard repair #224 describes is still entirely unlanded, and merging #224 is the
only way any of it reaches `main`.

The repairs #224 carries, none of which exist on `main` today, are: a floor on
the `pytest -m a11y` selected count so an all-skipped run cannot report green; a
per-source floor in `check_bcp47.py` whose "no tags found" guard was dead code;
`test_format_date_month_abbreviations`, which asserted only non-emptiness under a
docstring claiming twelve months; `test_aria_describedby_targets_exist`, whose
assertions all lived inside a `re.findall` loop that an empty match list silently
satisfied; `.NOTPARALLEL:` so `make -j verify` cannot defeat the documented
lock-check ordering; a corrected `.pre-commit-config.yaml` scope comment; and a
lockstep test for the docs-only a11y twin's path list.

### The a11y twin race is real, and observable right now

`a11y-docs-only.yml` publishes the job name `axe-core WCAG scan (merge gate)` —
a **required** context — with an unconditional `echo`. Its own comment claims the
real scan, "finishing later, its result governs." That is a race, not an
invariant, and both jobs really do publish on a mixed PR. On #225:

| Workflow | Job | Started | Completed | Conclusion |
| --- | --- | --- | --- | --- |
| `a11y-docs-only` | axe-core WCAG scan (merge gate) | 00:25:34Z | **00:25:36Z** | SUCCESS (echo only) |
| `a11y` | axe-core WCAG scan (merge gate) | 00:25:34Z | **00:26:58Z** | SUCCESS (real scan) |

The real scan happened to finish later here, so the claimed ordering held on this
run. It held by 82 seconds of luck, not by construction. #224 declines to change
the topology and adds a lockstep test instead; that is the right call for a PR,
but the race itself remains an owner decision.

## `ew_disrepair`: verdict

**Nothing on `main` mentions `ew_disrepair` or `UNREVIEWED`.** Both greps over
`origin/main` return nothing. The profile is introduced by **#224 and only #224**;
no other open PR's diff contains either string.

`#207` is an **open issue**, not a pull request — `gh pr view 207` fails with
*"Could not resolve to a PullRequest with the number of 207"*, while
`gh issue view 207` returns an OPEN issue titled *"Add a second jurisdiction
letter-framing profile to letter.py"*. The `(#207)` in commit `064619e` is an
issue reference, and that commit is on #224's branch, not on `main`.

**#224 does not quietly promote the profile.** Its source comment says
`UNREVIEWED: no solicitor or advice worker for England and Wales has read this
wording`, it cites no statute, section or jurisdiction-specific deadline, and it
leaves `cure_period_days` at the project's own 14-day default with a comment
saying that is not a legal deadline. The PR body repeats the warning under a
heading reading "Read this before merging". That is the correct handling.

**But merging it onto current `main` would promote it by accident, and the
promotion is invisible in the diff.**

`95dabb6 (#219)` — which is genuinely `(#219)`, is genuinely on `origin/main`, and
genuinely touches this exact surface (`src/habitable/letter.py` +201,
`tests/test_letter.py` +260) — added review fields to `LetterProfile`:

```python
reviewer: str = "Habitable maintainers"
reviewed_at: str = ""
expires_at: str = ""
```

#224's `ew_disrepair` was written against the pre-#219 dataclass and sets none of
them. `letter.py` **auto-merges without a conflict**, and the result was checked
by actually performing the merge:

```
LetterProfile(key='ew_disrepair', ..., cure_period_days=14,
              reviewer='Habitable maintainers', reviewed_at='', expires_at='')
```

An explicitly unreviewed jurisdiction framing silently acquires **"Habitable
maintainers"** as its reviewer, by dataclass default, on a document that leaves
the tenant's control and goes to a landlord under the tenant's name. `letter.py`
surfaces `framing_reviewed_at=profile.reviewed_at` in the letter result, and
`framing_expired()` is inert for it because `expires_at` is empty.

**The existing guard catches it.** Running `tests/test_letter.py` against the
merged tree:

```
FAILED tests/test_letter.py::test_every_builtin_framing_is_dated_and_none_expires
AssertionError: ew_disrepair ships undated
```

So the merge fails loudly rather than shipping quietly. The hazard is what
happens next: the obvious way to make that test green is to set
`reviewed_at=_BUILTIN_REVIEWED_AT` and leave `reviewer` at its default, which
would date and attribute an unreviewed profile as if a maintainer had read it.
**Do not resolve the conflict that way.** Either give `ew_disrepair` an honest
`reviewer` value that says nobody qualified has read it, or hold the profile out
of the rebase until a reviewer exists. #219 introduced the dating rule
specifically so a jurisdiction framing cannot be added without saying who stood
behind it; satisfying it with a default is the failure it was written to prevent.

## Non-diff hazards

### 1. CHANGELOG placement

`3007c0d docs(changelog): record the backlog drain under Unreleased` is **not on
`main`** — it is #224's own tip commit. So there is no already-landed changelog
move for other PRs to collide with.

`origin/main`'s `[Unreleased]` runs from line 8 to line 325, containing
`### Added` (10), `### Fixed` (234) and `### Changed` (311); `## [0.4.0]` begins at
line 326.

| PR | Hunk | Lands in | Verdict |
| --- | --- | --- | --- |
| #225 | `@@ -310,6 +310,36 @@` | `[Unreleased] / ### Changed` | Correct |
| #223 | `@@ -9,6 +9,77 @@` | `[Unreleased] / ### Added` | Correct |
| #222 | same hunk, subsumed by #223 | `[Unreleased] / ### Added` | Correct |
| #224 | `@@ -7,6 +7,106 @@` | `[Unreleased]`, but see below | **Needs repositioning** |

**No open PR's changelog hunk lands inside an already-released section.** The one
that needs work is #224, for a different reason. Merging it onto current `main`
produces an `[Unreleased]` section with six subsection headings, three of them
duplicated:

```
  8: ## [Unreleased]
 10: ### Fixed      <-- from #224
 71: ### Added      <-- from #224
 90: ### Changed    <-- from #224
110: ### Added      <-- already on main
334: ### Fixed      <-- already on main
411: ### Changed    <-- already on main
426: ## [0.4.0] — 2026-08-16
```

Everything stays under `[Unreleased]`, so nothing is misfiled into a release, but
the three pairs must be folded together by hand during #224's rebase.

For comparison, merging #225 and then #223 leaves the structure clean:
`[Unreleased]` with one `### Added`, one `### Fixed`, one `### Changed`.

### 2. Two PRs appending to the end of one file

Checked, and **this queue does not have it.** Every pair of open PRs touching a
common file was examined by hunk offset and then by actually merging them
together.

Shared files, once #222 is set aside as subsumed by #223:

| File | PRs | Hunk offsets | Collision risk |
| --- | --- | --- | --- |
| `CHANGELOG.md` (1339 lines) | #223, #224, #225 | 9, 7, 310 | None near EOF |
| `docs/capabilities.md` (46 lines) | #223, #224 | 31, 27 | Disjoint rows |
| `src/habitable/cli.py` (2016 lines) | #223, #224 | interior only | See below |
| `.github/workflows/*` | #217, #218 | different files entirely | None |
| `uv.lock` | #216 alone | — | None |

`docs/capabilities.md` looked like the dangerous one — two PRs editing a small
table — but they rewrite **different rows**: #223 changes the
`Building-level evidence roll-up (campaign)` and
`Joint multi-tenant submission index (joint)` rows; #224 changes the
`RFC 3161 token and authority trust` row. No overlap, no contradiction.

`main` + #225 + #223 merged cleanly, `python -m compileall` over `src tests
scripts` passed, and the full offline suite against the merged tree returned
**1241 passed, 3 deselected in 458s**, with zero failures. So the one pair in
this queue that can both be merged today does not interact badly.

`src/habitable/cli.py` is the one to watch, but only via #224, which already
conflicts there against `main` for an unrelated reason and has to be resolved by
hand regardless.

### 3. Generated files

The generated output tracked in this repository is `site/sample-packet/*`
(regenerated by `make site-sample` → `scripts/make_site_sample.py`) and `uv.lock`.

- **No open PR touches `site/sample-packet/`.** No regeneration step is required
  by any merge in this queue.
- `site/review/index.html`, which #224 edits, is hand-authored, not generated by
  `make_site_sample.py`.
- `uv.lock` is touched only by #216, and no open PR changes `pyproject.toml`, so
  `make lock-check` (`uv lock --check`) has nothing to drift against.

The one generated-artifact effect that does matter is not a file but a binary:
**#216 raises `ruff` 0.16.3 → 0.16.4 in `uv.lock`, and `make lint` runs whatever
`uv.lock` pins.** #216's own green run linted a base three commits stale, so
`ruff` 0.16.4 has never run over `letter.py` as #219 left it, `usecases` as #220
left it, or `joint.py` as #221 left it. Land #216 early so the rest of the queue
is gated by the version `main` will actually use.

### 4. The CodeQL alert blocking #222 and #223

The block is not a status check. All ten required contexts are green on both
PRs. The live ruleset carries `required_review_thread_resolution: true`, and both
PRs have exactly one unresolved review thread, auto-opened by CodeQL:

```
py/clear-text-logging-sensitive-data   high
src/habitable/cli.py:1466  (#222) / :1544 (#223)
"This expression logs sensitive data (secret) as clear text."
```

Line 1466 is `print(json.dumps(payload, indent=2, sort_keys=True))` inside
`_cmd_joint_check`, on the `--json` path.

On substance this reads as a false positive. `main` already prints the same
report (`print(json.dumps(check.to_json(), indent=2, sort_keys=True))`); what
#222 adds is an intermediate `payload`/`seal` binding and a localized
`index_seal["statement"]` string. The serialized payload holds
`joint_index_version`, `index_path`, `ok`, member and match counts, `unlisted`,
`problems`, and seal metadata (`present`, `verified`, …), plus per-member
`bundle_sha256`, `producer_fingerprint` and status fields. There is no key, no
password and no credential in it, and an RFC 3161 token is public evidence a
recipient is meant to check.

Dismissing an alert is a repository write, so this triage did not do it. **It is
an owner decision** and it is the only thing standing between #223 and merge.

### 5. Why #224 has no CI at all

Not starved and not budget-related. `gh api .../commits/3007c0d/check-runs`
returns `total_count: 0`, `/status` returns `state: pending, total_count: 0`, and
`actions/runs?head_sha=3007c0d` returns `total_count: 0`. `ci.yml` triggers on
plain `pull_request`, so it would normally fire. It cannot: GitHub builds
`refs/pull/224/merge` before dispatching `pull_request` workflows, and the PR
conflicts, so the merge ref does not exist and no run is ever created. **Resolving
the conflicts is what makes CI appear.** Until then #224 has never been tested by
CI at all, on any commit.

## Safe order of operations

1. **#225** — merge first. `CLEAN`, all required checks green, and it records a
   bypass that the live ruleset has carried throughout. Nothing depends on it,
   but it is free and it removes a documented lockout hazard from the committed
   file.
2. **#216** — update branch, let CI re-run against current `main`, then merge.
   Doing this early means `ruff` 0.16.4 gates everything that follows. *If the
   re-run goes red on code that 0.16.3 accepted, fix the code, not the pin.*
3. **#217** — update branch, merge. No test pins the codeql-action SHA.
4. **#209** — update branch, merge. Documentation only.
5. **#223** — merge once the owner has adjudicated the CodeQL alert on
   `cli.py:1466` and the thread is resolved. Its changelog hunk needs no
   repositioning. **No regeneration step.**
6. **#222** — **close as superseded** immediately after #223 lands. A squash
   merge of #223 will not auto-close it, and its diff will be empty in substance.
7. **#218** — do not merge as it stands. Update `_SETUP_BUILDX_SHA` in
   `tests/test_reproducible_build.py:22` to
   `37fe631027851001ddb9b187196cc803df7f5f0e` in the same PR, let CI go green,
   then merge.
8. **#224** — last, and only after real work:
   - rebase onto `origin/main`, resolving `src/habitable/cli.py` and
     `tests/test_guards.py` by hand;
   - **give `ew_disrepair` an honest `reviewer` and `reviewed_at`, or hold it
     out of the rebase.** Do not silence
     `test_every_builtin_framing_is_dated_and_none_expires` by inheriting the
     `"Habitable maintainers"` default;
   - **reposition the CHANGELOG entry**: fold its `### Fixed` / `### Added` /
     `### Changed` blocks into the existing ones under `[Unreleased]` instead of
     leaving six headings;
   - re-check its `letter.py` additions against #219's dating machinery, which it
     has never been tested against;
   - CI will run for the first time once the conflicts are gone. Read it.
9. **#213** — rework or close. As written it adds an unrunnable, unlinted,
   untyped script whose `main()` cannot return non-zero, duplicating a real check
   that already exists in `tests/test_app_i18n.py`. If the contributor wants to
   land it, it needs an actual assertion, a `Makefile`/CI wiring, and inclusion in
   the `ruff`/`mypy` surfaces.

**Merges needing a changelog reposition:** #224 only.
**Merges needing a regeneration step:** none.

## What was verified here, and what was taken on trust

### Verified directly

- The open set is nine PRs (`gh pr list`), matching the nine numbers given.
- Staleness was judged against `origin/main` after `git fetch origin`, never
  against local `main`, which is stale at `feac89a`; the working tree is checked
  out on #224's own head branch, which is what makes its unmerged commits look
  landed.
- `main` is not red: the full offline suite passes on a `main` + #225 + #223
  merge, so no PR in this queue is failing for a reason inherited from `main`.
- No `pre-push` hook is installed (`core.hooksPath` unset, `.git/hooks` holds
  only samples), so nothing was bypassed to push this report.
- Every PR's base branch, `mergeStateStatus`, `mergeable`, file list, body and
  full diff, read from `gh`.
- Every PR's conflict state via
  `git merge-tree --write-tree --messages <base> <head>`. Only #224 exits 1, and
  its conflicting paths really are `src/habitable/cli.py` and
  `tests/test_guards.py`.
- `c7e3553` and `3007c0d` are **not** ancestors of `origin/main`; both are on
  `bugfix/sweep-2026-08-28` only.
- `95dabb6` is genuinely `(#219)`, is genuinely on `origin/main`, and genuinely
  touches `src/habitable/letter.py` and `tests/test_letter.py`.
- #224's branch is exactly three commits behind `origin/main` (`95dabb6`,
  `7ecbd46`, `1c4d0a0`), merge base `feac89a`.
- #207 is an open **issue**, not a pull request.
- `ew_disrepair` and `UNREVIEWED` appear nowhere on `origin/main`, and in no open
  PR's diff except #224's.
- The post-merge `ew_disrepair` profile inherits `reviewer='Habitable
  maintainers'` and `reviewed_at=''`, produced by actually merging #224 into
  `origin/main` in a throwaway worktree and printing the dataclass.
- `tests/test_letter.py::test_every_builtin_framing_is_dated_and_none_expires`
  fails on that merged tree with `ew_disrepair ships undated`, run offline.
- #223 contains #222 in full: identical `git patch-id --stable`, `git range-diff`
  showing `19dd51a = e1dc8b1`, and byte-identical `joint.py`, `i18n.py` and
  `test_joint.py` in the merged tree.
- #218's failure cause, read from the job log: `ValueError: substring not found`
  in `test_relay_reproducibility_gate_is_wired_to_merge_and_release`, with
  `_SETUP_BUILDX_SHA` pinned at `tests/test_reproducible_build.py:22`.
- #224 has zero check-runs, zero statuses and zero workflow runs for its head
  SHA.
- The CodeQL alert on #222/#223 (`py/clear-text-logging-sensitive-data`, high,
  `cli.py:1466`) and the unresolved review thread that blocks both, read from the
  code-scanning and GraphQL APIs.
- The live ruleset's `required_status_checks` list and
  `required_review_thread_resolution: true`, read from
  `gh api repos/ChelseaKR/habitable/rulesets/18752848`.
- CHANGELOG section boundaries on `origin/main`, and the post-merge structure for
  #224 and for #225+#223, read out of real merge trees.
- The a11y twin publishing the same required context twice on #225, with
  timestamps.
- #213's script being referenced nowhere, and being outside both `make lint`'s
  explicit file list and `[tool.mypy] files`.

### Taken on trust

- **PR bodies' own test evidence.** #222's and #223's mutation-testing tables,
  #225's "`make verify`: exit 0", and #224's "1201 passed" were read but not
  re-run. #223's claims were corroborated to the extent that the offline suite
  against a real `main` + #225 + #223 merge returned 1241 passed / 0 failed;
  `ruff`, `mypy --strict` and the coverage floors were not re-run.
- **The live ruleset id `18752848` being the one governing `main`.** Read via
  the API, not cross-checked against a second source.
- **The CodeQL alert being a false positive.** The payload was read field by
  field and contains no credential, but CodeQL's taint path was not traced to its
  source. Treated as an owner decision, not resolved here.
- **`ruff` 0.16.4's behaviour on current `main`.** The local environment has
  0.16.3 and installing 0.16.4 would need network access, which this triage did
  not use. The recommendation to land #216 early is a precaution, not a
  reproduction of a failure.
- **Whether the fork PR #213's author intends further commits.** The judgement is
  on the code as it stands today.
