# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Is the site a visitor gets at habitable.chelseakr.com the site this repository has?

Publishing model assumed: **committed-tree publisher**
------------------------------------------------------
``.github/workflows/pages.yml`` checks the repository out and hands
``actions/upload-pages-artifact`` a directory that is already in the commit
(``path: site`` today). Nothing is rendered on the runner. The Pages API calls
this ``build_type: workflow``, which is true and misleading: a workflow performs
the publish, but the bytes it publishes were committed, not built.

That makes **deployed-SHA-versus-head the wrong measure here**, and wrong in the
expensive direction -- it cries wolf. This repository merges code, tests, docs
and app changes constantly and touches ``site/`` rarely. On the day this was
written the newest deployment was ``b1c62e172`` (2026-09-10) and ``main`` was
``589e30c1a``, five commits ahead: a SHA comparison reports five commits of
drift, and every one of those five is invisible to a visitor, because
``git rev-parse b1c62e172:site`` and ``git rev-parse 589e30c1a:site`` are the
same tree object. The bytes being served *are* the bytes ``main`` has. An
earlier sweep of this portfolio made exactly that mistake and had to correct it.

So the comparison this module implements is between the *published subtrees*:

    git rev-parse <deployed_sha>:<published path>
    git rev-parse <head>:<published path>

Equal tree object ids mean the visitor already has, byte for byte, what ``main``
has -- no matter how many commits or days separate the two SHAs. Unequal ids
mean a real difference in what is served, and only then does the clock matter.

The published path is read out of ``pages.yml`` at each end of the comparison
rather than hard-coded, because the publisher's ``path:`` is itself a
publication input: changing it changes what a visitor receives without changing
one byte of ``site/``. A sentinel that assumed ``site/`` forever would go quietly
blind on the commit that changed it.

Why the deployment record and not the publisher's run history
-------------------------------------------------------------
``pages.yml`` is path-filtered (``site/**`` and the workflow file). A push that
touches neither does not start it at all, and one that does may still be
superseded by its own ``concurrency`` group. Counting workflow runs therefore
answers a different question than "when did bytes last reach a reader". A
``github-pages`` deployment exists only because a publish was requested, it names
the commit it came from, and its statuses say whether that publish succeeded.

The rule this file follows: a detector that cannot tell must refuse, never
report a comfortable zero. Every unmeasurable case below raises
`StalenessUnknownError` rather than returning a number that would read as a
measurement.

This module publishes nothing and holds no credential that could. It reads the
deployment record and the local git history, and prints.

Standard library only, and it imports nothing from the rest of this repository,
so it runs on a runner's bare ``python3`` with no dependency resolution and
cannot be broken by one -- the same constraint the i18n gates in this directory
document, for the same reason. It is written to the 3.12 floor
``verifier-portability`` already holds the verifier subset to, not to the
project's 3.14 target, because the runner's ``python3`` is not this project's
interpreter.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_REPO = "ChelseaKR/habitable"

#: The environment a deployment has to belong to. This repository also carries
#: `pypi` deployments; those publish a wheel, not the site.
PAGES_ENVIRONMENT = "github-pages"

#: The publisher. Its `path:` decides which committed directory becomes the
#: site, so the file is both the thing that publishes and a publication input.
PUBLISHER_WORKFLOW = ".github/workflows/pages.yml"

#: How long a published-byte difference may wait before this reports. The site
#: is a landing page plus a synthetic sample packet, changed deliberately and
#: rarely; the threshold exists to catch a month, not an afternoon.
DEFAULT_MAX_AGE_DAYS = 14

_SHA = re.compile(r"^[0-9a-f]{40}$")

#: The publisher step, and the first `path:` belonging to it. Parsed with a
#: regex rather than a YAML library on purpose: the standard library has no YAML
#: parser, and adding a dependency to the one gate that must run on a bare
#: `python3` would defeat the point. The parse is deliberately narrow -- it
#: refuses rather than guesses -- so a workflow shape it does not understand
#: becomes a red run, not a silent fallback to `site/`.
_UPLOAD_STEP = re.compile(r"^[ \t-]*uses:\s*actions/upload-pages-artifact@", re.MULTILINE)
#: Where the uploader's own block ends: the next step's list item, or the next
#: `uses:` if a step is written without one. Cutting there is what keeps a
#: `path:` belonging to some later step from being read as the published one.
_NEXT_STEP = re.compile(r"^[ \t]*(?:-[ \t]|uses:)", re.MULTILINE)
_PATH_INPUT = re.compile(r"^[ \t]*path:[ \t]*(?P<value>[^\n#]*)", re.MULTILINE)

#: `path:` values that mean "the whole repository", which `git rev-parse` spells
#: as the root tree rather than as a subtree.
_ROOT_PATHS = frozenset({"", ".", "./"})


class StalenessUnknownError(Exception):
    """The comparison could not be made, so no number is reported.

    (`afterward` and `fare-policy-assistant` spell this `StalenessUnknown`; the
    `Error` suffix is this repository's N818 lint, not a difference in meaning.)

    Raised in preference to returning zero anywhere the inputs do not support a
    measurement. The caller turns this into a red run: a sentinel that cannot
    tell is a broken sentinel, and it has to look broken.
    """


@dataclass(frozen=True)
class DeployRecord:
    """The published build: which commit it came from, and when it went out."""

    deployment_id: int
    sha: str
    created_at: datetime


@dataclass(frozen=True)
class PublishedSite:
    """What a visitor receives: a directory, and that directory's exact bytes.

    Both halves matter. `tree` is the git object id of the published subtree, so
    two commits with the same `tree` serve identical bytes. `path` is on the
    record beside it because a publisher that starts uploading a different
    directory publishes different bytes while every tree id in the repository
    stays exactly where it was.
    """

    path: str
    tree: str


@dataclass(frozen=True)
class Commit:
    """One commit after the deployed one: when it landed, and what it touched."""

    sha: str
    committed_at: datetime
    paths: tuple[str, ...]


@dataclass(frozen=True)
class Drift:
    """How the published bytes compare with `main`'s, and how long that has held."""

    deployed: DeployRecord
    head: str
    deployed_site: PublishedSite
    head_site: PublishedSite
    deploy_age_days: int
    commits: int
    publication_commits: int
    waiting_days: int | None
    max_age_days: int

    @property
    def published_bytes_match(self) -> bool:
        """Does the visitor already have exactly what `main` has?

        The whole verdict rests here, and this is the line that must not become
        a SHA comparison. `deployed.sha != head` is true on almost every day in
        this repository and says nothing about what is being served.
        """
        return self.deployed_site == self.head_site

    @property
    def overdue(self) -> bool:
        """Report only when a real published-byte difference has waited too long.

        Two refusals to fire are deliberate. Matching subtrees are current
        *regardless of age*: a site nobody republished because nothing it
        publishes changed is correct, not stale, and this repository would
        otherwise raise an alarm every fortnight forever. And a difference that
        landed this morning is a deploy that has not happened yet, not a deploy
        that was forgotten -- `waiting_days` measures the oldest unpublished
        change, not the age of the last deploy, so a fortnight-old deployment
        does not make a one-day-old edit overdue.
        """
        if self.published_bytes_match or self.waiting_days is None:
            return False
        return self.waiting_days > self.max_age_days


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


def newest_successful_deployment(
    deployments: Iterable[Mapping[str, Any]],
    statuses_for: Any,
) -> DeployRecord:
    """The most recent `github-pages` deployment that actually published.

    `statuses_for` is called with a deployment id and returns that deployment's
    statuses, newest first. A deployment row is a *request* to publish; its
    statuses are what say whether bytes landed. A deployment whose newest status
    is `failure`, `error` or `in_progress` never became a site, and treating its
    commit as the live one would report the site as fresher than it is -- the
    precise direction of error this whole file exists to prevent.
    """
    candidates = [
        d
        for d in deployments
        if d.get("environment") in (None, PAGES_ENVIRONMENT) and _SHA.match(str(d.get("sha", "")))
    ]
    if not candidates:
        raise StalenessUnknownError(
            "no github-pages deployment in this repository's history: there is no published "
            "build to compare main against"
        )
    candidates.sort(key=lambda d: _parse_timestamp(str(d["created_at"])), reverse=True)

    for deployment in candidates:
        states = [str(s.get("state", "")) for s in statuses_for(deployment["id"])]
        if states and states[0] == "success":
            return DeployRecord(
                deployment_id=int(deployment["id"]),
                sha=str(deployment["sha"]),
                created_at=_parse_timestamp(str(deployment["created_at"])),
            )

    raise StalenessUnknownError(
        f"none of the {len(candidates)} github-pages deployment(s) reports a successful status: "
        "nothing here proves any build was ever published"
    )


def published_path(workflow: str) -> str:
    """The directory `pages.yml` uploads, read out of the workflow itself.

    Narrow by design. The alternative to refusing on an unrecognized shape is
    defaulting to `site`, and a default that happens to be right today is a
    detector that keeps answering confidently after the answer changes.
    """
    step = _UPLOAD_STEP.search(workflow)
    if step is None:
        raise StalenessUnknownError(
            f"{PUBLISHER_WORKFLOW} has no actions/upload-pages-artifact step: this is not the "
            "committed-tree publisher this sentinel knows how to measure"
        )
    rest = workflow[step.end() :]
    following = _NEXT_STEP.search(rest)
    block = rest[: following.start()] if following else rest
    found = _PATH_INPUT.search(block)
    if found is None:
        raise StalenessUnknownError(
            "the actions/upload-pages-artifact step declares no path: which directory reaches "
            "readers cannot be read off the publisher"
        )
    value = found.group("value").strip().strip("\"'").rstrip("/")
    if value.startswith(("/", "~")) or ".." in Path(value).parts:
        raise StalenessUnknownError(
            f"the publisher uploads {value!r}, which is not a path inside this repository: "
            "there is no committed subtree to compare"
        )
    return value


def _executable(name: str) -> str:
    resolved = shutil.which(name)
    if resolved is None:
        raise StalenessUnknownError(f"required executable not found on PATH: {name}")
    return resolved


def _run_git(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - resolved git path and constant arguments
        [_executable("git"), "-C", str(REPO_ROOT), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def _git(*args: str) -> str:
    result = _run_git(*args)
    if result.returncode != 0:
        raise StalenessUnknownError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def _has_commit(sha: str) -> bool:
    """Whether this clone contains the commit, without raising on absence.

    `git cat-file` exits non-zero for a commit that is simply not here, which is
    the ordinary shallow-clone case and not a git failure. Routing it through
    `_git` would report it as one, and the refusal the caller raises -- the one
    that names the shallow checkout and says why a zero would be wrong -- would
    never be reached.
    """
    return _run_git("cat-file", "-e", f"{sha}^{{commit}}").returncode == 0


def require_comparable(deployed_sha: str, head: str) -> None:
    """Refuse unless this clone can actually place the deployed commit on `main`.

    Both failures below read as "nothing has changed" if they are not caught,
    and both are ordinary. A shallow checkout does not contain the deployed
    commit at all, so `git rev-parse <deployed>:site` fails and `git log
    <deployed>..HEAD` lists nothing -- which is why the sentinel workflow checks
    out with `fetch-depth: 0`, and why this refuses rather than trusting that it
    did. A force-push or a rebase leaves the deployed commit off `main`
    entirely, where "what has happened since the deploy" is not a question with
    an answer.
    """
    if not _SHA.match(deployed_sha):
        raise StalenessUnknownError(f"deployed commit {deployed_sha!r} is not a commit id")
    if not _has_commit(deployed_sha):
        raise StalenessUnknownError(
            f"deployed commit {deployed_sha[:9]} is not in this clone: the checkout is shallow, "
            "and a comparison against a history that does not reach the published build would "
            "report no drift at all"
        )
    merge_base = _git("merge-base", deployed_sha, head)
    if merge_base != _git("rev-parse", deployed_sha):
        raise StalenessUnknownError(
            f"deployed commit {deployed_sha[:9]} is not an ancestor of {head}: the history has "
            "diverged and 'what has happened since the deploy' has no answer"
        )


def published_site(sha: str) -> PublishedSite:
    """Which directory that commit publishes, and the exact bytes it holds.

    This is the measurement. Everything else in this module exists to make sure
    it is asked of two commits that can meaningfully be compared.
    """
    workflow = _read_workflow(sha)
    path = published_path(workflow)
    spec = f"{sha}^{{tree}}" if path in _ROOT_PATHS else f"{sha}:{path}"
    result = _run_git("rev-parse", spec)
    if result.returncode != 0:
        raise StalenessUnknownError(
            f"commit {sha[:9]} has no {path!r} to publish, though its {PUBLISHER_WORKFLOW} "
            f"uploads it: {result.stderr.strip()}"
        )
    return PublishedSite(path=path, tree=result.stdout.strip())


def _read_workflow(sha: str) -> str:
    result = _run_git("show", f"{sha}:{PUBLISHER_WORKFLOW}")
    if result.returncode != 0:
        raise StalenessUnknownError(
            f"commit {sha[:9]} has no {PUBLISHER_WORKFLOW}: the directory it published cannot "
            f"be identified ({result.stderr.strip()})"
        )
    return result.stdout


def publication_inputs(deployed: PublishedSite, head: PublishedSite) -> tuple[str, ...]:
    """The paths whose change can change what a visitor receives.

    Both published directories, because a commit that moved the site from one to
    the other changed the published bytes from both ends. And the publisher
    itself, because its `path:` is what decides which directory is uploaded --
    without it, the one commit that can change the site without touching either
    directory would be invisible here.
    """
    return tuple(dict.fromkeys([deployed.path, head.path, PUBLISHER_WORKFLOW]))


def alters_publication(path: str, inputs: Sequence[str]) -> bool:
    """Is this changed file inside something the publisher uploads?"""
    return any(
        path == candidate or candidate in _ROOT_PATHS or path.startswith(f"{candidate}/")
        for candidate in inputs
    )


def commits_between(deployed_sha: str, head: str) -> list[Commit]:
    """Each commit after the deployed one, with its landing time and paths."""
    raw = _git("log", "--format=%x00%H %ct", "--name-only", f"{deployed_sha}..{head}")
    commits: list[Commit] = []
    for block in raw.split("\x00"):
        lines = [line for line in block.splitlines() if line.strip()]
        if not lines:
            continue
        sha, _, epoch = lines[0].partition(" ")
        commits.append(
            Commit(
                sha=sha,
                committed_at=datetime.fromtimestamp(int(epoch), tz=UTC),
                paths=tuple(lines[1:]),
            )
        )
    return commits


def measure(
    deployed: DeployRecord,
    head: str,
    now: datetime,
    max_age_days: int = DEFAULT_MAX_AGE_DAYS,
) -> Drift:
    """Place the published bytes against `main`'s, or refuse."""
    head_sha = _git("rev-parse", head)
    # Before anything reads a tree out of the deployed commit: on a shallow
    # clone that read fails with git's own message, and the refusal that
    # explains why a zero would be wrong would never be the one raised.
    require_comparable(deployed.sha, head_sha)

    deployed_site = published_site(deployed.sha)
    head_site = published_site(head_sha)
    commits = commits_between(deployed.sha, head_sha)
    inputs = publication_inputs(deployed_site, head_site)
    publishing = [c for c in commits if any(alters_publication(p, inputs) for p in c.paths)]

    waiting_days: int | None = None
    if deployed_site != head_site:
        if not publishing:
            # Not a tidy edge case: the two halves of this module disagreeing.
            # The subtrees differ, so something a visitor receives changed, yet
            # no commit in the range touched anything that could have changed
            # it. Reporting either half as the answer would be a guess.
            raise StalenessUnknownError(
                f"the published bytes differ ({deployed_site.path}@{deployed_site.tree[:9]} vs "
                f"{head_site.path}@{head_site.tree[:9]}) but no commit since the deploy touched "
                f"{', '.join(inputs)}: this sentinel cannot explain the difference it measured"
            )
        waiting_days = (now - min(c.committed_at for c in publishing)).days

    return Drift(
        deployed=deployed,
        head=head_sha,
        deployed_site=deployed_site,
        head_site=head_site,
        deploy_age_days=(now - deployed.created_at).days,
        commits=len(commits),
        publication_commits=len(publishing),
        waiting_days=waiting_days,
        max_age_days=max_age_days,
    )


def render(drift: Drift) -> str:
    """The report. States the measurement before its verdict, always."""
    # Named from both ends when they differ: a publisher that moved is a change
    # to what a reader receives, and a report showing only one of the two
    # directories would describe the wrong half of it.
    directory = (
        f"{drift.head_site.path}/"
        if drift.deployed_site.path == drift.head_site.path
        else f"{drift.deployed_site.path}/ (live) -> {drift.head_site.path}/ (main)"
    )
    lines = [
        f"Published directory:  {directory}  (read from {PUBLISHER_WORKFLOW})",
        f"Live deployment:      {drift.deployed.sha[:9]}  "
        f"({drift.deployed.created_at.date().isoformat()}, {drift.deploy_age_days} days ago, "
        f"deployment {drift.deployed.deployment_id})",
        f"main:                 {drift.head[:9]}  ({drift.commits} commits later)",
        f"Published subtree:    live {drift.deployed_site.tree[:9]}  "
        f"vs main {drift.head_site.tree[:9]}",
    ]
    if drift.published_bytes_match:
        lines.append(
            "\nCurrent: the two subtrees are the same git object, so a visitor is already "
            "receiving exactly the bytes main has. This holds regardless of how old the "
            "deployment is; the commits since it did not touch anything that is published."
        )
    elif drift.overdue:
        lines.append(
            f"\nOVERDUE: the published bytes differ from main's and the oldest unpublished "
            f"change has waited {drift.waiting_days} days, past the {drift.max_age_days}-day "
            f"threshold ({drift.publication_commits} commit(s) touched what is published). "
            "The live site is not what this repository says it is."
        )
    else:
        lines.append(
            f"\nWaiting: the published bytes differ from main's; the oldest unpublished change "
            f"is {drift.waiting_days} days old, within the {drift.max_age_days}-day threshold "
            f"({drift.publication_commits} commit(s) touched what is published)."
        )
    return "\n".join(lines)


def as_json(drift: Drift) -> dict[str, Any]:
    return {
        "deployed_sha": drift.deployed.sha,
        "deployed_at": drift.deployed.created_at.isoformat(),
        "deployment_id": drift.deployed.deployment_id,
        "head": drift.head,
        "published_path": drift.head_site.path,
        "deployed_tree": drift.deployed_site.tree,
        "head_tree": drift.head_site.tree,
        "published_bytes_match": drift.published_bytes_match,
        "deploy_age_days": drift.deploy_age_days,
        "commits": drift.commits,
        "publication_commits": drift.publication_commits,
        "waiting_days": drift.waiting_days,
        "overdue": drift.overdue,
    }


def _gh(path: str) -> Any:
    """Read the API through `gh`, which the runner already authenticates."""
    result = subprocess.run(  # noqa: S603 - resolved gh path and a constructed API path
        [_executable("gh"), "api", path],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise StalenessUnknownError(f"gh api {path} failed: {result.stderr.strip()}")
    parsed: Any = json.loads(result.stdout)
    return parsed


def _statuses_reader(repo: str, offline: Path | None) -> tuple[Any, Any]:
    """Where the deployment record comes from: the API, or a file for tests."""
    if offline is not None:
        payload = json.loads(offline.read_text(encoding="utf-8"))
        statuses = payload["statuses"]

        def from_file(deployment_id: Any) -> list[Mapping[str, Any]]:
            found: list[Mapping[str, Any]] = statuses.get(str(deployment_id), [])
            return found

        return payload["deployments"], from_file

    deployments = _gh(f"repos/{repo}/deployments?environment={PAGES_ENVIRONMENT}&per_page=20")

    def from_api(deployment_id: Any) -> list[Mapping[str, Any]]:
        fetched: list[Mapping[str, Any]] = _gh(
            f"repos/{repo}/deployments/{deployment_id}/statuses?per_page=10"
        )
        return fetched

    return deployments, from_api


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("--repo", default=DEFAULT_REPO)
    parser.add_argument("--head", default="origin/main")
    parser.add_argument("--max-age-days", type=int, default=DEFAULT_MAX_AGE_DAYS)
    parser.add_argument("--json", action="store_true", help="emit the measurement as JSON")
    parser.add_argument(
        "--deployments-json",
        type=Path,
        help="read deployments from a file instead of the API (offline use and tests)",
    )
    args = parser.parse_args(argv)

    try:
        deployments, statuses_for = _statuses_reader(args.repo, args.deployments_json)
        deployed = newest_successful_deployment(deployments, statuses_for)
        drift = measure(deployed, args.head, datetime.now(UTC), args.max_age_days)
    except StalenessUnknownError as exc:
        print(f"cannot measure deploy staleness: {exc}", file=sys.stderr)
        _write_github_output(None, str(exc))
        return 2

    print(json.dumps(as_json(drift), indent=2) if args.json else render(drift))
    _write_github_output(drift, None)
    return 0


def _write_github_output(drift: Drift | None, error: str | None) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    with Path(path).open("a", encoding="utf-8") as handle:
        if drift is None:
            handle.write("measured=false\n")
            handle.write(f"error={error or 'unknown'}\n")
        else:
            handle.write("measured=true\n")
            handle.write(f"overdue={str(drift.overdue).lower()}\n")
            handle.write(f"published_bytes_match={str(drift.published_bytes_match).lower()}\n")
            handle.write(f"published_path={drift.head_site.path}\n")
            handle.write(f"deploy_age_days={drift.deploy_age_days}\n")
            handle.write(f"waiting_days={drift.waiting_days if drift.waiting_days else 0}\n")
            handle.write(f"commits={drift.commits}\n")
            handle.write(f"publication_commits={drift.publication_commits}\n")
            handle.write(f"deployed_sha={drift.deployed.sha}\n")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
