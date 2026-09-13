# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""The detector that answers "is the live site the site this repository has?".

Written from both directions, because what it replaces was an absence: nothing
here was asking, and every gate was green. A detector that cannot fire is noise
and gets deleted; a detector that reports a number it did not really measure is
worse than none, because the number reads as a measurement and nobody re-derives
it.

The sharpest case in this file is
`test_a_commit_outside_the_published_tree_is_not_drift`. `pages.yml` uploads a
directory that is already committed, so the deployed commit and `main` can be
days and dozens of commits apart while a visitor holds byte-for-byte what `main`
holds. Comparing SHAs would call that stale every week of the year; comparing
the published subtree calls it what it is. That test is the one that fails if
anyone ever swaps the comparison back.

The rest cover every way the comparison can be meaningless -- no deployment at
all, a deployment that never succeeded, a commit this clone does not contain, a
history that has diverged, a publisher whose upload path cannot be read. Each of
those must end in a refusal. None of them may end in a comfortable zero.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = REPO_ROOT / "scripts"


def _script(name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    # Registered before execution, not after: `@dataclass` resolves annotations
    # through `sys.modules[cls.__module__]`, so a module that is not there yet
    # raises on the decorator rather than on anything to do with this repository.
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


staleness = _script("deploy_staleness")

NOW = datetime(2026, 9, 13, 12, 0, tzinfo=UTC)
DEPLOYED_AT = "2026-09-10T06:52:13Z"

# A minimal publisher of the same shape as the real one: check out, upload a
# committed directory, deploy it. Nothing is built on the runner, which is the
# whole reason the subtree comparison below is the right one.
PAGES_WORKFLOW = """\
name: pages

on:
  push:
    branches: [main]
    paths:
      - "site/**"

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - name: Upload static site
        uses: actions/upload-pages-artifact@fc324d3547104276b827a68afc52ff2a11cc49c9 # v5.0.0
        with:
          path: site
      - name: Deploy to GitHub Pages
        uses: actions/deploy-pages@368f82528645a54fb793d4d04e342629a3f51346 # v5.0.1
"""

WORKFLOW_PATH = ".github/workflows/pages.yml"


def _deployment(**over: Any) -> dict[str, Any]:
    row = {
        "id": 6366237074,
        "sha": "b" * 40,
        "environment": "github-pages",
        "created_at": DEPLOYED_AT,
    }
    row.update(over)
    return row


def _succeeded(_id: Any) -> list[Mapping[str, Any]]:
    return [{"state": "success"}]


def _never_succeeded(_id: Any) -> list[Mapping[str, Any]]:
    return [{"state": "failure"}, {"state": "in_progress"}]


# --- what the deployment record is allowed to mean --------------------------


def test_the_newest_successful_deployment_is_the_live_build() -> None:
    record = staleness.newest_successful_deployment([_deployment()], _succeeded)
    assert record.sha == "b" * 40
    assert record.created_at.date().isoformat() == "2026-09-10"
    assert record.deployment_id == 6366237074


def test_the_newest_deployment_wins_over_an_older_one() -> None:
    newer = _deployment(id=2, sha="d" * 40, created_at="2026-09-12T00:00:00Z")
    record = staleness.newest_successful_deployment([_deployment(), newer], _succeeded)
    assert record.sha == "d" * 40


def test_no_deployment_at_all_is_a_refusal_not_a_zero() -> None:
    with pytest.raises(staleness.StalenessUnknownError, match="no github-pages deployment"):
        staleness.newest_successful_deployment([], _succeeded)


def test_a_deployment_that_never_succeeded_is_a_refusal() -> None:
    """A deployment row is a request to publish, not a publish.

    Accepting one whose newest status is `failure` or `in_progress` reports the
    site as fresher than it is, which is the one direction of error this file
    exists to prevent.
    """
    with pytest.raises(staleness.StalenessUnknownError, match="successful status"):
        staleness.newest_successful_deployment([_deployment()], _never_succeeded)


def test_a_failed_newer_deployment_does_not_hide_the_successful_older_one() -> None:
    """A failed republish leaves the previous build serving; that is the live one."""
    failed = _deployment(id=9, sha="e" * 40, created_at="2026-09-12T00:00:00Z")

    def statuses(deployment_id: Any) -> list[Mapping[str, Any]]:
        return [{"state": "failure"}] if deployment_id == 9 else [{"state": "success"}]

    record = staleness.newest_successful_deployment([_deployment(), failed], statuses)
    assert record.sha == "b" * 40


def test_a_wheel_release_is_not_a_site_deployment() -> None:
    """This repository also deploys to `pypi`; those rows publish no site."""
    wheel = _deployment(id=7, environment="pypi", sha="f" * 40, created_at="2026-09-12T00:00:00Z")
    record = staleness.newest_successful_deployment([_deployment(), wheel], _succeeded)
    assert record.sha == "b" * 40


def test_a_row_without_a_commit_id_is_not_a_deployment() -> None:
    with pytest.raises(staleness.StalenessUnknownError, match="no github-pages deployment"):
        staleness.newest_successful_deployment([_deployment(sha="not-a-sha")], _succeeded)


# --- which directory the publisher actually uploads --------------------------


def test_the_published_directory_is_read_from_the_real_publisher() -> None:
    """The live coupling: this repository publishes `site/`, and says so itself.

    Read from the checked-in `pages.yml` rather than asserted as a constant, so
    the day the publisher starts uploading something else this test changes with
    it instead of quietly measuring the wrong directory.
    """
    workflow = (REPO_ROOT / WORKFLOW_PATH).read_text(encoding="utf-8")
    assert staleness.published_path(workflow) == "site"


def test_the_path_is_read_from_the_upload_step_not_a_later_one() -> None:
    workflow = PAGES_WORKFLOW.replace(
        "      - name: Deploy to GitHub Pages\n",
        "      - name: Something else\n        with:\n          path: not-the-site\n",
    )
    assert staleness.published_path(workflow) == "site"


def test_a_changed_upload_path_is_read_as_the_new_one() -> None:
    assert (
        staleness.published_path(PAGES_WORKFLOW.replace("path: site", "path: public")) == "public"
    )


@pytest.mark.parametrize("written", ['path: "site"', "path: 'site'", "path: site/"])
def test_quoting_and_a_trailing_slash_name_the_same_directory(written: str) -> None:
    assert staleness.published_path(PAGES_WORKFLOW.replace("path: site", written)) == "site"


def test_a_publisher_with_no_upload_step_is_a_refusal() -> None:
    """Not a fallback to `site`. A default that is right today is a detector

    that keeps answering confidently after the answer has changed.
    """
    stripped = PAGES_WORKFLOW.replace("actions/upload-pages-artifact@", "actions/nothing@")
    with pytest.raises(staleness.StalenessUnknownError, match="no actions/upload-pages-artifact"):
        staleness.published_path(stripped)


def test_an_upload_step_with_no_path_is_a_refusal() -> None:
    with pytest.raises(staleness.StalenessUnknownError, match="declares no path"):
        staleness.published_path(PAGES_WORKFLOW.replace("          path: site\n", ""))


@pytest.mark.parametrize("escape", ["path: /etc", "path: ../elsewhere"])
def test_a_path_outside_the_repository_is_a_refusal(escape: str) -> None:
    with pytest.raises(staleness.StalenessUnknownError, match="not a path inside this repository"):
        staleness.published_path(PAGES_WORKFLOW.replace("path: site", escape))


# --- which changed files can change what a visitor receives ------------------


def test_the_published_directory_and_the_publisher_are_the_publication_inputs() -> None:
    inputs = staleness.publication_inputs(
        staleness.PublishedSite(path="site", tree="a" * 40),
        staleness.PublishedSite(path="site", tree="b" * 40),
    )
    assert inputs == ("site", WORKFLOW_PATH)


def test_both_directories_count_when_the_publisher_moved() -> None:
    inputs = staleness.publication_inputs(
        staleness.PublishedSite(path="site", tree="a" * 40),
        staleness.PublishedSite(path="public", tree="b" * 40),
    )
    assert inputs == ("site", "public", WORKFLOW_PATH)


@pytest.mark.parametrize(
    "path",
    ["site/index.html", "site/sample-packet/packet.html", "site", WORKFLOW_PATH],
)
def test_publication_inputs_match_what_is_published(path: str) -> None:
    assert staleness.alters_publication(path, ("site", WORKFLOW_PATH))


@pytest.mark.parametrize(
    "path",
    ["README.md", "src/habitable/verify.py", "docs/mobile.md", "sitemap.xml", ".github/ci.yml"],
)
def test_everything_else_is_not_published(path: str) -> None:
    assert not staleness.alters_publication(path, ("site", WORKFLOW_PATH))


# --- the comparison against main, and every way it can be meaningless -------


def _git(root: Path, *args: str, when: datetime | None = None) -> None:
    env = None
    if when is not None:
        stamp = when.isoformat()
        env = {
            **os.environ,
            "GIT_AUTHOR_DATE": stamp,
            "GIT_COMMITTER_DATE": stamp,
        }
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, env=env)


def _commit(root: Path, path: str, body: str = "x", *, when: datetime | None = None) -> str:
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(body, encoding="utf-8")
    _git(root, "add", path)
    _git(root, "commit", "-m", f"touch {path}", when=when)
    return subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


@pytest.fixture
def clone(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A repository shaped like this one: a committed site and a publisher."""
    root = tmp_path / "clone"
    root.mkdir()
    _git(root, "init", "-b", "main")
    _git(root, "config", "user.email", "sentinel@example.test")
    _git(root, "config", "user.name", "sentinel")
    (root / WORKFLOW_PATH).parent.mkdir(parents=True, exist_ok=True)
    (root / WORKFLOW_PATH).write_text(PAGES_WORKFLOW, encoding="utf-8")
    _git(root, "add", WORKFLOW_PATH)
    _commit(root, "site/index.html", "<h1>habitable</h1>", when=NOW - timedelta(days=400))
    monkeypatch.setattr(staleness, "REPO_ROOT", root)
    return root


def _record(sha: str, created_at: datetime) -> Any:
    return staleness.DeployRecord(deployment_id=1, sha=sha, created_at=created_at)


def _head(root: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def test_a_commit_outside_the_published_tree_is_not_drift(clone: Path) -> None:
    """The case this repository is in, and the one a SHA comparison gets wrong.

    `pages.yml` uploads a directory that is already in the commit, so the
    deployed SHA and `main` drift apart on every merge that touches code, tests
    or docs -- none of which a visitor receives. The published subtrees are the
    same git object, so a reader already has, byte for byte, what `main` has.
    A SHA comparison would call this stale; it is current, and it is current
    however old the deployment is.
    """
    deployed = _head(clone)
    _commit(clone, "README.md", when=NOW - timedelta(days=100))
    _commit(clone, "src/habitable/verify.py", when=NOW - timedelta(days=90))

    drift = staleness.measure(_record(deployed, NOW - timedelta(days=200)), "HEAD", NOW)

    assert drift.deployed.sha != drift.head, "the fixture must make the two measures disagree"
    assert drift.deployed_site.tree == drift.head_site.tree
    assert drift.published_bytes_match is True
    assert drift.commits == 2
    assert drift.publication_commits == 0
    assert drift.waiting_days is None
    assert drift.deploy_age_days == 200
    assert not drift.overdue
    assert "Current" in staleness.render(drift)


def test_a_reverted_site_change_leaves_the_visitor_current(clone: Path) -> None:
    """Commits touched the published directory; the published bytes did not.

    Counting commits that touched `site/` would report drift here. The tree
    object is what a visitor gets, and it came back to where it started.
    """
    deployed = _head(clone)
    _commit(clone, "site/index.html", "<h1>draft</h1>", when=NOW - timedelta(days=90))
    _commit(clone, "site/index.html", "<h1>habitable</h1>", when=NOW - timedelta(days=89))

    drift = staleness.measure(_record(deployed, NOW - timedelta(days=200)), "HEAD", NOW)

    assert drift.publication_commits == 2
    assert drift.published_bytes_match is True
    assert not drift.overdue


def test_an_unpublished_site_change_past_the_threshold_is_overdue(clone: Path) -> None:
    deployed = _head(clone)
    _commit(clone, "site/index.html", "<h1>new</h1>", when=NOW - timedelta(days=40))
    _commit(clone, "README.md", when=NOW - timedelta(days=2))

    drift = staleness.measure(_record(deployed, NOW - timedelta(days=60)), "HEAD", NOW)

    assert drift.published_bytes_match is False
    assert drift.publication_commits == 1
    assert drift.waiting_days == 40
    assert drift.overdue
    report = staleness.render(drift)
    assert "OVERDUE" in report
    assert report.index("Published subtree") < report.index("OVERDUE")


def test_the_clock_runs_from_the_change_not_from_the_deploy(clone: Path) -> None:
    """A fortnight-old deployment does not make a one-day-old edit overdue.

    The question is how long a reader has been denied something, not how long
    ago the last publish happened. Measuring the deploy's age would fire here
    on a change that has waited three days.
    """
    deployed = _head(clone)
    _commit(clone, "site/index.html", "<h1>new</h1>", when=NOW - timedelta(days=3))

    drift = staleness.measure(_record(deployed, NOW - timedelta(days=60)), "HEAD", NOW)

    assert drift.deploy_age_days == 60
    assert drift.waiting_days == 3
    assert drift.published_bytes_match is False
    assert not drift.overdue
    assert "Waiting" in staleness.render(drift)


def test_a_publisher_that_moved_to_another_directory_is_drift(clone: Path) -> None:
    """The change that alters what a visitor receives without touching `site/`.

    Nothing under `site/` moves, no tree in the repository changes, and the
    reader gets different bytes because the publisher now uploads somewhere
    else. Hard-coding `site` would make this invisible.
    """
    deployed = _head(clone)
    _commit(clone, "public/index.html", "<h1>elsewhere</h1>", when=NOW - timedelta(days=40))
    (clone / WORKFLOW_PATH).write_text(
        PAGES_WORKFLOW.replace("path: site", "path: public"), encoding="utf-8"
    )
    _git(clone, "add", WORKFLOW_PATH)
    _git(clone, "commit", "-m", "publish public/", when=NOW - timedelta(days=39))

    drift = staleness.measure(_record(deployed, NOW - timedelta(days=60)), "HEAD", NOW)

    assert drift.deployed_site.path == "site"
    assert drift.head_site.path == "public"
    assert drift.published_bytes_match is False
    assert drift.overdue
    assert "site/ (live) -> public/ (main)" in staleness.render(drift)


def test_nothing_at_all_since_the_deploy_is_current(clone: Path) -> None:
    deployed = _head(clone)

    drift = staleness.measure(_record(deployed, NOW - timedelta(days=1)), "HEAD", NOW)

    assert drift.commits == 0
    assert drift.published_bytes_match is True
    assert not drift.overdue
    assert "Current" in staleness.render(drift)


def test_a_commit_this_clone_does_not_have_is_a_refusal(clone: Path) -> None:
    """The shallow-checkout case, which is the one that reports zero silently.

    On a shallow clone the deployed commit is simply absent: its published
    subtree cannot be read and `git log <absent>..HEAD` lists nothing, so the
    site reads as current. This is why the sentinel workflow checks out with
    `fetch-depth: 0`, and why the refusal exists rather than trusting that it
    did.
    """
    with pytest.raises(staleness.StalenessUnknownError, match="not in this clone"):
        staleness.measure(_record("a" * 40, NOW - timedelta(days=63)), "HEAD", NOW)


def test_a_diverged_history_is_a_refusal(clone: Path) -> None:
    _git(clone, "checkout", "-b", "other")
    orphan = _commit(clone, "orphan.txt", when=NOW - timedelta(days=5))
    _git(clone, "checkout", "main")

    with pytest.raises(staleness.StalenessUnknownError, match="not an ancestor"):
        staleness.measure(_record(orphan, NOW - timedelta(days=5)), "HEAD", NOW)


def test_a_malformed_deployed_sha_is_a_refusal(clone: Path) -> None:
    with pytest.raises(staleness.StalenessUnknownError, match="not a commit id"):
        staleness.measure(_record("nope", NOW), "HEAD", NOW)


def test_a_commit_with_no_publisher_is_a_refusal(clone: Path) -> None:
    """Which directory a commit published cannot be guessed after the fact."""
    deployed = _head(clone)
    _git(clone, "rm", "-q", WORKFLOW_PATH)
    _git(clone, "commit", "-m", "drop the publisher", when=NOW - timedelta(days=30))

    with pytest.raises(
        staleness.StalenessUnknownError, match=r"has no \.github/workflows/pages\.yml"
    ):
        staleness.measure(_record(deployed, NOW - timedelta(days=60)), "HEAD", NOW)


def test_a_published_directory_that_is_not_there_is_a_refusal(clone: Path) -> None:
    deployed = _head(clone)
    _git(clone, "rm", "-q", "-r", "site")
    _git(clone, "commit", "-m", "delete the site", when=NOW - timedelta(days=30))

    with pytest.raises(staleness.StalenessUnknownError, match="has no 'site' to publish"):
        staleness.measure(_record(deployed, NOW - timedelta(days=60)), "HEAD", NOW)


def test_a_difference_it_cannot_explain_is_a_refusal(
    clone: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The two halves of the module disagreeing must not resolve to a number.

    The subtrees differ, so a visitor is receiving something other than `main`,
    yet no commit in the range touched anything that could have changed it.
    Reporting either half as the answer would be a guess. The state should be
    unreachable; this asserts the refusal, not the reachability.
    """
    deployed = _head(clone)
    _commit(clone, "site/index.html", "<h1>new</h1>", when=NOW - timedelta(days=40))
    monkeypatch.setattr(staleness, "commits_between", lambda *_: [])

    with pytest.raises(staleness.StalenessUnknownError, match="cannot explain the difference"):
        staleness.measure(_record(deployed, NOW - timedelta(days=60)), "HEAD", NOW)


# --- the report, the JSON, and the exit code ---------------------------------


def test_the_report_states_the_measurement_before_its_verdict(clone: Path) -> None:
    deployed = _head(clone)
    _commit(clone, "site/index.html", "<h1>new</h1>", when=NOW - timedelta(days=40))
    drift = staleness.measure(_record(deployed, NOW - timedelta(days=60)), "HEAD", NOW)

    report = staleness.render(drift)

    assert deployed[:9] in report
    assert drift.deployed_site.tree[:9] in report
    assert drift.head_site.tree[:9] in report
    assert "site/" in report


def test_the_current_report_says_age_is_not_the_question(clone: Path) -> None:
    """The wording matters: a reader of a 200-day-old deployment needs to be

    told it is current on purpose, not left to assume nobody checked.
    """
    deployed = _head(clone)
    _commit(clone, "README.md", when=NOW - timedelta(days=100))
    drift = staleness.measure(_record(deployed, NOW - timedelta(days=200)), "HEAD", NOW)

    assert "regardless of how old the deployment is" in staleness.render(drift)


def test_the_json_carries_both_tree_ids(clone: Path) -> None:
    deployed = _head(clone)
    _commit(clone, "site/index.html", "<h1>new</h1>", when=NOW - timedelta(days=40))
    drift = staleness.measure(_record(deployed, NOW - timedelta(days=60)), "HEAD", NOW)

    payload = staleness.as_json(drift)

    assert payload["deployed_sha"] == deployed
    assert payload["published_path"] == "site"
    assert payload["deployed_tree"] != payload["head_tree"]
    assert payload["published_bytes_match"] is False
    assert payload["waiting_days"] == 40
    assert payload["overdue"] is True


def test_the_cli_refuses_with_a_nonzero_exit_when_it_cannot_measure(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Exit 2, not 0 with a reassuring report. The sentinel workflow turns a

    measurement into an issue and a refusal into a red run, so this exit code is
    the whole difference between "the site is current" and "nobody can tell".
    """
    payload = tmp_path / "deployments.json"
    payload.write_text('{"deployments": [], "statuses": {}}', encoding="utf-8")

    code = staleness.main(["--deployments-json", str(payload)])

    assert code == 2
    assert "cannot measure" in capsys.readouterr().err


# --- the sentinel must not be able to publish --------------------------------


def _executable_yaml(text: str) -> str:
    """The workflow with its prose removed.

    Written the first time this test ran, which it failed: the sentinel's header
    explains at length that it holds no `pages: write`, and the assertion read
    the explanation as the grant. A check whose verdict turns on a comment is
    the always-green this repository keeps deleting, wearing the other colour.
    """
    kept = []
    for line in text.splitlines():
        without_comment = line.split(" #", 1)[0].rstrip()
        if not without_comment.strip() or without_comment.lstrip().startswith("#"):
            continue
        kept.append(without_comment)
    return "\n".join(kept)


def test_the_sentinel_workflow_holds_no_publishing_grant() -> None:
    """It reports; it does not deploy, and it must stay unable to.

    `pages: write` and `id-token: write` are what `pages.yml` needs to publish.
    A sentinel that acquired either could turn "the site is behind" into "the
    site was quietly republished", which is a different tool with a different
    review.
    """
    sentinel = _executable_yaml(
        (REPO_ROOT / ".github/workflows/deploy-staleness.yml").read_text(encoding="utf-8")
    )

    assert "pages: write" not in sentinel
    assert "id-token: write" not in sentinel
    assert "permissions: {}" in sentinel
    assert "deployments: read" in sentinel
    assert "issues: write" in sentinel


def test_the_sentinel_workflow_refuses_a_shallow_checkout() -> None:
    """`fetch-depth: 0` is the precondition the script refuses without.

    Without it the deployed commit is absent, its published subtree cannot be
    read, and the run is red every week -- which is the designed behaviour, but
    a red that a one-line change prevents belongs in the file, not in a
    postmortem.
    """
    sentinel = _executable_yaml(
        (REPO_ROOT / ".github/workflows/deploy-staleness.yml").read_text(encoding="utf-8")
    )

    assert "fetch-depth: 0" in sentinel
    assert "persist-credentials: false" in sentinel
    assert "cancel-in-progress: false" in sentinel


def test_the_sentinel_does_not_change_when_the_publisher_fires() -> None:
    """The publisher's path filter is deliberate and is not this lane's to widen.

    `pages.yml` starts on a push that touches `site/**` or itself, and nothing
    else. Making staleness visible is a different job from changing publishing
    policy, and conflating the two is how a reporting tool quietly becomes a
    deploying one.
    """
    publisher = _executable_yaml((REPO_ROOT / WORKFLOW_PATH).read_text(encoding="utf-8"))

    assert '- "site/**"' in publisher
    assert '- ".github/workflows/pages.yml"' in publisher
