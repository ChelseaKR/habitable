# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""The project must stop pointing volunteers at work that is already finished.

Three times it has. Each was found by a person and fixed in the one document that was
wrong, so the three fixes shared no machinery and the fourth instance was going to be
found by another volunteer rather than by us:

* **#208** asked for a pseudo-locale / text-expansion check that had shipped six weeks
  earlier as ``tests/test_app_i18n.py::test_pseudo_locale_expansion_fits_compact_ui``.
  An outside contributor opened PR #213 against it and kept the branch current for
  eleven days.
* **b67b44a** removed four sentences that reserved jurisdiction work for a newcomer --
  "left open for a first-time contributor (issue #207)", "reserved as good first issue
  #207" -- after #207 had closed and the framing had shipped.
* **#254** found four of the six "Claim task" links on the public review page landing
  on closed issues holding somebody else's completed answer.

`scripts/check_stale_invitations.py` is the shared machinery, split where `make verify`
forces it to split. This file gates the offline half on every merge and proves the
network half can fail without needing a network to do it.

**What the offline half cannot know, stated plainly.** It cannot know whether any issue
is open; that is the tracker's answer and this gate has no network. So it checks the
*shape* of an invitation rather than its truth, on the reasoning that an invitation
addressed to one issue number is stale-by-construction -- the first person to finish the
work closes the thread and nothing in the tree changes. Two of the three instances had
exactly that shape and are caught below. **The third, #208, is not**, and no offline rule
could catch it: that bullet named no issue, no version and no date, and what went stale
was the world rather than the text. `docs/good-first-issues.md` still carries it. Nothing
here or in the scheduled workflow will ever notice, and the honest statement of coverage
is that a maintainer grepping the tree before applying `good first issue` is still the
only defence against that one.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_CHECKER = _ROOT / "scripts" / "check_stale_invitations.py"
_WORKFLOW = _ROOT / ".github" / "workflows" / "stale-invitations.yml"
_ISSUE_BASE = "https://github.com/ChelseaKR/habitable/issues"


def _run(root: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(_CHECKER), "--root", str(root), *extra],
        capture_output=True,
        check=False,
        text=True,
    )


def _plant(root: Path, relative: str, body: str) -> None:
    destination = root / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(body, encoding="utf-8")


def _states(root: Path, states: dict[str, str]) -> Path:
    """A saved tracker answer, standing in for the GitHub API. See `--states`."""
    path = root / "states.json"
    path.write_text(json.dumps(states), encoding="utf-8")
    return path


# The review page exactly as it read before #254 was fixed: six bounded tasks, each
# offered by number, four of those numbers already closed by whoever ran the task first.
_PRE_254_REVIEW_PAGE = "\n".join(
    f'<li><h3>Task {code}</h3><a href="{_ISSUE_BASE}/{number}">Claim task #{number}</a></li>'
    for code, number in (
        ("OR-01", 123),
        ("LA-01", 122),
        ("AX-01", 124),
        ("AX-02", 126),
        ("SE-01", 121),
        ("SE-02", 125),
    )
)

# The review page as it reads now: the six claims go to the issue *form*, and the four
# finished runs are linked as what they are. Copied in shape from `site/review/index.html`
# because this is the control -- the content that must stay green.
_CURRENT_REVIEW_PAGE = (
    "<p>Four tasks already carry one finished run: "
    f'<a href="{_ISSUE_BASE}/123">OR-01 (#123)</a>, '
    f'<a href="{_ISSUE_BASE}/122">LA-01 (#122)</a>, '
    f'<a href="{_ISSUE_BASE}/121">SE-01 (#121)</a>, and '
    f'<a href="{_ISSUE_BASE}/125">SE-02 (#125)</a>. '
    "Those threads are closed and stay closed—they are the record of a run, not a "
    "claim on the task. Read one for what a complete answer looks like, then file "
    "yours.</p>\n"
    '<li><a href="https://github.com/ChelseaKR/habitable/issues/new?template=review-task.yml'
    '&amp;task=OR-01">Claim task OR-01</a></li>\n'
)


def test_no_document_invites_a_reader_to_claim_a_fixed_issue_number() -> None:
    """The live tree, held to both offline rules.

    RULE A: a link whose own text asks the reader to take work on must not address one
    fixed issue. RULE B: prose must not reserve work by naming an issue number. Both are
    conditional in the same way `test_current_state_docs_name_every_framing_that_ships`
    is conditional -- a page is only held to them once it has chosen to make an
    invitation -- so ordinary prose that never offers work is left entirely alone and
    what fails is the real failure mode.
    """
    result = _run(_ROOT)
    assert result.returncode == 0, result.stdout + result.stderr


def test_the_gate_is_reading_the_documentation_rather_than_an_empty_set() -> None:
    """A guard that scans nothing passes everything.

    This repository has shipped that mistake more than once -- a green a11y gate that
    asserted nothing, a `check_bcp47.py` that walked a directory it no longer had, a
    fuzz assertion that could not fail -- so the counts are asserted rather than
    assumed. The floors are deliberately far below today's numbers: they exist to
    notice that the walker or the link parser has stopped working, not to freeze how
    much documentation the project is allowed to have.
    """
    result = _run(_ROOT, "--mode", "citations")
    assert result.returncode == 0, result.stdout + result.stderr
    header = re.match(r"(\d+) pages, (\d+) links, (\d+) fixed-issue citations", result.stdout)
    assert header, f"the citation report changed shape: {result.stdout[:200]!r}"
    pages, links, cited = (int(value) for value in header.groups())
    assert pages >= 50, f"only {pages} pages were walked; docs/ and site/ hold far more"
    assert links >= 200, f"only {links} links were parsed; the link parser is not working"
    assert cited >= 1, (
        f"{cited} links to a fixed issue were found. That is not impossible -- the "
        "documents may legitimately stop citing issue numbers -- but it is also exactly "
        "what a broken URL pattern looks like, and the scheduled resolver would have "
        "nothing left to check. Confirm by hand before relaxing this."
    )


def test_a_finished_run_linked_as_a_record_is_not_read_as_an_invitation(tmp_path: Path) -> None:
    """The control: the page #254 fixed must stay green.

    Four of the issues the review page links are closed *on purpose*. The tasks are
    repeatable by design -- a second keyboard walk on other hardware is a result, not a
    duplicate -- so each finished run keeps its own thread and the page links those
    threads as the record of a run. A checker that failed on "links to a closed issue"
    would go red on content that is correct, and a guard that cries wolf gets deleted
    rather than fixed. So this asserts the distinction from the safe side: the record
    links are classified as records, and the claim next to them still opens the form.
    """
    _plant(tmp_path, "site/review/index.html", _CURRENT_REVIEW_PAGE)
    offline = _run(tmp_path)
    assert offline.returncode == 0, offline.stdout + offline.stderr

    listing = _run(tmp_path, "--mode", "citations")
    assert listing.returncode == 0, listing.stdout + listing.stderr
    for number in (123, 122, 121, 125):
        assert f"habitable#{number} [?] record" in listing.stdout, (
            f"#{number} is linked as the record of a finished run and was classified as "
            f"an invitation:\n{listing.stdout}"
        )
    # The issue *form* is not a fixed issue, so it is not a citation at all -- which is
    # the whole reason #254's fix chose that shape.
    assert "issues/new" not in listing.stdout


def test_the_gate_catches_the_six_claim_links_issue_254_found(tmp_path: Path) -> None:
    """FAIL-BEFORE, planted: the review page as it read the day #254 was filed.

    Reading the checker proves the rule is written; it does not prove the rule can
    fail. So the pre-fix markup is planted and the gate is required to name every one
    of the six rows -- including `#124` and `#126`, which were still open at the time.
    That is deliberate and is the offline half's one real advantage over the network
    half: an invitation addressed to a single issue number is stale-by-construction, so
    it fails here the day it is written rather than the day somebody closes it.
    """
    _plant(tmp_path, "site/review/index.html", _PRE_254_REVIEW_PAGE)
    result = _run(tmp_path)
    assert result.returncode != 0, f"the gate accepted six dead claim links:\n{result.stdout}"
    for number in (121, 122, 123, 124, 125, 126):
        assert f"Claim task #{number}" in result.stdout, (
            f"the failure does not name #{number}:\n{result.stdout}"
        )
    assert "link an issue form or a label query instead" in result.stdout


def test_the_gate_catches_the_wording_that_reserved_already_shipped_work(tmp_path: Path) -> None:
    """FAIL-BEFORE, planted: the four sentences b67b44a had to remove by hand.

    These are quoted from `ROADMAP.md` and `docs/novel-use-cases-plan.md` as they read
    before b67b44a. Each was true when written and false once `ew_disrepair` shipped and
    #207 closed, and nothing in the tree changed on either day -- which is why a reader
    deciding what to contribute was still being pointed at finished work weeks later.
    """
    reserved = (
        "jurisdiction template growth ... is left open for a first-time contributor "
        "(issue #207), still gated on a named legal reviewer.\n\n"
        "It is doubly gated, and deliberately so: it is reserved as good first issue "
        "#207 because a sustained outside contributor is an open exit criterion.\n"
    )
    _plant(tmp_path, "docs/planning.md", reserved)
    result = _run(tmp_path)
    assert result.returncode != 0, f"the gate accepted a reservation by number:\n{result.stdout}"
    assert result.stdout.count("reserves work by naming issue #207") == 2, result.stdout
    assert "goes stale silently when that issue closes" in result.stdout


@pytest.mark.parametrize(
    "prose",
    [
        pytest.param(
            "Issue #207 shipped `ew_disrepair`, so the engineering path is walked, not "
            "hypothetical; further framings stay open to a newcomer, since a sustained "
            "outside contributor is an open workstream-D exit criterion.",
            id="b67b44a's own replacement wording",
        ),
        pytest.param(
            "See the [capability and claim ledger](capabilities.md), added in claim-ledger PR #84.",
            id="a claim ledger is not a claim on work",
        ),
        pytest.param(
            "Those threads are closed and stay closed—they are the record of a run, "
            "not a claim on the task.",
            id="a sentence that denies being a claim",
        ),
        pytest.param(
            "Pick one of the issues labeled [`good first issue`]"
            "(https://github.com/ChelseaKR/habitable/issues?q=is%3Aopen+label%3A%22good+"
            "first+issue%22) directly.",
            id="a label query, which is the shape the rules ask for",
        ),
    ],
)
def test_correct_prose_is_left_alone(tmp_path: Path, prose: str) -> None:
    """The four sentences most likely to be flagged wrongly, and must not be.

    Every one of these is real text from this repository, and the first is the sentence
    b67b44a wrote *as the fix*. A guard that fired on it would be telling the maintainer
    that the correct version of a document is the broken one, and would be switched off
    within a week. The rules are narrow for this reason and not by accident: the verb has
    to govern the number ("reserved as ... #207"), the head of a link's text has to be
    the ask ("Claim task ..."), and a hyphenated compound or a pull-request number is
    neither.
    """
    _plant(tmp_path, "docs/prose.md", f"# Prose\n\n{prose}\n")
    result = _run(tmp_path)
    assert result.returncode == 0, (
        f"the gate reported correct prose as a stale invitation:\n{result.stdout}"
    )


def test_dated_records_are_out_of_scope_on_purpose(tmp_path: Path) -> None:
    """An ADR or an audit says what was true on the day it was written.

    b67b44a held its own guard off them for this reason and the reasoning carries over
    unchanged: editing a record so that it stops naming work that really was open then
    would falsify the record, which is the opposite of the property being protected. So
    `docs/adr/`, `docs/audits/`, `docs/research/` and the dated roadmap drains may say
    "reserved as good first issue #207" forever, and the live planning documents may not.
    """
    reserved = "It is reserved as good first issue #207 until a newcomer takes it.\n"
    _plant(tmp_path, "docs/adr/0013-jurisdiction-framing.md", reserved)
    _plant(tmp_path, "docs/audits/some-audit.md", reserved)
    _plant(tmp_path, "docs/research/a-spike.md", reserved)
    _plant(tmp_path, "docs/roadmap-drain-2026-07-22.md", reserved)
    records_only = _run(tmp_path)
    assert records_only.returncode == 0, records_only.stdout + records_only.stderr

    _plant(tmp_path, "docs/novel-use-cases-plan.md", reserved)
    result = _run(tmp_path)
    assert result.returncode != 0, "a live planning document got the record exemption"
    assert "docs/novel-use-cases-plan.md" in result.stdout
    assert "docs/adr/" not in result.stdout


def test_the_resolver_fails_on_a_closed_issue_offered_as_claimable(tmp_path: Path) -> None:
    """The network half, proven able to fail without a network.

    `--states` substitutes a saved answer for the GitHub API so the *decision* is
    exercised here rather than only in a weekly job nobody has ever seen go red. The
    states below are the real ones from #254's table: #123, #122, #121 and #125 closed,
    #124 and #126 open. The run must name exactly the four that were closed -- naming
    all six would mean it was failing on "claimable" alone and had learned nothing from
    the tracker, and naming none would mean the schedule is decorative.
    """
    _plant(tmp_path, "site/review/index.html", _PRE_254_REVIEW_PAGE)
    states = _states(
        tmp_path,
        {
            "121": "closed",
            "122": "closed",
            "123": "closed",
            "125": "closed",
            "124": "open",
            "126": "open",
        },
    )
    result = _run(tmp_path, "--mode", "resolve", "--states", str(states))
    assert result.returncode != 0, f"a closed task was still claimable:\n{result.stdout}"
    failures = [line for line in result.stdout.splitlines() if line.startswith("::error::")]
    assert len(failures) == 4, f"expected #254's four closed rows, got:\n{result.stdout}"
    for number in (121, 122, 123, 125):
        assert any(f"habitable#{number} as claimable work" in line for line in failures), (
            f"#{number} was closed and offered as claimable, and was not reported"
        )
    for number in (124, 126):
        assert not any(f"habitable#{number} as" in line for line in failures), (
            f"#{number} was open; failing on it would make the tracker lookup pointless"
        )


def test_the_resolver_accepts_a_closed_issue_that_is_cited_as_a_record(tmp_path: Path) -> None:
    """The same four closed issues, linked the way the page links them today.

    This is the assertion that decides whether the whole check is usable. If a closed
    issue cited as a record failed here, the scheduled job would go red every week on
    `site/review/index.html` and `docs/embedding-the-verifier.md`, both of which are
    correct, and the job would be switched off. The distinction is carried entirely by
    how the page presents the link, which is the one signal a document controls on
    purpose.
    """
    _plant(tmp_path, "site/review/index.html", _CURRENT_REVIEW_PAGE)
    states = _states(
        tmp_path,
        {"121": "closed", "122": "closed", "123": "closed", "125": "closed"},
    )
    result = _run(tmp_path, "--mode", "resolve", "--states", str(states))
    assert result.returncode == 0, (
        f"a closed issue linked as the record of a finished run failed the gate:\n{result.stdout}"
    )
    assert "4 closed issue(s) are cited as records" in result.stdout


def test_the_resolver_refuses_to_report_green_when_it_read_nothing(tmp_path: Path) -> None:
    """A run that collected nothing and a run that found nothing are not the same.

    Issue #255 removed a required accessibility context that was a bare `echo`, and the
    lesson was that a job which cannot tell those two states apart reports the second
    when it means the first. If the page walker or the link parser ever stops matching,
    this job must go red and cost a maintainer an email, not go green and cost a
    volunteer eleven days.
    """
    (tmp_path / "docs").mkdir()
    result = _run(tmp_path, "--mode", "resolve")
    assert result.returncode != 0, "an empty tree resolved to a green"
    assert "checked nothing" in result.stdout


def test_the_scheduled_workflow_still_runs_the_resolver_it_claims_to() -> None:
    """The workflow, held to the four things that would silently hollow it out.

    A scheduled job is the easiest place in a repository to keep a check that no longer
    checks anything: nobody reads a green weekly run. So the trigger, the invocation, the
    absence of the test seam, and the action pinning are asserted from the YAML rather
    than trusted. The `--states` assertion is the important one -- passing it in CI would
    turn the only network check this project has into a job that reads a file the
    repository itself wrote and agrees with it.
    """
    text = _WORKFLOW.read_text(encoding="utf-8")
    assert re.search(r"^\s+- cron: \"[\d *]+\"", text, re.MULTILINE), "the schedule is gone"
    assert "workflow_dispatch:" in text, "the job can no longer be run by hand"
    assert "--mode resolve" in text, "the workflow no longer runs the resolver"
    assert "--states" not in re.sub(r"^\s*#.*$", "", text, flags=re.MULTILINE), (
        "the workflow passes the test seam, so the scheduled job would resolve issue "
        "state from a file in this repository instead of from the tracker"
    )
    assert "permissions:\n  contents: read\n" in text, "the top-level scope widened"

    for action in re.findall(r"uses: (\S+)", text):
        assert re.search(r"@[0-9a-f]{40}$", action), f"{action} is not pinned to a commit SHA"

    # `${{ }}` reaches the shell through `env:` only. zizmor fails the repository over
    # this and it is not a formality: a value interpolated into a script body is
    # executed by it.
    script = text.split("run: |", 1)[1]
    assert "${{" not in script, "an expression is interpolated into the step's script body"
