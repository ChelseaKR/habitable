# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Fail when a page invites a contributor to work that is no longer available.

Three times this project has pointed a volunteer at finished work, and each time the
fix was local to the one document that was wrong:

* **#208** asked for a pseudo-locale / text-expansion check that had shipped six weeks
  earlier. An outside contributor opened PR #213 against it and kept the branch current
  for eleven days before anyone noticed the work already existed.
* **b67b44a** ("stop the planning docs reserving jurisdiction work that already
  shipped") corrected four sentences that reserved `ew_disrepair` for a newcomer --
  "left open for a first-time contributor (issue #207)", "reserved as good first issue
  #207" -- after #207 had closed.
* **#254** found four of the six "Claim task" links on the public review page landing on
  closed issues holding somebody else's completed answer.

The three fixes shared no machinery, so the fourth instance was going to be found by
another volunteer rather than by us. This is the machinery. It is deliberately split at
the line `make verify` draws, because that gate is offline and the strongest check needs
the tracker:

``--mode offline``
    Two structural rules, no network, safe in the merge gate. See `RULE A` and `RULE B`
    below. They check the *shape* of an invitation, never its truth.

``--mode resolve``
    Resolves every ``github.com/<owner>/<repo>/issues/<N>`` link in the scanned pages
    against the GitHub API and fails when one that is **presented as claimable** points
    at a **closed** issue. That is #254, caught automatically. It needs network, so it
    runs from `.github/workflows/stale-invitations.yml` on a schedule, not on a merge.

Standard library only, like `check_doc_links.py`, so the offline half can run before the
project's dependencies are installed and needs nothing but a checkout.

Distinguishing a record from an invitation
------------------------------------------
The review page as it stands links four **closed** issues on purpose -- "Four tasks
already carry one finished run: OR-01 (#123), LA-01 (#122) ..." -- because those threads
are the record of a completed run, not a claim on the task. A checker that failed on
"link to a closed issue" would go red on the page #254 had just fixed, and a guard that
cries wolf on correct content is worse than no guard at all.

So the classification is deliberately narrow and reads only signals a document controls
on purpose:

* the **link text** must open with a verb that asks the reader to take the work on
  ("Claim task OR-01"), or use one of a short list of claim idioms; or
* the link must sit inside a sentence that **reserves** work by issue number (RULE B).

Everything else is a record. "OR-01 (#123)" and "#159" are records. So is "capability and
claim ledger", which is why the head-of-text rule exists rather than a substring search
for "claim". What this buys is zero false positives on the current tree; what it costs is
stated plainly in `tests/test_stale_invitations.py` -- an invitation phrased around its
link rather than in it ("read the task, then claim it here") is not caught.
"""

from __future__ import annotations

import argparse
import html
import http.client
import json
import os
import re
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

# The pages a contributor actually reads to decide what to work on. `docs/**` and
# `site/**` are the scope issue #273 names; the three root files are here because
# ROADMAP.md is where two of b67b44a's four stale reservations lived, and a guard that
# could not see the document that failed would be theatre.
_SCANNED_TREES = (("docs", "*.md"), ("site", "*.html"))
_SCANNED_ROOT_FILES = ("README.md", "ROADMAP.md", "CONTRIBUTING.md")

# Dated records, excluded for the same reason b67b44a excluded them from its own guard:
# an ADR, an audit, a research note or a dated roadmap drain says what was true on the
# day it was written. Editing one so it stops naming work that was open *then* would
# falsify the record -- the exact opposite of the property this checker protects.
_DATED_RECORDS = (
    "docs/adr/",
    "docs/audits/",
    "docs/research/",
    "docs/roadmap-drain-",
)

_SKIP_PARTS = {".git", ".venv", "build", "dist", "htmlcov", "node_modules"}

# A link to one fixed issue on a GitHub repository. `issues/new`, `issues?q=...` and
# every other query form are NOT this: they are the shapes an invitation is allowed to
# take, because they survive somebody finishing the work.
_ISSUE_URL = re.compile(
    r"^https?://(?:www\.)?github\.com/([\w.-]+)/([\w.-]+)/issues/(\d+)(?:[/?#]|$)",
    re.IGNORECASE,
)

_MARKDOWN_LINK = re.compile(r"\[([^\]\n]*)\]\(\s*(<[^>\n]+>|[^\s)]+)[^)]*\)")
_HTML_LINK = re.compile(r"<a\b[^>]*\bhref=\"([^\"]*)\"[^>]*>(.*?)</a>", re.DOTALL | re.IGNORECASE)
_HTML_TAG = re.compile(r"<[^>]+>")
_FENCE = re.compile(r"^\s*(`{3,}|~{3,})")

# RULE A's vocabulary: the head of a link's own text. These are the words a page uses
# when it is handing the reader a job, and only those -- no bare "take", no bare "start",
# because "Take the tour" and "Start here" are navigation, not work.
_CLAIMING_HEAD = re.compile(
    r"^(?:claim|take on|take this on|take up|pick up|pick this up|grab|adopt"
    r"|volunteer for|sign up for|work on|start work on)\b",
    re.IGNORECASE,
)
# ... plus a short list of idioms that put the verb next to its object anywhere in the
# text. "claim ledger" is not one of them, which is the point.
_CLAIMING_IDIOM = re.compile(
    r"\b(?:claim|take on|pick up|grab)\s+(?:it|this|one|the\s+)?(?:task|issue|ticket)?\b"
    r"(?=\s*(?:#\d|$|[.,;:!?]))",
    re.IGNORECASE,
)

# RULE B's vocabulary: prose that reserves work. Every phrase here appears in one of the
# three real instances or is its direct paraphrase. The trailing `(?![-\w])` is load
# bearing: without it, "claim-ledger PR #84" in docs/evidence-pack.md is a false
# positive, and a guard that fires on correct prose gets deleted rather than fixed.
_RESERVING_VERB = (
    r"claim|claiming|claimed by|take on|take up|pick up|grab|adopt"
    r"|volunteer for|sign up for|work on"
    r"|reserved as|reserved for|left open for|left unclaimed|stays? unclaimed"
    r"|deliberately unclaimed|up for grabs"
    r"|open for a (?:contributor|newcomer|volunteer|first-timer)"
    r"|available for a (?:contributor|newcomer|volunteer)"
)
_RESERVED_BY_NUMBER = re.compile(
    rf"(?P<verb>{_RESERVING_VERB})(?![-\w])(?P<gap>[^.\n]{{0,60}}?)"
    rf"(?:\bissues?\s*)?#(?P<number>\d{{2,5}})\b",
    re.IGNORECASE,
)
# A pull request cited by number is not an open invitation to anything, and #84 is not
# issue #84. Checked against the text immediately before the `#` rather than folded into
# the pattern above, so the reason stays readable.
_PULL_REQUEST_PREFIX = re.compile(r"(?:\bpr|\bpull\s+request|\bpull)\s*$", re.IGNORECASE)

_API_HOST = "api.github.com"
_USER_AGENT = "habitable-stale-invitation-check"


@dataclass(frozen=True)
class Citation:
    """One reference from a page to one fixed issue, and how the page presents it."""

    path: str
    line: int
    owner: str
    repo: str
    number: int
    text: str
    claimable: bool
    why: str

    def where(self) -> str:
        return f"{self.path}:{self.line}"

    def slug(self) -> str:
        return f"{self.owner}/{self.repo}#{self.number}"


@dataclass(frozen=True)
class Link:
    line: int
    text: str
    href: str


def _pages(root: Path) -> list[Path]:
    """Every page a contributor reads to decide what to work on, records excluded."""
    found: list[Path] = []
    for directory, pattern in _SCANNED_TREES:
        base = root / directory
        if not base.is_dir():
            continue
        found.extend(
            path
            for path in base.rglob(pattern)
            if not any(part in _SKIP_PARTS for part in path.parts)
        )
    found.extend(root / name for name in _SCANNED_ROOT_FILES if (root / name).is_file())
    return sorted(
        path for path in found if not path.relative_to(root).as_posix().startswith(_DATED_RECORDS)
    )


def _normalize(text: str) -> str:
    """Link text as a reader sees it: no tags, no entities, no Markdown emphasis."""
    plain = html.unescape(_HTML_TAG.sub(" ", text))
    plain = plain.replace("`", "").replace("*", "").replace("_", " ")
    plain = re.sub(r"\s+", " ", plain).strip()
    # Leading decoration a template puts in front of the words -- arrows, bullets,
    # dashes -- is not part of what the link says. `#` and `(` are kept, because
    # "#159" and "(#123)" are exactly the record shapes this has to recognise.
    return re.sub(r"^[^\w#(]+", "", plain)


def _links(text: str, suffix: str) -> Iterator[Link]:
    """Every link on the page, with the line it starts on and its visible text."""
    if suffix == ".md":
        open_fence = ""
        for number, line in enumerate(text.splitlines(), 1):
            fence = _FENCE.match(line)
            if fence is not None:
                marker = fence.group(1)
                if not open_fence:
                    open_fence = marker
                elif marker[0] == open_fence[0] and len(marker) >= len(open_fence):
                    open_fence = ""
                continue
            if open_fence:
                continue
            for match in _MARKDOWN_LINK.finditer(line):
                href = match.group(2).strip()
                if href.startswith("<") and href.endswith(">"):
                    href = href[1:-1]
                yield Link(number, _normalize(match.group(1)), href)
        return
    for match in _HTML_LINK.finditer(text):
        starts_on = text.count("\n", 0, match.start()) + 1
        yield Link(starts_on, _normalize(match.group(2)), html.unescape(match.group(1).strip()))


def _reservations(text: str) -> Iterator[tuple[int, str, int]]:
    """``(line, matched phrase, issue number)`` for every RULE B reservation."""
    for number, line in enumerate(text.splitlines(), 1):
        for match in _RESERVED_BY_NUMBER.finditer(line):
            head = line[: match.start("number") - 1]
            if _PULL_REQUEST_PREFIX.search(head[-16:]):
                continue
            yield number, match.group(0).strip(), int(match.group("number"))


def _is_claiming(link_text: str) -> str:
    """Why this link text reads as an invitation, or ``""`` if it does not."""
    if _CLAIMING_HEAD.match(link_text):
        return "the link text opens by asking the reader to take the work on"
    if _CLAIMING_IDIOM.search(link_text):
        return "the link text uses a claim idiom"
    return ""


def citations(root: Path) -> tuple[list[Citation], int, int]:
    """Every fixed-issue reference in the scanned pages, classified.

    Returns the citations plus the page and link counts, because "nothing was found"
    and "nothing was read" are the two states this repository has been burned by
    confusing, and a caller must be able to tell them apart.
    """
    found: list[Citation] = []
    pages = _pages(root)
    links_seen = 0
    for page in pages:
        relative = page.relative_to(root).as_posix()
        text = page.read_text(encoding="utf-8")
        reserved_lines = {line: phrase for line, phrase, _ in _reservations(text)}
        for link in _links(text, page.suffix):
            links_seen += 1
            match = _ISSUE_URL.match(link.href)
            if match is None:
                continue
            why = _is_claiming(link.text)
            if not why and link.line in reserved_lines:
                why = f"the sentence around it reserves work: {reserved_lines[link.line]!r}"
            found.append(
                Citation(
                    path=relative,
                    line=link.line,
                    owner=match.group(1),
                    repo=match.group(2),
                    number=int(match.group(3)),
                    text=link.text or link.href,
                    claimable=bool(why),
                    why=why or "cited as a record",
                )
            )
    return found, len(pages), links_seen


def offline_problems(root: Path) -> list[str]:
    """RULE A and RULE B: the two things an offline gate can honestly know.

    RULE A -- **an invitation may not be addressed to one issue number.** A fixed issue
    is a single-use invitation: the first person to finish the work closes the thread,
    and nothing in the tree changes, so every reader after that is handed somebody
    else's finished answer. #254 was six of these. The shapes that survive completion --
    an issue *form* (``issues/new?template=...``) or a label query
    (``issues?q=is%3Aopen+label%3A...``) -- are what an invitation must use instead.

    RULE B -- **prose may not reserve work by naming an issue number.** "reserved as
    good first issue #207" and "left open for a first-time contributor (issue #207)"
    were true when written and false the day #207 closed, with nothing to notice it.
    Same remedy: point at the label query, which cannot go stale, and let the tracker
    say who holds what.

    Neither rule knows whether any issue is open. That needs the tracker, and this half
    is offline on purpose.
    """
    problems: list[str] = []
    for page in _pages(root):
        relative = page.relative_to(root).as_posix()
        text = page.read_text(encoding="utf-8")
        # A "Claim task #123" link trips both rules at once. Reporting it twice buries
        # the other findings, so RULE A -- the more specific diagnosis, with the remedy
        # attached -- speaks first and RULE B stays quiet about the same number.
        already: set[tuple[int, int]] = set()
        for link in _links(text, page.suffix):
            match = _ISSUE_URL.match(link.href)
            if match is None or not _is_claiming(link.text):
                continue
            already.add((link.line, int(match.group(3))))
            problems.append(
                f"{relative}:{link.line}: {link.text!r} invites a reader to take on work "
                f"but links to one fixed issue ({link.href}). That invitation dies the "
                "moment somebody closes it; link an issue form or a label query instead."
            )
        for line, phrase, number in _reservations(text):
            if (line, number) in already:
                continue
            problems.append(
                f"{relative}:{line}: {phrase!r} reserves work by naming issue #{number}. "
                "The reservation goes stale silently when that issue closes; describe "
                "the work and link the `good first issue` label query instead."
            )
    return sorted(problems)


def _fetch_state(owner: str, repo: str, number: int, token: str | None) -> str:
    """``open`` / ``closed`` for one issue, straight from the tracker.

    `http.client` rather than `urllib.request` so the scheme is structurally https and
    the URL is assembled from a validated owner, repo and integer -- there is no string
    a document could contain that redirects this somewhere else.
    """
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": _USER_AGENT,
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    connection = http.client.HTTPSConnection(_API_HOST, timeout=30)
    try:
        connection.request("GET", f"/repos/{owner}/{repo}/issues/{number}", headers=headers)
        response = connection.getresponse()
        body = response.read()
        if response.status == 404:
            return "missing"
        if response.status != 200:
            raise RuntimeError(
                f"GitHub answered {response.status} for {owner}/{repo}#{number}: {body[:200]!r}"
            )
        state = json.loads(body).get("state")
    finally:
        connection.close()
    if state not in {"open", "closed"}:
        raise RuntimeError(f"GitHub reported no usable state for {owner}/{repo}#{number}")
    return str(state)


def _states(found: list[Citation], stub: Path | None) -> dict[int, str]:
    if stub is not None:
        raw: dict[str, str] = json.loads(stub.read_text(encoding="utf-8"))
        return {int(key): value for key, value in raw.items()}
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    resolved: dict[int, str] = {}
    for citation in found:
        if citation.number not in resolved:
            resolved[citation.number] = _fetch_state(
                citation.owner, citation.repo, citation.number, token
            )
    return resolved


def resolve_problems(found: list[Citation], states: dict[int, str]) -> list[str]:
    """The network half's verdict, kept a pure function of the resolved states.

    Split out from the fetching so `tests/test_stale_invitations.py` can hand it a
    closed issue and prove the job goes red -- the alternative being a scheduled
    workflow nobody has ever seen fail, which is this repository's most-repeated
    defect (a green a11y gate that asserted nothing, a dead `check_bcp47.py`, a fuzz
    assertion that could not fail).
    """
    problems: list[str] = []
    for citation in sorted(found, key=lambda item: (item.path, item.line, item.number)):
        state = states.get(citation.number, "unresolved")
        if state == "missing":
            problems.append(
                f"{citation.where()}: cites {citation.slug()}, which the tracker does not "
                "have. A link to an issue that does not exist is broken either way."
            )
            continue
        if state == "unresolved":
            problems.append(
                f"{citation.where()}: {citation.slug()} was never resolved, so this run "
                "checked nothing about it."
            )
            continue
        if citation.claimable and state == "closed":
            problems.append(
                f"{citation.where()}: {citation.text!r} offers {citation.slug()} as "
                f"claimable work, and that issue is CLOSED -- {citation.why}. A visitor "
                "who follows it lands on somebody else's finished answer (#254)."
            )
    return problems


def _report(found: list[Citation], states: dict[int, str]) -> str:
    lines = []
    for citation in sorted(found, key=lambda item: (item.path, item.line)):
        role = "CLAIMABLE" if citation.claimable else "record"
        lines.append(
            f"  {citation.where()}: {citation.slug()} [{states.get(citation.number, '?')}] "
            f"{role} — {citation.text!r}"
        )
    return "\n".join(lines)


def _run_offline(root: Path) -> int:
    problems = offline_problems(root)
    if problems:
        print("stale-invitation gate failed:")
        for problem in problems:
            print(f"- {problem}")
        return 1
    found, pages, links = citations(root)
    print(
        f"stale invitations: OK — {pages} pages, {links} links, {len(found)} fixed-issue "
        "citations, none of them shaped as an invitation. Whether those issues are still "
        "open is not knowable offline; `--mode resolve` answers that."
    )
    return 0


def _run_citations(root: Path) -> int:
    found, pages, links = citations(root)
    print(f"{pages} pages, {links} links, {len(found)} fixed-issue citations:")
    print(_report(found, {}))
    return 0


def _run_resolve(root: Path, stub: Path | None) -> int:
    found, pages, links = citations(root)
    if not pages or not links:
        # "Nothing was collected" and "nothing was wrong" are different answers, and a
        # scheduled job that cannot tell them apart is the always-green this project
        # keeps deleting (#255). A parser that stopped matching must go red.
        print(
            f"::error::read {pages} pages and {links} links, so this run checked nothing; "
            "refusing to report a green that asserted no property"
        )
        return 1
    states = _states(found, stub)
    problems = resolve_problems(found, states)
    print(f"{pages} pages, {links} links, {len(found)} fixed-issue citations resolved:")
    print(_report(found, states))
    if problems:
        print("\nstale-invitation gate failed:")
        for problem in problems:
            print(f"::error::{problem}")
        return 1
    closed = sum(1 for citation in found if states.get(citation.number) == "closed")
    print(
        f"\nOK — every claimable link points at an open issue. {closed} closed "
        "issue(s) are cited as records, which is what a record is for."
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="repository root (defaults to the parent of scripts/)",
    )
    parser.add_argument(
        "--mode",
        choices=("offline", "citations", "resolve"),
        default="offline",
        help="offline: the two structural rules, no network. citations: list what a "
        "resolve run would query. resolve: ask the tracker and fail on a closed "
        "issue offered as claimable work.",
    )
    parser.add_argument(
        "--states",
        type=Path,
        default=None,
        help="JSON mapping of issue number to open/closed, used INSTEAD of querying "
        "GitHub. This is the seam the test suite injects a closed issue through, and "
        "re-checks a saved API answer with; CI must never pass it, or the scheduled "
        "job would grade its own homework.",
    )
    args = parser.parse_args(argv)
    root = args.root.resolve()
    if args.mode == "offline":
        return _run_offline(root)
    if args.mode == "citations":
        return _run_citations(root)
    return _run_resolve(root, args.states)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
