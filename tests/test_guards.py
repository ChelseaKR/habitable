# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Invariant guards: no custody-actor identity in exports, and a verifier that stays
within its Apache-2.0 redistributable subset.

These pin two promises the project makes elsewhere in prose: a packet proves custody
*without naming who did what* (threat model §4, README hard rules), and the
verification subset can be embedded under Apache-2.0 without dragging in AGPL-only
modules (verify.py docstring, NOTICE)."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

import pytest

from habitable.capture import capture
from habitable.packet import build_packet
from habitable.sync import LocalDirTransport, sync
from habitable.tsa import LocalRfc3161TSA
from habitable.vault import Vault

_GENERATED_AT = "2026-01-02T00:10:00Z"
_TENANT_FILENAME = "TENANT-PRIVATE-FILENAME-9e21.jpg"
_A11Y_WORKFLOW = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "a11y.yml"


def test_packet_ids_do_not_encode_passphrase_derived_material(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    """FIX-01 regression: pre-fix, node_id = sha256(case_id+passphrase)[:16] was written
    to plaintext config.toml AND embedded in every exported id, letting an adversary with
    a seized device or a court packet brute-force the passphrase and bypass scrypt. Assert
    that value appears nowhere derivable — fail the build if the leak ever recurs."""
    case_id = "case-fix01"
    passphrase = "correct horse battery staple"
    leaked = "2f13b8afac7a8422"  # pre-FIX-01 sha256(case_id + passphrase)[:16]

    vault = make_vault(case_id=case_id, passphrase=passphrase)
    issue = vault.document.add_issue(category="mold", issue_id="i1")
    capture(vault, make_jpeg(), issue_id=issue, tsa=local_tsa)

    # The device id itself is random, not the passphrase-derived value.
    assert vault.document.clock.node_id != leaked

    # No passphrase-derived material in the two plaintext bootstrap files ...
    config_text = (vault.path / "config.toml").read_text(encoding="utf-8")
    assert leaked not in config_text
    assert "node_id" not in config_text
    assert leaked not in (vault.path / "keyfile.json").read_text(encoding="utf-8")

    # ... nor in the exported packet the modelled adversary (opposing counsel) receives.
    out = tmp_path / "packet"
    build_packet(vault, out, generated_at=_GENERATED_AT)
    assert leaked not in (out / "bundle.json").read_text(encoding="utf-8")


def test_export_drops_source_filename_and_importing_peer_identity(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    a = make_vault("A")
    b = make_vault("B", passphrase="pw-b")
    issue = a.document.add_issue(category="mold", issue_id="i1")
    capture(a, make_jpeg(_TENANT_FILENAME), issue_id=issue, tsa=local_tsa)

    # 1. The producer's OWN packet must not carry the tenant's source filename.
    out_a = tmp_path / "packet-a"
    build_packet(a, out_a, generated_at=_GENERATED_AT)
    bundle_a = (out_a / "bundle.json").read_text(encoding="utf-8")
    assert _TENANT_FILENAME not in bundle_a

    # 2. After B imports the item from A and exports, A's fingerprint — a custody-actor
    #    identity — must not appear, though B's own producer fingerprint legitimately may.
    transport = LocalDirTransport(tmp_path / "mbox")
    sync(a, b.identity.public(), transport, channel="room")
    sync(b, a.identity.public(), transport, channel="room")
    out_b = tmp_path / "packet-b"
    build_packet(b, out_b, generated_at=_GENERATED_AT)
    bundle_b = (out_b / "bundle.json").read_text(encoding="utf-8")

    a_fingerprint = a.identity.public().fingerprint
    assert a_fingerprint not in bundle_b
    assert b.identity.public().fingerprint in bundle_b  # producer identity is deliberate
    assert _TENANT_FILENAME not in bundle_b

    # 3. The vault still RETAINS the audit trail privately — moved, not deleted.
    imported = [e for e in b.custody.entries if e.action == "imported"]
    assert imported and imported[0].private_details.get("from") == a_fingerprint


def test_packet_ids_do_not_encode_wall_clock_or_node_id(
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    """A shared packet must not encode the device wall clock or the HLC node id in any
    exported identifier (issue/capture/timeline) or timestamp field. HLC stays the
    internal CRDT ordering key; the externally visible names are opaque, per-case-salted
    digests (packet v2). This pins the north-star promise that "nothing leaked"."""
    known_ms = 1_767_312_000_000  # a fixed device wall clock the export must never reveal
    vault = Vault.create(
        tmp_path / "vault", "pw", case_id="guard-4B", unit="4B", time_source=lambda: known_ms
    )
    node_id = vault.document.clock.node_id
    issue = vault.document.add_issue(category="mold", room="bathroom", title="mold")
    vault.document.add_timeline_entry(issue, "observed", "mold spreading after roof leak")
    vault.save()
    capture(vault, make_jpeg("evidence.jpg"), issue_id=issue, tsa=local_tsa)

    out = tmp_path / "packet"
    build_packet(vault, out, generated_at=_GENERATED_AT)
    bundle = (out / "bundle.json").read_text(encoding="utf-8")

    # No field encodes the raw HLC (15-digit ms . 6-digit counter . node_id) ...
    assert re.search(r"\d{15}\.\d{6}\.", bundle) is None
    # ... and neither the wall-clock ms (plain or zero-padded) nor the node id leaks anywhere.
    assert str(known_ms) not in bundle
    assert f"{known_ms:015d}" not in bundle
    assert node_id and node_id not in bundle
    # The ids are still present and opaque — the prefix is kept, the wall/node body is not.
    assert issue.startswith("issue-")
    assert '"cap-' in bundle and '"tl-' in bundle


# The exact module set the Apache-2.0 verification subset is allowed to load:
# verify + the pure helpers it imports, plus the side-effect-free parent package.
_ALLOWED_VERIFIER_MODULES = {
    "habitable",
    "habitable.canonical",
    "habitable.crypto",
    "habitable.errors",
    "habitable.evidence",
    "habitable.timeline",
    "habitable.tsa",
    "habitable.verify",
}


def test_verifier_imports_stay_within_apache_subset() -> None:
    """Importing habitable.verify must not pull in AGPL-only/heavy modules (relay, sync,
    cli, packet, pdf, app, capture, vault, ...). Run in a fresh process so an earlier
    test that imported those cannot mask a leak."""
    probe = (
        "import habitable.verify, sys;"
        "loaded={m for m in sys.modules if m == 'habitable' or m.startswith('habitable.')};"
        f"allowed={sorted(_ALLOWED_VERIFIER_MODULES)!r};"
        "extra=sorted(loaded - set(allowed));"
        "print('EXTRA:' + ','.join(extra));"
        "sys.exit(1 if extra else 0)"
    )
    result = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, (
        f"verifier pulled in non-subset modules: {result.stdout.strip()} {result.stderr.strip()}"
    )


# The import closure of habitable.verify — the source an embedder vendors and must be
# able to run on Python < 3.14 (verify.py docstring, NOTICE, docs/embedding-the-verifier.md).
_VERIFIER_SUBSET_FILES = (
    "canonical.py",
    "crypto.py",
    "errors.py",
    "evidence.py",
    "timeline.py",
    "tsa.py",
    "verify.py",
)
_EXCEPT_CLAUSE = re.compile(r"^\s*except\s+([^\n:]+):")


def test_verifier_subset_avoids_py314_only_except_syntax() -> None:
    """The Apache-2.0 verifier subset must avoid PEP 758 parenthesis-free multi-type
    `except A, B:` — valid only on Python >= 3.14 and a SyntaxError before it, which would
    break legal-aid embedders who vendor the subset onto older interpreters. The ruff
    formatter targets py314 and will try to reintroduce it, so this guard fails the gate
    if it does; reference a named tuple (e.g. `except _SOME_ERRORS:`) instead."""
    src = Path(__file__).resolve().parent.parent / "src" / "habitable"
    offenders: list[str] = []
    for name in _VERIFIER_SUBSET_FILES:
        for lineno, line in enumerate(src.joinpath(name).read_text("utf-8").splitlines(), 1):
            match = _EXCEPT_CLAUSE.match(line)
            if match is None:
                continue
            clause = match.group(1).strip()
            # `except (A, B):` is portable; `except A, B:` is the 3.14-only form.
            if "," in clause and not clause.startswith("("):
                offenders.append(f"{name}:{lineno}: {line.strip()}")
    assert not offenders, "parenthesis-free multi-type except in verifier subset:\n" + "\n".join(
        offenders
    )


def test_verifier_vocabulary_mirrors_the_use_case_registry() -> None:
    """`verify.py` restates the artifact/relationship vocabulary instead of importing
    it, because the Apache-2.0 subset must not depend on `habitable.usecases` (see the
    import guard above). Restating buys independence and costs drift: a term added to
    the registry but not to the verifier means a vault happily seals evidence that its
    own verifier then rejects, and an endpoint pair loosened on only one side means the
    two disagree about what is valid. Nothing but this test holds the copies equal."""
    from habitable import usecases, verify

    assert set(usecases.ARTIFACT_TYPES) == verify._ARTIFACT_TYPES
    assert set(usecases.RELATIONSHIP_TYPES) == verify._RELATIONSHIP_TYPES
    assert set(verify._RELATIONSHIP_ENDPOINT_KINDS) == set(usecases.RELATIONSHIP_ENDPOINT_KINDS)
    for relationship_type, pairs in usecases.RELATIONSHIP_ENDPOINT_KINDS.items():
        assert verify._RELATIONSHIP_ENDPOINT_KINDS[relationship_type] == set(pairs), (
            f"verifier and registry disagree on {relationship_type} endpoints"
        )
    # Every relationship type is constrained on both sides. A type present in the
    # vocabulary but absent from the endpoint table would accept any pair of records,
    # and the verifier's own check is written to skip an unknown key rather than fail.
    assert set(usecases.RELATIONSHIP_ENDPOINT_KINDS) == set(usecases.RELATIONSHIP_TYPES)


# --- the accessibility gate must be capable of failing --------------------------

# `make a11y` / the `a11y.yml` workflow run `pytest -m a11y`, and
# `axe-core WCAG scan (merge gate)` is a *required* status check in
# `.github/rulesets/main-branch.json`. Every test behind that marker guards its
# browser dependency with `pytest.importorskip` or `pytest.skip(...)` on a
# Playwright launch error, which is right for a contributor with no Chromium --
# and wrong for the merge gate, because pytest exits 0 when every selected test
# skips. If `playwright` or `axe-playwright-python` ever left the dev dependency
# group, or Chromium installed but would not launch, the required accessibility
# gate would report green having asserted nothing at all.
#
# This repo already writes this guard elsewhere (`test_golden.py`'s "no golden
# packets committed", `test_verify_fuzz.py`'s `assert _NAMES`); the a11y suite was
# the one required gate without it.
_MIN_A11Y_TESTS = 20


def test_the_accessibility_marker_still_selects_a_real_suite() -> None:
    """`pytest -m a11y` must select tests, not an empty set.

    A renamed or dropped marker, or a `pytest.ini` filter change, would otherwise
    turn the required gate into a no-op that still exits 0.
    """
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-m", "a11y", "--collect-only", "-q"],
        cwd=Path(__file__).resolve().parent.parent,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"a11y collection failed:\n{result.stdout}\n{result.stderr}"
    match = re.search(r"(\d+)/\d+ tests collected", result.stdout)
    assert match is not None, f"could not read a collected count from:\n{result.stdout[-2000:]}"
    collected = int(match.group(1))
    assert collected >= _MIN_A11Y_TESTS, (
        f"`pytest -m a11y` selected only {collected} test(s), below the floor of "
        f"{_MIN_A11Y_TESTS}. The accessibility merge gate is required, so an empty "
        "or gutted selection would pass it while checking nothing."
    )


def _browser_installing_job() -> str:
    """The `a11y.yml` job key whose steps install Chromium on purpose.

    Derived rather than hard-coded, so renaming the job is caught here instead
    of turning the guard below into a permanent skip -- which would be this
    file's own subject matter, a check that cannot fail.
    """
    text = _A11Y_WORKFLOW.read_text(encoding="utf-8")
    jobs = text.split("\njobs:\n", 1)
    assert len(jobs) == 2, "a11y.yml no longer has a jobs: block"
    current = ""
    for line in jobs[1].splitlines():
        key = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if key:
            current = key.group(1)
        elif "playwright install" in line:
            assert current, "a playwright install step outside any job"
            return current
    raise AssertionError(
        "no job in a11y.yml installs Chromium any more; the axe gate cannot be "
        "running a browser, so the required context it publishes asserts nothing"
    )


def test_the_browser_stack_is_a_failure_in_ci_not_a_skip() -> None:
    """In the axe job, a missing browser must fail rather than silently skip.

    Locally this skips: a contributor fixing a typo should not need Chromium.
    The scope is the *job that installs the browser on purpose* and then
    publishes `axe-core WCAG scan (merge gate)`, not CI at large: the
    `lint - types - tests` job deliberately installs no browser, so keying on
    `CI` alone asserted Chromium in a job that never had it and failed the
    merge gate for the absence it was designed to tolerate.

    Where it does apply, the point stands unchanged: the browser is installed
    on purpose there, so its absence means the gate did not run -- and a gate
    that did not run must not report success. That is the whole difference
    between "the scan found no violations" and "no scan happened".
    """
    job = _browser_installing_job()
    if os.environ.get("GITHUB_JOB") != job:
        pytest.skip(
            f"browser stack is asserted in the {job!r} job, which installs it; "
            "every other run may skip"
        )

    import axe_playwright_python.sync_playwright  # noqa: F401
    from playwright.sync_api import sync_playwright

    with sync_playwright() as driver:
        browser = driver.chromium.launch()
        try:
            assert browser.version, "Chromium launched but reported no version"
        finally:
            browser.close()


# --- the docs-only a11y twin must stay a true complement ------------------------


def test_the_a11y_docs_only_twin_matches_the_real_scans_ignore_list() -> None:
    """`a11y-docs-only.yml` reports a REQUIRED context with nothing but an `echo`.

    That is deliberate (CICD-STANDARD §11h): the real axe scan skips docs-only PRs
    via `paths-ignore`, and a required context that never reports leaves a PR stuck
    on "Expected — waiting for status". The twin publishes the same context name so
    docs-only PRs stay mergeable.

    Both files say in prose that the twin's `paths` "must stay the exact complement"
    of the real scan's `paths-ignore`, and until now nothing enforced it. If the real
    scan's ignore list grew an entry the twin did not, a PR touching only that path
    would skip the real scan *and* the twin, and the required context would never
    report. If the twin's list grew an entry the real scan did not ignore, an
    `echo` would satisfy the accessibility gate for a change that really does touch
    the UI.

    The topology is still the owner's call (issue #255 weighed a single conditional
    job against this), so on a PR touching both docs and code both jobs still run,
    both report to the same context, and GitHub still resolves it to whichever
    reported last. What changed is what the twin's report is worth. It used to be a
    bare `echo` -- an unconditional green that could win that race after a re-run or
    a cancelled scan, on a PR that really did touch the UI. It now reads the pull
    request's own changed-file list and refuses to report green for anything outside
    the set below, so the twin's last word is a red that blocks a merge rather than
    a green that asserted nothing. The two tests after this one pin the glob list it
    checks against and run the check itself against a planted code path.
    """
    workflows = Path(__file__).resolve().parent.parent / ".github" / "workflows"
    real = (workflows / "a11y.yml").read_text(encoding="utf-8")
    twin = (workflows / "a11y-docs-only.yml").read_text(encoding="utf-8")

    def path_globs(text: str, key: str) -> list[list[str]]:
        """Every `key:` block's list of quoted globs, in file order."""
        blocks: list[list[str]] = []
        lines = text.splitlines()
        for index, line in enumerate(lines):
            if line.strip() != f"{key}:":
                continue
            entries: list[str] = []
            for follow in lines[index + 1 :]:
                match = re.match(r'\s+-\s+"([^"]+)"\s*$', follow)
                if not match:
                    break
                entries.append(match.group(1))
            blocks.append(entries)
        return blocks

    ignored = path_globs(real, "paths-ignore")
    included = path_globs(twin, "paths")

    assert ignored, "a11y.yml declares no paths-ignore; this guard is reading nothing"
    assert included, "a11y-docs-only.yml declares no paths; this guard is reading nothing"

    # Every paths-ignore block in the real scan must be the same set.
    for block in ignored:
        assert set(block) == set(ignored[0]), f"a11y.yml's paths-ignore blocks disagree: {ignored}"

    assert set(included[0]) == set(ignored[0]), (
        "the docs-only twin's `paths` is no longer the exact complement of "
        f"a11y.yml's `paths-ignore`.\n  twin paths:       {sorted(included[0])}\n"
        f"  real paths-ignore: {sorted(ignored[0])}\n"
        "A mismatch either strands the required context with no report, or lets an "
        "`echo` satisfy the accessibility gate for a change that touches the UI."
    )

    # And the twin really must be publishing the required context name, or the
    # complement above is checking a relationship that no longer matters.
    required = (
        Path(__file__).resolve().parent.parent / ".github" / "rulesets" / "main-branch.json"
    ).read_text(encoding="utf-8")
    context = "axe-core WCAG scan (merge gate)"
    assert f'"context": "{context}"' in required, f"{context!r} is no longer a required check"
    assert f"name: {context}" in twin, "the twin no longer publishes the required context"
    assert f"name: {context}" in real, "the real scan no longer publishes the required context"


_TWIN_GUARD_STEP = "Fail unless every changed path is docs-only"


def _workflow_step_script(text: str, step_name: str) -> str:
    """The dedented `run: |` script of the step called ``step_name``.

    Parsed with the same regex-and-indentation discipline the rest of this file
    uses on workflow YAML, so the guard needs no YAML parser at test time -- and
    so a renamed step is an error here rather than a silently empty script.
    """
    lines = text.splitlines()
    start = next(
        (index for index, line in enumerate(lines) if line.strip() == f"- name: {step_name}"),
        None,
    )
    assert start is not None, f"no step named {step_name!r} in the workflow any more"
    for index in range(start + 1, len(lines)):
        stripped = lines[index].strip()
        if stripped.startswith("- name:"):
            break
        if stripped != "run: |":
            continue
        body = lines[index + 1 :]
        first = next((line for line in body if line.strip()), "")
        margin = len(first) - len(first.lstrip())
        collected: list[str] = []
        for line in body:
            if not line.strip():
                collected.append("")
                continue
            if not line.startswith(" " * margin):
                break
            collected.append(line[margin:])
        return "\n".join(collected)
    raise AssertionError(f"the step {step_name!r} no longer carries a `run: |` script")


def test_the_twins_own_glob_list_is_the_same_set_as_both_workflows_paths() -> None:
    """Three lists now have to agree, not two.

    The twin decides whether to report the required accessibility context by
    matching each changed path against a glob list written inside its own shell
    script. That list is a third copy of the same set: a11y.yml's `paths-ignore`,
    the twin's `paths`, and now the twin's assertion.

    A drift between them is not cosmetic. If the script's list were *wider* than
    the trigger, the twin would report green for a path the real scan is the only
    thing entitled to answer for -- which is precisely the unconditional green
    issue #255 removed, reintroduced one glob at a time. If it were narrower, an
    ordinary docs PR would go red for no reason and the required context would
    need a human to clear it.
    """
    workflows = Path(__file__).resolve().parent.parent / ".github" / "workflows"
    twin = (workflows / "a11y-docs-only.yml").read_text(encoding="utf-8")
    real = (workflows / "a11y.yml").read_text(encoding="utf-8")

    script = _workflow_step_script(twin, _TWIN_GUARD_STEP)
    array = re.search(r"docs_only_globs=\((.*?)\n\)", script, re.DOTALL)
    assert array, "the twin's guard step no longer declares a `docs_only_globs` array"
    asserted = set(re.findall(r'"([^"]+)"', array.group(1)))
    assert asserted, "the `docs_only_globs` array is empty; the twin would pass anything"

    for text, key, label in ((twin, "paths", "the twin's trigger"), (real, "paths-ignore", "a11y")):
        declared = re.search(rf"^\s+{key}:\n((?:\s+- \"[^\"]+\"\n)+)", text, re.MULTILINE)
        assert declared, f"{label} declares no `{key}:` list; this guard is reading nothing"
        globs = set(re.findall(r'"([^"]+)"', declared.group(1)))
        assert asserted == globs, (
            f"the twin asserts {sorted(asserted)} but {label} declares {sorted(globs)}. "
            "The set the twin *triggers* on and the set it *accepts* must be the same "
            "set, or the always-green it replaced comes back for the difference."
        )


def test_the_docs_only_twin_actually_fails_on_a_path_it_may_not_answer_for() -> None:
    """Run the twin's own gate, verbatim, against a planted code change.

    Reading the YAML proves the check is written; it does not prove the check can
    fail. That distinction is this file's whole subject (see the axe-marker and
    browser-stack guards above), and it mattered more here than anywhere: the step
    this replaces was `echo`, which is the check that cannot fail taken to its
    limit.

    So the step is deliberately a *pure* function of `$CHANGED_FILES` and its own
    glob list -- no `gh`, no network, no checkout -- and this test extracts that
    script from the workflow and executes it. `docs/**` must not stretch to
    `mdocs/`, `**.md` must reach a Markdown file at any depth, and an empty file
    list must be a failure rather than a vacuous pass, because "nothing was
    collected" and "nothing was wrong" are the two states the old echo could not
    tell apart.
    """
    workflows = Path(__file__).resolve().parent.parent / ".github" / "workflows"
    twin = (workflows / "a11y-docs-only.yml").read_text(encoding="utf-8")
    script = _workflow_step_script(twin, _TWIN_GUARD_STEP)

    bash = shutil.which("bash")
    assert bash, "bash is required to exercise the twin's gate; it must not be skipped away"

    def run(changed: list[str], tmp: Path) -> subprocess.CompletedProcess[str]:
        listing = tmp / "changed-files.txt"
        listing.write_text("".join(f"{name}\n" for name in changed), encoding="utf-8")
        step = tmp / "step.sh"
        step.write_text(script, encoding="utf-8")
        return subprocess.run(
            [bash, str(step)],
            capture_output=True,
            text=True,
            check=False,
            env={**os.environ, "CHANGED_FILES": str(listing)},
        )

    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)

        allowed = run(
            ["README.md", "docs/adr/0012-x.md", "docs/audits/deep/note.txt", "LICENSE"], tmp
        )
        assert allowed.returncode == 0, (
            f"the twin refuses an ordinary docs-only change:\n{allowed.stdout}{allowed.stderr}"
        )

        for path in ("app/index.html", "site/style.css", "src/habitable/verify.py", "Makefile"):
            blocked = run(["docs/plan.md", path], tmp)
            assert blocked.returncode != 0, (
                f"the twin reported green for a PR touching {path!r} -- the required "
                "accessibility context would be satisfied by a job that ran no scan"
            )
            assert path in blocked.stdout + blocked.stderr, "the failure must name the path"

        # `docs/**` is a directory, not a prefix: `mdocs/` is a different tree.
        assert run(["mdocs/notes.txt"], tmp).returncode != 0
        # ... and `**.md` really does span directories, so this stays green.
        assert run(["a/b/c/deep.md"], tmp).returncode == 0
        # An empty collection is a failure, not a pass: see the docstring.
        assert run([], tmp).returncode != 0


# --- the app and the CLI must mean the same thing by a category and a severity ---

_APP_INDEX = Path(__file__).resolve().parent.parent / "app" / "index.html"
_I18N = Path(__file__).resolve().parent.parent / "app" / "i18n"


def _select_options(html: str, select_id: str) -> list[tuple[str, str]]:
    """`(value, data-i18n key)` for every `<option>` inside one `<select>`."""
    block = re.search(rf'<select id="{select_id}".*?</select>', html, re.DOTALL)
    assert block, f"#{select_id} is no longer a <select> in app/index.html"
    return re.findall(r'<option value="([^"]*)"[^>]*data-i18n="([^"]+)"', block.group(0))


def test_the_app_can_only_store_severities_the_model_defines() -> None:
    """Issue #237: the Urgency menu offered `medium`, `high` and `urgent`.

    `ISSUE_SEVERITIES` is `low/moderate/severe/emergency/other`, and `--severity` is
    constrained to it, but the app's POST reaches `add_issue` through `appserver.py`
    without passing argparse. So the three strings the CLI refuses were exactly the
    three the app wrote -- and `htmlpacket.py`, `pdf.py` and `letter.py` print the
    stored value verbatim into the document a court or an inspector reads. Two
    tenants in the same building, one on each surface, produced packets whose
    urgency fields could not be compared.

    `other` is deliberately absent from the menu: it means nothing without the
    companion detail string the CLI requires, and a dropdown has nowhere to put one.
    """
    from habitable.model import ISSUE_SEVERITIES

    options = _select_options(_APP_INDEX.read_text(encoding="utf-8"), "ai-severity")
    assert options, "the Urgency select declares no translated options"

    stored = {value for value, _ in options if value}
    assert stored <= set(ISSUE_SEVERITIES), (
        "the app's Urgency menu can store a severity the CLI would refuse: "
        f"{sorted(stored - set(ISSUE_SEVERITIES))}. Either offer a member of "
        "ISSUE_SEVERITIES or map the value in appserver.py -- do not let the two "
        "surfaces disagree about what a severity is."
    )
    assert "other" not in stored, "`other` needs a detail string a <select> cannot collect"

    # An option nobody can read is not an option. Both bundles must label all of them.
    for name in ("en", "es"):
        bundle = json.loads((_I18N / f"{name}.json").read_text(encoding="utf-8"))
        missing = [key for _, key in options if key not in bundle]
        assert not missing, f"{name}.json has no label for {missing}"


def test_the_condition_datalist_suggests_only_categories_that_exist() -> None:
    """Issue #239: the Condition field stays free text, and now suggests.

    A `<select>` was rejected on purpose -- a closed list cannot express a real
    condition outside the six, and forcing one into the wrong bucket is a wrong
    record rather than an unvalidated one. A `<datalist>` normalises the common
    case without taking the escape hatch away.

    That only works if the suggestions are real. Each option's `value` is stored
    verbatim, so a typo here writes a category no template knows how to present,
    on every case that accepts the suggestion.
    """
    from habitable.model import ISSUE_CATEGORIES

    html = _APP_INDEX.read_text(encoding="utf-8")
    block = re.search(r'<datalist id="ai-category-options".*?</datalist>', html, re.DOTALL)
    assert block, "the Condition field no longer offers the vocabulary as suggestions"
    suggested = re.findall(r'<option value="([^"]+)"', block.group(0))

    assert suggested, "the datalist is empty"
    unknown = sorted(set(suggested) - set(ISSUE_CATEGORIES))
    assert not unknown, f"the app suggests categories the model does not define: {unknown}"
    assert "other" not in suggested, (
        "`other` is not a suggestion -- in the app, free text *is* the other path"
    )

    # The stored value must not be translated; the label the tenant reads must be.
    labelled = re.findall(r'<option value="([^"]+)"[^>]*data-i18n-label="([^"]+)"', block.group(0))
    assert len(labelled) == len(suggested), "every suggestion needs a translated label"
    for name in ("en", "es"):
        bundle = json.loads((_I18N / f"{name}.json").read_text(encoding="utf-8"))
        missing = [key for _, key in labelled if key not in bundle]
        assert not missing, f"{name}.json has no label for {missing}"


def test_category_aliases_are_synonyms_and_never_a_reclassification() -> None:
    """Issue #240: `no_heat`, `moisture` and `moho` normalise; nothing else does.

    An alias table is only safe while every entry means the same condition as its
    target. The moment one maps a distinct complaint onto a near-enough category --
    `noise` onto `structural`, say -- the CLI is silently refiling a tenant's
    record as something they did not report, which is worse than the free text
    #206 removed.
    """
    from habitable.model import ISSUE_CATEGORIES, ISSUE_CATEGORY_ALIASES

    assert ISSUE_CATEGORY_ALIASES, "the alias table is empty; this guard reads nothing"

    # The structural rules below are necessary and nowhere near sufficient: an
    # adversarial review showed that `{"leak": "structural", "cockroaches":
    # "structural"}` satisfies every one of them and passes the whole suite --
    # precisely the silent refiling this docstring says is forbidden. Whether a word
    # is a *synonym* of a category or a *different complaint* is a judgement no
    # assertion can make, so the table itself is pinned. Changing it then has to edit
    # this literal, and the reviewer of that diff is the check.
    assert ISSUE_CATEGORY_ALIASES == {
        "no_heat": "heat",
        "moisture": "water",
        "moho": "mold",
    }, (
        "the alias table changed. Every entry must be a word for the SAME condition "
        "as its target, never a near-enough category: mapping `noise` or `leak` onto "
        "`structural` refiles a tenant's record as something they did not report. If "
        "the new entry really is a synonym, update this literal and say why in the "
        "commit; if it is a distinct complaint, it belongs in `other` with a label."
    )
    for alias, target in ISSUE_CATEGORY_ALIASES.items():
        assert target in ISSUE_CATEGORIES, (
            f"{alias} normalises to {target}, which is not a category"
        )
        assert target != "other", f"{alias} -> other is a discard, not a synonym"
        assert alias not in ISSUE_CATEGORIES, f"{alias} is already a category; the alias shadows it"


def test_the_demo_seeds_a_severity_the_cli_would_accept() -> None:
    """Issue #238: `demo.py` and `prove.py` seeded `severity="high"`.

    `high` is not in `ISSUE_SEVERITIES`. `uv run habitable demo` is the first
    command the README, CONTRIBUTING and the good-first-issue guide all tell a
    newcomer to run, and the packet it builds is the synthetic one published for
    cold-read review -- so the project's own worked example modelled a value its
    own CLI refuses.
    """
    from habitable.model import ISSUE_SEVERITIES

    root = Path(__file__).resolve().parent.parent / "src" / "habitable"
    seeded: list[str] = []
    for module in ("demo.py", "prove.py"):
        seeded += [
            f"{module}: {value}"
            for value in re.findall(r'severity="([^"]*)"', (root / module).read_text("utf-8"))
            if value and value not in ISSUE_SEVERITIES
        ]
    assert not seeded, f"the worked examples seed severities the CLI would refuse: {seeded}"


def test_browser_tests_never_ask_the_page_to_eval_a_string() -> None:
    """A browser test must not need a privilege the app refuses to grant itself.

    `appserver.py` serves `script-src 'self'` with no `unsafe-eval`. Playwright's
    `wait_for_function` wraps a **bare expression** string in `eval`, which that
    header blocks; a string that *looks like a function* is passed through a
    different path and is fine.

    The difference is invisible until it bites. Four calls in this suite used the
    bare form. Three passed by ordering luck; the fourth failed only under the full
    run, in a test whose remaining assertions were therefore never reached under the
    headers the app actually serves -- and it passed in isolation, which is the
    worst way for a test to be wrong, because the obvious diagnosis is "flake".

    Weakening the CSP to make a test pass would be the wrong repair twice over: it
    is a real header on a real local server, and the test would then be asserting
    against a page the tenant never loads.
    """
    tests_dir = Path(__file__).resolve().parent
    offenders: list[str] = []
    for path in sorted(tests_dir.glob("test_*.py")):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for call in re.findall(r'wait_for_function\(\s*(["\'])(.*?)\1', line):
                body = call[1].strip()
                if body and not body.startswith(("(", "function", "async")):
                    offenders.append(f"{path.name}:{number}: {body[:60]}")

    assert not offenders, (
        "these wait_for_function calls pass a bare expression, which Playwright "
        "evaluates with `eval` and the app's own Content-Security-Policy forbids. "
        "Write them as `() => …` instead.\n  " + "\n  ".join(offenders)
    )
