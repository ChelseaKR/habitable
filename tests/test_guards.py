# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Invariant guards: no custody-actor identity in exports, and a verifier that stays
within its Apache-2.0 redistributable subset.

These pin two promises the project makes elsewhere in prose: a packet proves custody
*without naming who did what* (threat model §4, README hard rules), and the
verification subset can be embedded under Apache-2.0 without dragging in AGPL-only
modules (verify.py docstring, NOTICE)."""

from __future__ import annotations

import os
import re
import subprocess
import sys
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

    What this test does NOT fix, because it is a topology decision for the owner:
    on a PR touching both docs and code, both jobs run and both report to the same
    context. GitHub resolves it to whichever reported last. The comment asserts the
    real scan "finishing later, its result governs", which holds only because the
    echo is fast -- it is a race, not an invariant. A real scan that fails early
    (a checkout or `uv sync` failure) while the twin waits on a runner would report
    first and be overwritten by a green echo.
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
