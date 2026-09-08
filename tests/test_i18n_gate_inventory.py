# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""`docs/I18N.md`'s gate table must describe the gates the build actually runs.

Three files in this repository state which mechanical i18n gates are live, and
none of them read each other:

* the ``i18n`` target in the `Makefile`, which `make verify` composes;
* ``.github/workflows/i18n.yml``, whose header claims it "mirror[s] `make
  verify`'s `i18n` target byte-for-byte (no local/CI drift)";
* ``docs/I18N.md``'s AUTO-GATES table, whose preamble says it records "which
  mechanical AUTO-GATES (§4) are **live** ... so the i18n posture is a declared
  decision rather than a silent state".

The third had been wrong since the pseudo-locale gate was wired: its **G9** row
read ``DEFERRED (frontend-depth phase)`` with an em dash for "Where", while
`scripts/check_pseudo_locale.py` ran in `make verify` and in the workflow — as a
step the workflow itself names ``G9``. A conformance document that understates
an enforced gate is the same defect as one that overstates it: in both cases the
record and the build disagree, and only the record is read.

The comparison here is derived on both sides. The scripts come out of the
Makefile recipe and the workflow's own ``run:`` lines; the claims come out of the
table. Nothing is retyped, so correcting the table once cannot be undone by the
next gate somebody adds and forgets to record.

Each collector carries a floor. A regex that stops matching would otherwise
report an empty set, every "every X is also Y" assertion would hold vacuously,
and this module would pass hardest exactly when it had stopped reading anything.
"""

from __future__ import annotations

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_MAKEFILE = _ROOT / "Makefile"
_WORKFLOW = _ROOT / ".github" / "workflows" / "i18n.yml"
_DOC = _ROOT / "docs" / "I18N.md"

_SCRIPT = re.compile(r"scripts/[A-Za-z0-9_./-]+\.py")

#: The status words the table may use, and whether each one claims the gate runs
#: in the build. An unknown word is an error rather than a default: a status
#: nobody classified would otherwise be read as whichever branch is convenient.
_RUNS = {"LIVE": True, "PARTIAL": True, "DEFERRED": False, "N/A": False, "N/A BY DESIGN": False}


def _makefile_i18n_scripts() -> set[str]:
    """The scripts the `i18n` target runs, read off the recipe."""
    text = _MAKEFILE.read_text(encoding="utf-8")
    match = re.search(r"^i18n:.*?\n((?:\t.*\n|\n)*)", text, flags=re.MULTILINE)
    assert match is not None, "the Makefile has no `i18n:` target"
    scripts = set(_SCRIPT.findall(match.group(1)))
    assert scripts, "no scripts found in the `i18n:` recipe — this collector stopped reading"
    return scripts


def _workflow_scripts() -> set[str]:
    """The scripts `.github/workflows/i18n.yml` runs, read off its `run:` lines."""
    runs = re.findall(r"^\s*run:\s*(.+)$", _WORKFLOW.read_text(encoding="utf-8"), flags=re.M)
    assert runs, "no `run:` steps found in i18n.yml — this collector stopped reading"
    scripts = {script for line in runs for script in _SCRIPT.findall(line)}
    assert scripts, "no scripts found in i18n.yml's run steps"
    return scripts


def _gate_rows() -> dict[str, tuple[str, str]]:
    """``{gate id: (status word, "Where" cell)}`` from the AUTO-GATES table."""
    rows: dict[str, tuple[str, str]] = {}
    for line in _DOC.read_text(encoding="utf-8").splitlines():
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) != 4 or not re.fullmatch(r"G\d+", cells[0]):
            continue
        bold = re.search(r"\*\*(.+?)\*\*", cells[2])
        assert bold is not None, f"{cells[0]}: status cell has no bolded status word: {cells[2]!r}"
        word = bold.group(1).strip().upper()
        assert word in _RUNS, f"{cells[0]}: unrecognised status {word!r}; classify it in _RUNS"
        rows[cells[0]] = (word, cells[3])
    assert len(rows) >= 12, f"parsed {len(rows)} gate rows; the table declares G1-G12"
    return rows


def test_the_workflow_runs_exactly_the_makefile_target() -> None:
    """i18n.yml claims to mirror `make i18n` byte-for-byte. Held to it."""
    assert _workflow_scripts() == _makefile_i18n_scripts()


def test_every_gate_script_the_build_runs_exists() -> None:
    for script in _makefile_i18n_scripts() | _workflow_scripts():
        assert (_ROOT / script).is_file(), f"{script} is invoked by a gate but is not in the tree"


def test_every_gate_the_build_runs_is_recorded_as_running_in_the_doc() -> None:
    """The direction that was wrong: a merge-blocking gate the table denied.

    `scripts/check_pseudo_locale.py` ran in `make verify` and in the workflow
    while the G9 row said `DEFERRED` and named no file at all.
    """
    rows = _gate_rows()
    claimed = {
        script for word, where in rows.values() if _RUNS[word] for script in _SCRIPT.findall(where)
    }
    unrecorded = sorted(_makefile_i18n_scripts() - claimed)
    assert not unrecorded, (
        f"docs/I18N.md's gate table does not record {unrecorded} as running, but "
        "`make i18n` runs them. A conformance document that understates an enforced "
        "gate disagrees with the build just as much as one that overstates it."
    )


def test_no_row_calls_a_gate_deferred_while_the_build_runs_it() -> None:
    """The same disagreement seen from the other side."""
    running = _makefile_i18n_scripts() | _workflow_scripts()
    for gate, (word, where) in _gate_rows().items():
        if _RUNS[word]:
            continue
        contradicted = sorted(set(_SCRIPT.findall(where)) & running)
        assert not contradicted, f"{gate} is marked {word} but the build runs {contradicted}"


def test_every_script_a_row_names_is_in_the_tree() -> None:
    """A row may name a test module or a script; either way the path must exist."""
    named = {script for _, where in _gate_rows().values() for script in _SCRIPT.findall(where)}
    assert named, "no gate row names a script; the `Where` column stopped being read"
    for script in sorted(named):
        assert (_ROOT / script).is_file(), f"docs/I18N.md names {script}, which is not in the tree"
