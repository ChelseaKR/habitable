# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Guards for ADR 0017: corrections and edit history need one append-only change log.

Issues #241 (no correction path for a mistyped entry) and #261 (no complete
merge/conflict history) are one gap seen from two sides -- the case's own edit
history is not recoverable. ADR 0017 refuses the cheap fix and says why, and the
refusal rests on two facts about the code as it stands. Facts rot. These pin them,
so the next person who reaches for the cheap fix meets an argument rather than
silence.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path

from habitable.packet import _issue_json
from habitable.vault import Vault

_SRC = Path(__file__).resolve().parent.parent / "src" / "habitable"
_ADR = "docs/adr/0017-corrections-and-edit-history-need-one-append-only-change-log.md"


def test_a_corrected_field_would_be_invisible_in_the_packet(
    make_vault: Callable[..., Vault],
) -> None:
    """ADR 0017, fact 2: field provenance never leaves the device.

    `CaseDocument.update_issue()` already exists and already stamps every write
    with a signed `FieldProvenance` naming the device and the time -- so a
    `habitable issue correct` built on it would look, from inside the vault, like
    a fully attributed change. It would not look like anything at all from
    outside: `_issue_json` exports six flat fields, and neither `packet.py` nor
    `verify.py` mentions provenance, so the packet a court reads would simply
    show the corrected value as though it had always said that.

    That is the whole reason ADR 0017 refuses to ship the cheap version. A silent
    edit in the exported artifact is a worse record than a visible typo, and this
    test fails the moment the export grows a field that would change the
    calculation -- at which point the ADR must be revisited, not quietly
    outgrown.
    """
    vault = make_vault()
    issue_id = vault.document.add_issue(category="mold", room="bathrom", title="Mould")
    vault.document.update_issue(issue_id, room="bathroom")
    vault.save()

    issue = next(i for i in vault.document.issues() if i.issue_id == issue_id)
    exported = _issue_json(issue)

    assert exported["room"] == "bathroom"
    assert set(exported) == {
        "issue_id",
        "category",
        "room",
        "title",
        "status",
        "severity",
        "description",
    }, (
        "the exported issue payload changed shape. If a correction is now visible "
        f"to the packet's reader, ADR 0017's decision needs revisiting: {_ADR}"
    )

    # The vault knows the field was written; the packet cannot say so.
    provenance = vault.document.field_provenance(issue_id, "room")
    assert provenance is not None, "the edit lost its provenance inside the vault too"
    assert "provenance" not in str(exported)


def test_a_stored_field_is_only_mutated_beside_an_append_only_record() -> None:
    """ADR 0017, decision 3 and fact 4: the one permitted mutation, and its shape.

    `update_issue` has exactly one caller in `src/`: the timeline path reopens an
    issue's `status` when a `recurrence` event is recorded. That mutation is
    invisible in `_issue_json` too -- but it travels beside an append-only
    timeline entry which *does* export, so a reader can reconstruct why the
    status changed from the record they were handed.

    That is the rule ADR 0017 generalises rather than a special case: a stored
    field may be mutated only alongside an append-only record, exported with the
    packet, that says it was. A second caller is not automatically wrong; it is
    automatically a decision, and this guard makes someone make it.
    """
    callers = {
        path.name: [
            line.strip()
            for line in path.read_text(encoding="utf-8").splitlines()
            if re.search(r"\.update_issue\(", line) and "def update_issue" not in line
        ]
        for path in _SRC.glob("*.py")
    }
    found = {name: lines for name, lines in callers.items() if lines}

    assert found == {"vault.py": ['self.document.update_issue(issue_id, status="open")']}, (
        "`update_issue` gained or lost a caller. Every mutation of a stored issue "
        "field must be accompanied by an append-only record that exports with the "
        f"packet; see {_ADR} before adding one.\nfound: {found}"
    )

    # And the one that exists really is beside an appended timeline entry.
    vault_source = (_SRC / "vault.py").read_text(encoding="utf-8")
    recurrence = vault_source.index('if event_type == "recurrence":')
    window = vault_source[recurrence : recurrence + 600]
    assert "_append_timeline_binding" in window, (
        "the recurrence path no longer appends the timeline binding that makes its "
        "status mutation reconstructible by the packet's reader"
    )
