# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Invariant guards: no custody-actor identity in exports, and a verifier that stays
within its Apache-2.0 redistributable subset.

These pin two promises the project makes elsewhere in prose: a packet proves custody
*without naming who did what* (threat model §4, README hard rules), and the
verification subset can be embedded under Apache-2.0 without dragging in AGPL-only
modules (verify.py docstring, NOTICE)."""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

from habitable.capture import capture
from habitable.packet import build_packet
from habitable.sync import LocalDirTransport, sync
from habitable.tsa import LocalRfc3161TSA
from habitable.vault import Vault

_GENERATED_AT = "2026-01-02T00:10:00Z"
_TENANT_FILENAME = "TENANT-PRIVATE-FILENAME-9e21.jpg"


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


# The exact module set the Apache-2.0 verification subset is allowed to load:
# verify + the pure helpers it imports, plus the side-effect-free parent package.
_ALLOWED_VERIFIER_MODULES = {
    "habitable",
    "habitable.canonical",
    "habitable.crypto",
    "habitable.errors",
    "habitable.evidence",
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
