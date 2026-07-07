# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Invariant guards: no custody-actor identity in exports, and a verifier that stays
within its Apache-2.0 redistributable subset.

These pin two promises the project makes elsewhere in prose: a packet proves custody
*without naming who did what* (threat model §4, README hard rules), and the
verification subset can be embedded under Apache-2.0 without dragging in AGPL-only
modules (verify.py docstring, NOTICE)."""

from __future__ import annotations

import re
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

from habitable.canonical import sha256_bytes
from habitable.capture import capture
from habitable.packet import build_packet
from habitable.sync import LocalDirTransport, sync
from habitable.tsa import LocalRfc3161TSA
from habitable.vault import Vault

_GENERATED_AT = "2026-01-02T00:10:00Z"
_TENANT_FILENAME = "TENANT-PRIVATE-FILENAME-9e21.jpg"


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
    leaked = sha256_bytes((case_id + passphrase).encode())[:16]  # the pre-fix derivation

    vault = make_vault(case_id=case_id, passphrase=passphrase)
    issue = vault.document.add_issue(category="mold", issue_id="i1")
    capture(vault, make_jpeg(), issue_id=issue, tsa=local_tsa)

    # The device id itself is random, not the passphrase-derived value.
    assert vault.document.clock.node_id != leaked

    # No passphrase-derived material in the only two plaintext files ...
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


# The import closure of habitable.verify — the source an embedder vendors and must be
# able to run on Python < 3.14 (verify.py docstring, NOTICE, docs/embedding-the-verifier.md).
_VERIFIER_SUBSET_FILES = (
    "canonical.py",
    "crypto.py",
    "errors.py",
    "evidence.py",
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
