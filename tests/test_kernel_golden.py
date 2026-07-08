# SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0
# Copyright 2026 Chelsea Kelly-Reif
"""Cross-check the evidence kernel against its language-independent golden corpus.

``tests/golden/kernel/vectors.json`` freezes the pure kernel wire formats — canonical
serialization, SHA-256, and the chain-of-custody entry-hash rule — as a set of vectors
any independent reimplementation can also load and confirm. This is the EXP-13
excellence bar in executable form: two tools' verifiers cross-check the *same* corpus.

If a change to the kernel makes these fail, that is a wire-format break: either it is a
bug, or it is an intentional, documented major bump (regenerate via
``scripts/gen_kernel_corpus.py`` and note it in ``CHANGELOG.md``).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from habitable.evidence import CustodyLog
from habitable.kernel import (
    HASH_ALGORITHM,
    KERNEL_API_VERSION,
    KERNEL_NAME,
    canonical_json,
    sha256_bytes,
)

_CORPUS = Path(__file__).resolve().parent / "golden" / "kernel" / "vectors.json"


def _load() -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(_CORPUS.read_text(encoding="utf-8"))
    return loaded


def test_corpus_metadata_matches_kernel() -> None:
    corpus = _load()
    assert corpus["kernel"] == KERNEL_NAME
    assert corpus["kernel_api_version"] == KERNEL_API_VERSION
    assert corpus["hash_algorithm"] == HASH_ALGORITHM


def test_canonical_json_vectors_are_reproduced_byte_for_byte() -> None:
    vectors = _load()["canonical_json"]
    assert vectors, "no canonical vectors committed"
    for vec in vectors:
        raw = canonical_json(vec["value"])
        assert raw.decode("utf-8") == vec["canonical_utf8"], f"{vec['name']}: bytes drift"
        assert sha256_bytes(raw) == vec["sha256"], f"{vec['name']}: sha256 drift"


def test_custody_chain_vectors_verify_and_match_head() -> None:
    chains = _load()["custody_chain"]
    assert chains, "no custody-chain vectors committed"
    for chain in chains:
        log = CustodyLog.from_records(chain["records"])
        result = log.verify()
        assert result.ok, f"{chain['name']}: chain did not verify"
        assert result.length == chain["expected_length"], f"{chain['name']}: length drift"
        assert result.head_hash == chain["expected_head_hash"], f"{chain['name']}: head drift"
        # Independent re-derivation: every frozen entry_hash is exactly what the kernel
        # recomputes from that entry's public payload.
        for entry in log.entries:
            assert entry.recompute_hash() == entry.entry_hash, f"{chain['name']}: entry drift"


# The kernel must stay within the Apache-2.0-redistributable subset: importing it pulls
# in only the verification modules (plus itself), never relay/sync/cli/app/capture/vault.
_ALLOWED_KERNEL_MODULES = {
    "habitable",
    "habitable.anchor",
    "habitable.canonical",
    "habitable.crypto",
    "habitable.errors",
    "habitable.evidence",
    "habitable.kernel",
    "habitable.tsa",
    "habitable.verify",
}


def test_kernel_imports_stay_within_apache_subset() -> None:
    probe = (
        "import habitable.kernel, sys;"
        "loaded={m for m in sys.modules if m == 'habitable' or m.startswith('habitable.')};"
        f"allowed={sorted(_ALLOWED_KERNEL_MODULES)!r};"
        "extra=sorted(loaded - set(allowed));"
        "print('EXTRA:' + ','.join(extra));"
        "sys.exit(1 if extra else 0)"
    )
    result = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, (
        f"kernel pulled in non-subset modules: {result.stdout.strip()} {result.stderr.strip()}"
    )


def test_public_api_is_importable_and_complete() -> None:
    import habitable.kernel as kernel

    for name in kernel.__all__:
        assert hasattr(kernel, name), f"__all__ names missing attribute: {name}"
