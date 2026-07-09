# SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0
# Copyright 2026 Chelsea Kelly-Reif
"""Regenerate the evidence-kernel golden corpus from the live kernel primitives.

The corpus (``tests/golden/kernel/vectors.json``) is a language-independent set of
test vectors for the *pure* kernel primitives — canonical serialization, SHA-256, and
chain-of-custody hash-linking. Any independent reimplementation of the kernel (in any
language) can load this one file and confirm it computes the same bytes and hashes,
which is the EXP-13 excellence bar: two tools' verifiers cross-check the same corpus.

Run ``python scripts/gen_kernel_corpus.py`` after an intentional, documented change to
the kernel wire format; the values are asserted byte-for-byte by
``tests/test_kernel_golden.py``. Never edit the JSON by hand.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from habitable.evidence import GENESIS_PREV_HASH, CustodyEntry
from habitable.kernel import (
    HASH_ALGORITHM,
    KERNEL_API_VERSION,
    KERNEL_NAME,
    canonical_json,
    sha256_bytes,
)

_OUT = Path(__file__).resolve().parent.parent / "tests" / "golden" / "kernel" / "vectors.json"

# --- canonical_json / sha256 vectors -----------------------------------------
# Chosen to pin the guarantees other tools depend on: sorted keys, tight separators,
# non-ASCII kept as UTF-8, no NaN/Infinity, and stable number/bool/null encoding.
_CANONICAL_CASES: list[tuple[str, Any]] = [
    ("empty_object", {}),
    ("empty_array", []),
    ("key_ordering", {"b": 1, "a": 2, "c": 3}),
    ("nested_ordering", {"z": {"y": 2, "x": 1}, "a": [3, 2, 1]}),
    ("scalars", {"t": True, "f": False, "n": None, "i": 42, "s": "hi"}),
    ("unicode_kept_utf8", {"note": "café — malla ñoño 住宅"}),
    ("string_with_specials", {"s": 'quote " backslash \\ newline \n tab \t'}),
    ("negative_and_zero", {"neg": -17, "zero": 0}),
    ("deep_mixed", {"items": [{"id": "b"}, {"id": "a"}], "head": "0" * 64}),
]


def _canonical_vectors() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for name, value in _CANONICAL_CASES:
        raw = canonical_json(value)
        out.append(
            {
                "name": name,
                "value": value,
                "canonical_utf8": raw.decode("utf-8"),
                "sha256": sha256_bytes(raw),
            }
        )
    return out


# --- chain-of-custody hash-linking vectors -----------------------------------
# Each chain is built from fixed *public* fields (no random salt / identity), so the
# resulting entry hashes and head hash are fully deterministic and reproducible by an
# independent implementation of the same rule:
#   entry_hash = sha256(canonical_json(public_payload)); prev_hash links to the head.
_CHAIN_SPECS: list[tuple[str, list[dict[str, Any]]]] = [
    (
        "single_capture",
        [
            {
                "action": "captured",
                "item_id": "cap-0001",
                "hlc": "2026-01-02T00:00:00.000Z-0000-node",
                "actor_commitment": "a" * 64,
                "details": {"content_hash": "e3b0" + "c" * 60, "media_type": "image/jpeg"},
            }
        ],
    ),
    (
        "capture_then_timestamp_then_packet",
        [
            {
                "action": "captured",
                "item_id": "cap-0002",
                "hlc": "2026-01-02T00:00:00.000Z-0000-node",
                "actor_commitment": "b" * 64,
                "details": {"content_hash": "1111" + "2" * 60},
            },
            {
                "action": "timestamped",
                "item_id": "cap-0002",
                "hlc": "2026-01-02T00:05:00.000Z-0001-node",
                "actor_commitment": "b" * 64,
                "details": {"tsa": "freetsa.org"},
            },
            {
                "action": "included_in_packet",
                "item_id": "cap-0002",
                "hlc": "2026-01-02T00:10:00.000Z-0002-node",
                "actor_commitment": "b" * 64,
                "details": {"packet": "4B"},
            },
        ],
    ),
]


def _build_chain(steps: list[dict[str, Any]]) -> tuple[list[CustodyEntry], list[dict[str, Any]]]:
    entries: list[CustodyEntry] = []
    prev = GENESIS_PREV_HASH
    records: list[dict[str, Any]] = []
    for index, step in enumerate(steps, start=1):
        skeleton = CustodyEntry(
            seq=index,
            action=step["action"],
            item_id=step["item_id"],
            hlc=step["hlc"],
            actor_commitment=step["actor_commitment"],
            details=dict(step["details"]),
            prev_hash=prev,
            entry_hash="",
        )
        entry_hash = skeleton.recompute_hash()
        entry = CustodyEntry(
            seq=skeleton.seq,
            action=skeleton.action,
            item_id=skeleton.item_id,
            hlc=skeleton.hlc,
            actor_commitment=skeleton.actor_commitment,
            details=skeleton.details,
            prev_hash=prev,
            entry_hash=entry_hash,
        )
        entries.append(entry)
        records.append(entry.to_export_dict())
        prev = entry_hash
    return entries, records


def _chain_vectors() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for name, steps in _CHAIN_SPECS:
        entries, records = _build_chain(steps)
        out.append(
            {
                "name": name,
                "records": records,
                "expected_head_hash": entries[-1].entry_hash,
                "expected_length": len(entries),
            }
        )
    return out


def build() -> dict[str, Any]:
    return {
        "_comment": (
            "Language-independent golden corpus for the habitable evidence kernel. "
            "Generated by scripts/gen_kernel_corpus.py; asserted by "
            "tests/test_kernel_golden.py. Do not edit by hand."
        ),
        "kernel": KERNEL_NAME,
        "kernel_api_version": KERNEL_API_VERSION,
        "hash_algorithm": HASH_ALGORITHM,
        "canonical_json": _canonical_vectors(),
        "custody_chain": _chain_vectors(),
    }


def main() -> None:
    _OUT.parent.mkdir(parents=True, exist_ok=True)
    corpus = build()
    _OUT.write_text(json.dumps(corpus, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {_OUT} ({len(corpus['canonical_json'])} canonical, "
          f"{len(corpus['custody_chain'])} chain vectors)")


if __name__ == "__main__":
    main()
