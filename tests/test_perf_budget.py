# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Latency budget for the local (offline) path — asserted in CI.

Makes the README's "latency budgets for the local path are asserted in CI" true and
closes the roadmap's *Low-end-device performance* item. The full rationale — the
reference low-end device, the slowdown model, the tolerance band, and why network TSA
latency is deliberately excluded — lives in ``docs/performance-budget.md``. The budget
constants here MIRROR that document; keep the two in sync.

These tests are intentionally NOT marked ``integration``, so they run under
``make test`` (``pytest -m "not integration"``) and hence in CI. They use best-of-N with
``time.perf_counter`` and generous ceilings (>=5x local headroom), so noise can only make
a run slower and the minimum stays a robust lower bound — the budget catches an
order-of-magnitude regression, never a few percent of jitter.
"""

from __future__ import annotations

import math
import time
from collections.abc import Callable
from pathlib import Path

from habitable.canonical import sha256_bytes
from habitable.capture import capture
from habitable.evidence import CustodyAction
from habitable.packet import build_packet
from habitable.tsa import LocalRfc3161TSA
from habitable.vault import Vault

# The reference low-end phone is modeled as this many times slower than the CI runner
# for this (CPU + local-I/O bound) workload. See docs/performance-budget.md.
LOW_END_SLOWDOWN = 10.0

# Per-operation budgets on the *reference low-end device*, in milliseconds. These mirror
# the table in docs/performance-budget.md. CI runs on faster hardware, so each op must
# finish within ``budget / LOW_END_SLOWDOWN`` for the device budget to hold.
DEVICE_BUDGET_MS: dict[str, float] = {
    "content_hash": 500.0,
    "seal_store": 1000.0,
    "custody_append": 200.0,
    "crdt_merge": 300.0,
    "packet_assembly": 2000.0,
}

# A "multi-MB capture": large enough to be a realistic photo/short-clip payload, small
# enough that best-of-N stays well under a second per op.
PAYLOAD_MB = 4
PAYLOAD_SIZE = PAYLOAD_MB * 1024 * 1024


def _ci_budget_ms(op: str) -> float:
    """The ceiling the test enforces on CI hardware: device budget / slowdown."""
    return DEVICE_BUDGET_MS[op] / LOW_END_SLOWDOWN


def _best_ms(fn: Callable[[], object], *, repeats: int = 7, warmup: int = 2) -> float:
    """Best-of-N wall time for ``fn`` in milliseconds (minimum, after warmup)."""
    for _ in range(warmup):
        fn()
    best = math.inf
    for _ in range(repeats):
        start = time.perf_counter()
        fn()
        best = min(best, time.perf_counter() - start)
    return best * 1000.0


def _payload() -> bytes:
    # A fixed non-trivial byte pattern; SHA-256 and AEAD both touch every byte, so the
    # exact contents do not matter to the cost — only the size does.
    return b"\xa5" * PAYLOAD_SIZE


def test_content_hash_within_budget() -> None:
    """SHA-256 of a multi-MB capture — the fixity anchor — is well under budget."""
    payload = _payload()
    elapsed = _best_ms(lambda: sha256_bytes(payload))
    assert elapsed < _ci_budget_ms("content_hash"), (
        f"content hash of {PAYLOAD_MB} MB took {elapsed:.2f} ms "
        f"(CI budget {_ci_budget_ms('content_hash'):.0f} ms)"
    )


def test_seal_store_within_budget(make_vault: Callable[..., Vault]) -> None:
    """Sealing a multi-MB original (hash + AEAD-encrypt + write) is within budget."""
    vault = make_vault()
    payload = _payload()
    content_hash = sha256_bytes(payload)
    counter = {"n": 0}

    def seal() -> None:
        counter["n"] += 1
        vault.store_original_bytes(f"cap-{counter['n']}", payload, content_hash)

    elapsed = _best_ms(seal)
    assert elapsed < _ci_budget_ms("seal_store"), (
        f"seal/store of {PAYLOAD_MB} MB took {elapsed:.2f} ms "
        f"(CI budget {_ci_budget_ms('seal_store'):.0f} ms)"
    )


def test_custody_append_within_budget(make_vault: Callable[..., Vault]) -> None:
    """Appending one signed chain-of-custody entry is within budget."""
    vault = make_vault()
    counter = {"n": 0}

    def append() -> None:
        counter["n"] += 1
        vault.custody.append(
            CustodyAction.CAPTURED,
            f"cap-{counter['n']}",
            actor="tester",
            hlc=str(counter["n"]),
            details={"media_type": "image/jpeg"},
            identity=vault.identity,
        )

    elapsed = _best_ms(append)
    assert elapsed < _ci_budget_ms("custody_append"), (
        f"custody append took {elapsed:.3f} ms (CI budget {_ci_budget_ms('custody_append'):.0f} ms)"
    )


def test_crdt_merge_within_budget(make_vault: Callable[..., Vault]) -> None:
    """Merging another replica's case state (CRDT join) is within budget."""
    local = make_vault("local")
    peer = make_vault("peer", passphrase="pw-peer")
    for i in range(20):
        issue = peer.document.add_issue(category="mold", issue_id=f"i{i}")
        peer.document.add_timeline_entry(issue, "observed", "spreading")
        peer.document.add_capture(
            issue_id=issue,
            content_hash=sha256_bytes(f"payload-{i}".encode()),
            media_type="image/jpeg",
            sealed_name=f"cap{i}.enc",
            captured_at="2026-01-02T00:00:00Z",
            capture_id=f"cap{i}",
        )
    state = peer.document.to_state()

    elapsed = _best_ms(lambda: local.document.merge(state))
    assert elapsed < _ci_budget_ms("crdt_merge"), (
        f"CRDT merge took {elapsed:.3f} ms (CI budget {_ci_budget_ms('crdt_merge'):.0f} ms)"
    )


def test_packet_assembly_within_budget(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    """Assembling an export packet (bundle + HTML + PDF) is within budget."""
    vault = make_vault()
    issue = vault.document.add_issue(category="mold", room="bath", title="Mold", issue_id="i1")
    vault.document.add_timeline_entry(issue, "observed", "spreading")
    capture(vault, make_jpeg(with_location=True), issue_id=issue, tsa=local_tsa)
    counter = {"n": 0}

    def assemble() -> None:
        counter["n"] += 1
        build_packet(vault, tmp_path / f"pkt-{counter['n']}", generated_at="2026-01-02T00:10:00Z")

    # Packet assembly is the heaviest op (PDF rendering); fewer repeats keep runtime low.
    elapsed = _best_ms(assemble, repeats=5, warmup=1)
    assert elapsed < _ci_budget_ms("packet_assembly"), (
        f"packet assembly took {elapsed:.2f} ms "
        f"(CI budget {_ci_budget_ms('packet_assembly'):.0f} ms)"
    )
