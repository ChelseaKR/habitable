# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Local-path latency budget: capturing evidence must feel instant offline.

The promise is that capture never blocks on the network — hashing, sealing, and the
custody entry complete in a perceptible moment on the only device a tenant has. This
asserts the offline local path (no timestamp authority) stays well within budget, so a
regression that makes capture slow is caught here rather than felt in the apartment.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path

from habitable.capture import capture
from habitable.vault import Vault

# Generous budget (the real local path is tens of milliseconds); large enough to avoid
# flakiness on a loaded CI runner, small enough to catch an order-of-magnitude regression.
_LOCAL_CAPTURE_BUDGET_S = 2.0


def test_offline_capture_is_within_latency_budget(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
) -> None:
    vault = make_vault()
    issue = vault.document.add_issue(category="mold", issue_id="i1")
    photo = make_jpeg("a.jpg", with_location=True)

    start = time.perf_counter()
    result = capture(vault, photo, issue_id=issue, tsa=None)  # offline: hash + seal + custody only
    elapsed = time.perf_counter() - start

    assert not result.timestamped  # confirms we measured the pure local path, no network
    assert elapsed < _LOCAL_CAPTURE_BUDGET_S, (
        f"offline capture took {elapsed:.3f}s (budget {_LOCAL_CAPTURE_BUDGET_S}s)"
    )
