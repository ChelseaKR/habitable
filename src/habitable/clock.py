# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Hybrid logical clocks (HLC) for offline-first, conflict-free ordering.

Two organizers editing the same case offline need their edits to converge when
they reconnect, and a tenant's timeline must record events in a defensible order
even across devices whose wall clocks disagree. A hybrid logical clock gives a
single total order that (a) tracks physical time closely enough to be meaningful
to a court and (b) never goes backwards, so concurrent edits merge
deterministically.

The clock takes an injectable time source so tests are fully deterministic; see
:class:`HybridLogicalClock`.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass

__all__ = ["HLCTimestamp", "HybridLogicalClock", "wall_clock_ms"]


def wall_clock_ms() -> int:
    """Current wall-clock time in integer milliseconds since the Unix epoch."""
    return time.time_ns() // 1_000_000


@dataclass(frozen=True, order=True, slots=True)
class HLCTimestamp:
    """A point in a hybrid logical clock: physical ms, a counter, and a node id.

    Ordering is lexicographic over ``(wall_ms, counter, node_id)``, which is a
    *total* order — essential for last-writer-wins CRDT registers, where ties
    must break deterministically and identically on every device.
    """

    wall_ms: int
    counter: int
    node_id: str

    def encode(self) -> str:
        """Serialize to a sortable, round-trippable string."""
        return f"{self.wall_ms:015d}.{self.counter:06d}.{self.node_id}"

    @classmethod
    def decode(cls, raw: str) -> HLCTimestamp:
        """Parse a value produced by :meth:`encode`."""
        wall_str, counter_str, node_id = raw.split(".", 2)
        return cls(int(wall_str), int(counter_str), node_id)

    @classmethod
    def zero(cls, node_id: str) -> HLCTimestamp:
        """The earliest timestamp for a node."""
        return cls(0, 0, node_id)


class HybridLogicalClock:
    """A monotonic hybrid logical clock for a single node (device).

    Parameters
    ----------
    node_id:
        Stable identifier for this device. Used as the final tiebreaker so two
        nodes that tick at the same physical millisecond and counter still order
        deterministically.
    time_source:
        Returns the current wall-clock time in milliseconds. Inject a fake in
        tests for determinism; defaults to :func:`wall_clock_ms`.
    """

    __slots__ = ("_last", "_node_id", "_time_source")

    def __init__(self, node_id: str, time_source: Callable[[], int] = wall_clock_ms) -> None:
        if not node_id:
            raise ValueError("node_id must be a non-empty string")
        self._node_id = node_id
        self._time_source = time_source
        self._last = HLCTimestamp.zero(node_id)

    @property
    def node_id(self) -> str:
        return self._node_id

    @property
    def last(self) -> HLCTimestamp:
        """The most recently issued timestamp (without advancing the clock)."""
        return self._last

    def now(self) -> HLCTimestamp:
        """Issue a fresh timestamp for a local event."""
        physical = self._time_source()
        last = self._last
        if physical > last.wall_ms:
            issued = HLCTimestamp(physical, 0, self._node_id)
        else:
            issued = HLCTimestamp(last.wall_ms, last.counter + 1, self._node_id)
        self._last = issued
        return issued

    def update(self, remote: HLCTimestamp) -> HLCTimestamp:
        """Advance the clock on receiving ``remote`` and issue a local timestamp.

        Implements the standard HLC receive rule so causality is preserved across
        devices regardless of physical-clock skew.
        """
        physical = self._time_source()
        last = self._last
        wall = max(physical, last.wall_ms, remote.wall_ms)
        if wall == last.wall_ms and wall == remote.wall_ms:
            counter = max(last.counter, remote.counter) + 1
        elif wall == last.wall_ms:
            counter = last.counter + 1
        elif wall == remote.wall_ms:
            counter = remote.counter + 1
        else:
            counter = 0
        issued = HLCTimestamp(wall, counter, self._node_id)
        self._last = issued
        return issued
