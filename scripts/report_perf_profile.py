#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Characterise the *shape* of every budgeted local-path operation — report, never gate (#258).

``docs/performance-budget.md`` converts a human-facing device budget into a CI ceiling by
dividing by one number, ``LOW_END_SLOWDOWN = 10``. That number is a stated assumption, and
issue #258 does not primarily dispute its size — it disputes that a *single scalar* can
stand in for five operations at once:

    "Hashing a large photo is memory-bandwidth bound; scrypt is memory-hard by design and
    is the operation most likely to blow past a linear model on a device with less RAM;
    CRDT merge is allocation-heavy. A device that is 10x slower on one may be 3x on
    another and 40x on a third."

That is a claim about the *workloads*, not about any particular phone, which is why it is
answerable on one machine with no phone in the room. If the five operations have
materially different cost structures — one saturating memory bandwidth, one bound by the
interpreter and the allocator, one whose working set is chosen to exceed cache on purpose
— then no single multiplier can track all five across a change of hardware, and the budget
is necessarily loose somewhere and tight somewhere else. If instead they all turn out to
be plain CPU-bound work with cache-resident working sets, one scalar is defensible and the
issue's premise is wrong. Either answer is worth having; neither requires the phone.

This script produces the numbers for that argument. It **cannot** produce the number the
issue actually asks for — a measured ratio against named hardware — and it does not
pretend to. Nothing here runs on a phone. See "What this cannot tell you" below.

Why it reports instead of gating
--------------------------------
Every ``scripts/check_*.py`` in this repository is a blocking merge gate. This is named
``report_`` for the same reason ``report_readability.py`` and ``report_i18n_key_usage.py``
are, and for one more: a *timing* measurement must never gate. CI runners are shared and
noisy, the numbers here move with ambient load, and a threshold over them would produce
red builds that carry no information about the change under review. The existing
``tests/test_perf_budget.py`` gate is deliberately coarse — order-of-magnitude ceilings
over a best-of-N minimum — and this script exists to inform *that* document, not to add a
second, finer, flakier gate beside it. Exit status is 0 whatever it measures; only
operator error exits non-zero.

The sections, and what each one is evidence for
-----------------------------------------------
``noise``
    The floor everything else is quoted against. The same fixed kernel is timed in several
    independent processes; the spread of the per-process *minima* is the honest resolution
    of this machine. Every other section reports a spread rather than a single figure, and
    a difference smaller than this floor is not a difference. The ambient load average is
    recorded with it, because on a shared machine that is part of the measurement.

``headroom``
    How far under its CI ceiling each budgeted operation actually sits, with the ceilings
    read out of ``tests/test_perf_budget.py`` rather than copied. The tolerance-band
    paragraph in the document makes a numeric claim about this; this section is the only
    thing that checks it. The *spread* of the column is also evidence in its own right —
    five operations under one scalar cannot all have the same margin, and the one with the
    least margin is the one a per-operation correction would break first.

``throughput``
    Sweeps each byte-shovelling kernel across working sets from L1-resident to far beyond
    last-level cache, and quotes each against ``memcpy`` on the same buffers. ``memcpy`` is
    definitionally bandwidth-bound, so "fraction of measured streaming bandwidth" is a
    scale-free answer to "is this operation memory-bound or compute-bound?" that transfers
    across machines better than any absolute millisecond figure. This is the section that
    tests the issue's first clause.

``scaling``
    Sweeps each budgeted operation across its own input-size knob and reports the local
    log-log slope. Slope ~1 is linear in input; slope ~0 means the cost is fixed overhead
    the input does not touch; slope >1 is superlinear and would be a defect. An operation
    whose cost is dominated by fixed overhead does not degrade like one whose cost is
    dominated by bytes, which is a second, independent way for one scalar to be wrong.

``decompose``
    Splits ``seal_store`` into hash / AEAD / write, because the budget treats it as one
    operation while it is three with different bottlenecks. Whichever component dominates
    is the one that decides how the composite moves on different hardware.

``alloc``
    Allocation intensity per operation: peak traced allocation, generation-0 collections
    triggered, and the gc-on / gc-off time ratio. The last is the discriminator: if
    disabling the collector measurably speeds an operation up, that operation is paying
    for allocation churn, and it will move with a device's allocator and memory subsystem
    rather than with its clock speed. This tests the issue's third clause.

``kdf``
    scrypt across its cost parameter, reported as time *per MiB of working set*. Constant
    ms/MiB means the memory hardness is being paid at a flat rate; a rising curve locates
    the point where the working set outgrows a cache level and the cost per byte changes.
    A phone's caches and RAM are smaller, so the curve says where its cliff would be even
    though it cannot say how deep. This tests the issue's second clause.

``contention``
    Re-measures every operation while the machine is loaded with either (a) cache-resident
    SHA-256, which consumes cores and almost no memory bandwidth, or (b) large-buffer
    memcpy, which consumes bandwidth. Conditions are interleaved round-robin so ambient
    load drifts affect all three equally. An operation that slows under (b) but not (a) is
    bandwidth-bound; one that slows equally under both is competing only for the core.

What this cannot tell you
-------------------------
- **It is not a device measurement.** No number here is from a phone, and no ratio here is
  the reference-device ratio. A slower core with less cache and less RAM can only be
  characterised by running on it.
- **It cannot produce per-operation slowdown factors.** Establishing that the operations
  have different shapes shows a single scalar *must* be wrong; the factors that would
  replace it need two machines, one of which is the named device.
- **It cannot see the ARM/x86 or the OS split.** Everything here is one CPU, one libc, one
  filesystem, one Python build.
- **Its disk numbers are this disk's.** Flash on a cheap phone is a different device with
  different latency under write pressure, and none of that is modelled.

Running it
----------
    uv run python scripts/report_perf_profile.py                 # every section
    uv run python scripts/report_perf_profile.py --section kdf   # just one
    uv run python scripts/report_perf_profile.py --json out.json # machine-readable too

The machine is described in the header of every run, because a number without the machine
it came from is not a measurement.
"""

from __future__ import annotations

import argparse
import ast
import contextlib
import gc
import hashlib
import json
import math
import multiprocessing
import os
import platform
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
import tracemalloc
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from multiprocessing.process import BaseProcess
from multiprocessing.synchronize import Event as EventType
from pathlib import Path
from typing import Final

import piexif
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from PIL import Image

from habitable.canonical import JSONValue, sha256_bytes
from habitable.capture import capture
from habitable.evidence import CustodyAction
from habitable.packet import build_packet
from habitable.tsa import LocalRfc3161TSA
from habitable.vault import Vault

MIB: Final = 1024 * 1024

# A fixed instant, matching tests/conftest.py, so nothing here depends on the wall clock.
_FIXED_EPOCH: Final = 1_767_312_000
_GENERATED_AT: Final = "2026-01-02T00:10:00Z"

# Never a real passphrase; these vaults exist for the length of one process and are
# deleted with their temporary directory.
_VAULT_PHRASE: Final = "profile-only-throwaway"

# The reference kernel for the noise floor: SHA-256 over 4 MiB, which is exactly the
# payload the budget's `content_hash` row uses, so the floor is quoted in the same
# currency as the thing it bounds.
_NOISE_PAYLOAD_BYTES: Final = 4 * MIB

# Background-load workers for the `contention` section. Three, not one per core: the goal
# is to make the memory subsystem visibly contended while leaving the measured process a
# core to run on, so that what the section reports is bandwidth pressure and not simply
# the scheduler time-slicing the probe.
_HOG_WORKERS: Final = 3
_HOG_BUFFER_BYTES: Final = 64 * MIB


# --------------------------------------------------------------------------------------
# Timing primitives
# --------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Timing:
    """One probe's timings in milliseconds, always as a distribution and never as a point.

    ``min_ms`` is the headline for the same reason ``tests/test_perf_budget.py`` asserts on
    a minimum: noise can only ever make a run slower, so the minimum is a robust lower
    bound on "how fast can this go here". The other four fields exist so a reader can see
    how far the machine wandered while producing that bound, and refuse to believe a
    difference narrower than the wander.
    """

    label: str
    n: int
    min_ms: float
    p50_ms: float
    p90_ms: float
    max_ms: float
    payload_bytes: int = 0
    traffic_bytes: int = 0

    @property
    def spread(self) -> float:
        """p90 / min — how much slower an unlucky run was than the best one."""
        return self.p90_ms / self.min_ms if self.min_ms > 0 else math.inf

    def as_dict(self) -> dict[str, object]:
        return {
            "label": self.label,
            "n": self.n,
            "min_ms": round(self.min_ms, 6),
            "p50_ms": round(self.p50_ms, 6),
            "p90_ms": round(self.p90_ms, 6),
            "max_ms": round(self.max_ms, 6),
            "spread": round(self.spread, 4),
            "payload_bytes": self.payload_bytes,
            "traffic_bytes": self.traffic_bytes,
        }


def _percentile(ordered: Sequence[float], fraction: float) -> float:
    """Nearest-rank percentile over an already-sorted sequence."""
    if not ordered:
        return math.nan
    rank = max(1, math.ceil(fraction * len(ordered)))
    return ordered[min(rank, len(ordered)) - 1]


def time_op(
    label: str,
    fn: Callable[[], object],
    *,
    repeats: int = 15,
    warmup: int = 3,
    payload_bytes: int = 0,
    traffic_bytes: int = 0,
) -> Timing:
    """Time ``fn`` ``repeats`` times after ``warmup`` untimed runs, as a distribution.

    ``traffic_bytes`` is the DRAM traffic the kernel is expected to generate, which is not
    the same as its payload: SHA-256 reads its input once, while ``memcpy`` and an AEAD
    that returns a fresh buffer read one copy and write another. Reporting both keeps the
    "fraction of streaming bandwidth" comparison in the ``throughput`` section honest —
    comparing a read-only kernel's payload rate against a read-write kernel's would
    manufacture a factor of two out of bookkeeping.
    """
    for _ in range(warmup):
        fn()
    samples: list[float] = []
    for _ in range(repeats):
        start = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - start) * 1000.0)
    samples.sort()
    return Timing(
        label=label,
        n=len(samples),
        min_ms=samples[0],
        p50_ms=statistics.median(samples),
        p90_ms=_percentile(samples, 0.90),
        max_ms=samples[-1],
        payload_bytes=payload_bytes,
        traffic_bytes=traffic_bytes,
    )


# --------------------------------------------------------------------------------------
# Fixtures: the real operations the budget names, built the way the budget's test builds
# them so the numbers here and the numbers there describe the same work
# --------------------------------------------------------------------------------------


def _counter_clock(start_ms: int) -> Callable[[], int]:
    """A deterministic millisecond clock advancing 1ms per call (mirrors tests/conftest)."""
    state = {"t": start_ms}

    def tick() -> int:
        state["t"] += 1
        return state["t"]

    return tick


def _make_vault(root: Path, name: str, *, case_id: str = "case-4B", seq: int = 1) -> Vault:
    """A throwaway vault on a deterministic clock, in ``root``."""
    root.mkdir(parents=True, exist_ok=True)
    clock = _counter_clock(_FIXED_EPOCH * 1000 + seq * 1_000_000)
    return Vault.create(root / name, _VAULT_PHRASE, case_id=case_id, unit="4B", time_source=clock)


def _payload(size: int) -> bytes:
    """A fixed non-random byte pattern of ``size`` bytes.

    Contents are irrelevant to every kernel measured here — SHA-256, ChaCha20-Poly1305 and
    memcpy all touch every byte at a data-independent cost — and a fixed pattern keeps runs
    comparable without pulling in a random source.
    """
    return b"\xa5" * size


def _make_jpeg(path: Path) -> Path:
    """A tiny synthetic JPEG with EXIF, so `capture` exercises its real metadata path."""
    image = Image.new("RGB", (16, 16), (120, 30, 30))
    exif = {piexif.ExifIFD.DateTimeOriginal: b"2026:01:02 03:04:05"}
    payload = {"0th": {}, "Exif": exif, "GPS": {}, "1st": {}, "thumbnail": None}
    image.save(path, "jpeg", exif=piexif.dump(payload))
    return path


def _populated_peer_state(root: Path, issues: int) -> dict[str, JSONValue]:
    """A peer replica's CRDT state carrying ``issues`` issues, each with a timeline entry
    and a capture — the same shape ``tests/test_perf_budget.py`` merges, parameterised."""
    peer = _make_vault(root, f"peer-{issues}", seq=issues + 2)
    for i in range(issues):
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
    return peer.document.to_state()


@dataclass(slots=True)
class BudgetedOps:
    """Callables for the five budgeted operations, each ready to be timed repeatedly.

    Held together in one object because several of them need a live vault and a scratch
    directory that must outlive the individual measurement, and because the `alloc` and
    `contention` sections both want the same set of prepared callables rather than each
    rebuilding them slightly differently.
    """

    root: Path
    payload_bytes: int
    content_hash: Callable[[], object]
    seal_store: Callable[[], object]
    custody_append: Callable[[], object]
    crdt_merge: Callable[[], object]
    packet_assembly: Callable[[], object]

    def as_mapping(self) -> dict[str, Callable[[], object]]:
        return {
            "content_hash": self.content_hash,
            "seal_store": self.seal_store,
            "custody_append": self.custody_append,
            "crdt_merge": self.crdt_merge,
            "packet_assembly": self.packet_assembly,
        }


def build_budgeted_ops(root: Path, *, payload_mib: int = 4, merge_issues: int = 20) -> BudgetedOps:
    """Prepare the five budgeted operations against a live vault under ``root``."""
    payload = _payload(payload_mib * MIB)
    content_hash = sha256_bytes(payload)

    seal_vault = _make_vault(root, "seal", seq=1)
    seal_counter = {"n": 0}

    def seal() -> None:
        seal_counter["n"] += 1
        seal_vault.store_original_bytes(f"cap-{seal_counter['n']}", payload, content_hash)

    custody_vault = _make_vault(root, "custody", case_id="case-custody", seq=2)
    custody_counter = {"n": 0}

    def append() -> None:
        custody_counter["n"] += 1
        custody_vault.custody.append(
            CustodyAction.CAPTURED,
            f"cap-{custody_counter['n']}",
            actor="profiler",
            hlc=str(custody_counter["n"]),
            details={"media_type": "image/jpeg"},
            identity=custody_vault.identity,
        )

    merge_local = _make_vault(root, "merge-local", seq=3)
    merge_state = _populated_peer_state(root, merge_issues)

    packet_vault = _make_vault(root, "packet", case_id="case-packet", seq=4)
    issue = packet_vault.document.add_issue(
        category="mold", room="bath", title="Mold", issue_id="i1"
    )
    packet_vault.document.add_timeline_entry(issue, "observed", "spreading")
    tsa = LocalRfc3161TSA("profile-rfc3161", time_source=lambda: _FIXED_EPOCH)
    capture(packet_vault, _make_jpeg(root / "photo.jpg"), issue_id=issue, tsa=tsa)
    packet_counter = {"n": 0}
    packet_out = root / "packets"

    def assemble() -> None:
        packet_counter["n"] += 1
        build_packet(
            packet_vault, packet_out / f"pkt-{packet_counter['n']}", generated_at=_GENERATED_AT
        )

    return BudgetedOps(
        root=root,
        payload_bytes=payload_mib * MIB,
        content_hash=lambda: sha256_bytes(payload),
        seal_store=seal,
        custody_append=append,
        crdt_merge=lambda: merge_local.document.merge(merge_state),
        packet_assembly=assemble,
    )


# --------------------------------------------------------------------------------------
# Background load, for the contention section
# --------------------------------------------------------------------------------------


def _bandwidth_hog(stop: EventType, buffer_bytes: int) -> None:
    """Stream bytes between two buffers far larger than any cache, forever, until stopped.

    This is the load that a bandwidth-bound probe should notice and a cache-resident one
    should not. Two buffers, not one, so the traffic is a genuine read plus write rather
    than a read the prefetcher can serve from a resident line.
    """
    src = bytearray(buffer_bytes)
    dst = bytearray(buffer_bytes)
    while not stop.is_set():
        dst[:] = src


def _compute_hog(stop: EventType) -> None:
    """Hash a 16 KiB block in a tight loop: saturates a core, touches almost no DRAM.

    The control for ``_bandwidth_hog``. It consumes exactly the same number of cores at
    approximately the same duty cycle, so any *difference* in how a probe degrades between
    the two conditions is attributable to the memory subsystem rather than to the
    scheduler.
    """
    block = b"\x5a" * 16384
    while not stop.is_set():
        for _ in range(256):
            hashlib.sha256(block).digest()


@contextlib.contextmanager
def background_load(kind: str, *, workers: int = _HOG_WORKERS) -> Iterator[None]:
    """Run ``workers`` background hogs of ``kind`` ("none", "cpu" or "bandwidth")."""
    if kind == "none":
        yield
        return
    ctx = multiprocessing.get_context("spawn")
    stop = ctx.Event()
    procs: list[BaseProcess] = []
    for _ in range(workers):
        proc: BaseProcess = (
            ctx.Process(target=_bandwidth_hog, args=(stop, _HOG_BUFFER_BYTES))
            if kind == "bandwidth"
            else ctx.Process(target=_compute_hog, args=(stop,))
        )
        proc.start()
        procs.append(proc)
    # Let the workers reach steady state (spawn re-imports this module) before the probe
    # starts, or the first measurements would be taken against a load that is not yet on.
    deadline = time.perf_counter() + 2.0
    while time.perf_counter() < deadline:
        time.sleep(0.05)
    try:
        yield
    finally:
        stop.set()
        for proc in procs:
            proc.join(timeout=10)
            if proc.is_alive():
                proc.terminate()


# --------------------------------------------------------------------------------------
# Sections
# --------------------------------------------------------------------------------------


def _print_header(*, extra: str = "") -> None:
    """Column headings for a block of :class:`Timing` rows."""
    header = f"{'probe':<34}{'n':>4}{'min ms':>12}{'p50':>10}{'p90':>10}{'max':>10}{'p90/min':>9}"
    print(header + (f"{extra:>14}" if extra else ""))
    print("-" * (len(header) + (14 if extra else 0)))


def _format_timing(t: Timing, *, extra: str = "") -> str:
    line = (
        f"{t.label:<34}{t.n:>4}{t.min_ms:>12.4f}{t.p50_ms:>10.4f}"
        f"{t.p90_ms:>10.4f}{t.max_ms:>10.4f}{t.spread:>9.2f}"
    )
    return line + (f"{extra:>14}" if extra else "")


def section_noise(rounds: int) -> dict[str, object]:
    """Measure this machine's timing resolution, so every later claim has a floor.

    The point is not the absolute number. It is that a *separate process* re-running the
    identical kernel lands within some band of the last one, and any effect this script
    reports that is smaller than that band is indistinguishable from the machine having a
    slightly different mood. Running the rounds in subprocesses rather than in a loop is
    deliberate: it folds in interpreter start-up state, page-cache state, and whatever the
    scheduler is doing this second, all of which a single in-process loop hides.
    """
    print("\n== noise floor ==")
    print(f"load average at start: {os.getloadavg()}")
    # Allocated once, outside the timed region. Building the buffer inside it would fold a
    # 4 MiB allocation into every sample and report the allocator's tail as the hash's.
    buffer = _payload(_NOISE_PAYLOAD_BYTES)
    in_process = time_op(
        f"sha256 {_NOISE_PAYLOAD_BYTES // MIB} MiB (in-process)",
        lambda: hashlib.sha256(buffer).digest(),
        repeats=25,
        warmup=3,
        payload_bytes=_NOISE_PAYLOAD_BYTES,
    )
    # The same kernel with the buffer allocated fresh each time. Reported alongside because
    # the difference between the two rows is not noise -- it is the cost and the tail of a
    # 4 MiB allocation, which is exactly the kind of thing that is invisible on a machine
    # with spare RAM and is not invisible on a phone.
    fresh = time_op(
        f"sha256 {_NOISE_PAYLOAD_BYTES // MIB} MiB (fresh buffer each run)",
        lambda: hashlib.sha256(_payload(_NOISE_PAYLOAD_BYTES)).digest(),
        repeats=25,
        warmup=3,
        payload_bytes=_NOISE_PAYLOAD_BYTES,
    )
    _print_header()
    print(_format_timing(in_process))
    print(_format_timing(fresh))

    minima: list[float] = []
    script = (
        "import hashlib,time;"
        f"b=b'\\xa5'*{_NOISE_PAYLOAD_BYTES};"
        "hashlib.sha256(b).digest();"
        "xs=[];\n"
        "for _ in range(15):\n"
        "    t=time.perf_counter(); hashlib.sha256(b).digest(); xs.append(time.perf_counter()-t)\n"
        "print(min(xs)*1000)"
    )
    for _ in range(rounds):
        # A fixed, literal argv: the interpreter running this script and a constant program.
        proc = subprocess.run(  # noqa: S603
            [sys.executable, "-c", script], capture_output=True, text=True, check=True
        )
        minima.append(float(proc.stdout.strip()))
    minima.sort()
    band = (minima[-1] - minima[0]) / minima[0] if minima[0] else math.inf
    print(
        f"\ncross-process minima (n={len(minima)}): "
        f"best {minima[0]:.4f} ms, worst {minima[-1]:.4f} ms, "
        f"median {statistics.median(minima):.4f} ms"
    )
    print(
        f"RESOLUTION FLOOR: {band * 100:.2f}% — a reported difference smaller than this "
        "is not a difference."
    )
    return {
        "load_average": list(os.getloadavg()),
        "in_process": in_process.as_dict(),
        "fresh_buffer": fresh.as_dict(),
        "cross_process_minima_ms": [round(m, 6) for m in minima],
        "resolution_floor_fraction": round(band, 6),
    }


def section_throughput() -> dict[str, object]:
    """Sweep the byte-shovelling kernels across the cache hierarchy and rank them against
    ``memcpy``.

    ``memcpy`` between two oversized buffers is as close to a pure streaming-bandwidth
    kernel as this machine can be asked for, so its rate at a given working set is a local
    estimate of achievable bandwidth there. Quoting SHA-256 and ChaCha20-Poly1305 as a
    *fraction* of it answers the issue's "hashing a large photo is memory-bandwidth bound"
    claim in a form that survives being read on a different machine: an absolute GB/s
    figure says nothing about whether the kernel is waiting on memory, and a fraction does.
    """
    print("\n== throughput vs working set (is the kernel memory-bound?) ==")
    sizes = [64 * 1024, 512 * 1024, 4 * MIB, 16 * MIB, 64 * MIB]
    key = ChaCha20Poly1305(b"\x11" * 32)
    nonce = b"\x22" * 12
    results: list[dict[str, object]] = []

    print(f"{'kernel':<22}{'working set':>13}{'min ms':>11}{'GB/s (traffic)':>17}{'vs memcpy':>11}")
    print("-" * 74)
    for size in sizes:
        src = bytearray(_payload(size))
        dst = bytearray(size)
        buf = bytes(src)

        def _copy(d: bytearray = dst, s: bytearray = src) -> None:
            d[:] = s

        def _hash(b: bytes = buf) -> bytes:
            return hashlib.sha256(b).digest()

        def _aead(b: bytes = buf) -> bytes:
            return key.encrypt(nonce, b, None)

        repeats = 25 if size <= 4 * MIB else 11
        # memcpy moves the payload twice (one read, one write); SHA-256 reads it once;
        # ChaCha20-Poly1305 reads it and writes a fresh ciphertext buffer.
        copy_t = time_op(
            "memcpy", _copy, repeats=repeats, payload_bytes=size, traffic_bytes=2 * size
        )
        hash_t = time_op("sha256", _hash, repeats=repeats, payload_bytes=size, traffic_bytes=size)
        aead_t = time_op(
            "chacha20poly1305", _aead, repeats=repeats, payload_bytes=size, traffic_bytes=2 * size
        )
        peak = copy_t.traffic_bytes / (copy_t.min_ms / 1000.0) / 1e9
        for t in (copy_t, hash_t, aead_t):
            rate = t.traffic_bytes / (t.min_ms / 1000.0) / 1e9
            label = f"{size // 1024} KiB" if size < MIB else f"{size // MIB} MiB"
            print(f"{t.label:<22}{label:>13}{t.min_ms:>11.4f}{rate:>17.2f}{rate / peak:>10.0%}")
            entry = t.as_dict()
            entry["traffic_gb_s"] = round(rate, 4)
            entry["fraction_of_memcpy"] = round(rate / peak, 4)
            entry["working_set_bytes"] = size
            results.append(entry)
        print()
    return {"rows": results, "sizes_bytes": sizes}


def _loglog_slope(x0: float, y0: float, x1: float, y1: float) -> float:
    """Local exponent of y ~ x**k between two points."""
    if x0 <= 0 or x1 <= 0 or y0 <= 0 or y1 <= 0 or x0 == x1:
        return math.nan
    return math.log(y1 / y0) / math.log(x1 / x0)


def _print_sweep(title: str, knob: str, rows: list[tuple[float, Timing]]) -> None:
    print(f"\n-- {title} --")
    print(f"{knob:>14}{'min ms':>12}{'p90':>10}{'p90/min':>9}{'slope':>9}")
    previous: tuple[float, float] | None = None
    for value, timing in rows:
        slope = (
            _loglog_slope(previous[0], previous[1], value, timing.min_ms)
            if previous is not None
            else math.nan
        )
        slope_text = "     -   " if math.isnan(slope) else f"{slope:>9.2f}"
        print(
            f"{value:>14g}{timing.min_ms:>12.4f}{timing.p90_ms:>10.4f}{timing.spread:>9.2f}{slope_text}"
        )
        previous = (value, timing.min_ms)


def _sweep_bytes(root: Path) -> dict[str, list[tuple[float, Timing]]]:
    """``content_hash`` and ``seal_store`` across payload size."""
    hash_rows: list[tuple[float, Timing]] = []
    seal_rows: list[tuple[float, Timing]] = []
    seal_vault = _make_vault(root, "scale-seal", seq=11)
    counter = {"n": 0}
    for mib in (1, 2, 4, 8, 16, 32):
        payload = _payload(mib * MIB)
        digest = sha256_bytes(payload)

        def _hash(p: bytes = payload) -> str:
            return sha256_bytes(p)

        def _seal(p: bytes = payload, h: str = digest) -> None:
            counter["n"] += 1
            seal_vault.store_original_bytes(f"cap-{counter['n']}", p, h)

        hash_rows.append((float(mib), time_op(f"hash {mib} MiB", _hash, repeats=11)))
        seal_rows.append((float(mib), time_op(f"seal {mib} MiB", _seal, repeats=7, warmup=2)))
    return {"content_hash": hash_rows, "seal_store": seal_rows}


def _sweep_merge(root: Path) -> list[tuple[float, Timing]]:
    """``crdt_merge`` across the number of issues in the incoming replica state."""
    rows: list[tuple[float, Timing]] = []
    for issues in (5, 10, 20, 40, 80, 160):
        state = _populated_peer_state(root, issues)
        local = _make_vault(root, f"scale-merge-{issues}", seq=100 + issues)

        def _merge(v: Vault = local, st: dict[str, JSONValue] = state) -> None:
            v.document.merge(st)

        rows.append((float(issues), time_op(f"merge {issues}", _merge, repeats=9)))
    return rows


def _sweep_custody(root: Path) -> list[tuple[float, Timing]]:
    """``custody_append`` against a chain that keeps growing underneath it.

    The chain is hash-linked, so an implementation that re-walked or re-serialised it on
    every append would be O(n) in a log that only ever grows. Sweeping the chain length is
    how that shows up as a slope instead of as a surprise three years in.
    """
    rows: list[tuple[float, Timing]] = []
    vault = _make_vault(root, "scale-custody", case_id="case-cust", seq=300)
    appended = {"n": 0}

    def append_one() -> None:
        appended["n"] += 1
        vault.custody.append(
            CustodyAction.CAPTURED,
            f"cap-{appended['n']}",
            actor="profiler",
            hlc=str(appended["n"]),
            details={"media_type": "image/jpeg"},
            identity=vault.identity,
        )

    for target in (10, 100, 1000, 5000):
        while appended["n"] < target:
            append_one()
        rows.append((float(target), time_op(f"append @{target}", append_one, repeats=25)))
    return rows


def _sweep_packet(root: Path) -> list[tuple[float, Timing]]:
    """``packet_assembly`` across the number of captures the packet has to render."""
    rows: list[tuple[float, Timing]] = []
    tsa = LocalRfc3161TSA("profile-rfc3161", time_source=lambda: _FIXED_EPOCH)
    vault = _make_vault(root, "scale-packet", case_id="case-pkt", seq=400)
    issue = vault.document.add_issue(category="mold", room="bath", title="Mold", issue_id="i1")
    vault.document.add_timeline_entry(issue, "observed", "spreading")
    jpeg = _make_jpeg(root / "scale-photo.jpg")
    built = {"n": 0}

    def assemble() -> None:
        built["n"] += 1
        build_packet(vault, root / "scale-packets" / f"p{built['n']}", generated_at=_GENERATED_AT)

    for captures in (1, 2, 4, 8):
        while len(vault.document.captures()) < captures:
            capture(vault, jpeg, issue_id=issue, tsa=tsa)
        rows.append(
            (float(captures), time_op(f"packet x{captures}", assemble, repeats=5, warmup=1))
        )
    return rows


def section_scaling(root: Path) -> dict[str, object]:
    """Sweep each budgeted operation across its own input-size knob.

    The budget quotes one payload per operation and one multiplier for all of them. Two
    operations only move together across a change of hardware if their costs are made of
    the same stuff, and the cheapest way to see what an operation's cost is made of is to
    vary its input and watch. A local log-log slope near 1 says the cost is the input; near
    0 says the cost is fixed overhead the input never touches; above 1 says the
    implementation is superlinear in something and is a defect worth its own issue.
    """
    print("\n== scaling with input size (what is the cost actually made of?) ==")
    byte_rows = _sweep_bytes(root)
    _print_sweep("content_hash — payload MiB", "MiB", byte_rows["content_hash"])
    _print_sweep("seal_store — payload MiB", "MiB", byte_rows["seal_store"])
    merge_rows = _sweep_merge(root)
    _print_sweep("crdt_merge — issues in the incoming state", "issues", merge_rows)
    custody_rows = _sweep_custody(root)
    _print_sweep("custody_append — existing chain length", "chain", custody_rows)
    packet_rows = _sweep_packet(root)
    _print_sweep("packet_assembly — captures in the case", "captures", packet_rows)
    return {
        "content_hash": [(v, t.as_dict()) for v, t in byte_rows["content_hash"]],
        "seal_store": [(v, t.as_dict()) for v, t in byte_rows["seal_store"]],
        "crdt_merge": [(v, t.as_dict()) for v, t in merge_rows],
        "custody_append": [(v, t.as_dict()) for v, t in custody_rows],
        "packet_assembly": [(v, t.as_dict()) for v, t in packet_rows],
    }


def section_decompose(root: Path) -> dict[str, object]:
    """Split ``seal_store`` into its three parts, because the budget treats it as one.

    ``store_original_bytes`` re-hashes the plaintext to confirm fixity, AEAD-encrypts it,
    and writes the ciphertext. Those are a read-only compute kernel, a read-write compute
    kernel and a filesystem operation, and they answer to different properties of a device.
    Whichever one dominates here is the one that decides how the composite behaves
    elsewhere, so a budget that names only the composite is quietly betting on that split
    staying put.
    """
    print("\n== seal_store decomposition (which part is the operation?) ==")
    size = 4 * MIB
    payload = _payload(size)
    digest = sha256_bytes(payload)
    vault = _make_vault(root, "decompose", seq=500)
    key = ChaCha20Poly1305(b"\x33" * 32)
    nonce = b"\x44" * 12
    target = root / "decompose-out"
    target.mkdir(parents=True, exist_ok=True)
    ciphertext = key.encrypt(nonce, payload, b"aad")
    written = {"n": 0}

    def write_only() -> None:
        written["n"] += 1
        (target / f"blob-{written['n']}.bin").write_bytes(ciphertext)

    sealed = {"n": 0}

    def seal() -> None:
        sealed["n"] += 1
        vault.store_original_bytes(f"cap-{sealed['n']}", payload, digest)

    rows = [
        time_op("fixity re-hash (sha256)", lambda: sha256_bytes(payload), repeats=15),
        time_op("AEAD encrypt", lambda: key.encrypt(nonce, payload, b"aad"), repeats=15),
        time_op("write ciphertext to disk", write_only, repeats=15, warmup=2),
        time_op("store_original_bytes (whole)", seal, repeats=15, warmup=2),
    ]
    _print_header(extra="% of whole")
    whole = rows[-1].min_ms
    for row in rows:
        print(_format_timing(row, extra=f"{row.min_ms / whole:.0%}"))
    # The parts can sum to MORE than the whole, and saying so is the point. The standalone
    # write probe writes a fresh file into a directory this process has been hammering,
    # while the real seal writes into the vault; if the parts overshoot, the disk component
    # is the one that does not compose, and the reader should trust the compute rows and
    # treat the write row as an upper bound rather than an addend.
    parts = sum(r.min_ms for r in rows[:-1])
    print(f"\nparts sum to {parts / whole:.0%} of the whole (>100% means the parts do not compose)")
    return {
        "payload_bytes": size,
        "rows": [r.as_dict() for r in rows],
        "parts_over_whole": round(parts / whole, 4),
    }


def section_alloc(root: Path) -> dict[str, object]:
    """Quantify how much of each operation is allocator work rather than arithmetic.

    Three numbers per operation. ``peak KiB`` is the high-water mark of traced Python
    allocation, which says how much of the heap the operation touches. ``gen0`` counts the
    generation-0 collections the operation triggers, which is roughly proportional to how
    many container objects it churns. The one that decides the argument is ``gc off / on``:
    if turning the collector off makes an operation measurably faster, that operation is
    paying for allocation churn, and on a device it will move with the allocator, the
    memory subsystem and the amount of free RAM rather than with the clock. An operation
    at 1.00 is not paying that tax and will not move with it.
    """
    print("\n== allocation profile (which operations are allocator-bound?) ==")
    ops = build_budgeted_ops(root)
    print(
        f"{'operation':<20}{'peak KiB':>12}{'gen0 GCs':>11}"
        f"{'gc-on ms':>11}{'gc-off ms':>12}{'off/on':>9}"
    )
    print("-" * 75)
    rows: list[dict[str, object]] = []
    for name, fn in ops.as_mapping().items():
        fn()  # warm any lazily-built state before the traced run
        tracemalloc.start()
        before_gc = gc.get_stats()[0]["collections"]
        fn()
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        collections = gc.get_stats()[0]["collections"] - before_gc

        gc.enable()
        on = time_op(name, fn, repeats=9, warmup=2)
        gc.disable()
        try:
            off = time_op(name, fn, repeats=9, warmup=2)
        finally:
            gc.enable()

        ratio = off.min_ms / on.min_ms if on.min_ms else math.nan
        print(
            f"{name:<20}{peak / 1024:>12.1f}{collections:>11}"
            f"{on.min_ms:>11.4f}{off.min_ms:>12.4f}{ratio:>9.2f}"
        )
        rows.append(
            {
                "operation": name,
                "traced_peak_bytes": peak,
                "gen0_collections": collections,
                "gc_on": on.as_dict(),
                "gc_off": off.as_dict(),
                "off_over_on": round(ratio, 4),
            }
        )
    return {"rows": rows}


def section_kdf(max_exponent: int) -> dict[str, object]:
    """Sweep scrypt's cost parameter and report time *per MiB of working set*.

    scrypt's whole design is that cost is memory, so the interesting quantity is not how
    long a derivation takes but whether each additional MiB costs the same as the last one.
    A flat ms/MiB column means the machine is absorbing the working set at a constant rate.
    A rising column locates a level of the memory hierarchy the working set has outgrown,
    and that is the shape the issue predicts will "blow past a linear model on a device
    with less RAM" — because a smaller machine meets each of those steps at a smaller N,
    and eventually meets one this machine does not have at all.

    The sweep stops at ``max_exponent`` because the largest profile habitable can write
    (``paranoid``, N=2**20) has a 1 GiB working set, and allocating that on a shared
    machine is a rude thing to do without being asked.
    """
    print("\n== scrypt cost vs working set (the memory-hard operation) ==")
    print(f"{'N':>10}{'working set':>14}{'min ms':>12}{'p90':>10}{'p90/min':>9}{'ms per MiB':>13}")
    print("-" * 68)
    rows: list[dict[str, object]] = []
    salt = b"\x99" * 16
    for exponent in range(10, max_exponent + 1):
        n = 2**exponent
        footprint = 128 * n * 8  # 128 * N * r bytes, with r = 8 as KdfParams fixes it

        def derive(cost: int = n) -> bytes:
            return Scrypt(salt=salt, length=32, n=cost, r=8, p=1).derive(b"a-passphrase")

        repeats = 9 if footprint <= 32 * MIB else 5
        timing = time_op(f"scrypt N=2**{exponent}", derive, repeats=repeats, warmup=1)
        per_mib = timing.min_ms / (footprint / MIB)
        print(
            f"{n:>10}{footprint // MIB:>11} MiB{timing.min_ms:>12.3f}"
            f"{timing.p90_ms:>10.3f}{timing.spread:>9.2f}{per_mib:>13.4f}"
        )
        entry = timing.as_dict()
        entry["n"] = n
        entry["working_set_bytes"] = footprint
        entry["ms_per_mib"] = round(per_mib, 6)
        rows.append(entry)
    return {"rows": rows, "max_exponent": max_exponent}


def section_contention(root: Path) -> dict[str, object]:
    """Re-measure every operation under two loads that differ only in memory traffic.

    The two background loads occupy the same number of cores at the same duty cycle. One
    of them (cache-resident SHA-256) barely touches DRAM; the other (large-buffer memcpy)
    does almost nothing else. So the *difference* between how an operation degrades under
    the two is attributable to the memory subsystem and not to the scheduler — which is the
    only way to ask "is this bandwidth-bound?" on a machine whose bandwidth cannot be
    turned down.

    Conditions are interleaved in rounds rather than run in three blocks, because this
    machine is shared: a block layout would let a busy ten minutes land entirely on one
    condition and be reported as a property of that condition.
    """
    print("\n== contention sensitivity (bandwidth pressure vs core pressure) ==")
    print(f"load average at start: {os.getloadavg()}")
    ops = build_budgeted_ops(root).as_mapping()
    best: dict[str, dict[str, float]] = {
        name: {"none": math.inf, "cpu": math.inf, "bandwidth": math.inf} for name in ops
    }
    for _round in range(2):
        for kind in ("none", "cpu", "bandwidth"):
            with background_load(kind):
                for name, fn in ops.items():
                    timing = time_op(name, fn, repeats=7, warmup=1)
                    best[name][kind] = min(best[name][kind], timing.min_ms)

    print(
        f"{'operation':<20}{'idle ms':>11}{'+cpu load':>12}{'+bw load':>11}"
        f"{'cpu x':>8}{'bw x':>8}{'bw/cpu':>9}"
    )
    print("-" * 79)
    rows: list[dict[str, object]] = []
    for name in ops:
        idle = best[name]["none"]
        cpu_x = best[name]["cpu"] / idle
        bw_x = best[name]["bandwidth"] / idle
        print(
            f"{name:<20}{idle:>11.4f}{best[name]['cpu']:>12.4f}{best[name]['bandwidth']:>11.4f}"
            f"{cpu_x:>8.2f}{bw_x:>8.2f}{bw_x / cpu_x:>9.2f}"
        )
        rows.append(
            {
                "operation": name,
                "idle_min_ms": round(idle, 6),
                "cpu_load_min_ms": round(best[name]["cpu"], 6),
                "bandwidth_load_min_ms": round(best[name]["bandwidth"], 6),
                "cpu_slowdown": round(cpu_x, 4),
                "bandwidth_slowdown": round(bw_x, 4),
                "bandwidth_over_cpu": round(bw_x / cpu_x, 4),
            }
        )
    return {"rows": rows, "workers": _HOG_WORKERS, "hog_buffer_bytes": _HOG_BUFFER_BYTES}


_BUDGET_TEST: Final = Path(__file__).resolve().parent.parent / "tests" / "test_perf_budget.py"


def read_budget() -> tuple[float, dict[str, float]]:
    """Read ``LOW_END_SLOWDOWN`` and ``DEVICE_BUDGET_MS`` out of the budget test by parsing it.

    Deliberately *not* a copy of the numbers. The budget already lives in two places that
    must agree — the table in ``docs/performance-budget.md`` and the constants in
    ``tests/test_perf_budget.py`` — and a third copy in a script nobody runs on every PR is
    exactly how a document starts quoting a ceiling CI stopped enforcing. Parsing the test
    with ``ast`` (no import, so no test collection and no fixtures) means this report is
    wrong the moment it disagrees with the gate, rather than quietly stale.
    """
    tree = ast.parse(_BUDGET_TEST.read_text(encoding="utf-8"))
    found: dict[str, object] = {}
    for node in tree.body:
        targets = [node.target] if isinstance(node, ast.AnnAssign) else getattr(node, "targets", [])
        value = getattr(node, "value", None)
        for target in targets:
            if isinstance(target, ast.Name) and value is not None:
                with contextlib.suppress(ValueError):
                    found[target.id] = ast.literal_eval(value)
    slowdown = found.get("LOW_END_SLOWDOWN")
    budgets = found.get("DEVICE_BUDGET_MS")
    if not isinstance(slowdown, int | float) or not isinstance(budgets, dict):
        raise SystemExit(f"could not read the budget constants from {_BUDGET_TEST}")
    return float(slowdown), {str(k): float(v) for k, v in budgets.items()}


def section_headroom(root: Path) -> dict[str, object]:
    """Measure how far under its CI ceiling each budgeted operation actually sits.

    ``docs/performance-budget.md`` claims the ceilings "sit roughly 15-30x above the
    measured local latency of each operation". That is a factual claim about this
    repository, it is the claim the tolerance band rests on, and until this section existed
    nothing produced the numbers that would confirm or refute it. A single scalar over five
    operations cannot give five equal headrooms, so the spread of this column is itself
    evidence about the scalar: the operation with the least headroom is the one a modest
    per-operation correction would push through the ceiling first.
    """
    print("\n== headroom: measured latency vs the CI ceiling the gate enforces ==")
    slowdown, budgets = read_budget()
    print(f"(budget constants read from {_BUDGET_TEST.name}; LOW_END_SLOWDOWN = {slowdown:g})")
    ops = build_budgeted_ops(root).as_mapping()
    print(
        f"{'operation':<20}{'measured ms':>13}{'CI ceiling':>12}"
        f"{'headroom':>10}{'device budget':>15}{'modelled ms':>13}"
    )
    print("-" * 83)
    rows: list[dict[str, object]] = []
    for name, fn in ops.items():
        repeats = 5 if name == "packet_assembly" else 11
        timing = time_op(name, fn, repeats=repeats, warmup=2)
        ceiling = budgets[name] / slowdown
        rows.append(
            {
                "operation": name,
                "measured": timing.as_dict(),
                "ci_ceiling_ms": ceiling,
                "headroom": round(ceiling / timing.min_ms, 3),
                "device_budget_ms": budgets[name],
                "modelled_device_ms": round(timing.min_ms * slowdown, 4),
            }
        )
        print(
            f"{name:<20}{timing.min_ms:>13.4f}{ceiling:>12.0f}"
            f"{ceiling / timing.min_ms:>9.1f}x{budgets[name]:>15.0f}"
            f"{timing.min_ms * slowdown:>13.1f}"
        )
    ratios = [float(str(r["headroom"])) for r in rows]
    print(f"\nheadroom spans {min(ratios):.1f}x to {max(ratios):.1f}x across the five operations")
    return {"low_end_slowdown": slowdown, "rows": rows}


# --------------------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------------------


def _machine() -> dict[str, object]:
    """Everything a reader needs to know whether these numbers apply to them."""
    return {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python": sys.version.split()[0],
        "cpu_count": os.cpu_count(),
        "load_average": list(os.getloadavg()),
    }


SECTIONS: Final = (
    "noise",
    "headroom",
    "throughput",
    "scaling",
    "decompose",
    "alloc",
    "kdf",
    "contention",
)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--section",
        action="append",
        choices=SECTIONS,
        help="run only this section (repeatable); default is all of them",
    )
    parser.add_argument("--json", type=Path, help="also write the raw results here")
    parser.add_argument(
        "--noise-rounds", type=int, default=9, help="subprocess rounds for the noise floor"
    )
    parser.add_argument(
        "--max-kdf-exponent",
        type=int,
        default=18,
        help="largest scrypt N=2**k to derive (18 => a 256 MiB working set)",
    )
    args = parser.parse_args(argv)
    chosen = tuple(args.section) if args.section else SECTIONS

    machine = _machine()
    print("habitable — local-path performance profile (report only; never a gate)")
    for key, value in machine.items():
        print(f"  {key}: {value}")
    print(
        "\nNOTHING HERE WAS MEASURED ON A PHONE. This characterises the shape of each\n"
        "operation on one machine; it cannot produce the reference-device ratio that\n"
        "docs/performance-budget.md still needs. See the module docstring."
    )

    sections: dict[str, object] = {}
    root = Path(tempfile.mkdtemp(prefix="habitable-perf-"))
    # Keyed by section name and run in SECTIONS order, so `--section a --section b` always
    # produces the same report as `--section b --section a`. Order matters more than it
    # looks: `noise` establishes the floor the later sections are read against, and a
    # report that printed it last would invite reading the numbers before their error bar.
    runners: dict[str, Callable[[], dict[str, object]]] = {
        "noise": lambda: section_noise(args.noise_rounds),
        "headroom": lambda: section_headroom(root / "headroom"),
        "throughput": section_throughput,
        "scaling": lambda: section_scaling(root / "scaling"),
        "decompose": lambda: section_decompose(root / "decompose"),
        "alloc": lambda: section_alloc(root / "alloc"),
        "kdf": lambda: section_kdf(args.max_kdf_exponent),
        "contention": lambda: section_contention(root / "contention"),
    }
    try:
        for name in SECTIONS:
            if name in chosen:
                sections[name] = runners[name]()
    finally:
        shutil.rmtree(root, ignore_errors=True)

    if args.json:
        results = {"machine": machine, "sections": sections}
        args.json.write_text(json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
