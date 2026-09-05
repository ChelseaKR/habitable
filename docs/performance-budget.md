<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Low-end-device performance budget

The people this tool is for document a habitability problem on **the only device they
have** — often an old, slow phone — and they do it while under stress. Capture, hashing,
and sealing therefore have to feel instant, with no network in the loop. This document
states the latency budget for that **local path**, ties it to a **reference low-end
device**, and explains how CI asserts the budget on every run so a regression is caught
before it ships.

The budget is enforced by [`tests/test_perf_budget.py`](../tests/test_perf_budget.py),
which runs under `make test` (`pytest -m "not integration"`) and hence in CI. The constants
in that module mirror the table below, and `test_document_table_matches_the_constants`
fails if the two ever disagree.

## What is (and is not) on the local path

The **local path** is everything that happens between the tenant pressing *capture* and
having an evidence-grade, verifiable record on the device, plus the two other operations
a tenant triggers by hand that must stay responsive:

1. **Content hash** — SHA-256 of a multi-megabyte capture (the fixity anchor).
2. **Seal / store** — `Vault.store_original_bytes` (and `Vault.seal_original`): encrypt
   the original under the data key and write it immutably to disk, re-hashing to bind the
   ciphertext to its content hash.
3. **Custody append** — `CustodyLog.append`: hash-link and Ed25519-sign one chain-of-custody
   entry.
4. **CRDT merge** — `CaseDocument.merge`: join another replica's state during offline-first
   sync.
5. **Packet assembly** — `build_packet`: render the signed bundle, the accessible
   `packet.html`, and the PDF for a case.

**Explicitly excluded: RFC 3161 timestamp-authority network latency.** Fetching a trusted
timestamp is **deliberately off the capture path** — it is asynchronous and deferred. When
the device is offline (or the authority is slow) the capture is queued and shown as
*awaiting-timestamp*; the token is fetched later by `resolve_deferred` once the device is
online (see [`docs/evidence-method.md`](evidence-method.md) and `src/habitable/capture.py`).
Network round-trips to a public TSA are governed by that authority and the network, not by
this tool, so they are **not** part of this budget. Those paths are exercised by the
`integration`-marked tests, which do not run in the default gate.

**Not excluded on purpose, just missing: vault unlock.** The scrypt derivation that opens
the keyfile is on the local path — the tenant pays it before they can capture anything —
and it is not in the table below. It is measured in *What has actually been measured*, and
it is the largest single latency this project has. See *The gap this budget still has*.

## The reference low-end device

We do not have a lab of old phones in CI, so we model one. The reference target is an
**older low-end smartphone, assumed ~10× slower than the CI runner** for this workload
(single-threaded hashing, symmetric encryption, small-object JSON, and local file I/O).
That multiplier is a stated assumption. It has never been checked against a phone, and
nothing below changes that; what *has* been checked is whether one multiplier can describe
five operations at once, and the answer is in *What has actually been measured*.

The relationship the budget rests on:

```
device_latency  ≈  LOW_END_SLOWDOWN × ci_latency          (LOW_END_SLOWDOWN = 10)

so CI asserts:   ci_latency  <  device_budget / LOW_END_SLOWDOWN
```

If the CI-measured latency stays under `device_budget / 10`, then the reference device —
modeled as 10× slower — stays under its human-facing `device_budget`.

## The budget

`Device budget` is the human-facing target on the reference low-end phone. `CI-asserted`
is `device_budget ÷ 10`, the ceiling the test enforces on CI hardware. `Test constant` is
the key in `DEVICE_BUDGET_MS`, so the table and the gate can be checked against each other
mechanically rather than by eye.

| Operation | Test constant | What is measured | Payload | Device budget | CI-asserted |
|-----------|---------------|------------------|---------|--------------:|------------:|
| Content hash | `content_hash` | `sha256_bytes` of a capture | 4 MB | 500 ms | 50 ms |
| Seal / store | `seal_store` | `store_original_bytes`: hash + AEAD-encrypt + write | 4 MB | 1000 ms | 100 ms |
| Custody append | `custody_append` | `CustodyLog.append`: hash-link + Ed25519 sign | one entry | 200 ms | 20 ms |
| CRDT merge | `crdt_merge` | `CaseDocument.merge` of another replica | ~20-issue case | 300 ms | 30 ms |
| Packet assembly | `packet_assembly` | `build_packet`: bundle + `packet.html` + PDF | 1-item case | 2000 ms | 200 ms |

A capture as the tenant experiences it is the sum of hash + seal + two custody appends
(one at capture, one after the fixity re-check) plus the local model write — comfortably
inside a **perceptible moment** (well under one second) on the reference device, with the
trusted timestamp arriving later off the critical path.

## Tolerance band and why the test is not flaky

Timing tests are notorious for flaking. Two choices keep this one stable:

- **Best-of-N, not average.** Each operation is warmed up, then run N times and the
  **minimum** elapsed time (`time.perf_counter`) is taken. Noise — GC pauses, scheduler
  preemption, a busy CI box — can only make a run *slower*, so the minimum is a robust
  lower bound on "how fast can this go here." This is now measured rather than hoped: on the
  development machine described below, a fixed kernel's best-of-N minimum reproduced across
  nine independent processes inside a **0.11–0.15 % band**, and four of the five budgeted
  operations moved by **≤1 %** between a run at load average 25–33 and a run at load average
  88. It is not universal, though — packet assembly moved 10 % between those two runs — so
  "a slow neighbour never fails the test" is true of the compute-bound rows and only mostly
  true of the heaviest one. See *Finding 1*.
- **Headroom of 8.8×–78× locally**, measured, not assumed. The ceilings above sit that far
  above the measured latency of each operation, so ordinary machine-to-machine variation (a
  CI runner a few times slower than a dev laptop) still leaves margin. The budget catches
  an *order-of-magnitude* regression — an accidental re-hash, an O(n²) merge, re-encrypting
  bulk data on a passphrase change — not a few percent of jitter. The spread of that range
  is itself a finding and is discussed below; the thinnest margin is packet assembly's
  8.8×, and it is the row a per-operation correction would break first.

## What has actually been measured

Everything in this section was produced by
[`scripts/report_perf_profile.py`](../scripts/report_perf_profile.py), which reports and
never gates, and can be re-run by anyone:

```
uv run python scripts/report_perf_profile.py --max-kdf-exponent 20
```

**Read this first.** *None of these numbers came from a phone.* They were taken on
2026-09-05 on an Apple M1 Pro (8 performance + 2 efficiency cores, 16 GB, macOS 26.4,
CPython 3.14.5), which is faster than any CI runner this project uses and unlike any device
a tenant owns. They are not a device measurement and they are not a substitute for one.
What they *are* is a characterisation of each operation's **shape** — what its cost is made
of — and shape is a property of the workload rather than of the machine, so it is the part
of issue [#258](https://github.com/ChelseaKR/habitable/issues/258) that is answerable
without the hardware.

Two full profiles were taken, and the difference between them turned out to be as
informative as either one:

- **Run A**, at an ambient load average of **25–33**.
- **Run B**, at an ambient load average of **88** on the same ten cores, because the
  machine was shared with unrelated work at the time.

Every figure below is a best-of-N minimum. Where the two runs agree, the range is quoted;
where they do not, that is stated as the finding rather than smoothed away.

### The noise floor, so nothing below is read too precisely

The same fixed kernel (SHA-256 of 4 MiB), run in nine independent processes, produced
minima inside a **0.11 % band in run A and a 0.15 % band in run B**. Within a single
process, individual samples ran up to 3 % slower than the minimum in run A; under run B's
load the tail stretched much further (p90/min up to 8.1 on some probes) while the *minimum*
barely moved. This is the tolerance-band argument working exactly as the section above
claims it does — but only for some operations, which is Finding 1.

**A difference smaller than ~0.2 % is not a difference.** Disk-touching probes are the
exception and are noisy well beyond that; they are flagged where they appear.

### Finding 1 — best-of-N immunises four operations against a busy machine, and does not immunise two

Run B ran at roughly three times run A's load average. Best-of-N exists precisely so that a
busy neighbour cannot change the answer, and for most of the local path it does not:

| Operation | Run A min | Run B min | Change |
|-----------|----------:|----------:|-------:|
| Seal / store (4 MB) | 6.905 ms | 6.902 ms | −0.05 % |
| Content hash (4 MB) | 2.231 ms | 2.227 ms | −0.2 % |
| Custody append | 0.2562 ms | 0.2569 ms | +0.3 % |
| CRDT merge (20 issues) | 1.438 ms | 1.424 ms | −1.0 % |
| Packet assembly (1 item) | 20.65 ms | 22.81 ms | **+10.5 %** |
| scrypt unlock (N=2¹⁵) | 228.4 ms | 260.3 ms | **+13.9 %** |
| scrypt (N=2²⁰) | 7.48 s | 10.33 s | **+38.2 %** |

Four operations moved by 1 % or less; two moved by 10–38 %. Retrying cannot win back a
resource that is genuinely shared, and these two are the ones that depend on such a
resource — packet assembly allocates 32 MiB per run, and scrypt's whole design is to occupy
memory. **This is the issue's claim, measured, with no phone in it:** a change in the
machine underneath these five operations did not move them by a common factor. It moved
four of them by nothing and two of them by a lot. A single scalar cannot describe that, and
it did not take a slower CPU to show it — only a busier one.

### Finding 2 — the operations do not share a cost structure either

Sweeping each operation across its own size knob and taking the local log-log slope
(consistent across both runs unless noted):

| Operation | Knob swept | Slope | What that means |
|-----------|------------|------:|-----------------|
| Content hash | 1 → 32 MiB payload | 1.00 at every step, both runs | entirely proportional to bytes |
| Seal / store | 1 → 32 MiB payload | 0.81–1.58, disk-noisy | proportional on average; neither extreme reproduced |
| CRDT merge | 5 → 160 issues | 0.96–1.01 | proportional to the incoming state |
| Custody append | chain of 10 → 5 000 entries | **0.00** | fixed cost; the chain length is invisible to it |
| Packet assembly | 1 → 8 captures | **0.26–0.59** | mostly fixed overhead at the budgeted payload |

Custody append costs 0.2513–0.2524 ms whether the chain behind it holds ten entries or five
thousand: it is one Ed25519 signature and one hash, and it tracks core speed alone. Packet
assembly costs 20.5–23.3 ms for the budgeted 1-item case and only 54–61 ms for eight
captures — the payload the budget picked is the *most* overhead-dominated point on its
curve, so its budget is really a budget on ReportLab's start-up and the interpreter, not on
the case. Content hash and merge are the two that cleanly track their input.

For one scalar to be right for all five, the reference device would have to be uniformly
10× slower at SIMD/hardware-accelerated hashing, at Ed25519 signing, at interpreting CPython
bytecode, at rendering a PDF, and at writing flash. Those are five different subsystems on a
phone, and they are not one number.

### Finding 3 — but *not* for the reasons the issue predicted

Issue #258 names three mechanisms for why the scalar would break. Two are refuted outright
on this workload; the third is real but is a different mechanism than the one stated. It
matters that the reasons were wrong, because each would have pointed a device measurement at
the wrong instrument.

- **"Hashing a large photo is memory-bandwidth bound."** It is not — it is nowhere near it.
  `memcpy` between oversized buffers reaches 112–117 GB/s of traffic when cache-resident and
  68–85 GB/s from DRAM; SHA-256 sustains **1.86–1.88 GB/s**, i.e. **2 % of available
  streaming bandwidth**, and ChaCha20-Poly1305 sustains 2.65–2.77 GB/s (2–4 %). Both rates
  are *flat* across a 1 000× change in working set (64 KiB → 64 MiB) in both runs, which is
  the signature of a compute-bound kernel: a bandwidth-bound one would fall off the moment
  it left cache. Content hashing's best-of-N moved 0.2 % between a quiet machine and one at
  load 88, which is the same conclusion arrived at a second way.
- **"CRDT merge is allocation-heavy."** It is not. Merging a 20-issue replica peaks at
  **28.1 KiB** of traced allocation, triggers **zero** generation-0 collections, and runs
  within 1 % of the same speed with the garbage collector disabled. It is linear in issue
  count and it was one of the four operations run B could not perturb. The allocation-heavy
  operation in this budget is packet assembly, at **32.1 MiB** peak — and that is the
  operation run B *did* perturb.
- **"scrypt … is the operation most likely to blow past a linear model on a device with less
  RAM."** The instinct is right and the stated mechanism is wrong, which matters because
  they call for different instruments. scrypt does **not** scale superlinearly with its own
  cost parameter: swept from N=2¹⁰ to N=2²⁰ — a working set from 1 MiB to 1 GiB — cost per
  MiB moved from 6.998 to 7.301 ms on the quiet run, a **4.3 % rise across a 1 024× change
  in working set**, flat through and well past this machine's 12 MiB L2. What scrypt *is*
  uniquely sensitive to is **contention for memory it must share**: on the loaded run the
  same sweep scattered between 7.0 and 10.8 ms per MiB with no monotone trend, and the
  N=2²⁰ minimum rose 38 % while content hashing's moved 0.2 %. The cliff to look for on a
  phone is therefore a *capacity and contention* cliff — a working set competing with
  everything else the device is doing, paid in swap, compression, or an OOM kill — and not a
  bend in the N curve. **A 16 GB host structurally cannot produce that cliff; it needs the
  phone.**

The picture that replaces the issue's is: **every compute kernel on the local path is
compute-bound and unmoved by a busy machine, and the memory sensitivity that does exist is
concentrated in the two operations nobody named.** Deliberately loading three cores with
memcpy traffic, versus the same three cores running cache-resident SHA-256, is consistent
with that ordering in both runs, though the margins are small and shrink as ambient load
rises (run A / run B):

| Operation | Bandwidth-load ÷ CPU-load | Peak traced allocation | gen-0 GCs |
|-----------|--------------------------:|-----------------------:|----------:|
| Content hash | 1.01 / 1.00 | 0.5 KiB | 0 |
| Custody append | 1.00 / 1.01 | 2.1 KiB | 0 |
| CRDT merge | 1.00 / 1.00 | 28.1 KiB | 0 |
| Seal / store | 1.10 / 1.03 | 8.0 MiB | 0 |
| Packet assembly | **1.20 / 1.10** | **32.1 MiB** | 0–1 |

Read the direction, not the magnitude: three added hogs cannot move much on a box already
at load 88, so run B compresses every ratio toward 1.00. The ordering is the same in both.

### Finding 4 — the headroom is not uniform, and the thin end is packet assembly

Measured latency against the ceiling the gate actually enforces:

| Operation | Measured (A / B) | CI-asserted ceiling | Headroom |
|-----------|-----------------:|--------------------:|---------:|
| Content hash | 2.23 / 2.23 ms | 50 ms | 22.4–22.5× |
| Seal / store | 6.91 / 6.90 ms | 100 ms | 14.5× |
| Custody append | 0.256 / 0.257 ms | 20 ms | 77.8–78.1× |
| CRDT merge | 1.44 / 1.42 ms | 30 ms | 20.9–21.1× |
| Packet assembly | 20.6 / 22.8 ms | 200 ms | **8.8–9.7×** |

This is roughly an eight-fold spread, and it replaces this document's previous claim that
the ceilings sit "roughly 15–30× above the measured local latency of each operation" — a
claim that was outside the true range in both directions and had never been measured. Two
consequences. Custody append is guarded at ~78×, which means its ceiling would not notice a
regression that made signing seventy times slower. Packet assembly is guarded at 8.8–9.7×
and is simultaneously the operation with the largest allocation footprint, the flattest size
curve, and one of the two whose latency a busy machine can actually move: if the reference
device turns out to be worse than 10× on anything, this is the row that fails first, and it
fails on ReportLab and the interpreter rather than on anything this budget describes.

### Finding 5 — `seal_store` is three operations wearing one budget

Decomposing the 4 MB seal: the fixity re-hash is 2.226–2.228 ms (32–35 % of the whole) and
the AEAD encrypt 3.032 ms (44–48 %), both reproducing to three digits across the two runs.
The isolated write of the same ciphertext did not reproduce at all — 3.673 ms in run A and
2.264 ms in run B — and the parts sum to 118–129 % of the whole, which is the finding: the
two compute kernels compose and the disk term does not. Treat the write row as an upper
bound, not an addend. Two compute kernels and a filesystem write are budgeted here as one
number, and on a device the compute halves scale with the core while the write half scales
with flash under write pressure. Nothing measurable here can say how those two move relative
to each other; the disk term is the least trustworthy number in this document even on the
machine it was measured on.

## The gap this budget still has: vault unlock

scrypt is on the local path — the tenant pays it before they can capture anything, every
time they open a locked vault, which is exactly the moment this document says has to feel
instant — and it is in no row of the table above. Measured on the machine described, quiet
run first:

| KDF profile | N | Working set | Measured (A / B) | At this document's own 10× model |
|-------------|--:|------------:|-----------------:|---------------------------------:|
| `standard` (the default) | 2¹⁵ | 32 MiB | 228 / 260 ms | 2.3–2.6 s |
| `hardened` (`key harden`) | 2¹⁷ | 128 MiB | 951 / 1387 ms | 9.5–13.9 s |
| `paranoid` | 2²⁰ | 1 GiB | 7.48 / 10.33 s | 75–103 s |

Every unlock re-derives the key-encryption key
([`docs/key-management.md`](key-management.md)), so this is paid every time, not once at
setup. At the default profile it costs 228 ms on a quiet machine — more than seven times the
31.4 ms sum of all five budgeted operations there — and it is the one number here with no
ceiling of any kind over it. It is also, per Finding 1, the operation whose cost a busy
machine moves the most, so the honest figure is a range and the range widens with load. The
`paranoid` profile asks for a 1 GiB working set that a low-end phone does not have: the
capacity cliff of Finding 3, on the one operation that would actually meet it.
[`docs/crypto-spec.md`](crypto-spec.md) §3.1 describes a procedure for raising the profile,
with no latency ceiling to check the new cost against.

This is deliberately **not** fixed by adding a `kdf_unlock` row here, for two reasons worth
stating rather than leaving as an omission. First, a device budget is a number about the
device, and inventing one for the operation whose cost is *most* device-dependent would be
the same modelling error this document is already trying to stop making. Second, asserting
it in CI would mean paying a quarter-second per repeat inside the gate that runs on every
push — on the one operation whose minimum is demonstrably not load-stable, which is the
recipe for a flaky gate — to defend a number nobody has justified. The right fix is a
measured unlock latency from the named hardware, and until then the honest state is a
documented gap rather than a fabricated ceiling.

## Revisiting the model

`LOW_END_SLOWDOWN = 10` is unchanged, and nothing measured above justifies changing it: a
slowdown factor is a ratio between two machines, and only one of them has been measured. The
measurements do change what is known about it.

**Established without the hardware.** A single scalar cannot be right for all five
operations. Two independent lines of evidence say so. *They do not share a cost structure*:
one is pure fixed cost (custody append, slope 0.00), two are proportional to their input
(slope 1.00), one is dominated by fixed overhead at exactly the payload the budget picked
(packet assembly, slope 0.26), and one is a compute pair plus a disk term that does not
compose. And *they do not respond alike when the machine underneath them changes*: tripling
the ambient load moved four of the five by ≤1 % and moved packet assembly by 10 % and the
unbudgeted scrypt unlock by 14–38 %. That second result is the issue's own claim, produced
without a phone — a change of machine conditions that is not a single factor. The budget is
therefore loose somewhere and tight somewhere else *today*: custody append is guarded at
~78×, packet assembly at 8.8–9.7×.

**Corrected without the hardware.** The three mechanisms issue #258 offered are not what is
happening on this workload. Hashing is not bandwidth-bound (2 % of streaming bandwidth, flat
across a 1 000× working set, unmoved by a machine at load 88) and merge is not
allocation-heavy (28.1 KiB, zero collections); both are simply compute-bound. scrypt is not
superlinear in N either — flat within 4.3 % over a 1 024× working set on a quiet machine —
but its risk does not disappear, it *relocates*: from a scaling curve, which this machine can
measure, to memory capacity and contention, which it cannot. A device measurement built
around the original three would instrument the wrong things, and would look for the scrypt
cliff on the wrong axis.

**Still requires the named phone, and cannot be faked.** Everything that matters most:

- **Per-operation slowdown factors.** Establishing that the shapes differ, and that a change
  of machine conditions moves them by different factors, shows one scalar must be wrong; it
  cannot say whether the device is 3× or 40× on any given row. That is a ratio between two
  machines, and it needs the second machine.
- **The scrypt capacity cliff.** Whether a device with 1–2 GB of RAM can derive the default
  32 MiB profile at all without swapping — and what `hardened` does to it — is a question
  about that device's free memory. It cannot be produced on a 16 GB host, and this document
  should not pretend otherwise.
- **Unlock latency, and therefore whether the default KDF profile is right.** See above.
- **Flash under write pressure.** The seal's write half was measured on an NVMe SSD, and it
  was the one term that would not reproduce even there. Cheap eMMC with a full filesystem
  behaves differently in kind, not only in degree.
- **The cross-architecture and cross-runtime deltas.** One CPU, one libc, one Python build
  was measured. A phone build changes all three, and there is no on-device build yet — the
  same blocker as mobile packaging in [`ROADMAP.md`](../ROADMAP.md).

The suggested shape in the issue still stands: name a specific device, model and year; run
the same operations; record the measured numbers beside the modelled ones here; and if the
per-operation ratios are not roughly flat — which the evidence above now predicts they will
not be — replace the single scalar with per-operation factors. Until then the CI assertion
guards against regressions in the *shape* of the local path, which is where the risk of an
accidental slowdown actually lives, and this document does not claim more.

## Reproducing locally

```
uv run pytest tests/test_perf_budget.py -q                      # just the budget gate
make test                                                       # the full default gate
uv run python scripts/report_perf_profile.py                    # the profile above
uv run python scripts/report_perf_profile.py --section kdf      # one section
uv run python scripts/report_perf_profile.py --json out.json    # machine-readable
```

The profile script reports and never gates: it prints the machine it ran on and its load
average, quotes every figure as a distribution rather than a point, and exits 0 whatever it
finds. Timing must not gate — CI runners are shared and noisy, and a threshold over these
numbers would produce red builds that say nothing about the change under review. Run it at
least twice, and prefer runs at different ambient load: the disagreement between two runs
was the most informative measurement on this page.
