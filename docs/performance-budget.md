<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Low-end-device performance budget

The people this tool is for document a habitability problem on **the only device they
have** — often an old, slow phone — and they do it while under stress. Capture, hashing,
and sealing therefore have to feel instant, with no network in the loop. This document
states the latency budget for that **local path**, ties it to a **reference low-end
device**, and explains how CI asserts the budget on every run so a regression is caught
before it ships.

The budget is enforced by [`tests/test_perf_budget.py`](../tests/test_perf_budget.py),
which runs under `make test` (`pytest -m "not integration"`) and hence in CI. The
constants in that module mirror the table below; keep the two in sync.

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

## The reference low-end device

We do not have a lab of old phones in CI, so we model one. The reference target is an
**older low-end smartphone, assumed ~10× slower than the CI runner** for this workload
(single-threaded hashing, symmetric encryption, small-object JSON, and local file I/O).
That multiplier is intentionally conservative for CPU-and-disk-bound work like SHA-256 and
AEAD; a real budget on hardware should replace the model with a measurement (see *Revisiting
the model* below).

The relationship the budget rests on:

```
device_latency  ≈  LOW_END_SLOWDOWN × ci_latency          (LOW_END_SLOWDOWN = 10)

so CI asserts:   ci_latency  <  device_budget / LOW_END_SLOWDOWN
```

If the CI-measured latency stays under `device_budget / 10`, then the reference device —
modeled as 10× slower — stays under its human-facing `device_budget`.

## The budget

`Device budget` is the human-facing target on the reference low-end phone. `CI-asserted`
is `device_budget ÷ 10`, the ceiling the test enforces on CI hardware.

| Operation | What is measured | Payload | Device budget | CI-asserted |
|-----------|------------------|---------|--------------:|------------:|
| Content hash | `sha256_bytes` of a capture | 4 MB | 500 ms | 50 ms |
| Seal / store | `store_original_bytes`: hash + AEAD-encrypt + write | 4 MB | 1000 ms | 100 ms |
| Custody append | `CustodyLog.append`: hash-link + Ed25519 sign | one entry | 200 ms | 20 ms |
| CRDT merge | `CaseDocument.merge` of another replica | ~20-issue case | 300 ms | 30 ms |
| Packet assembly | `build_packet`: bundle + `packet.html` + PDF | 1-item case | 2000 ms | 200 ms |

A capture as the tenant experiences it is the sum of hash + seal + two custody appends
(one at capture, one after the fixity re-check) plus the local model write — comfortably
inside a **perceptible moment** (well under one second) on the reference device, with the
trusted timestamp arriving later off the critical path.

## Tolerance band and why the test is not flaky

Timing tests are notorious for flaking. Two choices keep this one stable:

- **Best-of-N, not average.** Each operation is warmed up, then run N times and the
  **minimum** elapsed time (`time.perf_counter`) is taken. Noise — GC pauses, scheduler
  preemption, a busy CI box — can only make a run *slower*, so the minimum is a robust
  lower bound on "how fast can this go here." A slow neighbor never fails the test.
- **≥5× headroom locally.** The CI-asserted ceilings above sit roughly 15–30× above the
  measured local latency of each operation, so ordinary machine-to-machine variation
  (a CI runner a few times slower than a dev laptop) still leaves comfortable margin. The
  budget catches an *order-of-magnitude* regression — an accidental re-hash, an O(n²)
  merge, re-encrypting bulk data on a passphrase change — not a few percent of jitter.

## Revisiting the model

The `LOW_END_SLOWDOWN = 10` figure is a **stated assumption**, not a measurement. When the
project can run the budget on real reference hardware (a named old Android phone, per the
mobile-packaging work in [`ROADMAP.md`](../ROADMAP.md)), replace the model with a measured
device latency and, if warranted, adjust the multiplier or move to a device-in-the-loop
check. Until then, the CI assertion guards against regressions on the *shape* of the local
path, which is where the risk of an accidental slowdown actually lives.

## Reproducing locally

```
uv run pytest tests/test_perf_budget.py -q      # just the budget
make test                                       # the full default gate (includes it)
```
