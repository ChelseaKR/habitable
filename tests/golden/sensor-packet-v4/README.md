<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# The instrument-data packet (`packet_version` 4)

This is the only packet in the corpus carrying a `sensor` record. Before it existed,
**no committed bundle held one at all** — measured across all six committed bundles in
issue #314 — so the instrument-data surface (EXP-09) sat outside the compatibility
guarantee entirely. `tests/golden/` is the corpus two documents point at as the promise
that old packets keep verifying, and a format surface absent from it is pinned by
nothing.

That surface is not a quiet corner. Both instrument-data defects found in one week were
found by *reading the code*, because there was no fixture that would have shown them:

- **#307** — a truncated series reported as complete. `parse_sensor_csv` keeps at most
  500 readings and the PDF table then shows at most forty of those, and each renderer
  named one of those reductions as though it were the other.
- **#311** — rows that could not be read at all were excluded from `total_rows` and from
  `mean`, and the only notice sat behind a collapsed `<details>` in the HTML while the
  PDF put it in the normal flow. One bundle, two renderings, one of them silent.

It is deliberately **not** named `packet-v*`. That glob is the one-fixture-per-format-
version corpus that `tests/test_golden.py`, `tests/test_verify_fuzz.py`,
`tests/test_contrib_importer.py` and `tests/test_property_invariants.py` enumerate; this
is a second packet of a version that already has one, and enrolling it in those
harnesses is a separate decision from committing it — the same reasoning
`scoped-packet-v3/README.md` records. `tests/test_golden.py` verifies it explicitly and
asserts what it is for.

## What it is evidence of

Two captures, chosen so the fixture pins the honesty notices rather than the happy path:

| capture | source rows | readings parsed | in `bundle.json` | `skipped_rows` | `truncated` |
|---|---|---|---|---|---|
| `clean.csv` | 6 | 6 | 6 | 0 | false |
| `lossy.csv` | 620 | 600 | 500 | 20 | true |

The second row is the one that matters: it is the only committed record where all three
numbers a recipient can be misled about are different from each other. A fixture whose
counts were all multiples of the 500-row cap could not tell "kept 500 of 600" apart from
"kept 500 of 620", and those are exactly the two counts #311 is about. `mean` is 56.54,
an average over the 600 readings that parsed — not over the 620 rows the instrument
wrote — which is the arithmetic the packet now says out loud instead of implying.

`clean.csv` is the complement, and it is load-bearing in the opposite direction: a
change that made every series read as damaged would pass a test that only checked the
lossy one.

## Regenerating it

    uv run python scripts/make_golden_sensor_packet.py

The script builds a fresh packet through the real pipeline with a deterministic clock
and a fixed-time local RFC 3161 issuer, and preserves this README. It is pinned to the
*current* packet version rather than frozen the way `scoped-packet-v3` is, because it
exists to pin a live format surface: `test_the_sensor_fixture_tracks_the_current_format`
fails on the next version bump until it is regenerated, which is the same discipline
`test_a_fixture_exists_for_every_version_we_have_ever_emitted` applies to the corpus
proper (issue #160).

## It verifies

`verify_packet` reports `structurally_intact`, `signature_ok` and `custody_ok` with no
problems — the same verdict every other fixture in this corpus gets. Synthetic
throughout: there is no real tenant, no real unit, and no real instrument behind it.
