# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Regenerate the instrument-data golden packet fixture.

``tests/golden/sensor-packet-v<PACKET_VERSION>/`` is the corpus's only packet carrying
a sensor record (EXP-09). Before it existed, the instrument-data surface was outside
the compatibility guarantee entirely: no committed bundle held a `sensor` object, so
nothing pinned how a series is emitted, rendered, or verified across a version bump
(issue #314). Both instrument-data defects found in the same week -- #307 (a truncated
series reported as complete) and #311 (unreadable rows excluded from the count and the
mean) -- were found by reading the code, because there was no fixture that would have
shown them.

Run it after an intentional, reviewed change to the sensor half of the export format:

    uv run python scripts/make_golden_sensor_packet.py

It builds a fresh packet with the real pipeline (a deterministic clock and a fixed-time
local RFC 3161 issuer), same as ``make_golden_packet.py``, and commits the verifiable
subset. The two captures are chosen so the fixture pins the *honesty notices* and not
just the happy path:

* ``clean.csv``  -- every row readable, nothing truncated. The complement: a series
  that must keep rendering as complete, so a future change cannot make every series
  read as damaged.
* ``lossy.csv``  -- 620 data rows of which 20 cannot be read, leaving 600 readings,
  of which ``parse_sensor_csv`` keeps 500. That is the record that carries all three
  numbers a recipient can be misled about at once: rows in the file, readings parsed,
  readings in the bundle.
"""

from __future__ import annotations

import shutil
import tempfile
from collections.abc import Callable
from pathlib import Path

from habitable.capture import capture
from habitable.packet import PACKET_VERSION, build_packet
from habitable.tsa import LocalRfc3161TSA
from habitable.vault import Vault

_FIXED_EPOCH = 1_767_312_000  # 2026-01-02T00:00:00Z — reproducible timestamps
_GENERATED_AT = "2026-01-02T00:10:00Z"
_ROOT = Path(__file__).resolve().parent.parent
_GOLDEN = _ROOT / "tests" / "golden" / f"sensor-packet-v{PACKET_VERSION}"

#: 620 data rows, 20 of them unreadable. Not a round hundred on purpose: a fixture whose
#: numbers are all multiples of the cap cannot distinguish "kept 500 of 600" from "kept
#: 500 of 620", and those are the two counts #311 is about.
_LOSSY_ROWS = 620
_LOSSY_UNREADABLE_EVERY = 31  # 620 // 31 == 20 unreadable rows


def _counter_ms(start_ms: int) -> Callable[[], int]:
    state = {"t": start_ms}

    def tick() -> int:
        state["t"] += 1
        return state["t"]

    return tick


def _clean_csv() -> bytes:
    """A short, wholly readable series: six hourly readings from a room logger."""
    rows = [b"Time,Temperature (F)\n"]
    for hour in range(6):
        rows.append(f"2026-01-02 {hour:02d}:00,{58.4 - hour * 1.7:.1f}\n".encode())
    return b"".join(rows)


def _lossy_csv() -> bytes:
    """A long export with dropped rows, of the kind a cheap logger really produces.

    Two ways a row fails, because the parser has two: a non-numeric value column (the
    instrument's own error marker) and a row with no value column at all.
    """
    rows = [b"Time,Temperature (F)\n"]
    for index in range(_LOSSY_ROWS):
        stamp = f"2026-01-02T{index // 60:02d}:{index % 60:02d}:00"
        if index % _LOSSY_UNREADABLE_EVERY == 0:
            # Alternate the two failure modes so the fixture exercises both.
            rows.append(
                f"{stamp},ERR\n".encode()
                if (index // _LOSSY_UNREADABLE_EVERY) % 2 == 0
                else f"{stamp}\n".encode()
            )
            continue
        rows.append(f"{stamp},{45.0 + (index % 97) * 0.25:.2f}\n".encode())
    return b"".join(rows)


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="golden-sensor-packet-"))
    vault = Vault.create(
        work / "vault",
        "golden-passphrase",
        case_id="golden-sensor-2C",
        unit="2C",
        time_source=_counter_ms(_FIXED_EPOCH * 1000),
    )
    issue = vault.document.add_issue(
        category="heat", room="bedroom", title="No heat", severity="severe"
    )
    vault.add_timeline_event(
        issue,
        event_type="condition_observed",
        text="bedroom logger left running for the week",
        occurred_at="2026-01-02",
        source="firsthand",
    )

    tsa = LocalRfc3161TSA("golden-tsa", time_source=lambda: _FIXED_EPOCH)
    for name, body in (("clean.csv", _clean_csv()), ("lossy.csv", _lossy_csv())):
        path = work / name
        path.write_bytes(body)
        capture(vault, path, issue_id=issue, tsa=tsa)

    out = work / "packet"
    build_packet(vault, out, generated_at=_GENERATED_AT, make_pdf=False)

    # Commit only the verifiable, self-contained subset (mirrors the other fixtures).
    # The README is written by hand and is not regenerated, so it is preserved.
    readme = _GOLDEN / "README.md"
    kept_readme = readme.read_bytes() if readme.is_file() else None
    if _GOLDEN.exists():
        shutil.rmtree(_GOLDEN)
    (_GOLDEN / "media").mkdir(parents=True)
    if kept_readme is not None:
        readme.write_bytes(kept_readme)
    shutil.copy(out / "bundle.json", _GOLDEN / "bundle.json")
    shutil.copy(out / "bundle.sig.json", _GOLDEN / "bundle.sig.json")
    for media_file in sorted((out / "media").iterdir()):
        shutil.copy(media_file, _GOLDEN / "media" / media_file.name)

    print(f"wrote {_GOLDEN.relative_to(_ROOT)} (packet_version={PACKET_VERSION})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
