<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Desktop packaging spike — Briefcase on macOS

> Roadmap item (workstream C): "Desktop packaging. *Objective:* a one-click desktop
> app for organizers. *Exit:* a packaged build (e.g. Briefcase/Tauri) that launches
> the app with no terminal." Issue #259. This document is the spike, not the build:
> it answers the narrower, answerable question the mobile spike answered for phones —
> **is the toolchain viable today against this app's real dependency stack, and if
> not, what specifically is blocking it?**

**Bottom line.** Yes, on Apple Silicon. Briefcase produced a macOS `.app` carrying
`cryptography`, `pillow`, `reportlab` and `piexif` — the exact stack that has no
mobile path at all. Desktop is not blocked by the thing that blocks mobile. Two real
obstacles were found and both are specific: the **universal2 (Intel-compatible)
build fails** because `cryptography` publishes arm64-only macOS wheels, and the
support package used here was **Python 3.12 while this project requires ≥3.14**.

Date: 2026-09-04. Briefcase 0.4.4, macOS arm64, host Python 3.12.14 in an isolated
venv (deliberately not the project environment — installing Briefcase there would
drift `uv.lock` and the merge gate would catch it).

## What was actually run

```console
$ briefcase new --no-input -Q app_name=habitablespike -Q gui_framework=Toga
$ # habitable's five real runtime dependencies added to the app's `requires`
$ briefcase create macOS --no-input
```

The app is a Toga hello-world carrying **habitable's dependency list**, not
habitable. That is the deliberate shape of a dependency-viability spike, and it is
also this spike's main limit — see *What this does not show*.

## Result 1 — the universal2 default fails, for a locatable reason

The first `briefcase create macOS` failed:

> Unable to install requirements. […] This may be because an x86_64 wheel that is
> compatible with Python 3.12 and a minimum macOS version of 11.0 is not available.
> You may need to build a non-universal app by setting `universal_build = False`.

Briefcase defaults to a **universal2** binary (arm64 + x86_64 in one bundle). The
arm64 half installed cleanly; the x86_64 half had nothing to install from. Queried
directly against the PyPI JSON API the same day, `cryptography` 50.0.1 publishes
exactly four macOS wheels:

```
cryptography-50.0.1-cp311-abi3-macosx_11_0_arm64.whl
cryptography-50.0.1-cp314-cp314t-macosx_11_0_arm64.whl
cryptography-50.0.1-cp39-abi3-macosx_11_0_arm64.whl
cryptography-50.0.1-pp311-pypy311_pp73-macosx_11_0_arm64.whl
```

All four are `arm64`. There is no Intel-Mac wheel. The other four dependencies are
fine: `pillow` ships both macOS architectures, and `asn1crypto`, `reportlab` and
`piexif` are pure-Python.

So a universal macOS build of habitable today means building `cryptography` from
source for x86_64, which needs a Rust toolchain in the build environment — the same
class of problem that ended the mobile path, arriving in a much smaller form.

## Result 2 — the arm64 build succeeds, with the whole native stack

With `universal_build = false`:

```console
[habitablespike] Created build/habitablespike/macos/app
```

```console
$ find build -name "*.app"
build/habitablespike/macos/app/Habitable Spike.app
$ ls "Habitable Spike.app/Contents/Resources/app_packages/"
cryptography/  PIL/  piexif/  reportlab/  …
```

Every native dependency is bundled. `du -sh build` → **256 MB** for the build tree,
which is a real distribution cost and should be measured properly before anyone
promises a download size.

## Result 3 — the Python version is the next question, not a solved one

The bundle carries `Python.framework/Versions/3.12`, matching the host interpreter
(`briefcase.toml`: "Generated using Python 3.12.14"). habitable pins
`requires-python = ">=3.14"`.

That gap is *probably* fine — `cryptography` ships `cp311-abi3` wheels, which load on
any later CPython, and `pillow` publishes cp314 wheels — but "probably" is not a
spike result. **Whether Briefcase publishes a macOS support package for Python 3.14
is the single next thing to check**, and it is cheap: run this same spike from a 3.14
host and see what framework version lands in the bundle.

## What this does not show

Stated plainly, because a spike that overstates itself is worse than no spike.

- **habitable was not packaged.** The bundle is a Toga hello-world with habitable's
  `requires`. Wiring `appserver.py`'s loopback API into a desktop shell — the actual
  product question — was not attempted.
- **The bundle was never launched.** `briefcase create` was run; `build` and `run`
  were not. Nothing here proves the bundled `cryptography` *imports*, only that it
  installed.
- **Python 3.12, not 3.14** (result 3).
- **macOS only.** Windows and Linux were not attempted. Both look easier on the wheel
  evidence — `cryptography` publishes `win_amd64` and `manylinux` x86_64/aarch64
  wheels — but that is an inference, not a run.
- **No signing or notarisation**, and no reproducible build recipe. An unsigned app
  shows a macOS user a security warning on first launch; that is a UX fact any
  eventual packaging must state rather than hide.

## Recommendation

Continue, and in this order:

1. Re-run this spike from a Python 3.14 host to settle result 3. Cheap, decisive.
2. Replace the Toga hello-world with the real loopback app and confirm it launches
   and serves. That converts a dependency spike into a product spike.
3. Decide the Intel-Mac question deliberately: ship arm64-only and say so, or take on
   a Rust-toolchain source build for x86_64. Do not discover it at release time.
4. Only then: signing, notarisation, size, and a reproducible recipe — the project
   already builds its wheel and relay image byte-identically twice and a desktop
   build should aim at the same bar or state why it cannot.

Nothing here is a decision to ship desktop packaging. It resolves the research
question the mobile spike resolved for phones, with the opposite answer.

## Sources

- Briefcase 0.4.4, run locally; `briefcase create macOS` logs retained in the run's
  own `logs/` directory (not committed — they contain absolute local paths)
- PyPI JSON API, queried directly 2026-09-04: `cryptography` 50.0.1, `pillow` 12.3.0,
  `reportlab` 5.0.1, `asn1crypto` 1.5.1, `piexif` 1.1.3 file listings
- [`native-mobile-packaging-spike.md`](native-mobile-packaging-spike.md) — the same
  question for phones, and its 2026-09-04 re-check
- `ROADMAP.md`, workstream C
