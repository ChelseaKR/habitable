<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Native mobile packaging spike — BeeWare/Briefcase vs. Tauri

> Roadmap item (workstream C, v0.3 milestone): "Native mobile packaging spike (BeeWare/Briefcase or
> Tauri)." This document is the spike: what each toolchain actually requires against *this app's*
> real dependency stack, an attempted proof-of-concept build, and a recommendation. The decision to
> build and ship native mobile support is **not** made here — that remains a human/product call. What
> this resolves is the narrower, answerable research question: is either toolchain viable *today*,
> and if not, what specifically is blocking it.

**Bottom line.** Briefcase's Android backend is mechanically proven — a real, installable debug APK
was built end-to-end in this spike. But packaging *habitable itself* (not a hello-world) is blocked
on both platforms by one dependency: `cryptography` has no official iOS or Android wheels, and the
one community-maintained Android build available (via Chaquopy) is a version below this project's
floor and two Python versions behind its `requires-python`. Tauri is not viable at all for this app's
Python engine on mobile — its mobile Python story (RustPython) cannot load any of habitable's three
compiled dependencies. Recommendation: **do not build native mobile now**; re-check the one blocking
signal (`cryptography` mobile wheels) periodically rather than re-running the full spike.

---

## 1. What "native mobile packaging" has to wrap

habitable is not a hosted web app with a thin native shell — it's local-first by design, so a native
app has to carry the *engine*, not just a UI:

- **Backend:** a localhost-only JSON API server (`src/habitable/appserver.py`) built on the Python
  standard library alone — `http.server.BaseHTTPRequestHandler` / `ThreadingHTTPServer`, no web
  framework. It holds the unlocked vault in memory and serves `/api/*` routes reused directly by the
  CLI's own tested core (`capture.py`, `packet.py`, `verify.py`, `vault.py`).
- **Frontend:** a dependency-free, no-build-step PWA — plain HTML/CSS/JS (`app/app.js`: "thin,
  accessible shell over the loopback JSON API. No frameworks."), a service worker
  (`app/service-worker.js`) that precaches the static shell cache-first and is network-only for
  `/api/`, and a `manifest.webmanifest` with the installability basics (192/512 px icons, a maskable
  icon, Apple touch icon).
- **Dependencies that matter for packaging** (`pyproject.toml`):

  | Package | Role | Native/compiled? |
  | --- | --- | --- |
  | `cryptography>=44` | vault encryption at rest (ChaCha20Poly1305), Ed25519/X25519 keys, HKDF, Scrypt KDF — `crypto.py` | **Yes** — Rust extension (`_rust.abi3.so`) since the project's Rust rewrite |
  | `pillow>=11` | image handling for captured photos | **Yes** — C extension |
  | `reportlab>=4.2` | PDF packet generation | No — pure-Python wheel |
  | `piexif>=1.1.3` | EXIF read/strip | No — pure-Python wheel |
  | `asn1crypto>=1.5` | RFC 3161 timestamp token parsing | No — pure-Python wheel |

  So two of five real dependencies are the whole packaging question: `cryptography` (hard, and it's
  load-bearing for literally every vault operation, not an optional feature) and `pillow` (softer).

`docs/mobile.md` already documents the PWA install path (Add to Home Screen, works today) and had a
short, honest paragraph gesturing at Briefcase/Tauri as "tracked work, not yet built." This spike
makes that concrete.

---

## 2. What each toolchain actually requires (verified against current docs/PyPI, not assumed)

### BeeWare / Briefcase

- **Android backend** generates a Gradle project using Google's [Chaquopy](https://chaquo.com/chaquopy/)
  plugin, which bundles its own CPython build (via NDK) inside the APK. Package resolution is
  two-tier: pure-Python packages come straight from PyPI; packages with compiled extensions are
  resolved first against PyPI's own (now-permitted) mobile wheel tags, falling back to **Chaquopy's
  own wheel repository** (`chaquo.com/pypi-13.1`) when PyPI has nothing for Android. Briefcase's own
  docs are explicit that "Chaquopy's repository... does not have binary wheels for *every* package
  ...or even every *version* of every package." [Briefcase Android/Gradle docs]
- **iOS backend** generates an Xcode project. It **requires a full Xcode.app install**, not just the
  Command Line Tools, on a macOS host. Pure-Python packages work; packages with compiled extensions
  need iOS-tagged wheels, resolved from PyPI or a secondary BeeWare-maintained repo of "some popular
  pre-compiled iOS wheels" — coverage is explicitly partial. Briefcase **cannot install packages
  published only as source tarballs**, even pure-Python ones. Command-line deployment targets the
  **simulator**; a physical device needs manual Xcode signing/provisioning outside Briefcase. App
  Store submission additionally requires purging static libraries via `cleanup_paths`. [Briefcase iOS
  docs]
- **PyPI mobile wheels.** In 2025 PyPI began accepting `ios_*` / `android_*` platform tags for
  wheels (an Anaconda-driven change), and `cibuildwheel` 3.1 added Android support (iOS support
  already existed) so package maintainers *can* now ship official mobile wheels without BeeWare's
  own tooling. Adoption is opt-in per project and, as of this spike, still thin — verified directly
  below for the packages this app actually needs.
- **BeeWare's `mobile-forge`** (a cross-compilation tool, iOS-tested, "in theory" usable for Android)
  ships a `cryptography` recipe capped at **3.4.8 — "the last version that could be built without a
  Rust compiler."** Modern `cryptography` (its Rust rewrite) is out of scope for that tool without
  someone doing the Rust cross-compilation work for iOS/Android targets, which nobody has done.
  [beeware/mobile-forge README]

### Direct verification against PyPI (2026-07-09)

Checked the actual files published for each dependency's latest release:

```
cryptography 49.0.0  → macOS / manylinux / musllinux / Windows / PyPy only. No ios_* or android_* wheels.
pillow       12.3.0  → adds official ios_13_0_arm64_iphoneos / iphonesimulator wheels (cp313–cp315).
                        No android_* wheels at all.
reportlab    5.0.0   → py3-none-any (pure Python) — platform-agnostic, no issue.
piexif       1.1.3   → py2.py3-none-any (pure Python) — no issue.
```

And Chaquopy's own Android wheel repository (`chaquo.com/pypi-13.1`), which is what Briefcase's
Android backend falls back to for compiled packages:

```
cryptography → tops out at 42.0.8, built only through cp313 (Python 3.13).
pillow       → tops out at 11.0.0, built only through cp313.
```

Both numbers matter together: habitable pins `requires-python = ">=3.14"` and `cryptography>=44`.
Chaquopy's Android build of `cryptography` is **two PyPI major versions below the floor this project
already pins**, and **one Python feature version behind** what the project targets. `pillow` 11.0.0
does satisfy `pillow>=11`, but is capped at the same Python 3.13 ceiling. Neither gap is a Briefcase
bug — it's downstream of `cryptography` and Chaquopy simply not having built anything newer yet.

### Tauri

- **Architecture.** Tauri 2.0 (Oct 2024) added Android/iOS targets alongside desktop, sharing a Rust
  core; the frontend is a system webview loading your own HTML/CSS/JS. habitable's frontend (plain,
  no-build-step JS) is actually a good fit for *that* half of Tauri.
- **Running Python at all requires a plugin**, since Tauri's own backend model is Rust (or JS in the
  webview) — there is no first-party Python support. The community `tauri-plugin-python` offers two
  interpreter choices:
  - **PyO3** (real CPython bindings) — "full compatibility," but "needs `libpython` to be available
    for the target platform," which is not set up for mobile.
  - **RustPython** (a from-scratch Python 3 interpreter written in Rust, not CPython) — "requires no
    extra steps as it will be linked statically."
  - **"Android and iOS currently only support RustPython"** — PyO3 is desktop-only in this plugin
    because there's no compiled CPython for mobile targets to link against.
- **RustPython cannot load `cryptography`, `pillow`, or any other compiled C extension.** Its own
  project material describes it as "a full Python 3 environment entirely in Rust... no compatibility
  hacks" — i.e., it does not implement the CPython C-API/ABI that compiled extensions are built
  against. There is no path from "RustPython runs on mobile" to "RustPython can `import cryptography`."
- **The alternative — a sidecar process running real CPython — is a dead end on iOS specifically.**
  Tauri's sidecar mechanism (bundling and spawning an external binary) is a normal pattern on desktop,
  but Apple's App Store Review Guidelines (2.5.2 / 4.7) prohibit apps from downloading or executing
  separate executable code outside the app's own signed binary — exactly what spawning a bundled
  CPython interpreter as a child process would do. It is not part of what any current Tauri mobile
  tooling supports.
- **Conclusion:** there is no currently-documented route for Tauri to carry habitable's actual engine
  (`crypto.py`, `capture.py`, `vault.py`, `pdf.py`, `exif.py`) onto Android or iOS without either (a)
  rewriting the trust-critical crypto/evidence core in Rust, or (b) waiting for PyO3-for-mobile
  tooling that does not exist in this ecosystem today. Both are far outside a packaging spike.

---

## 3. Proof-of-concept: what was actually built

Attempted in an isolated scratch location (not this repo, not committed), on this spike's macOS
sandbox: Python 3.9.12 (host tool runner only — already past EOL, which Briefcase itself warned
about), `uv` present, Homebrew OpenJDK 11 present but unused, **Xcode Command Line Tools only** (no
full `Xcode.app`), no preinstalled Android SDK, no Rust/`cargo`.

### Briefcase → Android: succeeded

```
$ pip install briefcase                     # 0.3.24
$ briefcase new --no-input -Q gui_framework=Toga ...   # vanilla Toga hello-world, NOT habitable's code
$ briefcase create android
$ briefcase build android
```

- `briefcase create android` auto-downloaded a JDK 17 runtime and a full Android SDK (command-line
  tools, platform-tools, build-tools 34, platform 34, the emulator package) into Briefcase's own
  cache directory, after walking through and accepting the Android SDK license terms.
- `briefcase build android` downloaded Gradle 8.2, and Chaquopy resolved `toga-android` /
  `toga-core` / `travertino` from PyPI, bundled a Python 3.9 runtime (`libpython3.9.so`) for
  `arm64-v8a`, `armeabi-v7a`, and `x86_64`, and produced a real signed-debug APK:

  ```
  build/habitablespike/android/gradle/app/build/outputs/apk/debug/app-debug.apk
  41 MB · BUILD SUCCESSFUL in 1m 21s · 41 Gradle tasks executed
  ```

This is a genuine, installable Android package, not a dry run — it confirms the Briefcase → Gradle →
Chaquopy pipeline mechanically works end-to-end for a dependency-free Python/Toga app. It does **not**
prove habitable itself can be packaged, since this hello-world app never imported `cryptography` or
`pillow` — that's precisely the part §2 shows is currently blocked. Actually booting an Android
emulator/AVD and installing the APK was not attempted: this sandbox has no virtualization/hardware
acceleration or display for a headless AVD boot, and pulling a system image (1 GB+) and booting it
would cost real time without adding information beyond what the successful `assembleDebug` build
already shows.

### Briefcase → iOS: blocked immediately, for a structural reason

```
$ briefcase create iOS
You have the Xcode command line tools installed; however, Briefcase requires
a full Xcode install.
```

This is itself a real finding, not just a sandbox artifact: iOS packaging categorically requires a
macOS host with a multi-gigabyte full Xcode install (and, for real distribution, an Apple Developer
account and signing setup) — a materially higher, more manual bar than Android's fully scriptable,
license-acceptable, headless-friendly toolchain. Android is the more tractable platform to spike and,
per §2, is also marginally closer to viable on the `cryptography` question (an old but real Android
build exists via Chaquopy; iOS has nothing newer than the 2021, pre-Rust 3.4.8).

### Tauri: not attempted

`rustc`/`cargo` are not installed in this sandbox, and — more importantly — §2 already establishes a
hard architectural blocker that a hello-world build would not resolve: RustPython (the only
interpreter Tauri's mobile plugin supports today) cannot load any of habitable's compiled
dependencies, and the sidecar alternative is against iOS App Store policy. Spending the build budget
proving "Tauri can render an empty webview on a phone" would not move this decision, so effort went
into the Briefcase POC instead, which was the option the research indicated might actually work.

---

## 4. Recommendation

1. **Rule out Tauri** for carrying habitable's Python engine to mobile. It would require rewriting
   the crypto/evidence/PDF core in Rust (or JS) — a rewrite of the exact trust-critical code this
   project is built to keep simple and auditable — which is a different, much larger project, not a
   packaging choice.
2. **Briefcase is the right toolchain if/when this is built**, and this spike proved its Android
   pipeline works mechanically. But it is **not buildable for habitable today**, on either platform,
   because of one dependency: `cryptography` has no official mobile wheels, and the one
   community-maintained fallback (Chaquopy, Android-only) is capped at a version (42.0.8) below this
   project's own `cryptography>=44` floor and a Python target (3.13) behind its `requires-python
   >=3.14`. Downgrading either pin to force a build would mean shipping years-old cryptography code
   in a tool whose entire premise is tamper-evidence against a "landlord who retaliates" — not an
   acceptable trade for a spike.
3. **Do not schedule native mobile build work now.** The gate isn't which packaging tool to use —
   it's whether `cryptography` (or an equivalent trustworthy crypto library with mobile wheels) is
   packageable for iOS/Android with a *current, maintained* build. That's an upstream ecosystem
   question, not something habitable's own team controls the timeline of.
4. **Concrete, cheap re-check trigger** (instead of re-running this whole spike): periodically check
   two things and stop there —
   - `pip index versions cryptography` mobile wheel tags on PyPI (`curl -s
     https://pypi.org/pypi/cryptography/json | grep -o '"[^"]*android[^"]*\.whl"'` /
     `...ios...`), and
   - Chaquopy's Android repo (`https://chaquo.com/pypi-13.1/cryptography/`) for a version ≥ this
     project's floor built for a current Python.

   If either turns green, the Briefcase Android POC in this spike (§3) is the starting point, not a
   from-scratch effort.
5. **Until then, Add-to-Home-Screen PWA remains the correct, supported mobile path** — no change to
   `docs/mobile.md`'s existing guidance there, just to its forward-looking paragraph (updated
   alongside this brief).

---

## Sources

- [Briefcase — Android/Gradle platform docs](https://briefcase.beeware.org/en/stable/reference/platforms/android/gradle.html)
- [Briefcase — iOS/Xcode platform docs](https://briefcase.beeware.org/en/stable/reference/platforms/iOS/xcode.html)
- [beeware/mobile-forge README](https://github.com/beeware/mobile-forge/blob/main/README.md) —
  `cryptography` recipe capped at 3.4.8, "the last version that could be built without a Rust
  compiler"
- [BeeWare Mobile Wheels tracker](https://beeware.org/mobile-wheels/) (JS-rendered; live package
  grid not fetchable headlessly, hence the direct PyPI/Chaquopy checks in §2 instead)
- [pyca/cryptography#11463](https://github.com/pyca/cryptography/issues/11463) — open request for an
  iOS wheel; no maintainer commitment, marked stale
- PyPI JSON API, queried directly: `cryptography` 49.0.0, `pillow` 12.3.0, `reportlab` 5.0.0,
  `piexif` 1.1.3 file listings (2026-07-09)
- Chaquopy Android package repository, queried directly: `chaquo.com/pypi-13.1/cryptography/`,
  `chaquo.com/pypi-13.1/pillow/` (2026-07-09)
- [Tauri 2.0 overview](https://v2.tauri.app/) — mobile targets, Rust core, webview frontend
- [`tauri-plugin-python` (marcomq)](https://github.com/marcomq/tauri-plugin-python) — PyO3 vs.
  RustPython interpreter choice; "Android and iOS currently only support RustPython"
- [RustPython project site](https://rustpython.github.io/) — "a full Python 3 environment entirely
  in Rust... no compatibility hacks" (no CPython C-API/ABI, no compiled-extension support)
- [Tauri — Embedding External Binaries (sidecar)](https://v2.tauri.app/develop/sidecar/)
- Apple App Store Review Guidelines §2.5.2 / §4.7 (no downloading/executing separate executable code
  outside the app binary, with a narrow emulator carve-out that doesn't apply here)
- This spike's own proof-of-concept run (§3): Briefcase 0.3.24, `briefcase new` / `create android` /
  `build android` against a vanilla Toga hello-world app, producing
  `app-debug.apk` (41 MB, BUILD SUCCESSFUL)
