<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Phone support and the local app

habitable is designed for field use, but the alpha does **not yet have a safe,
supported phone installation path**. The current web client is served by a Python
process that holds an unlocked vault in memory. It is for evaluation on the same
desktop or laptop only:

```console
$ uv run habitable app --vault ./case-4B
```

The command prints a URL whose fragment carries a **per-process session token**, e.g.
`http://127.0.0.1:8765/#token=…`. **Open that exact URL** — the app moves the token
into a request header and scrubs it from the address bar; every `/api/*` call must
present it, so anything else on the machine that can reach the port but lacks the
URL gets a `401`. Stopping the server (`Ctrl-C`) invalidates that session's token.
Treat the launch URL and the terminal line that prints it like a password while the
server is running. A reload in the same browser tab works because the token is kept
in that tab's `sessionStorage`; a fresh tab, installed-app launch, or browser restart
must be opened from the newly printed URL. The token is never written to request or
structured application logs.

The server rejects non-loopback binds. Do not expose it with
`--host 0.0.0.0`, a LAN address, a tunnel, port forwarding, or a public reverse
proxy. A shared Wi-Fi network can contain other participants or observers, and
plain HTTP does not provide a safe transport for an unlocked case API. A bearer
token alone would not protect that traffic from interception.

## What the PWA currently proves

The web client has an app manifest, install icons, responsive layouts, and a
cache-first static shell. Those pieces are tested and useful for evaluating the
interface. The service worker is intentionally network-only for `/api/`, so no
case data or evidence is placed in the browser cache. The local Python engine
must remain running for any capture, review, or export operation.

On a desktop browser that supports installation, the shell may be added to the
desktop or dock. That convenience does not turn it into a self-contained phone
app: it still depends on the loopback engine on the same device.

## Storage footprint — why a case is "kept twice" (R-03)

On a low-end phone, storage is scarce, so habitable is explicit about what a case
costs. `habitable status` prints a `storage:` line, and the app shows the same
numbers:

```text
storage: 12.4 MB total — 6.1 MB sealed originals + 6.1 MB shared copies
         (originals are kept twice by design)
```

The doubling is deliberate. Every original is **sealed** (encrypted) into the
vault and kept forever — that is the evidence. When you export a packet, habitable
also writes a **policy-processed shared copy** of roughly the same size. The default
removes embedded metadata; a nondefault policy may retain some or all of it. So
budget about **twice** the media size for a default packet: one encrypted vault
original plus one packet shared copy. `--include-originals` also writes a byte-exact
packet original, bringing the rough total to **three media-sized copies**, plus small
metadata overhead (the encrypted case document, custody log, timestamp tokens, and
keyfile). `Vault.storage_footprint()` reports the default two-copy estimate and does
not include that optional packet `originals/` directory.

To reclaim space, export finished issues to an external drive and keep the vault
itself somewhere durable — the sealed originals are the copy that must survive.

## Data cost and metered links (R-18, R-19)

Capture is always free: it hashes and seals on-device with no network. Only two
operations reach the network, and both now report what they cost:

- **Sync** (`habitable sync`) over a relay prints `data: sent X, received Y` so you
  can see what an exchange used. A directory/USB sync (`--dir`) is free.
- **Timestamp fetches** (`habitable resolve`, `habitable retimestamp`) against a
  public RFC 3161 authority print `network used: sent X, received Y`. A single
  timestamp is tiny — typically a **few KB** each way.

Because a desktop CLI cannot reliably tell a metered cellular link from free
Wi-Fi, habitable does not guess. Instead it offers an explicit gate:

- `--wifi-only` refuses any network fetch (relay sync, RFC 3161) and tells you how
  to proceed: `network fetch skipped: wifi-only mode; run with --allow-metered or
  on Wi-Fi`.
- `--allow-metered` permits the fetch for that run.
- The default is set by `[network] allow_metered` in the case `config.toml`
  (`true` by default); set it `false` to make wifi-only the standing policy. The
  app shows the current setting read-only.

Offline authorities used in tests and demos (`--dev-tsa`) never touch the network,
so the gate does not apply to them.

## What must exist before a phone pilot

A supported phone build must carry the vault, cryptography, capture, packet, and
verification engine on the device. It must also pass these release gates:

- installation and update without Git, Python, `uv`, or a terminal;
- no unlocked API exposed beyond the device;
- capture, backup, restore, export, and verification on a clean target device;
- offline and interrupted-operation tests;
- safe key storage and a documented recovery ceremony;
- an independent security review and a recorded human accessibility pass.

BeeWare/Briefcase, Tauri with an embedded runtime, or another on-device package
may satisfy those requirements. Signed App Store and Play Store distribution
also requires platform accounts and signing keys. Until a build meets the gates,
describe phone support as **planned**, not shipped, and use synthetic data only.

**Packaging-toolchain spike (2026-07-09).** A concrete spike — not just design notes — compared
Briefcase and Tauri against this app's real dependency stack and attempted a proof-of-concept build;
see [`docs/research/native-mobile-packaging-spike.md`](research/native-mobile-packaging-spike.md).
Short version: the current Tauri community-plugin path is unsuitable — mobile currently means
RustPython, which cannot load `cryptography`, `pillow`, or other CPython extensions. A CPython
backend or sidecar is not a documented, supported Tauri-mobile path and would need separate platform
and App Review validation. The spike reports a successful Briefcase hello-world Android build, but
does not commit the APK or a reproducible build recipe. Packaging habitable itself has no
off-the-shelf path today: `cryptography` has no official iOS or Android wheels, and the Chaquopy
Android fallback is below this project's version and Python floors. A maintained, reviewed
cross-build could change that; absent one, the cheap re-check is whether a current mobile wheel
appears. None of this changes the current boundary: there is no supported phone installation path.
