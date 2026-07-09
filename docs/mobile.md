<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Phone support and the local app

habitable is designed for field use, but the alpha does **not yet have a safe,
supported phone installation path**. The current web client is served by a Python
process that holds an unlocked vault in memory. It is for evaluation on the same
desktop or laptop only:

```console
$ uv run habitable app --vault ./case-4B
```

The server now rejects non-loopback binds. Do not expose it with
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
