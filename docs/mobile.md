<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Using habitable on a phone

habitable is **local-first**: the case lives on a device, not a server. On a
phone the practical path today is the **installable web app (PWA)**, served by the
local app server. This page covers installing it, offline behaviour, and the
honest state of fully-native packaging.

## Install as an app (works today)

1. On the device (or a laptop the phone can reach), start the server:
   ```console
   $ uv run habitable app --vault ./case-4B --host 0.0.0.0
   ```
2. Open the printed URL in the phone browser and **Add to Home Screen**:
   - **Android / Chrome:** ⋮ menu → *Add to Home screen* / *Install app*.
   - **iOS / Safari:** Share → *Add to Home Screen*.
3. It launches standalone (its own icon, no browser chrome), using the maskable
   icon and theme colour from `manifest.webmanifest`.

The manifest ships PNG icons at 192 and 512 px, a dedicated **maskable** icon, an
Apple touch icon, and the Apple/standalone meta tags — the installability basics a
PWA needs. `tests/test_app_pwa.py` checks these stay present.

## Offline behaviour

The service worker (`service-worker.js`) precaches the static shell (HTML, CSS,
JS, i18n, icons) **cache-first**, so the interface loads with no connection and
navigations fall back to the cached shell. It is **network-only for `/api/`**, so
evidence and case status are never cached — they always come from the local
server, which must be running to read or write data. Capture itself never blocks
on the network; trusted timestamps are fetched when a connection returns (the
*Resolve awaiting timestamps* action).

## Toward fully-native packaging (roadmap, honest constraints)

Because habitable is local-first, a "native app" is not just a wrapper around a
hosted website — it must carry the local engine (vault, crypto, capture, packet,
verify) with it. That makes the usual hosted-PWA routes a poor fit:

- A **Trusted Web Activity** (Android) assumes a PWA hosted at an https origin
  with Digital Asset Links; habitable has no server to host, by design.
- A thin **Capacitor/Cordova** shell would still need the engine on-device.

The realistic native path is to **embed the engine on the device** — e.g. package
the Python core with [BeeWare/Briefcase](https://beeware.org/) (which targets
Android and iOS) or a Tauri/embedded-runtime shell, exposing the same loopback API
the PWA already speaks. That is tracked work, not yet built; producing signed App
Store / Play Store binaries additionally requires the platform SDKs, developer
accounts, and signing keys, which are out of scope for this repository's CI.

Until then, **Add to Home Screen is the supported mobile install**, and it covers
the field use case: a tenant documenting a problem in the apartment on the only
device they have.
