# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""PWA installability + service-worker safety (mobile packaging basics)."""

from __future__ import annotations

import json
from pathlib import Path

_APP = Path(__file__).resolve().parent.parent / "app"


def test_manifest_is_installable() -> None:
    manifest = json.loads((_APP / "manifest.webmanifest").read_text(encoding="utf-8"))
    for key in ("name", "short_name", "start_url", "display", "icons"):
        assert key in manifest, f"manifest missing {key!r}"
    assert manifest["display"] in {"standalone", "fullscreen", "minimal-ui"}
    assert manifest["icons"], "manifest needs at least one icon"
    for icon in manifest["icons"]:
        assert icon.get("src"), "each icon needs a src"
        assert (_APP / icon["src"]).is_file(), f"icon file missing: {icon['src']}"
    assert manifest.get("theme_color") and manifest.get("background_color")


def test_manifest_has_required_png_and_maskable_icons() -> None:
    """Installability needs raster 192/512 icons and a maskable icon."""
    manifest = json.loads((_APP / "manifest.webmanifest").read_text(encoding="utf-8"))
    png = [i for i in manifest["icons"] if i.get("type") == "image/png"]
    sizes = {i.get("sizes") for i in png}
    assert "192x192" in sizes and "512x512" in sizes, "need 192 and 512 PNG icons"
    maskable = any("maskable" in i.get("purpose", "") for i in manifest["icons"])
    assert maskable, "need a maskable icon"


def test_apple_and_standalone_meta_present() -> None:
    index = (_APP / "index.html").read_text(encoding="utf-8")
    assert 'rel="apple-touch-icon"' in index
    assert (_APP / "icons" / "apple-touch-icon.png").is_file()
    assert "apple-mobile-web-app-capable" in index
    assert "mobile-web-app-capable" in index


def test_service_worker_never_caches_api() -> None:
    sw = (_APP / "service-worker.js").read_text(encoding="utf-8")
    for event in ("install", "activate", "fetch"):
        assert f'"{event}"' in sw or f"'{event}'" in sw, f"service worker missing {event} handler"
    assert "/api" in sw, "service worker must special-case /api (network-only)"
    assert "caches" in sw, "service worker should cache the static shell"
    assert "habitable-shell-v9-repair-trail" in sw, (
        "repair-trail shell changes must invalidate the old cache"
    )


def test_app_registers_service_worker() -> None:
    app_js = (_APP / "app.js").read_text(encoding="utf-8")
    assert "serviceWorker" in app_js and "register(" in app_js


def test_app_references_only_existing_local_assets() -> None:
    index = (_APP / "index.html").read_text(encoding="utf-8")
    for asset in ("styles.css", "app.js", "manifest.webmanifest", "icons/icon.svg"):
        assert asset in index, f"index.html should reference {asset}"
        assert (_APP / asset).is_file()
