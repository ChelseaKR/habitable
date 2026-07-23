#!/usr/bin/env python3
"""Render the committed English and Spanish app previews from synthetic data."""

from __future__ import annotations

import threading
from pathlib import Path
from tempfile import TemporaryDirectory

from playwright.sync_api import sync_playwright

from habitable.appserver import make_app_server
from habitable.capture import capture
from habitable.tsa import DevTSA
from habitable.vault import Vault

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "site" / "img"
SYNTHETIC_PHOTO = ROOT / "site" / "sample-packet" / "media" / "cap-ae643da894ad9b22.jpg"


def _synthetic_vault(path: Path) -> Vault:
    vault = Vault.create(
        path,
        "synthetic-preview-only",
        case_id="sample-unit-4B",
        unit="4B",
    )
    issue_id = vault.document.add_issue(
        category="mold",
        room="bathroom",
        title="Black mold on bathroom ceiling",
        issue_id="sample-condition",
        severity="high",
        description="Synthetic condition used only for interface review.",
    )
    capture(
        vault,
        SYNTHETIC_PHOTO,
        issue_id=issue_id,
        tsa=DevTSA(name="synthetic-preview"),
        source_name="bathroom-ceiling.jpg",
    )
    notice_id = vault.add_timeline_event(
        issue_id,
        event_type="notice_sent",
        text="Repair request sent by email.",
        occurred_at="2026-01-03",
        source="message",
    )
    receipt_id = vault.add_timeline_event(
        issue_id,
        event_type="delivery_confirmed",
        text="Email delivery confirmation retained.",
        occurred_at="2026-01-03",
        source="document",
        notice_entry_id=notice_id,
    )
    vault.add_timeline_event(
        issue_id,
        event_type="recurrence",
        text="Condition recorded again after the notice.",
        occurred_at="2026-01-18",
        source="firsthand",
        notice_entry_id=notice_id,
        receipt_entry_id=receipt_id,
    )
    return vault


def main() -> None:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix="habitable-preview-") as temp_dir:
        vault = _synthetic_vault(Path(temp_dir) / "vault")
        server = make_app_server("127.0.0.1", 0, vault)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        url = f"http://127.0.0.1:{server.server_address[1]}/index.html#token={server.session_token}"
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch()
                page = browser.new_page(
                    viewport={"width": 2200, "height": 3000},
                    device_scale_factor=1,
                    locale="en-US",
                )
                page.goto(url, wait_until="networkidle")
                page.wait_for_function("document.getElementById('st-unit').textContent === '4B'")
                page.screenshot(path=OUTPUT / "app-en.png")

                page.locator("#lang-es").click()
                page.wait_for_function("document.documentElement.lang === 'es'")
                page.screenshot(path=OUTPUT / "app-es.png")
                browser.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    main()
