# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""The accessible HTML packet: structure + a real axe-core scan."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from habitable.capture import capture
from habitable.packet import build_packet
from habitable.tsa import LocalRfc3161TSA
from habitable.vault import Vault


def _packet(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    tsa: LocalRfc3161TSA,
    out: Path,
) -> Path:
    vault = make_vault()
    issue = vault.document.add_issue(category="mold", room="bath", title="Mold", issue_id="i1")
    vault.document.add_timeline_entry(issue, "observed", "spreading")
    capture(vault, make_jpeg(with_location=True), issue_id=issue, tsa=tsa)
    result = build_packet(vault, out, generated_at="2026-01-02T00:10:00Z")
    assert result.html_path is not None and result.html_path.is_file()
    return result.html_path


def test_html_packet_is_structurally_accessible(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    html = _packet(make_vault, make_jpeg, local_tsa, tmp_path / "pkt").read_text(encoding="utf-8")
    assert html.startswith("<!doctype html>")
    assert 'lang="en"' in html
    assert html.count("<h1>") == 1
    assert '<main id="main">' in html
    assert '<a class="skip" href="#main">' in html
    assert 'scope="col"' in html  # appendix table has header scopes
    assert "<caption>" in html
    # Images carry meaningful alt text (not empty).
    assert 'alt="Evidence photo' in html
    # No unescaped angle brackets from data (template/user content escaped).
    assert "<script" not in html.lower()


def test_html_packet_escapes_user_content(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    vault = make_vault()
    issue = vault.document.add_issue(
        category="mold", title="<img src=x onerror=alert(1)>", issue_id="i1"
    )
    capture(vault, make_jpeg(), issue_id=issue, tsa=local_tsa)
    result = build_packet(vault, tmp_path / "pkt", generated_at="2026-01-02T00:10:00Z")
    assert result.html_path is not None
    html = result.html_path.read_text(encoding="utf-8")
    assert "<img src=x onerror=alert(1)>" not in html  # escaped
    assert "&lt;img src=x onerror=alert(1)&gt;" in html


def _inspector(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    tsa: LocalRfc3161TSA,
    out: Path,
) -> Path:
    vault = make_vault()
    issue = vault.document.add_issue(category="mold", room="bath", title="Mold", issue_id="i1")
    vault.document.add_timeline_entry(issue, "observed", "spreading")
    capture(vault, make_jpeg(with_location=True), issue_id=issue, tsa=tsa)
    result = build_packet(vault, out, generated_at="2026-01-02T00:10:00Z", inspector_view=True)
    assert result.inspector_path is not None and result.inspector_path.is_file()
    assert result.inspector_path.name == "inspector.html"
    # packet.html is unchanged / still produced alongside the derived view.
    assert result.html_path is not None and result.html_path.is_file()
    return result.inspector_path


def test_inspector_view_is_structurally_accessible(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    html = _inspector(make_vault, make_jpeg, local_tsa, tmp_path / "pkt").read_text(
        encoding="utf-8"
    )
    assert html.startswith("<!doctype html>")
    assert 'lang="en"' in html
    assert html.count("<h1>") == 1
    assert '<main id="main">' in html
    assert '<a class="skip" href="#main">' in html
    # Nested room -> condition headings: the room is an h2 that precedes its h3.
    assert '<h2 id="room-0">Room: bath</h2>' in html
    assert "<h3>Condition: mold</h3>" in html
    assert html.index("Room: bath") < html.index("Condition: mold")
    # The evidence appendix (with header scopes) is reused.
    assert 'scope="col"' in html
    assert "<caption>" in html
    assert "<script" not in html.lower()


def test_inspector_view_groups_and_orders_timeline(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    html = _inspector(make_vault, make_jpeg, local_tsa, tmp_path / "pkt").read_text(
        encoding="utf-8"
    )
    # The room heading precedes the condition, which precedes the issue timeline.
    room_pos = html.index("Room: bath")
    note_pos = html.index("spreading")
    capture_pos = html.index("Evidence captured")
    assert room_pos < note_pos
    # The timeline note (00:00:00Z) is chronologically before the capture (03:04:05Z).
    assert note_pos < capture_pos
    # Both a timeline note and a capture event appear in the merged timeline.
    assert "observed:" in html
    assert "trusted-timestamped" in html


def test_inspector_view_escapes_user_content(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    vault = make_vault()
    issue = vault.document.add_issue(
        category="mold", room="<b>bath</b>", title="<img src=x onerror=alert(1)>", issue_id="i1"
    )
    vault.document.add_timeline_entry(issue, "observed", "<script>evil()</script>")
    capture(vault, make_jpeg(), issue_id=issue, tsa=local_tsa)
    result = build_packet(
        vault, tmp_path / "pkt", generated_at="2026-01-02T00:10:00Z", inspector_view=True
    )
    assert result.inspector_path is not None
    html = result.inspector_path.read_text(encoding="utf-8")
    assert "<img src=x onerror=alert(1)>" not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html
    assert "<b>bath</b>" not in html
    assert "&lt;b&gt;bath&lt;/b&gt;" in html
    assert "<script>evil()</script>" not in html
    assert "&lt;script&gt;evil()&lt;/script&gt;" in html


@pytest.mark.a11y
def test_html_packet_passes_axe(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    pytest.importorskip("playwright.sync_api")
    pytest.importorskip("axe_playwright_python.sync_playwright")
    from axe_playwright_python.sync_playwright import Axe
    from playwright.sync_api import Error as PlaywrightError
    from playwright.sync_api import sync_playwright

    html_path = _packet(make_vault, make_jpeg, local_tsa, tmp_path / "pkt")
    with sync_playwright() as p:
        try:
            browser = p.chromium.launch()
        except PlaywrightError as exc:
            pytest.skip(f"Chromium not available: {exc}")
        try:
            page = browser.new_page()
            page.goto(html_path.as_uri(), wait_until="load")
            results = Axe().run(page)
        finally:
            browser.close()
    blocking = [
        v
        for v in results.response.get("violations", [])
        if v.get("impact") in {"moderate", "serious", "critical"}
    ]
    assert not blocking, [v["id"] for v in blocking]
