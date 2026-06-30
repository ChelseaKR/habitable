# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""The repair-request letter generator: content, jurisdiction framing, rendering."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from habitable.capture import capture
from habitable.errors import LetterError
from habitable.letter import (
    LetterOptions,
    build_letter,
    render_letter_html,
    resolve_profile,
)
from habitable.tsa import LocalRfc3161TSA
from habitable.vault import Vault


def _case(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], tsa: LocalRfc3161TSA
) -> Vault:
    vault = make_vault()
    issue = vault.document.add_issue(
        category="mold",
        room="bathroom",
        title="Black mold on ceiling",
        severity="high",
        description="Mold spread after a roof leak.",
        issue_id="i1",
    )
    vault.document.add_timeline_entry(issue, "observed", "spreading")
    capture(vault, make_jpeg(with_location=True), issue_id=issue, tsa=tsa)
    vault.save()
    return vault


def test_build_letter_draws_from_logged_evidence(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], local_tsa: LocalRfc3161TSA
) -> None:
    vault = _case(make_vault, make_jpeg, local_tsa)
    letter = build_letter(
        vault,
        LetterOptions(
            recipient_name="Acme Property Mgmt",
            sender_name="Tenant T",
            cure_period_days=21,
            date="2026-01-10",
        ),
    )
    assert letter.date == "2026-01-10"
    assert letter.recipient_name == "Acme Property Mgmt"
    assert letter.cure_period_days == 21
    assert len(letter.issues) == 1
    only = letter.issues[0]
    assert only.title == "Black mold on ceiling"
    assert only.evidence_count == 1
    assert only.timestamped_count == 1
    assert only.first_documented  # a date was derived
    assert "21 days" in letter.demand
    assert "not legal advice" in letter.disclaimer.lower()


def test_letter_html_is_accessible_and_escaped(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], local_tsa: LocalRfc3161TSA
) -> None:
    vault = make_vault()
    vault.document.add_issue(
        category="mold",
        title="Leak",
        description="Danger <script>alert(1)</script> here",
        issue_id="i1",
    )
    letter = build_letter(vault, LetterOptions(sender_name="T", recipient_name="LL"))
    html = render_letter_html(letter)
    assert html.startswith("<!doctype html>")
    assert html.count("<h1>") == 1
    assert 'lang="en"' in html
    assert '<a class="skip" href="#main">' in html
    assert '<main id="main">' in html
    # User content is escaped — no live script element.
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_letter_pdf_renders(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    from habitable.pdf import render_letter_pdf

    vault = _case(make_vault, make_jpeg, local_tsa)
    letter = build_letter(vault, LetterOptions(sender_name="T", recipient_name="LL"))
    out = tmp_path / "letter.pdf"
    render_letter_pdf(letter, out)
    data = out.read_bytes()
    assert data.startswith(b"%PDF-")
    assert b"/Lang" in data
    assert out.stat().st_size > 1000


def test_jurisdiction_profiles_and_fallback() -> None:
    assert resolve_profile("").key == "generic"
    assert resolve_profile("us_habitability").key == "us_habitability"
    assert resolve_profile("US Habitability").key == "us_habitability"  # normalized
    assert resolve_profile("narnia").key == "generic"  # unknown → generic, never refuses
    # Built-in profiles never assert a specific statute/code section.
    for profile in (resolve_profile("generic"), resolve_profile("us_habitability")):
        assert "§" not in profile.legal_reference
        assert "U.S.C" not in profile.legal_reference


def test_cure_period_precedence(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], local_tsa: LocalRfc3161TSA
) -> None:
    vault = make_vault()
    vault.document.add_issue(category="heat", title="No heat", issue_id="i1")
    # Explicit option wins; otherwise the profile default (14) applies.
    explicit = build_letter(vault, LetterOptions(cure_period_days=30))
    assert explicit.cure_period_days == 30
    default = build_letter(vault, LetterOptions())
    assert default.cure_period_days == 14


def test_letter_without_issues_is_an_error(make_vault: Callable[..., Vault]) -> None:
    vault = make_vault()
    with pytest.raises(LetterError):
        build_letter(vault, LetterOptions())


def test_letter_can_scope_to_one_issue(make_vault: Callable[..., Vault]) -> None:
    vault = make_vault()
    vault.document.add_issue(category="mold", title="Mold", issue_id="i1")
    vault.document.add_issue(category="heat", title="No heat", issue_id="i2")
    letter = build_letter(vault, LetterOptions(issue_ids=("i2",)))
    assert [i.issue_id for i in letter.issues] == ["i2"]


@pytest.mark.a11y
def test_letter_html_passes_axe(make_vault: Callable[..., Vault], tmp_path: Path) -> None:
    pytest.importorskip("playwright.sync_api")
    pytest.importorskip("axe_playwright_python.sync_playwright")
    from axe_playwright_python.sync_playwright import Axe
    from playwright.sync_api import Error as PlaywrightError
    from playwright.sync_api import sync_playwright

    vault = make_vault()
    vault.document.add_issue(
        category="mold",
        title="Black mold",
        description="Spread after a roof leak.",
        issue_id="i1",
    )
    letter = build_letter(vault, LetterOptions(sender_name="Tenant", recipient_name="Landlord"))
    out = tmp_path / "letter.html"
    out.write_text(render_letter_html(letter), encoding="utf-8")

    with sync_playwright() as p:
        try:
            browser = p.chromium.launch()
        except PlaywrightError as exc:
            pytest.skip(f"Chromium not available: {exc}")
        try:
            page = browser.new_page()
            page.goto(out.as_uri(), wait_until="load")
            results = Axe().run(page)
        finally:
            browser.close()
    blocking = [
        v
        for v in results.response.get("violations", [])
        if v.get("impact") in {"moderate", "serious", "critical"}
    ]
    assert not blocking, [v["id"] for v in blocking]
