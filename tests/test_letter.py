# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""The repair-request letter generator: content, jurisdiction framing, rendering."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

import pytest

from habitable.capture import capture
from habitable.errors import LetterError
from habitable.letter import (
    PROFILES,
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
    # Built-in profiles never assert a specific statute/code section — in *any*
    # reader-visible field (the framing and legal reference both render into the
    # letter), not just the legal-reference line.
    for profile in PROFILES.values():
        for text in (profile.label, profile.framing, profile.legal_reference):
            assert "§" not in text
            assert "U.S.C" not in text
            assert "U. S. C" not in text


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


# --- Issue #161: the letter declares only what it is -------------------------


def _spanish_vault(make_vault: Callable[..., Vault], name: str = "es-vault") -> Vault:
    """A vault configured `language = "es"` — a supported, documented setup, and
    the one a Spanish-speaking union would use."""
    vault = make_vault(name=name)
    vault.config = replace(vault.config, language="es")
    vault.document.add_issue(category="mold", title="Mold", issue_id="i1")
    vault.save()
    return vault


def test_a_spanish_vault_is_never_given_an_english_letter_labelled_spanish(
    make_vault: Callable[..., Vault],
) -> None:
    """The absence under test: `lang="es"` must not appear on English prose.

    Before this fix, `language="es"` produced a letter whose body was
    byte-identical to the English one and whose only difference was the `lang`
    attribute — a WCAG 3.1.1 failure that makes a screen reader pronounce
    English with Spanish phonetics, and a document that tells a Spanish-speaking
    tenant it is in their language when it is not.
    """
    vault = _spanish_vault(make_vault)
    letter = build_letter(vault, LetterOptions(sender_name="T", recipient_name="LL"))
    html = render_letter_html(letter)

    assert 'lang="es"' not in html
    assert 'lang="en"' in html
    assert letter.language == "en"
    assert letter.requested_language == "es"
    # The unmet request is reported rather than silently dropped.
    assert "es" in letter.language_limitation
    assert "does not ship a reviewed translation" in letter.language_limitation


def test_the_letter_is_byte_identical_in_both_locales_which_is_the_point(
    make_vault: Callable[..., Vault],
) -> None:
    """Pins *why* `lang="es"` was a lie, so a future partial translation cannot
    quietly reintroduce it: as long as the rendered documents are identical, the
    language attribute must be too."""
    english = build_letter(
        _spanish_vault(make_vault, "en-side"),
        LetterOptions(sender_name="T", language="en", date="2026-01-10"),
    )
    spanish = build_letter(
        _spanish_vault(make_vault, "es-side"),
        LetterOptions(sender_name="T", language="es", date="2026-01-10"),
    )

    assert render_letter_html(english) == render_letter_html(spanish)
    assert english.language == spanish.language == "en"
    assert english.language_limitation == ""
    assert spanish.language_limitation != ""


def test_a_letter_with_no_evidence_does_not_claim_a_verifiable_packet(
    make_vault: Callable[..., Vault],
) -> None:
    """The absence under test: no packet offer when there is no packet.

    A case with an issue and zero captures used to produce "documented by 0
    photograph(s) ... A complete, independently-verifiable evidence packet is
    available on request" — an overstatement a landlord's representative can
    call, on the first document carrying the tenant's name.
    """
    vault = make_vault()
    vault.document.add_issue(category="mold", title="Mold", issue_id="i1")
    vault.save()

    letter = build_letter(vault, LetterOptions(sender_name="T", recipient_name="LL"))
    html = render_letter_html(letter)

    assert "0 photograph(s)" not in letter.evidence_summary
    assert "evidence packet is available on request" not in letter.evidence_summary
    assert "independently-verifiable" not in html
    # Says plainly what is true instead of dropping the subject.
    assert "No photographs of these conditions are attached" in letter.evidence_summary
    assert letter.evidence_summary in html


def test_a_letter_with_evidence_still_offers_the_packet(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], local_tsa: LocalRfc3161TSA
) -> None:
    """Positive control: the claim is gated, not removed."""
    vault = _case(make_vault, make_jpeg, local_tsa)
    letter = build_letter(vault, LetterOptions(sender_name="T", recipient_name="LL"))

    assert "1 photograph(s)" in letter.evidence_summary
    assert "evidence packet is available on request" in letter.evidence_summary
    assert "timestamp tokens whose validity and authority trust must be checked" in (
        letter.evidence_summary
    )


@pytest.mark.parametrize("language", ["en", "es"])
def test_the_lang_attribute_matches_the_language_of_the_content(
    make_vault: Callable[..., Vault], language: str
) -> None:
    """Issue #161 item 4: assert the attribute against the prose, per locale.

    The English marker strings below are the letter's own fixed copy; if a
    reviewed translation ever lands, this test fails until the `lang` attribute
    follows it.
    """
    vault = _spanish_vault(make_vault)
    letter = build_letter(vault, LetterOptions(sender_name="T", language=language))
    html = render_letter_html(letter)

    assert f'lang="{letter.language}"' in html
    english_markers = ("Conditions requiring repair", "Sincerely,", "not legal advice")
    content_is_english = all(marker in html for marker in english_markers)
    assert content_is_english is (letter.language == "en")


@pytest.mark.a11y
def test_letter_html_in_a_spanish_configured_vault_passes_axe(
    make_vault: Callable[..., Vault], tmp_path: Path
) -> None:
    """Issue #161 item 4 asked for an axe scan of the letter. One already exists
    (``test_letter_html_passes_axe``, since PR #16) — but it only ever built a
    letter from an English-configured vault, and axe could not have caught this
    defect regardless: a document declaring ``lang="es"`` over English prose
    passes ``html-has-lang`` and ``valid-lang`` cleanly, because no automated
    checker reads the prose. The content-versus-attribute assertion above is what
    catches it; this scan just extends the existing a11y coverage to the
    Spanish-configured vault, which is the configuration that was broken.
    """
    pytest.importorskip("playwright.sync_api")
    pytest.importorskip("axe_playwright_python.sync_playwright")
    from axe_playwright_python.sync_playwright import Axe
    from playwright.sync_api import Error as PlaywrightError
    from playwright.sync_api import sync_playwright

    letter = build_letter(
        _spanish_vault(make_vault, "axe-es"),
        LetterOptions(sender_name="Tenant", recipient_name="Landlord"),
    )
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
