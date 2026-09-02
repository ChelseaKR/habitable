# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""The repair-request letter generator: content, jurisdiction framing, rendering."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import replace
from datetime import date
from pathlib import Path

import pytest

from habitable.capture import capture
from habitable.config import Config, LetterTemplate
from habitable.errors import ConfigError, LetterError
from habitable.letter import (
    PROFILES,
    LetterOptions,
    build_letter,
    framing_expired,
    letter_lines,
    render_letter_html,
    resolve_profile,
    review_local_law,
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
    assert resolve_profile("ew_disrepair").key == "ew_disrepair"  # issue #207
    assert resolve_profile("EW Disrepair").key == "ew_disrepair"  # normalized
    assert resolve_profile("narnia").key == "generic"  # unknown → generic, never refuses
    # Built-in profiles never assert a specific statute/code section — in *any*
    # reader-visible field (the framing and legal reference both render into the
    # letter), not just the legal-reference line.
    #
    # The three literal needles below only ever caught U.S.-shaped citations, so a
    # profile for any other jurisdiction could have carried "Landlord and Tenant
    # Act 1985 s.11", "Section 1941", or "Art. 6" past them untouched. Adding a
    # non-U.S. profile is exactly the change that makes that gap reachable, so the
    # guard is widened in the same breath: a citation is a named instrument, a
    # section marker, or a bare year-numbered Act, and none belongs in framing
    # this project states plainly is not legal advice.
    citation_shapes = re.compile(
        r"§"
        r"|U\.\s?S\.\s?C"
        r"|\bs(?:ec|ect|ection)?\.?\s*\d"
        r"|\bart(?:icle)?\.?\s*\d"
        r"|\bAct\s+(?:of\s+)?\d{4}\b"
        r"|\b\d{4}\s+Act\b"
        r"|\bc\.\s*\d+\b",
        re.IGNORECASE,
    )
    assert len(PROFILES) >= 3, "the statute guard must run against every shipped profile"
    for profile in PROFILES.values():
        for field, text in (
            ("label", profile.label),
            ("framing", profile.framing),
            ("legal_reference", profile.legal_reference),
        ):
            found = citation_shapes.search(text)
            assert found is None, (
                f"profile {profile.key!r} field {field} cites {found.group(0)!r}; "
                "built-in framing must stay hedged and statute-free"
            )
        # A profile that hedges nothing is a legal claim wearing framing's clothes.
        hedged = ("generally", "in most", "many", "normally", "depend", "confirm", "vary")
        assert any(word in profile.legal_reference.casefold() for word in hedged), (
            f"profile {profile.key!r} states its legal reference without hedging"
        )


#: The documents whose job is to describe what ships *today*. A reader consults
#: these to learn the current state, so naming some built-in framings and not
#: others is a false claim about the product rather than a formatting slip.
#:
#: ADRs and `CHANGELOG.md` are deliberately absent. They are dated records of a
#: decision or a release as it stood, and editing them to mention work that came
#: later would falsify the record, which is the opposite of the property this
#: guard exists to protect. `ROADMAP.md` is absent because it names no framing
#: key at all; it describes the workstream, not the profile list.
_CURRENT_STATE_DOCS = (
    "docs/capabilities.md",
    "docs/letter-generator.md",
    "docs/novel-use-cases-plan.md",
)


def test_current_state_docs_name_every_framing_that_ships() -> None:
    """A doc that names one built-in framing must name all of them.

    `ew_disrepair` shipped from issue #207 while `docs/capabilities.md` still
    said no framing beyond `generic`/`us_habitability` existed (#228 fixed that
    one by hand) and `docs/novel-use-cases-plan.md` still described the work as
    unstarted and reserved. Both were true when written and false once the code
    changed, which is exactly the drift nobody re-reads a planning document to
    catch.

    The rule is deliberately conditional rather than a blanket "every doc must
    list every profile": a document is only held to it once it has chosen to
    enumerate the framings. That keeps prose that never mentions them free, and
    makes the failure mode -- a partial list that reads as complete -- the thing
    that fails.
    """
    root = Path(__file__).resolve().parent.parent
    shipped = sorted(PROFILES)
    assert len(shipped) >= 3, "guard is only meaningful once a third framing exists"

    for relative in _CURRENT_STATE_DOCS:
        text = (root / relative).read_text(encoding="utf-8")
        named = [key for key in shipped if key in text]
        if not named:
            continue
        missing = [key for key in shipped if key not in named]
        assert not missing, (
            f"{relative} names built-in letter framings {named} but not {missing}; "
            "a partial list reads as the complete one"
        )


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


# --- ADR 0013: dated, expiring jurisdiction framing and local-law wording -------
#
# The `[letter] header`/`footer` is the documented home for a *locally verified*
# statutory citation, and it is the one string this project emits that can stop
# being true on a date nobody is watching: a statute is amended, an ordinance is
# repealed, and the citation keeps going out on correspondence carrying a
# tenant's name. These tests pin the fail-closed direction.

_CITATION = "Notice under the Example City housing code, § 12-34"
_UNION_FOOTER = "Prepared with the Example Tenant Union. Not legal advice."


def _local_law_template(
    *,
    local_law_reviewer: str = "",
    local_law_reviewed_at: str = "",
    local_law_expires_at: str = "",
) -> LetterTemplate:
    return LetterTemplate(
        header=_CITATION,
        footer=_UNION_FOOTER,
        local_law_reviewer=local_law_reviewer,
        local_law_reviewed_at=local_law_reviewed_at,
        local_law_expires_at=local_law_expires_at,
    )


def test_expired_local_law_wording_is_left_out_of_the_letter(
    make_vault: Callable[..., Vault],
) -> None:
    vault = make_vault()
    vault.document.add_issue(category="heat", title="No heat", issue_id="i1")
    letter = build_letter(
        vault,
        LetterOptions(),
        template=_local_law_template(
            local_law_reviewer="Example Legal Aid",
            local_law_reviewed_at="2025-01-01",
            local_law_expires_at="2026-01-01",
        ),
        today=date(2026, 8, 26),
    )
    assert letter.local_law.state == "expired"
    assert not letter.local_law.usable
    # The landlord's copy simply does not carry wording whose review lapsed.
    assert letter.header == ""
    assert letter.footer == ""
    html = render_letter_html(letter)
    assert _CITATION not in html
    assert "§ 12-34" not in html
    # ...and the withholding is never silent.
    assert "2026-01-01" in letter.local_law_limitation
    assert "left out of this letter" in letter.local_law_limitation


def test_current_local_law_wording_is_kept_and_reported_clean(
    make_vault: Callable[..., Vault],
) -> None:
    vault = make_vault()
    vault.document.add_issue(category="heat", title="No heat", issue_id="i1")
    letter = build_letter(
        vault,
        LetterOptions(),
        template=_local_law_template(
            local_law_reviewer="Example Legal Aid",
            local_law_reviewed_at="2026-01-01",
            local_law_expires_at="2027-01-01",
        ),
        today=date(2026, 8, 26),
    )
    assert letter.local_law.state == "current"
    assert letter.local_law.usable
    assert letter.header == _CITATION
    assert letter.footer == _UNION_FOOTER
    assert letter.local_law_limitation == ""
    assert _CITATION in render_letter_html(letter)


def test_undated_local_law_wording_is_used_but_reported_as_undated(
    make_vault: Callable[..., Vault],
) -> None:
    # Refusing undated wording would break every config written before the field
    # existed, so it is used -- and the operator is told nothing can tell them
    # when it stopped being true.
    vault = make_vault()
    vault.document.add_issue(category="heat", title="No heat", issue_id="i1")
    letter = build_letter(
        vault, LetterOptions(), template=_local_law_template(), today=date(2026, 8, 26)
    )
    assert letter.local_law.state == "undated"
    assert letter.header == _CITATION
    assert "no review date" in letter.local_law_limitation


def test_a_letter_with_no_local_law_wording_says_nothing_about_it(
    make_vault: Callable[..., Vault],
) -> None:
    vault = make_vault()
    vault.document.add_issue(category="heat", title="No heat", issue_id="i1")
    letter = build_letter(vault, LetterOptions(), today=date(2026, 8, 26))
    assert letter.local_law.state == "absent"
    assert letter.local_law_limitation == ""
    assert letter.framing_limitation == ""


def test_local_law_expires_at_the_start_of_its_named_day(
    make_vault: Callable[..., Vault],
) -> None:
    # Same calendar-date semantics as ADR 0012's profile expiry: a review expires
    # at the start of its named day, not partway through it in some timezone.
    vault = make_vault()
    vault.document.add_issue(category="heat", title="No heat", issue_id="i1")

    def _state(today: date) -> str:
        return build_letter(
            vault,
            LetterOptions(),
            template=_local_law_template(local_law_expires_at="2026-08-26"),
            today=today,
        ).local_law.state

    assert _state(date(2026, 8, 25)) == "current"
    assert _state(date(2026, 8, 26)) == "expired"
    assert _state(date(2026, 8, 27)) == "expired"


def test_a_backdated_letter_cannot_resurrect_expired_wording(
    make_vault: Callable[..., Vault],
) -> None:
    # `options.date` is caller-controlled. If the expiry check read it, anyone
    # could bring lapsed legal wording back by dating the letter into the past.
    #
    # `today` is deliberately NOT passed here. Pinning it would make this test
    # unable to fail for the exact bug it is named after: an implementation that
    # derived `today` from `options.date` would still be judged against the
    # pinned date and pass. Left to the real clock, the expiry below is already
    # in the past and only recedes further, so this is stable, not flaky.
    vault = make_vault()
    vault.document.add_issue(category="heat", title="No heat", issue_id="i1")
    letter = build_letter(
        vault,
        LetterOptions(date="2025-06-01"),
        template=_local_law_template(local_law_expires_at="2026-01-01"),
    )
    assert letter.date == "2025-06-01"
    assert letter.local_law.state == "expired"
    assert letter.header == ""


def test_withheld_wording_is_absent_from_both_renderings(
    make_vault: Callable[..., Vault],
) -> None:
    # The HTML and the PDF read the same two fields, so they cannot disagree
    # about what was withheld.
    vault = make_vault()
    vault.document.add_issue(category="heat", title="No heat", issue_id="i1")
    letter = build_letter(
        vault,
        LetterOptions(),
        template=_local_law_template(local_law_expires_at="2026-01-01"),
        today=date(2026, 8, 26),
    )
    flat = " ".join(text for _role, text in letter_lines(letter))
    assert _CITATION not in flat
    assert _CITATION not in render_letter_html(letter)


def test_an_expired_framing_falls_back_to_generic_and_says_so(
    make_vault: Callable[..., Vault], monkeypatch: pytest.MonkeyPatch
) -> None:
    # No built-in framing expires today, so pin the enforcement against a
    # deliberately-expired one: the mechanism must exist before a dated
    # jurisdiction framing is added, not after.
    expired = replace(PROFILES["us_habitability"], expires_at="2026-01-01")
    monkeypatch.setitem(PROFILES, "us_habitability", expired)
    vault = make_vault()
    vault.document.add_issue(category="heat", title="No heat", issue_id="i1")
    letter = build_letter(
        vault,
        LetterOptions(jurisdiction="us_habitability"),
        today=date(2026, 8, 26),
    )
    assert letter.profile_key == "generic"
    assert letter.framing_expired_fallback == "us_habitability"
    assert letter.framing == PROFILES["generic"].framing
    assert "us_habitability" in letter.framing_limitation


def test_an_unexpired_framing_is_used_unchanged(make_vault: Callable[..., Vault]) -> None:
    vault = make_vault()
    vault.document.add_issue(category="heat", title="No heat", issue_id="i1")
    letter = build_letter(
        vault, LetterOptions(jurisdiction="us_habitability"), today=date(2026, 8, 26)
    )
    assert letter.profile_key == "us_habitability"
    assert letter.framing_expired_fallback == ""
    assert letter.framing_limitation == ""


def test_every_builtin_framing_is_dated_and_none_expires() -> None:
    # A framing may not ship without saying when it was last read against the
    # "asserts no statute" rule. None sets an expiry: a framing that names no
    # statute has no specifics to go stale, and expiring it would only take the
    # safe fallback away from a tenant on a date.
    for profile in PROFILES.values():
        assert profile.reviewed_at, f"{profile.key} ships undated"
        assert profile.reviewer
        assert profile.expires_at == ""
        assert not framing_expired(profile, today=date(2999, 1, 1))


@pytest.mark.parametrize(
    "bad",
    [
        "2026-13-45",  # not a real calendar day
        "20260826",  # accepted by date.fromisoformat, rejected here on purpose
        "2026-08-26T00:00:00",  # a timestamp, not a calendar day
        # Fullwidth digits, written as escapes so the linter is not asked to
        # judge ambiguous glyphs: `\d` matches these, `[0-9]` does not.
        "\uff12\uff10\uff12\uff16-\uff10\uff18-\uff12\uff16",
        "not-a-date",
    ],
)
def test_config_refuses_a_review_date_that_is_not_a_plain_calendar_day(bad: str) -> None:
    # A value that parses in one place but not another is how a date meant to
    # expire quietly never does.
    with pytest.raises(ConfigError):
        LetterTemplate(header=_CITATION, local_law_expires_at=bad)
    with pytest.raises(ConfigError):
        LetterTemplate(header=_CITATION, local_law_reviewed_at=bad)


def test_config_round_trips_the_local_law_review_block(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text(
        "\n".join(
            [
                "[letter]",
                'header = "Notice under the Example City housing code"',
                'local_law_reviewer = "Example Legal Aid"',
                'local_law_reviewed_at = "2026-01-01"',
                'local_law_expires_at = "2027-01-01"',
            ]
        ),
        encoding="utf-8",
    )
    letter_config = Config.from_toml(path).letter
    assert letter_config.local_law_reviewer == "Example Legal Aid"
    assert letter_config.local_law_reviewed_at == "2026-01-01"
    assert letter_config.local_law_expires_at == "2027-01-01"
    assert review_local_law(letter_config, today=date(2026, 8, 26)).state == "current"
