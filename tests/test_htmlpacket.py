# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""The accessible HTML packet: structure + a real axe-core scan."""

from __future__ import annotations

import copy
import json
import re
from collections.abc import Callable
from pathlib import Path

import pytest

from habitable.canonical import JSONValue
from habitable.capture import capture
from habitable.htmlpacket import _PROFILE_TEXT, render_packet_html
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


def test_byteless_item_renders_a_visible_warning_not_an_empty_figure(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    """issue #158 decision 3: ``build_packet`` now refuses to ever produce a
    byteless item (see tests/test_media_types.py), so this state can only
    reach ``render_packet_html`` via a hand-crafted or otherwise
    non-conformant bundle -- exactly the defense-in-depth scenario the visible
    rendering exists for (a packet from an older/different tool, or a future
    code path that bypasses ``build_packet``). Simulate that by mutating an
    otherwise-real, freshly built bundle's one item down to no bytes at all.
    """
    vault = make_vault()
    issue = vault.document.add_issue(category="mold", title="Mold", issue_id="i1")
    capture(vault, make_jpeg(with_location=True), issue_id=issue, tsa=local_tsa)
    out = tmp_path / "pkt"
    build_packet(vault, out, generated_at="2026-01-02T00:10:00Z", make_pdf=False)

    bundle = json.loads((out / "bundle.json").read_text(encoding="utf-8"))
    bundle["items"][0]["shared_name"] = ""
    bundle["items"][0]["shared_hash"] = ""
    bundle["items"][0]["has_original"] = False

    rendered = tmp_path / "byteless.html"
    render_packet_html(bundle, out / "media", rendered)
    html = rendered.read_text(encoding="utf-8")

    assert (
        "No photo, recording, or file was included for this item. Its content hash "
        "and timestamp exist, but there are no evidence bytes here to view or "
        "verify." in html
    )
    assert '<img src="media/' not in html  # never a silently empty figure
    assert "NONE — no evidence bytes" in html  # the appendix table says so too


def test_original_only_item_renders_a_visible_notice_with_a_download_link(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    """An item with an embedded original but no shared preview copy (e.g. a
    HEIC capture exported with ``--include-originals``, see
    tests/test_media_types.py) is a deliberate, disclosed, higher-disclosure
    choice, not a defect -- it must be visibly explained, not rendered as an
    empty figure either."""
    vault = make_vault()
    issue = vault.document.add_issue(category="mold", title="Mold", issue_id="i1")
    capture(vault, make_jpeg(with_location=True), issue_id=issue, tsa=local_tsa)
    out = tmp_path / "pkt"
    build_packet(
        vault, out, generated_at="2026-01-02T00:10:00Z", make_pdf=False, include_originals=True
    )

    bundle = json.loads((out / "bundle.json").read_text(encoding="utf-8"))
    original_item = copy.deepcopy(bundle["items"][0])
    original_item["shared_name"] = ""
    original_item["shared_hash"] = ""
    assert original_item["has_original"] is True
    bundle["items"][0] = original_item

    rendered = tmp_path / "original-only.html"
    render_packet_html(bundle, out / "media", rendered)
    html = rendered.read_text(encoding="utf-8")

    capture_id = original_item["capture_id"]
    assert "No shared preview copy was made for this item" in html
    assert "sealed original file is embedded and hash-verified" in html
    assert f'<a href="originals/{capture_id}">download the original</a>' in html
    assert "may retain full metadata, including location" in html
    assert '<img src="media/' not in html
    assert "original only (no shared preview)" in html  # the appendix table too


def _profile_packet(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    tsa: LocalRfc3161TSA,
    out: Path,
    profile_id: str,
    *,
    inspector_view: bool = False,
) -> tuple[Path, dict[str, JSONValue]]:
    """Export a one-issue packet under *profile_id* and return its HTML + bundle."""
    vault = make_vault()
    issue = vault.document.add_issue(category="mold", room="bath", title="Mold", issue_id="i1")
    vault.document.set_use_case_profile(profile_id)
    capture(vault, make_jpeg(), issue_id=issue, tsa=tsa)
    result = build_packet(
        vault,
        out,
        generated_at="2026-01-02T00:10:00Z",
        make_pdf=False,
        inspector_view=inspector_view,
    )
    assert result.html_path is not None
    bundle = json.loads(result.bundle_path.read_text(encoding="utf-8"))
    assert bundle["use_case_profile"]["profile_id"] == profile_id
    return result.html_path, bundle


def test_profile_locale_text_is_at_parity() -> None:
    """EN/ES parity for the packet renderer's own labels.

    ``scripts/check_i18n_parity.py`` is the merge gate for ``app/i18n/*.json``,
    the browser app's bundle. It never reads this module, so the packet
    renderer's strings would drift silently: a missing Spanish key raises
    ``KeyError`` mid-export, and a dropped ``{placeholder}`` quietly ships a
    Spanish sentence with a fact missing from it.
    """
    en, es = _PROFILE_TEXT["en"], _PROFILE_TEXT["es"]

    assert set(en) == set(es)
    for locale, strings in (("en", en), ("es", es)):
        for key, value in strings.items():
            assert value.strip(), f"{locale}: {key} is empty"
    for key in en:
        assert set(re.findall(r"{(\w+)}", en[key])) == set(re.findall(r"{(\w+)}", es[key])), key


def test_packet_html_carries_the_profiles_disclosures_and_review_state(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    """Issue #277: a profile's limits used to reach a recipient only through
    ``handoff-<id>.html`` and ``bundle.json``.

    The disclosures exist so a recipient does not over-read the document, and the
    recipient most likely to over-read it is the one handed the packet and
    nothing else. ``inspector_handoff`` is the sharpest case: it is
    ``external_review_required`` and its one disclosure refuses exactly the
    reading its name invites.
    """
    html_path, _ = _profile_packet(
        make_vault, make_jpeg, local_tsa, tmp_path / "pkt", "inspector_handoff"
    )
    html = html_path.read_text(encoding="utf-8")

    assert '<h2 id="profile-heading">Workflow profile</h2>' in html
    assert "<strong>Inspector handoff</strong>" in html
    assert "This profile is not an inspector finding or code determination." in html
    assert "External review required." in html
    assert "not a legal, medical, inspector, or accessibility approval" in html
    # A real heading, not a styled paragraph, and nested under the page's one h1.
    assert "<h3>What this profile does not establish</h3>" in html
    assert html.count("<h1>") == 1
    # The warning is carried by its words, never by the border colour alone.
    assert "<strong>External review required." in html
    # Read before the packet's own claims, not after them.
    assert html.index("Workflow profile") < html.index("What this packet proves")


def test_packet_html_names_who_reviewed_a_maintainer_reviewed_profile(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    """ "Reviewed" with no reviewer is the reading this project most needs to
    prevent, so a maintainer-reviewed profile is still stated out loud -- and
    stated as *not* legal, medical, inspector, or accessibility review."""
    html_path, _ = _profile_packet(
        make_vault, make_jpeg, local_tsa, tmp_path / "pkt", "repair_delivery"
    )
    html = html_path.read_text(encoding="utf-8")

    assert "Reviewed by the project maintainers." in html
    assert "Reviewed by Habitable maintainers on 2026-07-23." in html
    assert "Maintainer review is not legal, medical, inspector, or accessibility review." in html
    assert "External review required" not in html
    assert "Delivery and receipt remain assertions unless independently authenticated." in html


def test_packet_html_says_nothing_about_a_profile_when_none_was_selected(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    """The block is additive, never a placeholder.

    A packet exported without the workflow machinery -- the published
    ``site/sample-packet``, every fixture in ``tests/golden/``, and any packet
    produced before profiles existed -- must render exactly as it did before, so
    there is nothing here for a reader to mistake for an absent profile.
    """
    html = _packet(make_vault, make_jpeg, local_tsa, tmp_path / "pkt").read_text(encoding="utf-8")

    assert "Workflow profile" not in html
    assert "profile-heading" not in html


def test_packet_html_says_a_profile_was_dropped_for_an_expired_review(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    """ADR 0012's fallback was invisible to a reader of ``packet.html``.

    ``packet.py`` records the dropped profile in the bundle's signed
    ``disclosures`` array and in ``use_case_profile_fallback``, but this renderer
    read ``disclosures`` only to pick a privacy sentence -- so an export whose
    workflow guidance was withdrawn for staleness was indistinguishable from one
    that never chose a workflow at all. Exercised through a hand-built bundle
    because no shipped profile sets ``expires_at`` yet (see
    ``tests/test_usecases.py``).
    """
    vault = make_vault()
    issue = vault.document.add_issue(category="mold", title="Mold", issue_id="i1")
    capture(vault, make_jpeg(), issue_id=issue, tsa=local_tsa)
    out = tmp_path / "pkt"
    build_packet(vault, out, generated_at="2026-01-02T00:10:00Z", make_pdf=False)

    bundle = json.loads((out / "bundle.json").read_text(encoding="utf-8"))
    bundle["use_case_profile"] = None
    bundle["use_case_profile_fallback"] = {
        "requested_profile_id": "public_housing_remediation",
        "requested_profile_version": 1,
        "expires_at": "2026-01-01",
    }
    rendered = tmp_path / "expired.html"
    render_packet_html(bundle, out / "media", rendered)
    html = rendered.read_text(encoding="utf-8")

    assert '<h2 id="profile-heading">Workflow profile</h2>' in html
    assert "public_housing_remediation" in html
    assert "had passed its review date (2026-01-01)" in html
    assert "carries no workflow profile" in html


def test_spanish_packet_localizes_the_block_and_marks_signed_english_as_english(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    """The labels are bilingual; the signed disclosure sentences are not.

    A profile's ``disclosures`` are English-only strings inside the signed
    bundle, and a renderer must not translate, paraphrase, or reorder a signed
    claim. So they are emitted verbatim and marked ``lang="en"`` inside a
    Spanish document, which is what stops a screen reader from reading English
    with Spanish phonemes (WCAG 2.2 3.1.2).
    """
    out = tmp_path / "pkt"
    english_path, bundle = _profile_packet(
        make_vault, make_jpeg, local_tsa, out, "accommodation_request"
    )
    bundle["language"] = "es"
    rendered = tmp_path / "es.html"
    render_packet_html(bundle, out / "media", rendered)
    html = rendered.read_text(encoding="utf-8")

    assert '<h2 id="profile-heading">Perfil de flujo de trabajo</h2>' in html
    assert "<strong>Registro de solicitud de adaptación</strong>" in html
    assert "Se requiere revisión externa." in html
    assert "<h3>Lo que este perfil no establece</h3>" in html
    assert (
        '<li lang="en">Technical integrity does not establish disability, '
        "entitlement, receipt, or compliance.</li>" in html
    )
    # The same profile in an English packet carries the sentence with no
    # redundant attribute: the disclosure is already in the document's language.
    english = english_path.read_text(encoding="utf-8")
    assert (
        "Technical integrity does not establish disability, entitlement, "
        "receipt, or compliance." in english
    )
    assert '<li lang="en">' not in english


def test_packet_html_prints_an_unfamiliar_review_state_verbatim(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    """The review-state vocabulary is packet-visible format (issue #277 finding
    4) and this renderer has no standing to change it. It therefore maps only the
    two states the verifier accepts today and prints anything else as itself: a
    future ``externally_reviewed`` must surface as an honest unfamiliar word, not
    as a wrong familiar one.
    """
    out = tmp_path / "pkt"
    _, bundle = _profile_packet(make_vault, make_jpeg, local_tsa, out, "repair_delivery")
    profile = bundle["use_case_profile"]
    assert isinstance(profile, dict)
    profile["review_state"] = "externally_reviewed"
    profile["external_review_required"] = False
    review = profile["review"]
    assert isinstance(review, dict)
    review["reviewer"] = "Named outside reviewer"
    rendered = tmp_path / "future.html"
    render_packet_html(bundle, out / "media", rendered)
    html = rendered.read_text(encoding="utf-8")

    assert "Recorded review state: externally_reviewed." in html
    assert "Reviewed by Named outside reviewer on 2026-07-23." in html
    assert "Maintainer review" not in html
    assert "External review required" not in html


def test_inspector_view_carries_the_profile_block_too(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    """``inspector.html`` is handed to a recipient on its own at least as often as
    ``packet.html`` is, and it is the view the ``inspector_handoff`` profile is
    named after -- so it must carry the same refusal to be read as a finding."""
    _, _ = _profile_packet(
        make_vault,
        make_jpeg,
        local_tsa,
        tmp_path / "pkt",
        "inspector_handoff",
        inspector_view=True,
    )
    html = (tmp_path / "pkt" / "inspector.html").read_text(encoding="utf-8")

    assert '<h2 id="profile-heading">Workflow profile</h2>' in html
    assert "This profile is not an inspector finding or code determination." in html
    assert "External review required." in html
    assert html.count("<h1>") == 1


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
    assert "timestamp token attached; authority trust not assessed" in html


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


@pytest.mark.a11y
def test_profile_bearing_packets_pass_axe_in_both_languages(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    """``test_html_packet_passes_axe`` scans a packet with no workflow profile, so
    on its own it would never see the block added for issue #277.

    Both languages are scanned because the Spanish rendering is the one that
    mixes languages: localized labels around signed English disclosure sentences
    carrying ``lang="en"``. That is the arrangement axe's ``valid-lang`` and
    ``html-has-lang`` rules exist to check, and getting it wrong is invisible to
    a sighted reviewer.
    """
    pytest.importorskip("playwright.sync_api")
    pytest.importorskip("axe_playwright_python.sync_playwright")
    from axe_playwright_python.sync_playwright import Axe
    from playwright.sync_api import Error as PlaywrightError
    from playwright.sync_api import sync_playwright

    out = tmp_path / "pkt"
    english, bundle = _profile_packet(
        make_vault, make_jpeg, local_tsa, out, "accommodation_request"
    )
    bundle["language"] = "es"
    spanish = tmp_path / "es.html"
    render_packet_html(bundle, out / "media", spanish)

    violations: dict[str, list[str]] = {}
    with sync_playwright() as p:
        try:
            browser = p.chromium.launch()
        except PlaywrightError as exc:
            pytest.skip(f"Chromium not available: {exc}")
        try:
            page = browser.new_page()
            for label, path in (("en", english), ("es", spanish)):
                page.goto(path.as_uri(), wait_until="load")
                results = Axe().run(page)
                violations[label] = [
                    v["id"]
                    for v in results.response.get("violations", [])
                    if v.get("impact") in {"moderate", "serious", "critical"}
                ]
        finally:
            browser.close()
    assert violations == {"en": [], "es": []}
