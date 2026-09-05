# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Signed recipient handoff manifests and accessible HTML rendering."""

from __future__ import annotations

from html import escape
from pathlib import Path
from typing import cast

from .canonical import JSONValue
from .usecases import UseCaseProfile

__all__ = ["build_handoff_manifest", "render_handoff_html"]


#: Bumped from 1 when the per-section id lists were removed (issue #181). A v1
#: manifest gave *every* section the whole bundle's ids, so a packet holding one
#: artifact and no delivery receipt rendered "Delivery -- 1 evidence item(s), 1
#: relationship(s)". Old packets still verify: the verifier's handoff checks are
#: structural and never read ``sections``.
HANDOFF_MANIFEST_VERSION = 2


def build_handoff_manifest(
    bundle: dict[str, JSONValue], profile: UseCaseProfile
) -> dict[str, JSONValue]:
    """Build a presentation-only manifest over facts already in the bundle.

    Sections carry their id and nothing else. A profile declares a recipient's
    expected *reading order* (condition, notice, delivery, response, follow-up)
    but nothing in the case model records which record belongs to which section,
    so no section can honestly claim membership. Section-scoped counts return
    when routing does; until then the only counts in this manifest are
    ``counts``, which are bundle-wide and labelled as such.

    Issue #277 put the choice the other way round: either give the sections
    membership, or stop the profile summaries promising an ordering this manifest
    does not produce. The summaries were corrected (see the note above
    ``usecases._PROFILES``), because giving a section members is not a change
    this module can make. Membership is a *fact about a record*, so recording it
    means a field on ``Artifact``/``EvidenceRelationship`` -- case schema, sync,
    packet format, and the verifier -- and deriving it here instead would mean
    guessing, e.g. that a ``delivery_receipt`` artifact belongs to the "delivery"
    section. ADR 0010 rejected exactly that when it rejected free-form tags:
    "typos and inference replace reviewed semantics". Issue #181 is the same
    lesson learned the expensive way -- v1 of this manifest handed every section
    the whole bundle's ids, so a packet with no delivery receipt still rendered a
    populated Delivery section. A section that claims a member it cannot justify
    is worse than a section that claims none.
    """
    issues = _object_list(bundle.get("issues"))
    items = _object_list(bundle.get("items"))
    artifacts = [item for item in items if item.get("record_kind") == "artifact"]
    relationships = _object_list(bundle.get("relationships"))
    sections: list[JSONValue] = [
        {"section_id": section_id} for section_id in profile.handoff_sections
    ]
    bundle_disclosures = bundle.get("disclosures", [])
    disclosures = (
        [str(value) for value in bundle_disclosures] if isinstance(bundle_disclosures, list) else []
    )
    disclosures.extend(profile.disclosures)
    return {
        "handoff_manifest_version": HANDOFF_MANIFEST_VERSION,
        # Explicit, so a reader is told the absence is a limit of this tool and
        # not an empty packet -- and so a future routing implementation has a
        # field to flip rather than a silence to reinterpret.
        "section_membership": "not_recorded",
        "profile_id": profile.profile_id,
        "profile": profile.to_json(),
        "scope": bundle.get("scope"),
        "sections": sections,
        "counts": {
            "issues": len(issues),
            "items": len(items),
            "artifacts": len(artifacts),
            "relationships": len(relationships),
        },
        "disclosures": cast(JSONValue, disclosures),
        "source_of_truth": "bundle.json",
        "presentation_only": True,
    }


def render_handoff_html(manifest: dict[str, JSONValue], out_path: Path, *, language: str) -> None:
    """Render one keyboard/screen-reader-friendly handoff summary."""
    profile = manifest.get("profile")
    profile_map = profile if isinstance(profile, dict) else {}
    names = profile_map.get("name")
    summaries = profile_map.get("summary")
    name_map = names if isinstance(names, dict) else {}
    summary_map = summaries if isinstance(summaries, dict) else {}
    locale = "es" if language == "es" else "en"
    name = _string(name_map.get(locale)) or _string(name_map.get("en"))
    summary = _string(summary_map.get(locale)) or _string(summary_map.get("en"))
    review_state = _string(profile_map.get("review_state"))
    sections = _object_list(manifest.get("sections"))
    disclosures_raw = manifest.get("disclosures")
    disclosures = (
        [str(value) for value in disclosures_raw] if isinstance(disclosures_raw, list) else []
    )
    review_warning = ""
    if review_state == "external_review_required":
        review_warning = (
            '<p class="warning"><strong>External review required.</strong> '
            "This workflow is implemented for synthetic evaluation; it is not "
            "a legal, medical, inspector, or accessibility approval.</p>"
        )
    # Bundle-wide, printed once, labelled as covering the whole handoff. Before
    # issue #181 these same two numbers were printed under *every* section
    # heading, so a packet with no delivery receipt still read "Delivery -- 1
    # evidence item(s), 1 relationship(s)".
    counts = manifest.get("counts")
    count_map = counts if isinstance(counts, dict) else {}
    totals_html = (
        "<section><h2>This handoff as a whole</h2><p>"
        + str(_count(count_map.get("items")))
        + " evidence item(s), of which "
        + str(_count(count_map.get("artifacts")))
        + " document(s), across "
        + str(_count(count_map.get("issues")))
        + " condition(s), with "
        + str(_count(count_map.get("relationships")))
        + " stated relationship(s). These totals cover the whole packet.</p></section>"
    )
    section_note = (
        "<p>The headings below are the order this recipient is expected to read in. "
        "This packet does not record which record belongs to which heading, so no "
        "heading claims a count of its own; <code>bundle.json</code> lists every "
        "record.</p>"
        if sections
        else ""
    )
    section_html = "".join(
        "<section><h2>"
        + escape(_string(section.get("section_id")).replace("_", " ").title())
        + "</h2></section>"
        for section in sections
    )
    disclosure_html = "".join(f"<li>{escape(value)}</li>" for value in disclosures)
    out_path.write_text(
        '<!doctype html><html lang="'
        + locale
        + '"><head><meta charset="utf-8"><meta name="viewport" '
        + 'content="width=device-width,initial-scale=1"><title>'
        + escape(name)
        + "</title><style>body{font:1rem/1.55 system-ui;max-width:52rem;margin:auto;"
        + "padding:2rem;color:#17252a}h1,h2{line-height:1.2}.warning{border-inline-start:"
        + ".4rem solid #a44700;padding:1rem;background:#fff3df}code{overflow-wrap:anywhere}"
        + "</style></head><body><main><h1>"
        + escape(name)
        + "</h1><p>"
        + escape(summary)
        + "</p>"
        + review_warning
        + totals_html
        + section_note
        + section_html
        + "<section><h2>Limits and disclosures</h2><ul>"
        + disclosure_html
        + "</ul></section><p>Presentation only. <code>bundle.json</code> is the "
        + "signed source of truth.</p></main></body></html>",
        encoding="utf-8",
    )


def _object_list(value: JSONValue | None) -> list[dict[str, JSONValue]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _string(value: JSONValue | None) -> str:
    return value if isinstance(value, str) else ""


def _count(value: JSONValue | None) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0
