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


def build_handoff_manifest(
    bundle: dict[str, JSONValue], profile: UseCaseProfile
) -> dict[str, JSONValue]:
    """Build a presentation-only manifest over facts already in the bundle."""
    issues = _object_list(bundle.get("issues"))
    items = _object_list(bundle.get("items"))
    artifacts = [item for item in items if item.get("record_kind") == "artifact"]
    relationships = _object_list(bundle.get("relationships"))
    issue_ids = [_string(item.get("issue_id")) for item in issues]
    item_ids = [_string(item.get("capture_id")) for item in items]
    artifact_ids = [_string(item.get("capture_id")) for item in artifacts]
    relationship_ids = [_string(item.get("relationship_id")) for item in relationships]
    sections: list[JSONValue] = []
    for section_id in profile.handoff_sections:
        sections.append(
            {
                "section_id": section_id,
                "issue_ids": cast(JSONValue, issue_ids),
                "item_ids": cast(JSONValue, item_ids),
                "artifact_ids": cast(JSONValue, artifact_ids),
                "relationship_ids": cast(JSONValue, relationship_ids),
            }
        )
    bundle_disclosures = bundle.get("disclosures", [])
    disclosures = (
        [str(value) for value in bundle_disclosures] if isinstance(bundle_disclosures, list) else []
    )
    disclosures.extend(profile.disclosures)
    return {
        "handoff_manifest_version": 1,
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
    section_html = "".join(
        "<section><h2>"
        + escape(_string(section.get("section_id")).replace("_", " ").title())
        + "</h2><p>Presentation pointers: "
        + str(len(_string_list(section.get("item_ids"))))
        + " evidence item(s), "
        + str(len(_string_list(section.get("relationship_ids"))))
        + " relationship(s).</p></section>"
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


def _string_list(value: JSONValue | None) -> list[str]:
    return [str(item) for item in value] if isinstance(value, list) else []
