# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Render a human-readable, paginated evidence packet PDF.

The PDF is for people — a tenant, an organizer, a judge, an inspector. The
machine-verifiable truth lives in ``bundle.json``; this document presents it. Text
is real (selectable/searchable), the document language and title are set for
assistive technology, and every visual status also appears in words, never by
colour alone — the same accessibility discipline the project applies everywhere.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Image,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from .canonical import JSONValue

__all__ = ["render_packet_pdf"]


def render_packet_pdf(bundle: Mapping[str, JSONValue], media_dir: Path, out_path: Path) -> None:
    """Render ``bundle`` to a paginated PDF at ``out_path``."""
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="Small", parent=styles["Normal"], fontSize=8, leading=10))
    unit = _s(bundle, "unit") or _s(bundle, "case_id")
    title = "habitability evidence packet"
    if unit:
        title = f"{title} — unit {unit}"

    doc = SimpleDocTemplate(
        str(out_path),
        pagesize=letter,
        title=title,
        author="habitable",
        subject="Tenant habitability evidence with trusted timestamps and chain of custody",
        lang="en",
        leftMargin=0.9 * inch,
        rightMargin=0.9 * inch,
        topMargin=0.9 * inch,
        bottomMargin=0.9 * inch,
    )

    story: list[Any] = [Paragraph(title, styles["Title"])]
    template = _map(bundle, "template")
    if _s(template, "header"):
        story.append(Paragraph(_s(template, "header"), styles["Normal"]))
        story.append(Spacer(1, 0.1 * inch))
    appendix = _map(bundle, "appendix")
    story.append(
        Paragraph(
            f"Generated {_s(bundle, 'generated_at')} · "
            f"{_i(appendix, 'item_count')} media item(s), "
            f"{_i(appendix, 'timestamped_count')} trusted-timestamped · "
            f"producer {_s(bundle, 'producer_fingerprint')}",
            styles["Normal"],
        )
    )
    story.append(Spacer(1, 0.2 * inch))
    story.append(
        Paragraph(
            "This packet documents habitability conditions. It is evidence, not legal advice, "
            "and it does not guarantee admissibility. Integrity is independently checkable against "
            "the accompanying <b>bundle.json</b> with the <b>habitable verify</b> tool.",
            styles["Small"],
        )
    )
    story.append(Spacer(1, 0.3 * inch))

    items_by_issue = _items_by_issue(bundle)
    for issue in _list(bundle, "issues"):
        if isinstance(issue, dict):
            _render_issue(story, issue, bundle, items_by_issue, media_dir, styles)

    story.append(PageBreak())
    story.append(Paragraph("Evidence appendix", styles["Heading1"]))
    story.append(
        Paragraph(
            "Each item lists its content hash, trusted-timestamp status, and custody status. "
            "These verify independently against bundle.json.",
            styles["Small"],
        )
    )
    story.append(Spacer(1, 0.15 * inch))
    story.append(_appendix_table(bundle, styles))

    if _s(template, "footer"):
        story.append(Spacer(1, 0.2 * inch))
        story.append(Paragraph(_s(template, "footer"), styles["Small"]))

    doc.build(story)


def _render_issue(
    story: list[Any],
    issue: Mapping[str, JSONValue],
    bundle: Mapping[str, JSONValue],
    items_by_issue: dict[str, list[Mapping[str, JSONValue]]],
    media_dir: Path,
    styles: Any,
) -> None:
    issue_id = _s(issue, "issue_id")
    heading = _s(issue, "title") or _s(issue, "category") or issue_id
    story.append(Paragraph(f"Issue: {heading}", styles["Heading2"]))
    story.append(
        Paragraph(
            f"Category: {_s(issue, 'category')} · Room: {_s(issue, 'room') or '—'} · "
            f"Severity: {_s(issue, 'severity') or '—'} · Status: {_s(issue, 'status')}",
            styles["Normal"],
        )
    )
    if _s(issue, "description"):
        story.append(Paragraph(_s(issue, "description"), styles["Normal"]))
    story.append(Spacer(1, 0.1 * inch))

    timeline = [
        entry
        for entry in _list(bundle, "timeline")
        if isinstance(entry, dict) and _s(entry, "issue_id") == issue_id
    ]
    if timeline:
        story.append(Paragraph("Timeline", styles["Heading3"]))
        for entry in timeline:
            if isinstance(entry, dict):
                story.append(
                    Paragraph(f"· <b>{_s(entry, 'kind')}</b>: {_s(entry, 'text')}", styles["Small"])
                )
        story.append(Spacer(1, 0.1 * inch))

    for item in items_by_issue.get(issue_id, []):
        shared_name = _s(item, "shared_name")
        caption = (
            f"Captured {_s(item, 'captured_at')} · hash {_s(item, 'content_hash')[:16]}… · "
            + ("timestamped" if item.get("timestamp") else "awaiting timestamp")
        )
        media_path = media_dir / shared_name if shared_name else None
        if media_path is not None and media_path.exists():
            try:
                story.append(
                    Image(str(media_path), width=2.4 * inch, height=2.4 * inch, kind="proportional")
                )
            except Exception:
                story.append(Paragraph("[image could not be rendered]", styles["Small"]))
        story.append(Paragraph(caption, styles["Small"]))
        story.append(Spacer(1, 0.12 * inch))


def _appendix_table(bundle: Mapping[str, JSONValue], styles: Any) -> Any:
    rows: list[list[Any]] = [["Capture", "Content hash (SHA-256)", "Timestamp", "Authority"]]
    for item in _list(bundle, "items"):
        if not isinstance(item, dict):
            continue
        token = item.get("timestamp")
        timestamp_status = "verified" if isinstance(token, dict) else "awaiting"
        authority = _s(token, "tsa_name") if isinstance(token, dict) else "—"
        rows.append(
            [
                Paragraph(_s(item, "capture_id"), styles["Small"]),
                Paragraph(_s(item, "content_hash"), styles["Small"]),
                Paragraph(timestamp_status, styles["Small"]),
                Paragraph(authority, styles["Small"]),
            ]
        )
    table = Table(rows, colWidths=[1.4 * inch, 3.2 * inch, 1.0 * inch, 1.1 * inch], repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#222222")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    return table


def _items_by_issue(bundle: Mapping[str, JSONValue]) -> dict[str, list[Mapping[str, JSONValue]]]:
    grouped: dict[str, list[Mapping[str, JSONValue]]] = {}
    for item in _list(bundle, "items"):
        if isinstance(item, dict):
            grouped.setdefault(_s(item, "issue_id"), []).append(item)
    return grouped


# --- typed extraction helpers -------------------------------------------------


def _s(mapping: Mapping[str, JSONValue], key: str) -> str:
    value = mapping.get(key)
    return value if isinstance(value, str) else ""


def _i(mapping: Mapping[str, JSONValue], key: str) -> int:
    value = mapping.get(key)
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _list(mapping: Mapping[str, JSONValue], key: str) -> list[JSONValue]:
    value = mapping.get(key)
    return value if isinstance(value, list) else []


def _map(mapping: Mapping[str, JSONValue], key: str) -> Mapping[str, JSONValue]:
    value = mapping.get(key)
    return value if isinstance(value, dict) else {}
