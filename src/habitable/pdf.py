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
from typing import Any, ClassVar
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import (
    Image,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from .bundleview import (
    ChronologyEntry,
    CoverSheet,
    IntegritySummary,
    chronology,
    cover_sheet,
    integrity_summary,
)
from .canonical import JSONValue
from .disclosure import proof_statement
from .letter import RepairLetter, letter_lines

__all__ = ["render_letter_pdf", "render_packet_pdf"]


class _AccessibleCanvas(Canvas):  # type: ignore[misc]  # reportlab ships no stubs
    """A canvas that adds PDF/UA-friendly catalog hints.

    Declares the document language (also set via SimpleDocTemplate) and asks
    viewers to show the document *title* rather than the file name — small but
    real steps toward an accessible packet. Full PDF/UA tagging (a structure
    tree) is tracked in the ACR.
    """

    def save(self) -> None:
        self.setViewerPreference("DisplayDocTitle", "true")
        super().save()


class _PacketDoc(SimpleDocTemplate):  # type: ignore[misc]  # reportlab ships no stubs
    """A document that records a navigable outline (bookmarks) for its headings.

    A PDF outline lets everyone — especially screen-reader and keyboard users —
    jump between sections. (reportlab's open-source API has no marked-content, so
    a full PDF/UA structure tree is not produced; see docs/accessibility/ACR.md.)
    """

    _HEADING_LEVELS: ClassVar[dict[str, int]] = {
        "Title": 0,
        "Heading1": 0,
        "Heading2": 1,
        "Heading3": 2,
    }

    def afterFlowable(self, flowable: Any) -> None:  # noqa: N802 - reportlab override name
        if not isinstance(flowable, Paragraph):
            return
        level = self._HEADING_LEVELS.get(flowable.style.name)
        text = flowable.getPlainText()
        if level is None or not text:
            return
        counter = getattr(self, "_outline_n", 0)
        self._outline_n = counter + 1
        key = f"sec-{counter}"
        self.canv.bookmarkPage(key)
        self.canv.addOutlineEntry(text, key, level=level, closed=False)


def _para(text: str, style: Any) -> Any:
    """A Paragraph with its text escaped — bundle content is data, not markup.

    ReportLab parses inline markup inside a Paragraph (including ``<img src=...>``,
    which it will read from a local path or fetch over the network at build time).
    Every dynamic, bundle-derived string is therefore escaped before it reaches a
    Paragraph, so a hostile packet template or a tenant's own text cannot trigger a
    file read or an outbound request.
    """
    return Paragraph(escape(text), style)


# The PDF is a print/presentation convenience. Per docs/adr/0004, the *conformant*
# accessible rendering of a packet is packet.html, which ships alongside every export;
# the disclaimer points a reader who needs an accessible record to it.
_PACKET_DISCLAIMER = (
    "This packet documents habitability conditions. It is evidence, not legal advice, "
    "and it does not guarantee admissibility. Integrity is independently checkable against "
    "the accompanying <b>bundle.json</b> with the <b>habitable verify</b> tool. "
    "An accessible version of this packet is provided as <b>packet.html</b>, alongside this PDF."
)


def render_packet_pdf(bundle: Mapping[str, JSONValue], media_dir: Path, out_path: Path) -> None:
    """Render ``bundle`` to a paginated PDF at ``out_path``."""
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="Small", parent=styles["Normal"], fontSize=8, leading=10))
    unit = _s(bundle, "unit") or _s(bundle, "case_id")
    title = "habitability evidence packet"
    if unit:
        title = f"{title} — unit {unit}"
    # Declare the configured language so assistive tech reads the packet correctly.
    lang = _s(bundle, "language") or "en"

    doc = _PacketDoc(
        str(out_path),
        pagesize=letter,
        title=title,
        author="habitable",
        subject="Tenant habitability evidence with trusted timestamps and chain of custody",
        lang=lang,
        leftMargin=0.9 * inch,
        rightMargin=0.9 * inch,
        topMargin=0.9 * inch,
        bottomMargin=0.9 * inch,
    )

    story: list[Any] = [_para(title, styles["Title"])]
    template = _map(bundle, "template")
    if _s(template, "header"):
        story.append(_para(_s(template, "header"), styles["Normal"]))
        story.append(Spacer(1, 0.1 * inch))
    appendix = _map(bundle, "appendix")
    # Cover sheet: the front-matter facts a court/inspector reads first.
    _render_cover_sheet(story, cover_sheet(bundle), styles)
    story.append(Spacer(1, 0.2 * inch))
    story.append(Paragraph(_PACKET_DISCLAIMER, styles["Small"]))
    story.append(Spacer(1, 0.2 * inch))
    _render_proof_statement(story, lang, styles)
    story.append(Spacer(1, 0.15 * inch))
    _render_disclosures(story, lang, _bool(appendix, "includes_originals"), styles)
    story.append(Spacer(1, 0.3 * inch))

    # Chronological evidence timeline: notes and photos interleaved across issues.
    _render_chronology(story, chronology(bundle), styles)

    items_by_issue = _items_by_issue(bundle)
    for issue in _list(bundle, "issues"):
        if isinstance(issue, dict):
            _render_issue(story, issue, bundle, items_by_issue, media_dir, styles)

    # Chain-of-custody / integrity summary: hashes, attestations, custody proof.
    _render_integrity(story, integrity_summary(bundle), styles)

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
        story.append(_para(_s(template, "footer"), styles["Small"]))

    doc.build(story, canvasmaker=_AccessibleCanvas)


def _render_proof_statement(story: list[Any], lang: str, styles: Any) -> None:
    """Append the plain-language 'what this proves / what it does not' block."""
    stmt = proof_statement(lang)
    story.append(_para(stmt.heading, styles["Heading2"]))
    story.append(_para(stmt.proves_heading, styles["Heading3"]))
    for line in stmt.proves:
        story.append(_para(f"- {line}", styles["Small"]))
    story.append(_para(stmt.not_heading, styles["Heading3"]))
    for line in stmt.not_proves:
        story.append(_para(f"- {line}", styles["Small"]))
    story.append(_para(stmt.verify_line, styles["Small"]))


def _render_disclosures(story: list[Any], lang: str, includes_originals: bool, styles: Any) -> None:
    """Append the localized 'what this packet discloses' (location handling) block."""
    stmt = proof_statement(lang)
    story.append(_para(stmt.privacy_heading, styles["Heading3"]))
    story.append(_para(f"- {stmt.privacy_stripped}", styles["Small"]))
    if includes_originals:
        story.append(_para(f"- {stmt.privacy_originals_warning}", styles["Small"]))


def _render_cover_sheet(story: list[Any], cover: CoverSheet, styles: Any) -> None:
    """Append the cover-sheet facts table (case, scope, counts, date range)."""
    story.append(_para("Cover sheet", styles["Heading2"]))
    span = (
        f"{cover.earliest} to {cover.latest}"
        if cover.earliest and cover.latest
        else (cover.earliest or cover.latest or "—")
    )
    facts: list[tuple[str, str]] = [
        ("Case", cover.case_id or "—"),
        ("Unit", cover.unit or "—"),
        ("Covers", cover.scope),
        ("Generated", cover.generated_at or "—"),
        ("Producer device", cover.producer_fingerprint or "—"),
        ("Issues", str(cover.issue_count)),
        (
            "Media items",
            f"{cover.item_count} ({cover.timestamped_count} trusted-timestamped)",
        ),
        ("Chain-of-custody entries", str(cover.custody_length)),
        ("Date range of evidence", span),
        ("Sealed originals embedded", "yes" if cover.includes_originals else "no"),
    ]
    rows: list[list[Any]] = [
        [_para(label, styles["Small"]), _para(value, styles["Small"])] for label, value in facts
    ]
    table = Table(rows, colWidths=[2.2 * inch, 4.5 * inch])
    table.setStyle(
        TableStyle(
            [
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eeeeee")),
            ]
        )
    )
    story.append(table)


def _render_chronology(story: list[Any], entries: tuple[ChronologyEntry, ...], styles: Any) -> None:
    """Append the unified, chronological evidence timeline (notes + photos)."""
    story.append(Paragraph("Chronological evidence timeline", styles["Heading2"]))
    if not entries:
        story.append(_para("No timeline entries or captures recorded.", styles["Small"]))
        story.append(Spacer(1, 0.2 * inch))
        return
    story.append(
        Paragraph(
            "Notes are placed when they were logged; photos when they were captured. "
            "The order of record is fixed by the append-only chain of custody.",
            styles["Small"],
        )
    )
    for entry in entries:
        when = escape(entry.when or "undated")
        label = escape(entry.label)
        issue = escape(entry.issue_title)
        text = escape(entry.text)
        line = f"· <b>{when}</b> — [{label}] {issue}: {text}"
        if entry.detail:
            line = f"{line} ({escape(entry.detail)})"
        story.append(Paragraph(line, styles["Small"]))
    story.append(Spacer(1, 0.25 * inch))


def _render_integrity(story: list[Any], summary: IntegritySummary, styles: Any) -> None:
    """Append the chain-of-custody / integrity summary section."""
    story.append(PageBreak())
    story.append(Paragraph("Chain of custody & integrity", styles["Heading1"]))
    story.append(
        Paragraph(
            f"Hash algorithm {escape(summary.algorithm)} · "
            f"{summary.custody_length} custody entr"
            f"{'y' if summary.custody_length == 1 else 'ies'} (append-only, hash-linked) · "
            f"{summary.timestamped_count}/{summary.item_count} items trusted-timestamped. "
            "The chain head below commits to the entire history; any insertion, deletion, "
            "or reordering changes it. All of this verifies independently against bundle.json.",
            styles["Small"],
        )
    )
    if summary.custody_head:
        story.append(_para(f"Custody chain head: {summary.custody_head}", styles["Small"]))
    story.append(Spacer(1, 0.15 * inch))

    rows: list[list[Any]] = [
        ["Capture", "Content hash (SHA-256)", "Timestamp authorities", "Custody"]
    ]
    for row in summary.rows:
        authorities = ", ".join(row.authorities) if row.authorities else "—"
        if row.archive_count:
            authorities = f"{authorities} · +{row.archive_count} archive"
        custody = f"{row.custody_entries} entr{'y' if row.custody_entries == 1 else 'ies'}"
        rows.append(
            [
                _para(row.capture_id, styles["Small"]),
                _para(row.content_hash, styles["Small"]),
                _para(f"{row.timestamp_status}: {authorities}", styles["Small"]),
                _para(custody, styles["Small"]),
            ]
        )
    table = Table(rows, colWidths=[1.3 * inch, 2.9 * inch, 1.9 * inch, 0.6 * inch], repeatRows=1)
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
    story.append(table)


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
    story.append(_para(f"Issue: {heading}", styles["Heading2"]))
    story.append(
        _para(
            f"Category: {_s(issue, 'category')} · Room: {_s(issue, 'room') or '—'} · "
            f"Severity: {_s(issue, 'severity') or '—'} · Status: {_s(issue, 'status')}",
            styles["Normal"],
        )
    )
    if _s(issue, "description"):
        story.append(_para(_s(issue, "description"), styles["Normal"]))
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
                # Keep the literal <b> formatting, but escape the dynamic parts.
                kind = escape(_s(entry, "kind"))
                text = escape(_s(entry, "text"))
                story.append(Paragraph(f"· <b>{kind}</b>: {text}", styles["Small"]))
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
        story.append(_para(caption, styles["Small"]))
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
                _para(_s(item, "capture_id"), styles["Small"]),
                _para(_s(item, "content_hash"), styles["Small"]),
                _para(timestamp_status, styles["Small"]),
                _para(authority, styles["Small"]),
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


def render_letter_pdf(repair_letter: RepairLetter, out_path: Path) -> None:
    """Render a repair-request letter to an accessible PDF at ``out_path``.

    Shares the packet's accessibility hygiene (declared language, displayed title,
    selectable text). Every dynamic value is escaped before it reaches a Paragraph,
    so letter content is treated as data, never markup. The conformant accessible
    rendering remains the HTML letter (per ADR 0004); this is a print convenience.
    """
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="Small", parent=styles["Normal"], fontSize=9, leading=12))
    styles.add(ParagraphStyle(name="Disclaimer", parent=styles["Normal"], fontSize=8, leading=10))
    doc = _PacketDoc(
        str(out_path),
        pagesize=letter,  # the reportlab US-letter page size, not the document
        title=repair_letter.subject,
        author="habitable",
        subject="Tenant repair-request / habitability notice letter",
        lang=repair_letter.language or "en",
        leftMargin=1.0 * inch,
        rightMargin=1.0 * inch,
        topMargin=1.0 * inch,
        bottomMargin=1.0 * inch,
    )
    story: list[Any] = [_para(repair_letter.subject, styles["Title"])]
    for role, text in letter_lines(repair_letter):
        if not text:
            continue
        if role == "subject":
            story.append(_para(text, styles["Heading2"]))
        elif role == "issue":
            story.append(_para(text, styles["Normal"]))
            story.append(Spacer(1, 0.06 * inch))
        elif role == "disclaimer":
            story.append(Spacer(1, 0.15 * inch))
            story.append(_para(text, styles["Disclaimer"]))
        elif role == "address":
            story.append(_para(text, styles["Small"]))
        else:  # meta, body
            style = styles["Small"] if role == "meta" else styles["Normal"]
            story.append(_para(text, style))
            story.append(Spacer(1, 0.08 * inch))
    doc.build(story, canvasmaker=_AccessibleCanvas)


# --- typed extraction helpers -------------------------------------------------


def _s(mapping: Mapping[str, JSONValue], key: str) -> str:
    value = mapping.get(key)
    return value if isinstance(value, str) else ""


def _i(mapping: Mapping[str, JSONValue], key: str) -> int:
    value = mapping.get(key)
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _bool(mapping: Mapping[str, JSONValue], key: str) -> bool:
    return mapping.get(key) is True


def _list(mapping: Mapping[str, JSONValue], key: str) -> list[JSONValue]:
    value = mapping.get(key)
    return value if isinstance(value, list) else []


def _map(mapping: Mapping[str, JSONValue], key: str) -> Mapping[str, JSONValue]:
    value = mapping.get(key)
    return value if isinstance(value, dict) else {}
