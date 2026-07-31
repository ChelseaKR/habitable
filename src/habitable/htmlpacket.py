# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Render an accessible HTML version of an evidence packet.

ReportLab's open-source API cannot emit a fully tagged PDF/UA structure tree, so
the packet also ships ``packet.html`` — a self-contained, WCAG 2.2 AA rendering
(semantic landmarks, one ``h1``, a captioned appendix table with header scopes,
meaningful image alt text, high-contrast text, the document language). It is the
fully accessible human-readable view; ``bundle.json`` remains the machine-verifiable
record. Every dynamic value is HTML-escaped — bundle content is data, not markup.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from html import escape
from pathlib import Path

from .bundleview import (
    ChronologyEntry,
    CoverSheet,
    IntegritySummary,
    chronology,
    cover_sheet,
    integrity_summary,
)
from .canonical import JSONValue
from .disclosure import (
    PacketTrustText,
    packet_trust_text,
    proof_statement,
    scope_statement,
    shared_metadata_may_be_retained,
)

__all__ = ["render_inspector_html", "render_packet_html"]

_STYLE = """
:root { color-scheme: light dark; }
body { max-width: 50rem; margin: 0 auto; padding: 1.5rem;
  font: 16px/1.6 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  color: #111; background: #fff; }
a.skip { position: absolute; left: -999px; }
a.skip:focus { position: static; }
:focus-visible { outline: 3px solid #1f4e5f; outline-offset: 2px; }
h1, h2, h3 { line-height: 1.25; }
.warning { border: 2px solid #7a1f1f; background: #fdecec; color: #5a1414;
  padding: .6rem .8rem; border-radius: 6px; font-weight: 600; }
.meta { color: #333; }
dl.cover { display: grid; grid-template-columns: max-content 1fr; gap: .2rem .8rem; }
dl.cover dt { font-weight: 600; }
dl.cover dd { margin: 0; }
figure { margin: 0 0 1rem; border: 1px solid #ccc; border-radius: 6px; padding: .6rem; }
img { max-width: 100%; height: auto; }
figcaption { font-size: .9rem; color: #222; }
table { border-collapse: collapse; width: 100%; }
caption { text-align: left; font-weight: 600; margin-bottom: .4rem; }
th, td { border: 1px solid #999; padding: .35rem .5rem; text-align: left;
  vertical-align: top; font-size: .9rem; }
th { background: #1f4e5f; color: #fff; }
footer { margin-top: 2rem; border-top: 1px solid #ccc; padding-top: 1rem;
  color: #222; font-size: .9rem; }
.sensor-chart { max-width: 30rem; height: auto; display: block; margin: .4rem 0; }
.sensor-chart .line { fill: none; stroke: #1f4e5f; stroke-width: 2; }
.sensor-chart .point { fill: #1f4e5f; }
.sensor-chart .axis { stroke: #999; stroke-width: 1; }
details.sensor-readings summary { cursor: pointer; font-weight: 600; }
"""


def render_packet_html(bundle: Mapping[str, JSONValue], media_dir: Path, out_path: Path) -> None:
    """Write an accessible, self-contained HTML packet to ``out_path``."""
    lang = _s(bundle, "language") or "en"
    unit = _s(bundle, "unit") or _s(bundle, "case_id")
    title = "Habitability evidence packet"
    if unit:
        title = f"{title} — unit {unit}"
    appendix = _map(bundle, "appendix")
    template = _map(bundle, "template")
    items_by_issue = _items_by_issue(bundle)
    trust = packet_trust_text(lang)
    timestamp_summary = trust.timestamp_summary.format(
        attached=_i(appendix, "timestamped_count"), total=_i(appendix, "item_count")
    )

    parts: list[str] = [
        "<!doctype html>",
        f'<html lang="{escape(lang)}">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>{escape(title)}</title>",
        f"<style>{_STYLE}</style>",
        "</head>",
        "<body>",
        '<a class="skip" href="#main">Skip to content</a>',
        "<header><h1>" + escape(title) + "</h1>",
        f'<p class="meta">Generated {escape(_s(bundle, "generated_at"))} · '
        f"{escape(timestamp_summary)} "
        f"· producer {escape(_s(bundle, 'producer_fingerprint'))}</p>",
    ]
    if _s(template, "header"):
        parts.append(f'<p class="meta">{escape(_s(template, "header"))}</p>')
    parts.append(f'<p class="warning">{escape(trust.view_notice)}</p>')
    parts.append("</header>")
    parts.append('<main id="main">')
    item_count = _i(appendix, "item_count")
    awaiting = item_count - _i(appendix, "timestamped_count")
    parts.extend(_cover_section(cover_sheet(bundle)))
    parts.extend(_proof_section(lang))
    parts.extend(_scope_section(lang, _map(bundle, "scope")))
    parts.extend(
        _disclosure_section(
            lang,
            _bool(appendix, "includes_originals"),
            metadata_may_be_retained=shared_metadata_may_be_retained(_list(bundle, "disclosures")),
            awaiting=awaiting,
            total=item_count,
        )
    )
    parts.extend(_chronology_section(chronology(bundle), lang))

    for issue in _list(bundle, "issues"):
        if isinstance(issue, dict):
            parts.extend(_issue_section(issue, bundle, items_by_issue, trust))

    parts.extend(_integrity_section(integrity_summary(bundle)))

    parts.append("<h2>Evidence appendix</h2>")
    parts.append(f"<p>{escape(trust.appendix_intro)}</p>")
    parts.append(_appendix_table(bundle, trust))
    parts.append("</main>")

    footer = "habitable — local-first, end-to-end-encrypted habitability evidence."
    if _s(template, "footer"):
        footer = _s(template, "footer")
    parts.append(f"<footer><p>{escape(footer)}</p></footer>")
    parts.append("</body></html>")

    out_path.write_text("\n".join(parts), encoding="utf-8")


def _cover_section(cover: CoverSheet) -> list[str]:
    """The cover-sheet facts as an accessible description list."""
    span = (
        f"{cover.earliest} to {cover.latest}"
        if cover.earliest and cover.latest
        else (cover.earliest or cover.latest or "—")
    )
    facts = [
        ("Case", cover.case_id or "—"),
        ("Unit", cover.unit or "—"),
        ("Covers", cover.scope),
        ("Generated", cover.generated_at or "—"),
        ("Producer device", cover.producer_fingerprint or "—"),
        ("Issues", str(cover.issue_count)),
        (
            "Media items",
            f"{cover.item_count} ({cover.timestamped_count} timestamp tokens attached; "
            "authority trust not assessed here)",
        ),
        ("Chain-of-custody entries", str(cover.custody_length)),
        ("Date range of evidence", span),
        ("Sealed originals embedded", "yes" if cover.includes_originals else "no"),
    ]
    out = [
        '<section aria-labelledby="cover-heading">',
        '<h2 id="cover-heading">Cover sheet</h2>',
        '<dl class="cover">',
    ]
    for label, value in facts:
        out.append(f"<dt>{escape(label)}</dt><dd>{escape(value)}</dd>")
    out.append("</dl>")
    out.append("</section>")
    return out


def _chronology_section(entries: tuple[ChronologyEntry, ...], lang: str) -> list[str]:
    """The unified, chronological evidence timeline (notes + photos)."""
    spanish = lang.lower().startswith("es")
    out = [
        '<section aria-labelledby="chronology-heading">',
        '<h2 id="chronology-heading">'
        + ("Cronología de la evidencia" if spanish else "Chronological evidence timeline")
        + "</h2>",
    ]
    if not entries:
        out.append(
            "<p>"
            + (
                "No hay eventos ni capturas registrados."
                if spanish
                else "No timeline events or captures recorded."
            )
            + "</p>"
        )
        out.append("</section>")
        return out
    out.append(
        "<p>La fecha de ocurrencia es la que informa la persona; la fecha de registro "
        "la agrega el dispositivo. Los eventos de la versión 3 están vinculados a la "
        "custodia. Las fotos aparecen cuando fueron capturadas.</p>"
        if spanish
        else "<p>Occurred is the date reported by the person; recorded is the separate "
        "device time when the entry was added. Version 3 events are custody-bound. "
        "Photos appear when captured.</p>"
    )
    out.append("<ol>")
    for entry in entries:
        when = escape(entry.when or ("sin fecha" if spanish else "undated"))
        when_label = escape(entry.when_label)
        label = escape(entry.label)
        issue = escape(entry.issue_title)
        text = escape(entry.text)
        detail = f' <span class="meta">({escape(entry.detail)})</span>' if entry.detail else ""
        out.append(
            f"<li><strong>{when_label}: {when}</strong> — "
            f'<span class="meta">[{label}] {issue}:</span> {text}{detail}</li>'
        )
    out.append("</ol>")
    out.append("</section>")
    return out


def _integrity_section(summary: IntegritySummary) -> list[str]:
    """The chain-of-custody / integrity summary: custody proof + per-item attestations."""
    out = [
        '<section aria-labelledby="integrity-heading">',
        '<h2 id="integrity-heading">Chain of custody &amp; integrity</h2>',
        f"<p>Hash algorithm {escape(summary.algorithm)} · {summary.custody_length} custody "
        f"entr{'y' if summary.custody_length == 1 else 'ies'} (append-only, hash-linked) · "
        f"{summary.timestamped_count}/{summary.item_count} items have timestamp tokens attached. "
        "This view does not validate token signatures or authority trust; use habitable verify "
        "with recipient-selected roots. The chain "
        "head below commits to the entire history; any insertion, deletion, or reordering changes "
        "it.</p>",
    ]
    if summary.custody_head:
        out.append(
            f'<p class="meta">Custody chain head: <code>{escape(summary.custody_head)}</code></p>'
        )
    out.append("<table>")
    out.append(
        "<caption>Per-item content hash, timestamp-token presence, named authority, "
        "and custody depth. Authority trust is not assessed here.</caption>"
    )
    out.append(
        "<thead><tr>"
        '<th scope="col">Capture</th>'
        '<th scope="col">Content hash (SHA-256)</th>'
        '<th scope="col">Timestamp authorities</th>'
        '<th scope="col">Custody</th>'
        "</tr></thead><tbody>"
    )
    for row in summary.rows:
        authorities = ", ".join(row.authorities) if row.authorities else "—"
        if row.archive_count:
            authorities = f"{authorities} · +{row.archive_count} archive"
        custody = f"{row.custody_entries} entr{'y' if row.custody_entries == 1 else 'ies'}"
        out.append(
            "<tr>"
            f"<td>{escape(row.capture_id)}</td>"
            f"<td>{escape(row.content_hash)}</td>"
            f"<td>{escape(row.timestamp_status)}: {escape(authorities)}</td>"
            f"<td>{escape(custody)}</td>"
            "</tr>"
        )
    out.append("</tbody></table>")
    out.append("</section>")
    return out


def render_inspector_html(bundle: Mapping[str, JSONValue], media_dir: Path, out_path: Path) -> None:
    """Write an accessible ``inspector.html`` organized room → condition → timeline.

    A recipient-oriented (inspector) view of the *same signed bundle* as
    ``packet.html``: issues are grouped by room, then by condition (issue
    category), and each issue shows one chronologically merged timeline that
    interleaves timeline notes and capture events. It reuses the packet's style,
    proof/disclosure sections, and evidence appendix; it never alters the bundle.
    """
    lang = _s(bundle, "language") or "en"
    unit = _s(bundle, "unit") or _s(bundle, "case_id")
    title = "Inspector rollup — habitability evidence"
    if unit:
        title = f"{title} — unit {unit}"
    appendix = _map(bundle, "appendix")
    template = _map(bundle, "template")
    trust = packet_trust_text(lang)
    timestamp_summary = trust.timestamp_summary.format(
        attached=_i(appendix, "timestamped_count"), total=_i(appendix, "item_count")
    )

    parts: list[str] = [
        "<!doctype html>",
        f'<html lang="{escape(lang)}">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>{escape(title)}</title>",
        f"<style>{_STYLE}</style>",
        "</head>",
        "<body>",
        '<a class="skip" href="#main">Skip to content</a>',
        "<header><h1>" + escape(title) + "</h1>",
        f'<p class="meta">Generated {escape(_s(bundle, "generated_at"))} · '
        f"{escape(timestamp_summary)} · producer "
        f"{escape(_s(bundle, 'producer_fingerprint'))}</p>",
        '<p class="meta">Organized by room, then condition, then a chronological '
        "timeline. This is a derived view of the signed bundle.json.</p>",
    ]
    if _s(template, "header"):
        parts.append(f'<p class="meta">{escape(_s(template, "header"))}</p>')
    parts.append(f'<p class="warning">{escape(trust.view_notice)}</p>')
    parts.append("</header>")
    parts.append('<main id="main">')
    parts.extend(_proof_section(lang))
    parts.extend(_disclosure_section(lang, _bool(appendix, "includes_originals")))
    parts.extend(_inspector_rollup(bundle))

    parts.append("<h2>Evidence appendix</h2>")
    parts.append(f"<p>{escape(trust.appendix_intro)}</p>")
    parts.append(_appendix_table(bundle, trust))
    parts.append("</main>")

    footer = "habitable — local-first, end-to-end-encrypted habitability evidence."
    if _s(template, "footer"):
        footer = _s(template, "footer")
    parts.append(f"<footer><p>{escape(footer)}</p></footer>")
    parts.append("</body></html>")

    out_path.write_text("\n".join(parts), encoding="utf-8")


def _inspector_rollup(bundle: Mapping[str, JSONValue]) -> list[str]:
    """Group issues by room → condition (category); one merged timeline per issue."""
    events_by_issue: dict[str, list[ChronologyEntry]] = {}
    for entry in chronology(bundle):
        events_by_issue.setdefault(entry.issue_id, []).append(entry)

    rooms: dict[str, list[Mapping[str, JSONValue]]] = {}
    for raw_issue in _list(bundle, "issues"):
        if isinstance(raw_issue, dict):
            room = _s(raw_issue, "room") or "Unspecified room"
            rooms.setdefault(room, []).append(raw_issue)

    out: list[str] = []
    for room_index, room in enumerate(sorted(rooms)):
        room_id = f"room-{room_index}"
        out.append(f'<section aria-labelledby="{room_id}">')
        out.append(f'<h2 id="{room_id}">Room: {escape(room)}</h2>')
        conditions: dict[str, list[Mapping[str, JSONValue]]] = {}
        for room_issue in rooms[room]:
            condition = _s(room_issue, "category") or "Uncategorized"
            conditions.setdefault(condition, []).append(room_issue)
        for condition in sorted(conditions):
            out.append(f"<h3>Condition: {escape(condition)}</h3>")
            for condition_issue in conditions[condition]:
                out.extend(_inspector_issue(condition_issue, events_by_issue))
        out.append("</section>")
    return out


def _inspector_issue(
    issue: Mapping[str, JSONValue],
    events_by_issue: dict[str, list[ChronologyEntry]],
) -> list[str]:
    issue_id = _s(issue, "issue_id")
    label = _s(issue, "title") or _s(issue, "category") or issue_id
    out = [
        f'<p class="meta">{escape(label)} — status '
        f"{escape(_s(issue, 'status') or '—')}, "
        f"severity {escape(_s(issue, 'severity') or '—')}</p>",
    ]
    if _s(issue, "description"):
        out.append(f"<p>{escape(_s(issue, 'description'))}</p>")

    events = events_by_issue.get(issue_id, [])
    if not events:
        out.append("<p>No timeline entries or captures recorded.</p>")
        return out
    out.append("<ol>")
    for event in events:
        when = escape(event.when or "undated")
        stamp = f'<time datetime="{escape(event.when)}">{when}</time>'
        detail = f' <span class="meta">({escape(event.detail)})</span>' if event.detail else ""
        out.append(
            f"<li><strong>{escape(event.when_label)}:</strong> {stamp} — "
            f"<strong>{escape(event.label)}:</strong> {escape(event.text)}{detail}</li>"
        )
    out.append("</ol>")
    return out


def _proof_section(lang: str) -> list[str]:
    """The plain-language 'what this proves / what it does not' block, up front."""
    stmt = proof_statement(lang)
    out = [
        '<section aria-labelledby="proves-heading">',
        f'<h2 id="proves-heading">{escape(stmt.heading)}</h2>',
        f"<h3>{escape(stmt.proves_heading)}</h3>",
        "<ul>",
        *(f"<li>{escape(line)}</li>" for line in stmt.proves),
        "</ul>",
        f"<h3>{escape(stmt.not_heading)}</h3>",
        "<ul>",
        *(f"<li>{escape(line)}</li>" for line in stmt.not_proves),
        "</ul>",
        f"<p>{escape(stmt.verify_line)}</p>",
        "</section>",
    ]
    return out


def _scope_section(lang: str, scope: Mapping[str, JSONValue]) -> list[str]:
    """The minimal-disclosure scope block: what this export covers and omits (R-35)."""
    stmt = scope_statement(
        lang,
        scope_type=_s(scope, "type"),
        issue_id=_s(scope, "issue_id"),
        since=_s(scope, "since"),
    )
    return [
        '<section aria-labelledby="scope-heading">',
        f'<h2 id="scope-heading">{escape(stmt.heading)}</h2>',
        f"<p>{escape(stmt.statement)}</p>",
        "<ul>",
        *(f"<li>{escape(line)}</li>" for line in stmt.exclusions),
        "</ul>",
        "</section>",
    ]


def _disclosure_section(
    lang: str,
    includes_originals: bool,
    *,
    metadata_may_be_retained: bool = False,
    awaiting: int = 0,
    total: int = 0,
) -> list[str]:
    """A short, localized note of what the packet reveals."""
    stmt = proof_statement(lang)
    notes = [stmt.privacy_metadata_warning if metadata_may_be_retained else stmt.privacy_stripped]
    if includes_originals:
        notes.append(stmt.privacy_originals_warning)
    if awaiting > 0:
        notes.append(stmt.awaiting_timestamp_note.format(awaiting=awaiting, total=total))
    return [
        '<section aria-labelledby="discloses-heading">',
        f'<h2 id="discloses-heading">{escape(stmt.privacy_heading)}</h2>',
        "<ul>",
        *(f"<li>{escape(note)}</li>" for note in notes),
        "</ul>",
        "</section>",
    ]


def _issue_section(
    issue: Mapping[str, JSONValue],
    bundle: Mapping[str, JSONValue],
    items_by_issue: dict[str, list[Mapping[str, JSONValue]]],
    trust: PacketTrustText,
) -> list[str]:
    issue_id = _s(issue, "issue_id")
    heading = _s(issue, "title") or _s(issue, "category") or issue_id
    out = [
        "<section>",
        f"<h2>Issue: {escape(heading)}</h2>",
        f'<p class="meta">Category: {escape(_s(issue, "category") or "—")} · '
        f"Room: {escape(_s(issue, 'room') or '—')} · "
        f"Severity: {escape(_s(issue, 'severity') or '—')} · "
        f"Status: {escape(_s(issue, 'status') or '—')}</p>",
    ]
    if _s(issue, "description"):
        out.append(f"<p>{escape(_s(issue, 'description'))}</p>")

    timeline = [
        entry
        for entry in chronology(bundle)
        if entry.issue_id == issue_id and entry.kind in {"event", "note"}
    ]
    if timeline:
        out.append("<h3>Timeline</h3><ul>")
        out += [
            f"<li><strong>{escape(entry.when_label)}: "
            f"{escape(entry.when or 'undated')} · {escape(entry.label)}:</strong> "
            f"{escape(entry.text)}"
            + (f' <span class="meta">({escape(entry.detail)})</span>' if entry.detail else "")
            + "</li>"
            for entry in timeline
        ]
        out.append("</ul>")

    items = items_by_issue.get(issue_id, [])
    if items:
        out.append("<h3>Captured evidence</h3>")
        for item in items:
            if item.get("sensor") is not None:
                out.append(_sensor_figure(item, trust))
            else:
                out.extend(_evidence_figure(item, trust))
    relationships = [
        relationship
        for relationship in _list(bundle, "relationships")
        if isinstance(relationship, dict) and _s(relationship, "issue_id") == issue_id
    ]
    if relationships:
        out.append("<h3>Evidence relationships</h3>")
        out.append(
            '<table><thead><tr><th scope="col">Relationship</th>'
            '<th scope="col">Source record</th><th scope="col">Target record</th>'
            '<th scope="col">Assertion</th></tr></thead><tbody>'
        )
        for relationship in relationships:
            out.append(
                "<tr>"
                f"<td>{escape(_s(relationship, 'relationship_type').replace('_', ' '))}</td>"
                f"<td><code>{escape(_s(relationship, 'source_id'))}</code></td>"
                f"<td><code>{escape(_s(relationship, 'target_id'))}</code></td>"
                f"<td>{escape(_s(relationship, 'assertion') or '—')}</td>"
                "</tr>"
            )
        out.append("</tbody></table>")
    out.append("</section>")
    return out


def _evidence_figure(item: Mapping[str, JSONValue], trust: PacketTrustText) -> list[str]:
    """Render one evidence item: a photo inline, or -- for video/audio (EXP-07) --
    a poster frame and/or transcript plus a link to the shared media file. Video
    and audio are never embedded as playable <video>/<audio> elements here: doing
    so accessibly requires caption/track markup this packet cannot yet author, so
    the honest accessible fallback is a still poster frame with real alt text and
    a plain-text transcript, exactly the excellence bar EXP-07 sets."""
    media_type = _s(item, "media_type")
    shared = _s(item, "shared_name")
    poster = _s(item, "poster_name")
    transcript = _s(item, "transcript")
    stamp = _timestamp_status(item.get("timestamp"), trust)
    content_hash = _s(item, "content_hash")
    captured_at = _s(item, "captured_at")
    is_video = media_type.startswith("video/")
    is_audio = media_type.startswith("audio/")
    is_artifact = _s(item, "record_kind") == "artifact"

    out = ["<figure>"]
    if is_artifact and not media_type.startswith("image/"):
        artifact = _map(item, "artifact")
        out.append(
            f"<p><strong>{escape(_s(artifact, 'title') or 'Supporting document')}</strong> · "
            f"{escape(_s(artifact, 'artifact_type').replace('_', ' '))}</p>"
        )
        out.append(
            f'<p class="meta">Source assertion: {escape(_s(artifact, "source") or "—")} · '
            f"Issuer assertion: {escape(_s(artifact, 'issuer') or '—')}</p>"
        )
        if transcript:
            out.append(f"<p>{escape(transcript)}</p>")
        if shared:
            out.append(
                f'<p><a href="media/{escape(shared)}">Download supporting document '
                "(verify its hash against bundle.json before opening)</a></p>"
            )
    elif is_video or is_audio:
        kind = "video" if is_video else "audio"
        if poster:
            alt = (
                f"Poster frame from evidence {kind} for this issue, captured {captured_at}, "
                f"content hash {content_hash[:12]}, {stamp}."
            )
            out.append(f'<img src="media/{escape(poster)}" alt="{escape(alt)}">')
        if transcript:
            out.append(
                f"<details><summary>Transcript</summary><p>{escape(transcript)}</p></details>"
            )
        elif not poster:
            out.append(
                '<p class="warning">No transcript or poster frame was recorded for this '
                f"{escape(kind)} — it does not yet meet the accessibility bar.</p>"
            )
        if shared:
            out.append(
                f'<p><a href="media/{escape(shared)}">Download the {escape(kind)} '
                "(verify its hash against bundle.json before playing)</a></p>"
            )
    elif shared:
        alt = (
            f"Evidence photo for this issue, captured {captured_at}, "
            f"content hash {content_hash[:12]}, {stamp}."
        )
        out.append(f'<img src="media/{escape(shared)}" alt="{escape(alt)}">')
    out.append(
        f"<figcaption>Captured {escape(captured_at)} · "
        f"hash {escape(content_hash[:16])}… · {escape(stamp)}</figcaption>"
    )
    out.append("</figure>")
    return out


def _photo_figure(item: Mapping[str, JSONValue], trust: PacketTrustText | None = None) -> str:
    """Legacy photo-only renderer retained for embedders; token trust is never assumed."""
    trust = trust or packet_trust_text("en")
    shared = _s(item, "shared_name")
    stamp = _timestamp_status(item.get("timestamp"), trust)
    content_hash = _s(item, "content_hash")
    alt = (
        f"Evidence photo for this issue, captured {_s(item, 'captured_at')}, "
        f"content hash {content_hash[:12]}, {stamp}."
    )
    out = ["<figure>"]
    if shared:
        out.append(f'<img src="media/{escape(shared)}" alt="{escape(alt)}">')
    out.append(
        f"<figcaption>Captured {escape(_s(item, 'captured_at'))} · "
        f"hash {escape(content_hash[:16])}… · {escape(stamp)}</figcaption>"
    )
    out.append("</figure>")
    return "".join(out)


def _sensor_figure(item: Mapping[str, JSONValue], trust: PacketTrustText | None = None) -> str:
    """Render an instrument CSV capture (EXP-09): a small line chart plus its
    accessible text equivalent — a summary sentence and the full readings table.

    The chart is marked ``aria-hidden``: it is a visual convenience over data that
    is already fully present, in reading order, as text and a table right below
    it — so a screen-reader user loses nothing by skipping the SVG.
    """
    trust = trust or packet_trust_text("en")
    sensor = _map(item, "sensor")
    stamp = _timestamp_status(item.get("timestamp"), trust)
    content_hash = _s(item, "content_hash")
    label_header = _s(sensor, "label_header") or "Reading"
    value_header = _s(sensor, "value_header") or "Value"
    unit = _s(sensor, "unit")
    unit_suffix = f" {unit}" if unit else ""
    readings = [r for r in _list(sensor, "readings") if isinstance(r, dict)]
    minimum, maximum, mean = _f(sensor, "minimum"), _f(sensor, "maximum"), _f(sensor, "mean")
    total_rows = _i(sensor, "total_rows")

    summary = (
        f"Instrument data ({value_header}): {total_rows} reading(s), "
        f"ranging {minimum:g}{unit_suffix} to {maximum:g}{unit_suffix}, "
        f"averaging {mean:g}{unit_suffix}."
    )

    out = ['<figure class="sensor-evidence">']
    chart = _sensor_chart_svg(readings, minimum, maximum)
    if chart:
        out.append(chart)
    out.append(
        f"<figcaption>{escape(summary)} Captured {escape(_s(item, 'captured_at'))} · "
        f"hash {escape(content_hash[:16])}… · {escape(stamp)}</figcaption>"
    )
    out.append('<details class="sensor-readings">')
    out.append(f"<summary>Show all {len(readings)} reading(s)</summary>")
    out.append("<table>")
    out.append(
        "<caption>Instrument readings for this capture "
        "(independent corroboration, verify against bundle.json).</caption>"
    )
    out.append(
        "<thead><tr>"
        f'<th scope="col">{escape(label_header)}</th>'
        f'<th scope="col">{escape(value_header)}{escape(f" ({unit})" if unit else "")}</th>'
        "</tr></thead><tbody>"
    )
    for reading in readings:
        out.append(
            f"<tr><td>{escape(_s(reading, 'label'))}</td><td>{_fmt(_f(reading, 'value'))}</td></tr>"
        )
    out.append("</tbody></table>")
    for warning in _list(sensor, "warnings"):
        if isinstance(warning, str):
            out.append(f"<p><em>{escape(warning)}</em></p>")
    out.append("</details></figure>")
    return "".join(out)


def _sensor_chart_svg(
    readings: Sequence[Mapping[str, JSONValue]], minimum: float, maximum: float
) -> str:
    n = len(readings)
    if n < 2:
        return ""
    width, height, pad = 480, 140, 24
    span = (maximum - minimum) or 1.0
    step = (width - 2 * pad) / (n - 1)

    def y_of(value: float) -> float:
        return pad + (maximum - value) / span * (height - 2 * pad)

    points = " ".join(
        f"{pad + i * step:.1f},{y_of(_f(r, 'value')):.1f}" for i, r in enumerate(readings)
    )
    circles = "".join(
        f'<circle class="point" cx="{pad + i * step:.1f}" cy="{y_of(_f(r, "value")):.1f}" r="2.5"/>'
        for i, r in enumerate(readings)
        if n <= 60  # avoid clutter on long series
    )
    baseline_y = height - pad
    return (
        f'<svg class="sensor-chart" viewBox="0 0 {width} {height}" '
        f'aria-hidden="true" focusable="false">'
        f'<line class="axis" x1="{pad}" y1="{baseline_y}" x2="{width - pad}" y2="{baseline_y}"/>'
        f'<polyline class="line" points="{points}"/>'
        f"{circles}"
        "</svg>"
    )


def _appendix_table(bundle: Mapping[str, JSONValue], trust: PacketTrustText) -> str:
    rows = [
        "<table>",
        f"<caption>{escape(trust.appendix_caption)}</caption>",
        "<thead><tr>"
        '<th scope="col">Capture</th>'
        '<th scope="col">Content hash (SHA-256)</th>'
        f'<th scope="col">{escape(trust.timestamp_heading)}</th>'
        f'<th scope="col">{escape(trust.authority_heading)}</th>'
        "</tr></thead>",
        "<tbody>",
    ]
    for item in _list(bundle, "items"):
        if not isinstance(item, dict):
            continue
        token = item.get("timestamp")
        status = _timestamp_status(token, trust)
        authority = _s(token, "tsa_name") if isinstance(token, dict) else "—"
        rows.append(
            "<tr>"
            f"<td>{escape(_s(item, 'capture_id'))}</td>"
            f"<td>{escape(_s(item, 'content_hash'))}</td>"
            f"<td>{escape(status)}</td>"
            f"<td>{escape(authority)}</td>"
            "</tr>"
        )
    rows.append("</tbody></table>")
    return "".join(rows)


def _timestamp_status(token: JSONValue | None, trust: PacketTrustText) -> str:
    """Describe token presence honestly; rendering does not perform verification."""
    if not isinstance(token, dict):
        return trust.awaiting
    return trust.dev_untrusted if _s(token, "kind") == "dev" else trust.attached_unassessed


def _items_by_issue(bundle: Mapping[str, JSONValue]) -> dict[str, list[Mapping[str, JSONValue]]]:
    grouped: dict[str, list[Mapping[str, JSONValue]]] = {}
    for item in _list(bundle, "items"):
        if isinstance(item, dict):
            grouped.setdefault(_s(item, "issue_id"), []).append(item)
    return grouped


def _s(mapping: Mapping[str, JSONValue], key: str) -> str:
    value = mapping.get(key)
    return value if isinstance(value, str) else ""


def _i(mapping: Mapping[str, JSONValue], key: str) -> int:
    value = mapping.get(key)
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _f(mapping: Mapping[str, JSONValue], key: str) -> float:
    value = mapping.get(key)
    if isinstance(value, bool):
        return 0.0
    return float(value) if isinstance(value, (int, float)) else 0.0


def _fmt(value: float) -> str:
    return f"{value:g}"


def _bool(mapping: Mapping[str, JSONValue], key: str) -> bool:
    return mapping.get(key) is True


def _list(mapping: Mapping[str, JSONValue], key: str) -> list[JSONValue]:
    value = mapping.get(key)
    return value if isinstance(value, list) else []


def _map(mapping: Mapping[str, JSONValue], key: str) -> Mapping[str, JSONValue]:
    value = mapping.get(key)
    return value if isinstance(value, dict) else {}
