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

#: A packet is a record about somebody's home: rooms, dates, photographs, and
#: the conditions they are living in. Wherever one is put -- a review host, a
#: shared folder behind a web server, the sample published on this project's own
#: GitHub Pages site -- it should not be for a search engine to collect. A
#: `noindex` cannot stop a determined crawler, and it does not pretend to; what
#: it does is stop the ordinary, well-behaved ones, which is the difference
#: between a packet being findable by name and being findable at all.
_ROBOTS = '<meta name="robots" content="noindex, nofollow">'

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
.notice { border: 2px solid #1f4e5f; background: #eaf2f5; color: #12333d;
  padding: .6rem .8rem; border-radius: 6px; }
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

#: Locale text for the workflow-profile block (issue #277).
#:
#: These are *rendering labels*, not signed claims, which is why they live here
#: rather than in ``disclosure.py``: that module holds the proof/scope/privacy
#: wording shared with ``packet.pdf``, and this section exists only in the HTML
#: views. ``_chronology_section`` already carries its own EN/ES text in this
#: module for the same reason. ``scripts/check_i18n_parity.py`` guards
#: ``app/i18n/*.json`` -- the browser app's bundle -- and never reads the packet
#: renderer, so parity here is held instead by
#: ``test_profile_locale_text_is_at_parity`` in ``tests/test_htmlpacket.py``:
#: same keys in both maps, no empty value, same ``{placeholders}`` per key.
#:
#: The *disclosure sentences themselves* are not here: they are English-only
#: strings carried inside the signed bundle (``usecases.UseCaseProfile``), and
#: this renderer must not translate, paraphrase, or reorder a signed claim. They
#: are emitted verbatim and marked ``lang="en"`` when the surrounding document is
#: not English, so a screen reader announces them in the language they are
#: actually written in (WCAG 2.2 3.1.2, Language of Parts).
_PROFILE_TEXT: dict[str, dict[str, str]] = {
    "en": {
        "heading": "Workflow profile",
        "intro": (
            "This packet was assembled under a workflow profile. A profile selects "
            "prompts, vocabulary, and the order a recipient is expected to read in. "
            "It is presentation policy only: it changes no hash, no timestamp, no "
            "custody entry, and no verifier verdict."
        ),
        "external_lead": "External review required.",
        "external": (
            "This workflow is implemented for synthetic evaluation. It is not a "
            "legal, medical, inspector, or accessibility approval, and shipping it "
            "is not a claim that it is fit for a real matter."
        ),
        "maintainer": (
            "Reviewed by the project maintainers. Maintainer review is not legal, "
            "medical, inspector, or accessibility review."
        ),
        "reviewer": "Reviewed by {reviewer}.",
        "reviewer_dated": "Reviewed by {reviewer} on {reviewed_at}.",
        "state": "Recorded review state: {review_state}.",
        "limits_heading": "What this profile does not establish",
        "fallback": (
            "The workflow profile requested for this export ({profile_id}) had passed "
            "its review date ({expires_at}), so this packet carries no workflow "
            "profile and none of that profile's guidance."
        ),
        "fallback_undated": (
            "The workflow profile requested for this export ({profile_id}) had passed "
            "its review date, so this packet carries no workflow profile and none of "
            "that profile's guidance."
        ),
    },
    "es": {
        "heading": "Perfil de flujo de trabajo",
        "intro": (
            "Este paquete se preparó con un perfil de flujo de trabajo. Un perfil "
            "elige indicaciones, vocabulario y el orden de lectura que se espera de "
            "quien lo recibe. Es solo política de presentación: no cambia ningún "
            "hash, marca de tiempo, registro de custodia ni veredicto de verificación."
        ),
        "external_lead": "Se requiere revisión externa.",
        "external": (
            "Este flujo de trabajo está implementado para evaluación sintética. No "
            "es una aprobación legal, médica, de inspección ni de accesibilidad, y "
            "publicarlo no afirma que sirva para un asunto real."
        ),
        "maintainer": (
            "Revisado por el equipo del proyecto. La revisión del equipo no es "
            "revisión legal, médica, de inspección ni de accesibilidad."
        ),
        "reviewer": "Revisado por {reviewer}.",
        "reviewer_dated": "Revisado por {reviewer} el {reviewed_at}.",
        "state": "Estado de revisión registrado: {review_state}.",
        "limits_heading": "Lo que este perfil no establece",
        "fallback": (
            "El perfil de flujo de trabajo solicitado para esta exportación "
            "({profile_id}) superó su fecha de revisión ({expires_at}), por lo que "
            "este paquete no lleva ningún perfil ni su orientación."
        ),
        "fallback_undated": (
            "El perfil de flujo de trabajo solicitado para esta exportación "
            "({profile_id}) superó su fecha de revisión, por lo que este paquete no "
            "lleva ningún perfil ni su orientación."
        ),
    },
}


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
        _ROBOTS,
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
    # Directly after the cover sheet: the profile is part of *what this packet
    # is*, and its review state has to be read before, not after, the claims the
    # rest of the page makes (issue #277).
    parts.extend(_profile_section(lang, bundle))
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
        _ROBOTS,
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
    # An inspector rollup is handed to a recipient on its own at least as often
    # as ``packet.html`` is, so it carries the same profile block (issue #277).
    parts.extend(_profile_section(lang, bundle))
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


def _profile_text(lang: str) -> dict[str, str]:
    """Return the workflow-profile labels for ``lang``, falling back to English.

    Matches ``_chronology_section``'s ``startswith("es")`` rule rather than
    inventing a second locale-resolution scheme in one module. Any language the
    packet does not ship gets English, which is the same fallback
    ``disclosure._resolve_lang`` applies to the signed proof and scope text.
    """
    return _PROFILE_TEXT["es" if lang.lower().startswith("es") else "en"]


def _profile_section(lang: str, bundle: Mapping[str, JSONValue]) -> list[str]:
    """The selected workflow profile, its review state, and its disclosures.

    Issue #277: before this existed, ``grep -ci profile htmlpacket.py`` returned
    zero. A profile's disclosures -- "This profile is not an inspector finding or
    code determination", "Technical integrity does not establish disability,
    entitlement, receipt, or compliance" -- and its ``external_review_required``
    warning reached a recipient only through ``handoff-<id>.html`` and
    ``bundle.json``. That is backwards: the disclosures exist so a recipient does
    not over-read the document, and the recipient most likely to over-read it is
    the one who was handed the packet and nothing else.

    **Why this does not contradict the ADR 0011 seal precedent.** ADR 0011 says
    ``packet.html`` and ``packet.pdf`` "cannot show the seal", and that the seal
    "is not mentioned in ``bundle.json``'s ``disclosures``. It deliberately
    cannot be: a disclosure lives inside the bundle, so an attacker could add a
    reassuring line to an unsealed forgery or delete an accurate one." Both
    sentences turn on *where the seal lives*: the seal is a statement about the
    bundle, made from outside it, in ``bundle.sig.json``, which the bundle cannot
    authenticate. A profile is the opposite on every axis that argument uses. It
    is bundle *content* (``use_case_profile``), so it is covered by the producer
    signature and, when a packet is sealed, by ``bundle_sha256`` and therefore by
    the seal itself; ``verify._verify_v4_profile_and_handoffs`` already refuses a
    handoff view that "suppresses required disclosures"; and its failure
    direction is inverted -- a stripped seal claim leaves a reader *more*
    reassured than the evidence warrants, while a stripped disclosure leaves them
    with a limit removed, which is exactly what a signature and a seal are for.
    Rendering it is the same act as rendering the narrative, the item list, or
    the existing privacy disclosures, all of which this file already reads
    straight out of the bundle. ADR 0010 decision 5 points the same way: a
    presentation layer "cannot suppress disclosures".

    Nothing here is a format change. Every value is read from fields
    ``packet.py`` already writes; no field is added, renamed, or reinterpreted.
    In particular ``review_state`` is *displayed*, never mapped: the two states
    the verifier accepts today get their own sentence, and any other value is
    printed verbatim rather than silently treated as one of them, so a future
    vocabulary change (issue #277 finding 4, a packet-visible format decision
    this renderer has no standing to make) shows up here as an honest unfamiliar
    word instead of a wrong familiar one.

    A packet with no profile and no expiry fallback renders nothing at all -- no
    heading, no placeholder -- so every packet exported without the workflow
    machinery renders exactly as it did before, ``site/sample-packet/packet.html``
    included (verified byte-for-byte; it carries ``use_case_profile: null``).
    The ``tests/golden/`` corpus pins signed *bundle* bytes and ships no rendered
    HTML, so it is untouched either way, and packets from before profiles existed
    simply have no such key to read.
    """
    text = _profile_text(lang)
    profile = _map(bundle, "use_case_profile")
    fallback = _map(bundle, "use_case_profile_fallback")
    if not profile and not fallback:
        return []

    out = [
        '<section aria-labelledby="profile-heading">',
        f'<h2 id="profile-heading">{escape(text["heading"])}</h2>',
    ]
    if not profile:
        out.append(f'<p class="warning">{escape(_fallback_sentence(text, fallback))}</p>')
        out.append("</section>")
        return out

    spanish = lang.lower().startswith("es")
    locale = "es" if spanish else "en"
    names = _map(profile, "name")
    summaries = _map(profile, "summary")
    name = _s(names, locale) or _s(names, "en") or _s(profile, "profile_id")
    summary = _s(summaries, locale) or _s(summaries, "en")
    # A hand-crafted or future bundle can carry a profile object with no name and
    # no summary; emit no paragraph at all rather than an empty ``<strong>``.
    if name or summary:
        tail = f" — {escape(summary)}" if summary and name else escape(summary)
        out.append(f"<p><strong>{escape(name)}</strong>{tail}</p>" if name else f"<p>{tail}</p>")
    out.append(f"<p>{escape(text['intro'])}</p>")
    out.extend(_profile_review_state(text, profile))

    # Emitted verbatim and in order: these are signed strings, so the renderer
    # neither translates nor rewords them. ``lang`` marks them as English inside a
    # non-English document rather than letting a screen reader read English with
    # Spanish phonemes.
    disclosures = [value for value in _list(profile, "disclosures") if isinstance(value, str)]
    if disclosures:
        item_lang = ' lang="en"' if spanish else ""
        out.append(f"<h3>{escape(text['limits_heading'])}</h3>")
        out.append("<ul>")
        out.extend(f"<li{item_lang}>{escape(value)}</li>" for value in disclosures)
        out.append("</ul>")
    out.append("</section>")
    return out


def _profile_review_state(text: Mapping[str, str], profile: Mapping[str, JSONValue]) -> list[str]:
    """One sentence naming how far this profile has actually been reviewed.

    ``external_review_required`` is the warning, because it is the state that
    tells a recipient the workflow has had no lawyer, clinician, inspector, or
    accessibility reviewer look at it. ``maintainer_reviewed`` still gets a
    visible note rather than silence: "reviewed" without saying *by whom* is the
    reading this project most needs to prevent. Any third value is shown as
    itself; see ``_profile_section``.
    """
    review = _map(profile, "review")
    reviewer = _s(review, "reviewer")
    reviewed_at = _s(review, "reviewed_at")
    state = _s(profile, "review_state")
    if profile.get("external_review_required") is True or state == "external_review_required":
        return [
            '<p class="warning"><strong>'
            + escape(text["external_lead"])
            + "</strong> "
            + escape(text["external"])
            + "</p>"
        ]
    if state == "maintainer_reviewed":
        note = text["maintainer"]
    else:
        note = text["state"].format(review_state=state or "—")
    if reviewer:
        key = "reviewer_dated" if reviewed_at else "reviewer"
        note = f"{note} {text[key].format(reviewer=reviewer, reviewed_at=reviewed_at)}"
    return [f'<p class="notice">{escape(note)}</p>']


def _fallback_sentence(text: Mapping[str, str], fallback: Mapping[str, JSONValue]) -> str:
    """Say that an expired profile was dropped from this export (ADR 0012).

    ``packet.py`` already records this in the bundle's signed ``disclosures``
    array, but ``packet.html`` renders that array only to decide which privacy
    sentence to print, so the reader was never told. Without it the packet is
    silently indistinguishable from one exported with no profile chosen at all.
    """
    profile_id = _s(fallback, "requested_profile_id") or "—"
    expires_at = _s(fallback, "expires_at")
    key = "fallback" if expires_at else "fallback_undated"
    return text[key].format(profile_id=profile_id, expires_at=expires_at)


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
    a plain-text transcript, exactly the excellence bar EXP-07 sets.

    issue #158 (decision 3): if none of the above produces an inline image, a
    poster frame, or a download link, this item carries no rendered evidence
    bytes. That state must never look the same as an intact one -- it renders a
    visible notice (an embedded original still exists to download) or a visible
    warning (nothing at all was included), never a silently empty figure.
    """
    media_type = _s(item, "media_type")
    shared = _s(item, "shared_name")
    stamp = _timestamp_status(item.get("timestamp"), trust)
    content_hash = _s(item, "content_hash")
    captured_at = _s(item, "captured_at")
    is_video = media_type.startswith("video/")
    is_audio = media_type.startswith("audio/")
    is_artifact = _s(item, "record_kind") == "artifact"

    out = ["<figure>"]
    if is_artifact and not media_type.startswith("image/"):
        body, rendered_evidence_bytes = _document_artifact_body(item)
    elif is_video or is_audio:
        body, rendered_evidence_bytes = _video_audio_body(item, stamp, captured_at, content_hash)
    elif shared:
        alt = (
            f"Evidence photo for this issue, captured {captured_at}, "
            f"content hash {content_hash[:12]}, {stamp}."
        )
        body = [f'<img src="media/{escape(shared)}" alt="{escape(alt)}">']
        rendered_evidence_bytes = True
    else:
        body, rendered_evidence_bytes = [], False
    out.extend(body)

    if not rendered_evidence_bytes:
        out.append(_no_evidence_bytes_notice(item))
    out.append(
        f"<figcaption>Captured {escape(captured_at)} · "
        f"hash {escape(content_hash[:16])}… · {escape(stamp)}</figcaption>"
    )
    out.append("</figure>")
    return out


def _document_artifact_body(item: Mapping[str, JSONValue]) -> tuple[list[str], bool]:
    """The body of a non-image artifact's figure (a repair request, receipt,
    etc.): title, source/issuer assertions, transcript, and a download link
    for its shared copy. Returns whether a real download link was rendered."""
    shared = _s(item, "shared_name")
    transcript = _s(item, "transcript")
    artifact = _map(item, "artifact")
    out = [
        f"<p><strong>{escape(_s(artifact, 'title') or 'Supporting document')}</strong> · "
        f"{escape(_s(artifact, 'artifact_type').replace('_', ' '))}</p>",
        f'<p class="meta">Source assertion: {escape(_s(artifact, "source") or "—")} · '
        f"Issuer assertion: {escape(_s(artifact, 'issuer') or '—')}</p>",
    ]
    if transcript:
        out.append(f"<p>{escape(transcript)}</p>")
    if not shared:
        return out, False
    out.append(
        f'<p><a href="media/{escape(shared)}">Download supporting document '
        "(verify its hash against bundle.json before opening)</a></p>"
    )
    return out, True


def _video_audio_body(
    item: Mapping[str, JSONValue], stamp: str, captured_at: str, content_hash: str
) -> tuple[list[str], bool]:
    """The body of a video/audio figure: poster frame and/or transcript (EXP-07's
    accessible fallback -- never a playable element), plus a download link for
    the shared file. Returns whether a poster frame or download link -- real
    evidence bytes, as opposed to just a transcript -- was rendered."""
    poster = _s(item, "poster_name")
    shared = _s(item, "shared_name")
    transcript = _s(item, "transcript")
    kind = "video" if _s(item, "media_type").startswith("video/") else "audio"
    out: list[str] = []
    rendered_evidence_bytes = False
    if poster:
        alt = (
            f"Poster frame from evidence {kind} for this issue, captured {captured_at}, "
            f"content hash {content_hash[:12]}, {stamp}."
        )
        out.append(f'<img src="media/{escape(poster)}" alt="{escape(alt)}">')
        rendered_evidence_bytes = True
    if transcript:
        out.append(f"<details><summary>Transcript</summary><p>{escape(transcript)}</p></details>")
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
        rendered_evidence_bytes = True
    return out, rendered_evidence_bytes


def _no_evidence_bytes_notice(item: Mapping[str, JSONValue]) -> str:
    """The visible fallback for an item with no rendered evidence bytes (issue
    #158, decision 3): a link to the embedded original if one exists, else a
    plain warning that nothing was included at all. Never a silently empty
    figure -- see :func:`_evidence_figure`."""
    if item.get("has_original") is True:
        capture_id = _s(item, "capture_id")
        return (
            '<p class="notice">No shared preview copy was made for this item. The '
            "sealed original file is embedded and hash-verified — "
            f'<a href="originals/{escape(capture_id)}">download the original</a> '
            "(verify its hash against bundle.json before opening; it may retain full "
            "metadata, including location).</p>"
        )
    return (
        '<p class="warning">No photo, recording, or file was included for this '
        "item. Its content hash and timestamp exist, but there are no evidence "
        "bytes here to view or verify.</p>"
    )


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
        '<th scope="col">Media</th>'
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
            f"<td>{escape(_item_media_status(item))}</td>"
            "</tr>"
        )
    rows.append("</tbody></table>")
    return "".join(rows)


def _item_media_status(item: Mapping[str, JSONValue]) -> str:
    """Plain-language summary of what evidence bytes, if any, this item carries.

    issue #158 (decision 3): the appendix table used to say nothing about
    whether an item's photo/recording/file actually shipped -- a byteless item
    read exactly like an intact one next to its content hash and timestamp
    column. This makes that state visible here too, not only in the per-item
    figure (:func:`_evidence_figure`) and the machine-readable report.
    """
    if _s(item, "shared_name") or _s(item, "poster_name") or item.get("sensor") is not None:
        return "included"
    if item.get("has_original") is True:
        return "original only (no shared preview)"
    return "NONE — no evidence bytes"


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
