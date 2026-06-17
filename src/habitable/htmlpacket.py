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

from collections.abc import Mapping
from html import escape
from pathlib import Path

from .canonical import JSONValue

__all__ = ["render_packet_html"]

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
        f"{_i(appendix, 'item_count')} item(s), {_i(appendix, 'timestamped_count')} "
        f"trusted-timestamped · producer {escape(_s(bundle, 'producer_fingerprint'))}</p>",
    ]
    if _s(template, "header"):
        parts.append(f'<p class="meta">{escape(_s(template, "header"))}</p>')
    parts.append(
        '<p class="warning">This packet is evidence, not legal advice, and does not '
        "guarantee admissibility. Verify integrity with <code>habitable verify</code> "
        "against the accompanying bundle.json.</p>"
    )
    parts.append("</header>")
    parts.append('<main id="main">')

    for issue in _list(bundle, "issues"):
        if isinstance(issue, dict):
            parts.extend(_issue_section(issue, bundle, items_by_issue))

    parts.append("<h2>Evidence appendix</h2>")
    parts.append(_appendix_table(bundle))
    parts.append("</main>")

    footer = "habitable — local-first, end-to-end-encrypted habitability evidence."
    if _s(template, "footer"):
        footer = _s(template, "footer")
    parts.append(f"<footer><p>{escape(footer)}</p></footer>")
    parts.append("</body></html>")

    out_path.write_text("\n".join(parts), encoding="utf-8")


def _issue_section(
    issue: Mapping[str, JSONValue],
    bundle: Mapping[str, JSONValue],
    items_by_issue: dict[str, list[Mapping[str, JSONValue]]],
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
        e
        for e in _list(bundle, "timeline")
        if isinstance(e, dict) and _s(e, "issue_id") == issue_id
    ]
    if timeline:
        out.append("<h3>Timeline</h3><ul>")
        out += [
            f"<li><strong>{escape(_s(e, 'kind'))}:</strong> {escape(_s(e, 'text'))}</li>"
            for e in timeline
            if isinstance(e, dict)
        ]
        out.append("</ul>")

    items = items_by_issue.get(issue_id, [])
    if items:
        out.append("<h3>Captured evidence</h3>")
        for item in items:
            shared = _s(item, "shared_name")
            stamp = "trusted-timestamped" if item.get("timestamp") else "awaiting timestamp"
            content_hash = _s(item, "content_hash")
            alt = (
                f"Evidence photo for this issue, captured {_s(item, 'captured_at')}, "
                f"content hash {content_hash[:12]}, {stamp}."
            )
            out.append("<figure>")
            if shared:
                out.append(f'<img src="media/{escape(shared)}" alt="{escape(alt)}">')
            out.append(
                f"<figcaption>Captured {escape(_s(item, 'captured_at'))} · "
                f"hash {escape(content_hash[:16])}… · {escape(stamp)}</figcaption>"
            )
            out.append("</figure>")
    out.append("</section>")
    return out


def _appendix_table(bundle: Mapping[str, JSONValue]) -> str:
    rows = [
        "<table>",
        "<caption>Per-item content hash, trusted-timestamp status, and authority "
        "(verify independently against bundle.json).</caption>",
        "<thead><tr>"
        '<th scope="col">Capture</th>'
        '<th scope="col">Content hash (SHA-256)</th>'
        '<th scope="col">Timestamp</th>'
        '<th scope="col">Authority</th>'
        "</tr></thead>",
        "<tbody>",
    ]
    for item in _list(bundle, "items"):
        if not isinstance(item, dict):
            continue
        token = item.get("timestamp")
        status = "verified" if isinstance(token, dict) else "awaiting"
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


def _list(mapping: Mapping[str, JSONValue], key: str) -> list[JSONValue]:
    value = mapping.get(key)
    return value if isinstance(value, list) else []


def _map(mapping: Mapping[str, JSONValue], key: str) -> Mapping[str, JSONValue]:
    value = mapping.get(key)
    return value if isinstance(value, dict) else {}
