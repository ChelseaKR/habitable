# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Generate a repair-request / notice letter from the logged evidence.

A tenant who has captured evidence still has to *ask* for the repair — usually in
writing, often as a precondition to any further remedy. This module turns the case
the tenant already documented (issues, the timeline, and the timestamped photos)
into a dated, on-paper repair-request letter addressed to the landlord, and renders
it both as accessible HTML and as a PDF.

Jurisdiction-awareness, honestly scoped
---------------------------------------
Habitability law is state- and city-specific, and habitable is not a lawyer. The
generator is therefore **framing-only and template-driven**: a :class:`LetterProfile`
supplies the wording (an opening framing, a hedged reference to the kind of law that
commonly applies, and a default cure period). The built-in profiles deliberately make
**no claim about a specific statute or code section** — they use widely-recognized
concepts ("the implied warranty of habitability, where it is recognized") and tell the
reader to confirm their own jurisdiction's specifics. A union can override every word
via the ``[letter]`` block in ``config.toml`` (see :mod:`habitable.config`), which is
the right place to encode locally-verified, jurisdiction-specific wording. The letter
carries a standing "this is not legal advice" disclaimer.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from html import escape

from .config import LetterTemplate
from .errors import LetterError
from .vault import Vault

__all__ = [
    "PROFILES",
    "LetterIssue",
    "LetterOptions",
    "LetterProfile",
    "RepairLetter",
    "build_letter",
    "render_letter_html",
    "resolve_profile",
]


@dataclass(frozen=True, slots=True)
class LetterProfile:
    """Jurisdiction-aware *framing* for a letter (presentation only, never a legal claim)."""

    key: str
    label: str
    framing: str
    legal_reference: str
    cure_period_days: int = 14


# Built-in profiles. These intentionally cite no specific statute: they describe
# commonly-recognized concepts in hedged terms and defer to local confirmation.
# A union encodes verified, jurisdiction-specific wording in config instead.
PROFILES: dict[str, LetterProfile] = {
    "generic": LetterProfile(
        key="generic",
        label="Generic (no jurisdiction assumed)",
        framing=(
            "I am writing to formally request repairs to the conditions described below, "
            "which affect the habitability of my home."
        ),
        legal_reference=(
            "Many jurisdictions require a landlord to maintain rental housing in a safe and "
            "habitable condition, and to make timely repairs after written notice. Please "
            "treat this letter as that written notice."
        ),
        cure_period_days=14,
    ),
    "us_habitability": LetterProfile(
        key="us_habitability",
        label="United States — implied warranty of habitability (generic framing)",
        framing=(
            "I am writing to give you written notice of conditions affecting the habitability "
            "of my home and to request that they be repaired."
        ),
        legal_reference=(
            "In most U.S. jurisdictions a residential tenancy carries an implied warranty of "
            "habitability and a duty to repair within a reasonable time after written notice; "
            "the specific deadlines, remedies (such as repair-and-deduct or rent withholding), "
            "and notice requirements vary by state and city. Please confirm the rules that apply "
            "where the property is located."
        ),
        cure_period_days=14,
    ),
}

_DEFAULT_PROFILE = "generic"


@dataclass(frozen=True, slots=True)
class LetterOptions:
    """Inputs a tenant/organizer supplies for one letter."""

    recipient_name: str = ""
    recipient_address: str = ""
    sender_name: str = ""
    sender_contact: str = ""
    property_address: str = ""
    jurisdiction: str = ""  # profile key or a free-text label resolved against PROFILES
    cure_period_days: int | None = None
    date: str = ""  # ISO date; defaults to today (UTC)
    issue_ids: tuple[str, ...] = ()  # empty = every issue in the case
    language: str = "en"


@dataclass(frozen=True, slots=True)
class LetterIssue:
    """One issue as it appears in the letter, with a reference to its evidence."""

    issue_id: str
    title: str
    room: str
    severity: str
    description: str
    first_documented: str
    evidence_count: int
    timestamped_count: int
    content_hashes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RepairLetter:
    """A fully-resolved letter, ready to render to HTML or PDF."""

    date: str
    recipient_name: str
    recipient_address: str
    sender_name: str
    sender_contact: str
    property_address: str
    subject: str
    framing: str
    legal_reference: str
    cure_period_days: int
    issues: tuple[LetterIssue, ...]
    evidence_summary: str
    demand: str
    closing: str
    disclaimer: str
    profile_label: str
    language: str = "en"
    header: str = ""
    footer: str = ""


_DISCLAIMER = (
    "This letter was generated from documented evidence as a convenience. It is not legal "
    "advice. Habitability requirements, notice rules, and deadlines vary by jurisdiction; "
    "confirm the rules that apply to you, and seek legal aid where you can."
)


def resolve_profile(jurisdiction: str) -> LetterProfile:
    """Resolve a jurisdiction key (or label) to a :class:`LetterProfile`.

    Falls back to the generic profile for an unknown/empty key, so the generator
    never refuses to produce a letter — it just makes no jurisdiction-specific claim.
    """
    key = jurisdiction.strip().lower().replace(" ", "_")
    return PROFILES.get(key, PROFILES[_DEFAULT_PROFILE])


def build_letter(
    vault: Vault, options: LetterOptions, *, template: LetterTemplate | None = None
) -> RepairLetter:
    """Assemble a :class:`RepairLetter` from the case's logged evidence."""
    tmpl = template if template is not None else vault.config.letter
    profile = resolve_profile(options.jurisdiction or tmpl.jurisdiction)
    cure_days = _first_positive(
        options.cure_period_days, tmpl.cure_period_days, profile.cure_period_days
    )

    selected = _select_issue_ids(vault, options.issue_ids)
    issues = tuple(_letter_issue(vault, issue_id) for issue_id in selected)
    if not issues:
        raise LetterError("no issues to write about: add an issue (and ideally evidence) first")

    unit = options.property_address or vault.document.get_meta("unit") or vault.document.case_id
    total_items = sum(i.evidence_count for i in issues)
    total_stamped = sum(i.timestamped_count for i in issues)
    stamped_clause = (
        f", {total_stamped} of them carrying timestamp tokens whose validity and "
        "authority trust must be checked independently"
        if total_stamped
        else ""
    )
    evidence_summary = (
        f"These conditions are documented by {total_items} photograph(s){stamped_clause}, "
        "with content hashes that allow each photo's integrity to be verified. "
        "A complete, independently-verifiable evidence packet is available on request."
    )
    demand = (
        f"Please arrange to inspect and repair these conditions within {cure_days} days of the "
        "date of this letter, and let me know in writing when the work will be done. I am "
        "available to provide access at a reasonable time."
    )
    closing = "Thank you for your prompt attention to these repairs."

    return RepairLetter(
        date=options.date or _today_iso(),
        recipient_name=options.recipient_name or tmpl.recipient_name,
        recipient_address=options.recipient_address or tmpl.recipient_address,
        sender_name=options.sender_name or tmpl.sender_name,
        sender_contact=options.sender_contact or tmpl.sender_contact,
        property_address=unit,
        subject=f"Repair request — {unit}",
        framing=profile.framing,
        legal_reference=profile.legal_reference,
        cure_period_days=cure_days,
        issues=issues,
        evidence_summary=evidence_summary,
        demand=demand,
        closing=closing,
        disclaimer=_DISCLAIMER,
        profile_label=profile.label,
        language=options.language or vault.config.language,
        header=tmpl.header,
        footer=tmpl.footer,
    )


def _letter_issue(vault: Vault, issue_id: str) -> LetterIssue:
    issue = next((i for i in vault.document.issues() if i.issue_id == issue_id), None)
    if issue is None:
        raise LetterError(f"unknown issue: {issue_id!r}")
    captures = vault.document.captures(issue_id)
    timestamped = sum(1 for c in captures if vault.get_token(c.capture_id) is not None)
    first = ""
    dated = sorted(c.captured_at for c in captures if c.captured_at)
    if dated:
        first = dated[0]
    else:
        timeline = vault.document.timeline(issue_id)
        if timeline:
            first = (
                timeline[0].occurred_at or timeline[0].recorded_at or _hlc_to_iso(timeline[0].hlc)
            )
    return LetterIssue(
        issue_id=issue_id,
        title=issue.title or issue.category or issue_id,
        room=issue.room,
        severity=issue.severity,
        description=issue.description,
        first_documented=first,
        evidence_count=len(captures),
        timestamped_count=timestamped,
        content_hashes=tuple(c.content_hash for c in captures),
    )


def render_letter_html(letter: RepairLetter) -> str:
    """Render an accessible, self-contained HTML letter (every value escaped)."""
    parts: list[str] = [
        "<!doctype html>",
        f'<html lang="{escape(letter.language)}">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>{escape(letter.subject)}</title>",
        f"<style>{_STYLE}</style>",
        "</head>",
        "<body>",
        '<a class="skip" href="#main">Skip to content</a>',
        "<header>",
        f"<h1>{escape(letter.subject)}</h1>",
        f'<p class="meta">{escape(letter.date)}</p>',
        "</header>",
        '<main id="main">',
    ]
    if letter.header:
        parts.append(f'<p class="meta">{escape(letter.header)}</p>')
    parts += [
        '<address class="block">',
        _address_block(letter.sender_name, letter.sender_contact, "Sender"),
        "</address>",
        '<address class="block">',
        _address_block(letter.recipient_name, letter.recipient_address, "Recipient"),
        "</address>",
        f"<p><strong>Re: {escape(letter.subject)}"
        f"{_property_suffix(letter.property_address)}</strong></p>",
        f"<p>{escape(_salutation(letter.recipient_name))}</p>",
        f"<p>{escape(letter.framing)}</p>",
        "<section aria-labelledby='conditions'>",
        "<h2 id='conditions'>Conditions requiring repair</h2>",
        "<ol>",
    ]
    for issue in letter.issues:
        parts.append(f"<li>{_issue_html(issue)}</li>")
    parts += [
        "</ol>",
        "</section>",
        f"<p>{escape(letter.evidence_summary)}</p>",
        f"<p>{escape(letter.legal_reference)}</p>",
        f"<p>{escape(letter.demand)}</p>",
        f"<p>{escape(letter.closing)}</p>",
        "<p>Sincerely,</p>",
        f"<p class='sig'>{escape(letter.sender_name or '________________________')}<br>"
        f"{escape(letter.sender_contact)}</p>",
        f"<p class='disclaimer'>{escape(letter.disclaimer)}</p>",
        "</main>",
    ]
    footer = letter.footer or f"Framing profile: {letter.profile_label}. Not legal advice."
    parts.append(f"<footer><p>{escape(footer)}</p></footer>")
    parts.append("</body></html>")
    return "\n".join(parts)


def _issue_html(issue: LetterIssue) -> str:
    meta = " · ".join(
        part
        for part in (
            f"Room: {escape(issue.room)}" if issue.room else "",
            f"Severity: {escape(issue.severity)}" if issue.severity else "",
            f"First documented: {escape(issue.first_documented)}" if issue.first_documented else "",
        )
        if part
    )
    out = [f"<strong>{escape(issue.title)}</strong>"]
    if meta:
        out.append(f'<br><span class="meta">{meta}</span>')
    if issue.description:
        out.append(f"<br>{escape(issue.description)}")
    if issue.evidence_count:
        stamped = (
            f", {issue.timestamped_count} timestamp token(s) attached"
            if issue.timestamped_count
            else ""
        )
        out.append(
            f'<br><span class="meta">Documented by {issue.evidence_count} photo(s){stamped}.</span>'
        )
    return "".join(out)


def _address_block(name: str, detail: str, role: str) -> str:
    lines = [escape(name or f"[{role}]")]
    if detail:
        lines.append(escape(detail))
    return "<br>".join(lines)


# --- shared helpers (used by the PDF renderer too) ----------------------------


def letter_lines(letter: RepairLetter) -> list[tuple[str, str]]:
    """A flat, ordered list of ``(role, text)`` blocks for a sequential renderer.

    ``role`` is one of ``meta``, ``address``, ``subject``, ``body``, ``issue``,
    ``disclaimer``; the PDF renderer maps these to paragraph styles. Centralizing the
    letter's *content order* here keeps the HTML and PDF renderings in lockstep.
    """
    blocks: list[tuple[str, str]] = [("meta", letter.date)]
    if letter.header:
        blocks.append(("meta", letter.header))
    blocks.append(("address", _flat_address(letter.sender_name, letter.sender_contact, "Sender")))
    blocks.append(
        ("address", _flat_address(letter.recipient_name, letter.recipient_address, "Recipient"))
    )
    blocks.append(("subject", f"Re: {letter.subject}{_property_suffix(letter.property_address)}"))
    blocks.append(("body", _salutation(letter.recipient_name)))
    blocks.append(("body", letter.framing))
    blocks.append(("subject", "Conditions requiring repair"))
    for index, issue in enumerate(letter.issues, start=1):
        blocks.append(("issue", f"{index}. {_issue_text(issue)}"))
    blocks.append(("body", letter.evidence_summary))
    blocks.append(("body", letter.legal_reference))
    blocks.append(("body", letter.demand))
    blocks.append(("body", letter.closing))
    blocks.append(("body", "Sincerely,"))
    blocks.append(("body", letter.sender_name or "________________________"))
    if letter.sender_contact:
        blocks.append(("body", letter.sender_contact))
    blocks.append(("disclaimer", letter.disclaimer))
    if letter.footer:
        blocks.append(("disclaimer", letter.footer))
    return blocks


def _issue_text(issue: LetterIssue) -> str:
    meta = " · ".join(
        part
        for part in (
            f"Room: {issue.room}" if issue.room else "",
            f"Severity: {issue.severity}" if issue.severity else "",
            f"First documented: {issue.first_documented}" if issue.first_documented else "",
        )
        if part
    )
    text = issue.title
    if meta:
        text = f"{text} ({meta})"
    if issue.description:
        text = f"{text}. {issue.description}"
    if issue.evidence_count:
        stamped = (
            f", {issue.timestamped_count} timestamp token(s) attached"
            if issue.timestamped_count
            else ""
        )
        text = f"{text} [documented by {issue.evidence_count} photo(s){stamped}]"
    return text


def _flat_address(name: str, detail: str, role: str) -> str:
    return ", ".join(part for part in (name or f"[{role}]", detail) if part)


def _salutation(recipient_name: str) -> str:
    return f"Dear {recipient_name}," if recipient_name else "To whom it may concern,"


def _property_suffix(property_address: str) -> str:
    return f" ({property_address})" if property_address else ""


def _select_issue_ids(vault: Vault, issue_ids: Sequence[str]) -> list[str]:
    if issue_ids:
        return list(issue_ids)
    return [issue.issue_id for issue in vault.document.issues()]


def _first_positive(*values: int | None) -> int:
    for value in values:
        if isinstance(value, int) and value > 0:
            return value
    return 14


def _today_iso() -> str:
    return datetime.now(tz=UTC).strftime("%Y-%m-%d")


def _hlc_to_iso(hlc: str) -> str:
    head = hlc.split(".", 1)[0]
    if not head.isdigit():
        return ""
    try:
        return datetime.fromtimestamp(int(head) / 1000, tz=UTC).strftime("%Y-%m-%d")
    except ValueError, OSError, OverflowError:
        return ""


_STYLE = """
:root { color-scheme: light dark; }
body { max-width: 44rem; margin: 0 auto; padding: 1.5rem;
  font: 16px/1.6 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  color: #111; background: #fff; }
a.skip { position: absolute; left: -999px; }
a.skip:focus { position: static; }
:focus-visible { outline: 3px solid #1f4e5f; outline-offset: 2px; }
h1, h2 { line-height: 1.25; }
.meta { color: #333; }
.block { font-style: normal; margin: 0 0 1rem; white-space: normal; }
.sig { margin-top: 2rem; }
.disclaimer { margin-top: 2rem; font-size: .9rem; color: #444;
  border-top: 1px solid #ccc; padding-top: 1rem; }
footer { margin-top: 2rem; border-top: 1px solid #ccc; padding-top: 1rem;
  color: #222; font-size: .9rem; }
"""
