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

English only, and labelled as such
----------------------------------
Everything the rest of habitable produces is bilingual (EN/ES). The letter is not:
every string in this module is an English literal. It is emitted in English,
declares ``lang="en"`` whatever the vault's configured language, and reports the
unmet request rather than quietly relabelling English prose as Spanish. See
:data:`LETTER_LANGUAGE` for why a legal-register translation is a review task
rather than a code task, and ``docs/letter-generator.md`` for the user-facing
statement of the same limit.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime
from html import escape

from .config import LetterTemplate
from .errors import LetterError
from .vault import Vault

__all__ = [
    "LETTER_LANGUAGE",
    "LOCAL_LAW_STATES",
    "PROFILES",
    "LetterIssue",
    "LetterOptions",
    "LetterProfile",
    "LocalLawReview",
    "RepairLetter",
    "build_letter",
    "framing_expired",
    "render_letter_html",
    "resolve_profile",
    "review_local_law",
]


@dataclass(frozen=True, slots=True)
class LetterProfile:
    """Jurisdiction-aware *framing* for a letter (presentation only, never a legal claim).

    ``reviewer``/``reviewed_at``/``expires_at`` date the wording the same way
    :class:`habitable.usecases.UseCaseProfile` dates a workflow's review, so a
    jurisdiction framing cannot be added without saying who stood behind it and
    when. ``expires_at`` empty means the framing never goes stale; see
    :data:`PROFILES` for why that is the honest setting for the two built-ins and
    ``docs/adr/0013-dated-expiring-letter-jurisdiction-framing.md`` for the rule.
    """

    key: str
    label: str
    framing: str
    legal_reference: str
    cure_period_days: int = 14
    reviewer: str = "Habitable maintainers"
    reviewed_at: str = ""
    expires_at: str = ""


# The day the two built-in framings were last read end to end against the rule
# that they assert no statute -- the mechanical half of that read is
# `test_jurisdiction_profiles_and_fallback`, which fails the build on a `§` or a
# `U.S.C` in any reader-visible field.
_BUILTIN_REVIEWED_AT = "2026-08-26"

# Built-in profiles. These intentionally cite no specific statute: they describe
# commonly-recognized concepts in hedged terms and defer to local confirmation.
# A union encodes verified, jurisdiction-specific wording in config instead.
#
# Neither built-in sets `expires_at`, and that is a decision rather than an
# oversight. An expiry exists to stop *stale specifics* going out unread; a
# framing that names no statute, no deadline, and no remedy has no specifics to
# go stale, and giving it one would only mean `habitable letter` stopped
# producing the fallback framing on a date -- taking the safe default away from a
# tenant to punish a maintainer. Wording that does make a jurisdiction-specific
# claim lives in `[letter] header`/`footer`, and that is exactly what
# `review_local_law` dates and expires.
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
        reviewed_at=_BUILTIN_REVIEWED_AT,
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
        reviewed_at=_BUILTIN_REVIEWED_AT,
    ),
}

_DEFAULT_PROFILE = "generic"


#: Every state union-supplied local-law wording can be in. Exhaustive on purpose:
#: a reader of a letter's provenance should never meet a fifth value.
#:
#: - ``absent``  — the union supplied no ``header``/``footer`` wording at all.
#: - ``undated`` — wording is present but carries no review date. Used, and said so.
#: - ``current`` — wording is dated and has not reached its expiry.
#: - ``expired`` — wording reached its expiry and is left out of the letter.
LOCAL_LAW_STATES = ("absent", "undated", "current", "expired")


@dataclass(frozen=True, slots=True)
class LocalLawReview:
    """Who checked the union's local-law wording, when, and whether it still holds."""

    state: str
    reviewer: str = ""
    reviewed_at: str = ""
    expires_at: str = ""

    @property
    def usable(self) -> bool:
        """Whether the wording may go into a letter at all.

        Fail-closed direction: only ``expired`` withholds wording. Undated wording
        is still the union's own considered text, and refusing it would break every
        config written before this field existed; it is reported instead.
        """
        return self.state != "expired"


#: A letter whose config supplied no local-law wording. Module-level so
#: :class:`RepairLetter` can default to it without a factory.
_NO_LOCAL_LAW = LocalLawReview(state="absent")

# The one language the letter is written in, and therefore the only value its
# `lang` attribute may take (issue #161).
#
# Every string this module produces -- the profile framing, the hedged legal
# reference, the disclaimer, the evidence sentence, the demand, the closing, and
# every section label -- is an English literal. `LetterOptions.language` and
# `Config.language` accept "es", and until this constant existed a vault
# configured `language = "es"` produced a byte-identical English letter whose
# only difference was `<html lang="es">`. That is a WCAG 3.1.1 failure that makes
# a screen reader pronounce English words with Spanish phonetics, and it tells a
# Spanish-speaking tenant they are holding a document in their language when they
# are not.
#
# The fix is deliberately *not* to machine-translate the letter. This is the one
# document that leaves the tenant's control and lands in a landlord's -- and
# possibly a court's -- hands, it carries legal framing, and a legal-register
# Spanish translation needs a Spanish-speaking legal-aid reviewer before this
# project may put it in a tenant's name. Until that review happens the honest
# behaviour is the one this project applies elsewhere: decline to claim the
# language rather than assert it. The letter is emitted in English, labelled
# English, and the unmet request is reported to the person generating it
# (`RepairLetter.language_limitation`, surfaced by `habitable letter`).
#
# Translating it is tracked as the open gap in docs/capabilities.md and
# docs/letter-generator.md. When a reviewed translation lands, this becomes a
# per-locale lookup and the `lang` attribute follows the prose automatically,
# because `render_letter_html` reads `RepairLetter.language` and nothing else.
LETTER_LANGUAGE = "en"


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
    # The language asked for; empty means "whatever the vault is configured for".
    # This used to default to "en", which made `options.language or
    # vault.config.language` in `build_letter` dead code: a vault configured
    # `language = "es"` was never consulted, so `habitable letter` could not
    # reach the vault's setting at all and a Spanish-speaking union's
    # configuration was silently ignored (found while fixing issue #161).
    language: str = ""


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
    # The language the letter's text is actually *written in*. Always "en"
    # today; see LETTER_LANGUAGE and issue #161. `render_letter_html` derives
    # the document's `lang` attribute from this field and from nothing else, so
    # the attribute cannot drift from the prose again.
    language: str = LETTER_LANGUAGE
    # The language that was asked for (CLI/vault config). When this differs
    # from `language`, the letter is not in the requested language and the
    # caller is expected to say so -- see `language_limitation`.
    requested_language: str = LETTER_LANGUAGE
    header: str = ""
    footer: str = ""
    #: The framing profile actually used, after any expiry fallback.
    profile_key: str = _DEFAULT_PROFILE
    #: When that framing was last reviewed ("" if the framing predates dating).
    framing_reviewed_at: str = ""
    #: The key of a framing that was asked for and dropped because its review had
    #: expired, or "" when nothing was dropped.
    framing_expired_fallback: str = ""
    #: Whether the union's own local-law wording is dated, current, or stale, and
    #: therefore whether ``header``/``footer`` above still carry it.
    local_law: LocalLawReview = _NO_LOCAL_LAW

    @property
    def language_limitation(self) -> str:
        """A plain statement of the unmet language request, or ``""``.

        Not part of the letter body: this is for the tenant/organizer producing
        the document, not for the landlord receiving it.
        """
        if self.requested_language == self.language:
            return ""
        return (
            f"this letter was requested in {self.requested_language!r} but is written in "
            f"{self.language!r}: habitable does not ship a reviewed translation of the "
            "repair-request letter"
        )

    @property
    def local_law_limitation(self) -> str:
        """A plain statement about the union-supplied local-law wording, or ``""``.

        Not part of the letter body: like :attr:`language_limitation` this is for
        the tenant/organizer producing the document, not for the landlord
        receiving it. The landlord's copy simply does not carry wording whose
        review has lapsed, which is the point.
        """
        if self.local_law.state == "expired":
            return (
                "the locally verified wording in [letter] expired on "
                f"{self.local_law.expires_at} and was left out of this letter: re-check it "
                "against current local law, then update local_law_reviewed_at and "
                "local_law_expires_at in config.toml"
            )
        if self.local_law.state == "undated":
            return (
                "the locally verified wording in [letter] carries no review date, so nothing "
                "can tell you when it stopped being true: set local_law_reviewed_at and "
                "local_law_expires_at in config.toml"
            )
        return ""

    @property
    def framing_limitation(self) -> str:
        """A plain statement that an expired framing was swapped out, or ``""``."""
        if not self.framing_expired_fallback:
            return ""
        return (
            f"the {self.framing_expired_fallback!r} framing's review has expired, so this "
            f"letter uses the {self.profile_key!r} framing instead"
        )


_DISCLAIMER = (
    "This letter was generated from documented evidence as a convenience. It is not legal "
    "advice. Habitability requirements, notice rules, and deadlines vary by jurisdiction; "
    "confirm the rules that apply to you, and seek legal aid where you can."
)


def framing_expired(profile: LetterProfile, *, today: date | None = None) -> bool:
    """Whether *profile*'s review window has passed.

    The letter-side twin of :func:`habitable.usecases.profile_expired`, with the
    same semantics: no ``expires_at`` never expires, comparison is by calendar
    date so a framing expires at the start of its named day rather than partway
    through it in some timezone, and ``today`` is injectable so callers and tests
    pin the comparison instead of reading the wall clock.

    Presently inert — neither built-in framing sets ``expires_at`` (see
    :data:`PROFILES`) — and deliberately so: this is the enforcement a dated
    jurisdiction framing needs to exist *before* one is added, not after.
    """
    if not profile.expires_at:
        return False
    if today is None:
        today = datetime.now(tz=UTC).date()
    return today >= date.fromisoformat(profile.expires_at)


def review_local_law(template: LetterTemplate, *, today: date | None = None) -> LocalLawReview:
    """Classify the union-supplied ``[letter]`` local-law wording against its review dates.

    ``header``/``footer`` are the documented home for a locally verified statutory
    citation, and a citation is the one string here that can quietly stop being
    true. This decides nothing about the law; it only reports whether the human
    who checked the wording said it was still good as of *today*.
    """
    if not (template.header or template.footer):
        return _NO_LOCAL_LAW
    review = LocalLawReview(
        state="undated",
        reviewer=template.local_law_reviewer,
        reviewed_at=template.local_law_reviewed_at,
        expires_at=template.local_law_expires_at,
    )
    if not (review.reviewed_at or review.expires_at):
        return review
    if today is None:
        today = datetime.now(tz=UTC).date()
    if review.expires_at and today >= date.fromisoformat(review.expires_at):
        return replace(review, state="expired")
    return replace(review, state="current")


def resolve_profile(jurisdiction: str) -> LetterProfile:
    """Resolve a jurisdiction key (or label) to a :class:`LetterProfile`.

    Falls back to the generic profile for an unknown/empty key, so the generator
    never refuses to produce a letter — it just makes no jurisdiction-specific claim.
    """
    key = jurisdiction.strip().lower().replace(" ", "_")
    return PROFILES.get(key, PROFILES[_DEFAULT_PROFILE])


def build_letter(
    vault: Vault,
    options: LetterOptions,
    *,
    template: LetterTemplate | None = None,
    today: date | None = None,
) -> RepairLetter:
    """Assemble a :class:`RepairLetter` from the case's logged evidence.

    *today* dates the review checks on the jurisdiction framing and the union's
    local-law wording. It is injectable so the decision is reproducible under test
    instead of depending on the day the suite happens to run; it defaults to the
    real UTC date. It deliberately is **not** derived from ``options.date``, which
    a caller controls: a backdated letter must not be able to resurrect wording
    whose review has lapsed.
    """
    tmpl = template if template is not None else vault.config.letter
    requested_profile = resolve_profile(options.jurisdiction or tmpl.jurisdiction)
    profile = requested_profile
    expired_framing = ""
    if framing_expired(requested_profile, today=today):
        # Same direction as an expired use-case profile at export (ADR 0012):
        # fall back to wording that claims less and say so, rather than either
        # refusing a tenant their letter or sending a lapsed framing.
        expired_framing = requested_profile.key
        profile = PROFILES[_DEFAULT_PROFILE]
    local_law = review_local_law(tmpl, today=today)
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
    evidence_summary = _evidence_summary(total_items, total_stamped)
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
        language=LETTER_LANGUAGE,
        requested_language=options.language or vault.config.language or LETTER_LANGUAGE,
        # Wording whose review has lapsed does not reach the landlord's copy. Both
        # renderers read these two fields and nothing else, so HTML and PDF cannot
        # disagree about what was withheld, and the HTML footer falls back to the
        # built-in "Framing profile: … Not legal advice." line on its own.
        header=tmpl.header if local_law.usable else "",
        footer=tmpl.footer if local_law.usable else "",
        profile_key=profile.key,
        framing_reviewed_at=profile.reviewed_at,
        framing_expired_fallback=expired_framing,
        local_law=local_law,
    )


def _evidence_summary(total_items: int, total_stamped: int) -> str:
    """What the letter may say about the evidence behind it (issue #161).

    The sentence used to be built unconditionally, so a case with issues and no
    captures produced "documented by 0 photograph(s) ... A complete,
    independently-verifiable evidence packet is available on request." A
    landlord's representative can call that, the tenant has nothing to send, and
    the first thing on the record is an overstatement — on the document carrying
    the tenant's name. With no captures the letter now says what is true: the
    request stands on its own and no documented evidence backs it yet.
    """
    if total_items <= 0:
        return (
            "No photographs of these conditions are attached to this request yet. "
            "This letter is the written notice itself; if I document these conditions "
            "later, I will provide that documentation separately."
        )
    stamped_clause = (
        f", {total_stamped} of them carrying timestamp tokens whose validity and "
        "authority trust must be checked independently"
        if total_stamped
        else ""
    )
    return (
        f"These conditions are documented by {total_items} photograph(s){stamped_clause}, "
        "with content hashes that allow each photo's integrity to be verified. "
        "A complete, independently-verifiable evidence packet is available on request."
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
