# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Read a sealed RFC 5322 message as a non-authoritative header summary (issue #304).

Use case 1 -- the repair notice and its delivery ledger -- shipped for *outbound*
letters. Inbound correspondence is the other half of "did the landlord know", and
a landlord's reply is the evidence most likely to decide a habitability dispute.
Sealing an ``.eml`` already worked (``habitable artifact reply.eml``): the bytes are
hashed, encrypted, custody-bound and RFC 3161 timestamped like any other document.
Two things did not.

**The message was opaque.** Nothing read its headers, so a packet carried a sealed
blob a recipient had to download and open in a mail client. This module parses the
sealed original into a small summary -- sender, ``Date:``, ``Message-ID:``,
``Subject:``, the attachment inventory and a plain-text body -- so both renderings
can show the message itself.

**Its attachments were inside it.** An ``.eml`` with two attachments sealed as *one*
item, so the photographs a landlord attached to a reply were present in the bytes and
absent from the evidence list, the custody chain and the packet's item count. That is
the shape of issue #158, where a capture type known to one table and not another
exported with no bytes at all and still verified clean. :func:`attachments` is the
decomposition; :func:`habitable.artifact.capture_correspondence` seals each part as
its own custody-bound artifact and joins it back with a ``supports`` relationship.

Two honesty rules run through the whole module, and both are load-bearing enough to
have their own tests.

*Every header is a claim by whoever sent the message.* A ``Date:`` header is typed by
the sending client and is not evidence of when anything happened; ``habitable`` does
not verify DKIM or ARC and says so, the same disclosure EXIF already gets. So the
summary carries :attr:`CorrespondenceSummary.header_dates_are_claims` as a constant
true, the verifier refuses a packet that sets it otherwise, and no renderer prints a
header date in a position where a reader looks for a proof. The only time bound on an
item is still its RFC 3161 token, and an item carrying a summary with a ``Date:``
header and no token is still *awaiting timestamp*.

*Absent, unreadable and present are three different states* -- four for a body, which
can also be present in a form this packet declines to render. A well-formed message
that simply has no ``Subject:`` must not render as a summary of blanks, because a
blank reads as "the sender left it empty" rather than as "the message never had one".
:class:`MessageHeader` carries the state beside the value so each one gets its own
sentence.

Where the summary is computed, and why it is not stored on the record: the packet
builder derives it from the sealed original it has just read back and hash-checked,
exactly as :mod:`habitable.sensor` derives ``item.sensor`` from an instrument CSV.
A summary stored at capture time would be one more producer assertion inside the
signed document; a summary derived from the hashed bytes is something a recipient
holding the original can recompute and contradict. The capture-time work is the part
that *cannot* be redone later -- refusing a file that is not a message, and sealing
the attachments as their own items before the case record closes over them.
"""

from __future__ import annotations

import email.errors
import email.policy
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from email.message import EmailMessage
from email.parser import BytesParser

from .errors import CaptureError
from .verify import (
    CORRESPONDENCE_BODY_STATES,
    CORRESPONDENCE_HEADER_STATES,
    CORRESPONDENCE_SCHEMA,
)

__all__ = [
    "CORRESPONDENCE_BODY_STATES",
    "CORRESPONDENCE_HEADER_STATES",
    "CORRESPONDENCE_SCHEMA",
    "Attachment",
    "CorrespondenceBody",
    "CorrespondenceSummary",
    "CorrespondenceView",
    "MessageHeader",
    "attachments",
    "correspondence_view",
    "parse_message",
    "read_message",
    "summarize",
]

#: The MIME type an ``.eml`` capture carries, in one place: ``artifact._DOCUMENT_TYPES``
#: maps the extension to it, ``packet._DOCUMENT_EXT_BY_TYPE`` maps it back out, and the
#: packet builder decides whether to summarize an item by comparing against it.
MESSAGE_MEDIA_TYPE = "message/rfc822"

#: A packet renders at most this many characters of a message body inline. The whole
#: body stays in the sealed original and in the verbatim ``.eml`` copy under ``media/``;
#: this only bounds what is inlined into ``bundle.json`` and read out on the page. Like
#: the sensor cap it is disclosed rather than silent -- :class:`CorrespondenceBody`
#: carries the untruncated character count beside the text.
_MAX_BODY_CHARS = 5_000

#: Parser defects that mean the bytes are not a message this project will seal.
#:
#: Every member is matched **by name** and the tuple is exhaustive over what
#: :func:`_refusals` inspects; an unrecognised defect class is reported under its own
#: sentence rather than folded into the last one. A trailing catch-all reads exactly
#: like a match and would tell a tenant to fix the wrong thing (the ceqa-preflight
#: lesson: one sentence over five different facts).
_FATAL_DEFECTS: tuple[tuple[type[email.errors.MessageDefect], str], ...] = (
    (
        email.errors.MissingHeaderBodySeparatorDefect,
        "its header block is not separated from the body by a blank line",
    ),
    (
        email.errors.StartBoundaryNotFoundDefect,
        "it declares a multipart body whose boundary never appears, so its parts cannot be read",
    ),
    (
        email.errors.MultipartInvariantViolationDefect,
        "it declares a multipart body that holds no parts",
    ),
    (
        email.errors.CloseBoundaryNotFoundDefect,
        "its multipart body is truncated: the closing boundary is missing",
    ),
)

#: Defects that mean a header's bytes could not be turned into characters. Named
#: rather than "any defect at all", because ``InvalidDateDefect`` is a defect and a
#: perfectly readable string -- see :func:`_header`.
_DECODING_DEFECTS = (
    email.errors.UndecodableBytesDefect,
    email.errors.CharsetError,
    email.errors.InvalidBase64CharactersDefect,
    email.errors.InvalidBase64PaddingDefect,
    email.errors.InvalidBase64LengthDefect,
)

#: Referenced by name so the formatter cannot rewrite the ``except`` clause into a
#: shape that is harder to read here (and, in the verifier subset, unparseable before
#: Python 3.14 -- see ``exif._IMAGE_READ_ERRORS`` for that story).
_HEADER_READ_ERRORS = (
    email.errors.MessageError,
    UnicodeError,
    ValueError,
    IndexError,
    LookupError,
)

#: The headers summarized, in the order a reader meets them. ``field`` is the key in
#: :class:`CorrespondenceSummary` and in ``bundle.json``; ``header`` is the RFC 5322
#: name read out of the message.
_SUMMARY_HEADERS: tuple[tuple[str, str], ...] = (
    ("from_header", "From"),
    ("date_header", "Date"),
    ("subject", "Subject"),
    ("message_id", "Message-ID"),
)


@dataclass(frozen=True, slots=True)
class MessageHeader:
    """One summarized header, with the state that says how to read the value.

    ``present`` is a value the parser decoded. ``absent`` is a header the message
    never carried. ``unreadable`` is a header that is there and whose value could not
    be decoded -- an RFC 2047 encoded word in an unknown charset, say. The last two
    both carry an empty ``value``, and they are not the same fact: one is a sender who
    wrote nothing, the other is a sender who wrote something this reader cannot show.
    Collapsing them into ``""`` is this project's own dominant defect (absence
    rendered as a value), so the state travels with the value everywhere.
    """

    name: str
    state: str
    value: str = ""

    def to_dict(self) -> dict[str, object]:
        return {"name": self.name, "state": self.state, "value": self.value}


@dataclass(frozen=True, slots=True)
class Attachment:
    """One non-body part of a message, as the message itself declares it.

    ``payload`` is ``None`` when the part's content could not be decoded. That part is
    still counted -- it exists, and the sealed original still holds its bytes -- but no
    separate item is sealed for it, and the packet names it rather than letting the
    inventory quietly shrink.
    """

    index: int
    filename: str
    media_type: str
    payload: bytes | None

    @property
    def readable(self) -> bool:
        return self.payload is not None


@dataclass(frozen=True, slots=True)
class CorrespondenceBody:
    """The message body as this packet renders it, and what it left out.

    Four states, because "no text to show" has four different causes and a reader
    deserves the right sentence for each:

    ``present``
        a ``text/plain`` part was decoded; ``text`` holds up to
        :data:`_MAX_BODY_CHARS` of it and ``characters`` is the untruncated length.
    ``absent``
        the message carries no body part at all.
    ``not_plain_text``
        the message has a body, in a form this packet declines to render -- an
        HTML-only mail, most often. The bytes are in the sealed original and in the
        verbatim ``.eml`` under ``media/``; rendering attacker-supplied markup inside
        an evidence packet is not something this project will do quietly, so it says
        so instead.
    ``unreadable``
        a ``text/plain`` part exists and its content could not be decoded.
    """

    state: str
    media_type: str = ""
    text: str = ""
    characters: int = 0
    truncated: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "state": self.state,
            "media_type": self.media_type,
            "text": self.text,
            "characters": self.characters,
            "truncated": self.truncated,
        }


@dataclass(frozen=True, slots=True)
class CorrespondenceSummary:
    """What a sealed ``.eml`` says about itself. Every field is the sender's claim.

    ``attachment_count`` is read from the message's own part walk, not from how many
    items a capture happened to create. The two numbers answer different questions and
    a loop that produced two items over a two-part message is indistinguishable, from
    the output side, from one that produced two over five; ``attachments_readable`` is
    the second number, and the packet prints both.
    """

    correspondence_schema: int
    from_header: MessageHeader
    date_header: MessageHeader
    subject: MessageHeader
    message_id: MessageHeader
    attachment_count: int
    attachments_readable: int
    attachments: tuple[dict[str, object], ...]
    body: CorrespondenceBody
    header_dates_are_claims: bool = True
    warnings: tuple[str, ...] = field(default_factory=tuple)

    @property
    def headers(self) -> tuple[MessageHeader, ...]:
        return (self.from_header, self.date_header, self.subject, self.message_id)

    def to_dict(self) -> dict[str, object]:
        return {
            "correspondence_schema": self.correspondence_schema,
            "from_header": self.from_header.to_dict(),
            "date_header": self.date_header.to_dict(),
            "subject": self.subject.to_dict(),
            "message_id": self.message_id.to_dict(),
            "attachment_count": self.attachment_count,
            "attachments_readable": self.attachments_readable,
            "attachments": [dict(entry) for entry in self.attachments],
            "body": self.body.to_dict(),
            "header_dates_are_claims": self.header_dates_are_claims,
            "warnings": list(self.warnings),
        }


# --- parsing ------------------------------------------------------------------


def parse_message(raw: bytes) -> EmailMessage:
    """Parse ``raw`` as an RFC 5322 message, or refuse it by name.

    ``BytesParser`` will accept very nearly anything -- a JPEG parses as a message
    with no headers and a binary body -- so "it parsed" is not a check. The refusals
    are enumerated in :func:`_refusals` and every one of them names what was wrong
    with the file rather than reporting that parsing failed.
    """
    reasons = _refusals(raw)
    if reasons:
        raise CaptureError("this file is not a readable email message: " + "; ".join(reasons))
    return _parse(raw)


def read_message(raw: bytes, *, source: str) -> EmailMessage:
    """:func:`parse_message`, with the file named in the refusal.

    A refusal that does not name the record sends the reader into the module instead
    of into the data. ``parse`` has no path to name; the caller does.
    """
    try:
        return parse_message(raw)
    except CaptureError as exc:
        raise CaptureError(f"{source}: {exc}") from exc


def _parse(raw: bytes) -> EmailMessage:
    parsed = BytesParser(policy=email.policy.default).parsebytes(raw)
    assert isinstance(parsed, EmailMessage)
    return parsed


def _all_defects(message: EmailMessage) -> Iterator[email.errors.MessageDefect]:
    yield from message.defects
    for part in message.walk():
        if part is message:
            continue
        yield from part.defects


def _refusals(raw: bytes) -> list[str]:
    """Every reason this file is not a message, each as its own sentence."""
    reasons: list[str] = []
    if not raw.strip():
        return ["the file is empty"]
    message = _parse(raw)
    if not message.keys():
        reasons.append("it carries no header line at all, so it is not RFC 5322 correspondence")
    seen: set[type[email.errors.MessageDefect]] = {type(d) for d in _all_defects(message)}
    for defect_type, sentence in _FATAL_DEFECTS:
        if any(issubclass(found, defect_type) for found in seen):
            reasons.append(sentence)
    return reasons


def _header(message: EmailMessage, name: str) -> MessageHeader:
    """Read one header into its three states, never raising and never guessing.

    ``unreadable`` is about **decoding**, not about meaning, and the difference
    decides what a recipient is shown. ``Date: next Tuesday sometime`` records an
    ``InvalidDateDefect`` and is *not* unreadable here: this module never turns a
    ``Date:`` header into a time, so an unparseable date is simply the text the
    sender wrote, and suppressing it would delete evidence in the name of rigour.
    What makes a header unreadable is bytes that could not be turned into
    characters -- a decoding defect, or a value carrying U+FFFD, which is what an
    undecodable byte becomes on the way through.
    """
    if name not in message:
        return MessageHeader(name=name, state="absent")
    try:
        raw = message[name]
    except _HEADER_READ_ERRORS:
        return MessageHeader(name=name, state="unreadable")
    if any(isinstance(defect, _DECODING_DEFECTS) for defect in getattr(raw, "defects", ())):
        return MessageHeader(name=name, state="unreadable")
    try:
        value = str(raw).strip()
    except _HEADER_READ_ERRORS:
        return MessageHeader(name=name, state="unreadable")
    if "�" in value:
        return MessageHeader(name=name, state="unreadable")
    # A header that is present and empty is a sender who wrote nothing into it. That
    # is a real, different fact from "no such header", and rendering the two the same
    # way is what makes a summary of blanks -- so the empty value keeps state
    # "present" and the renderer says "present and empty" rather than showing nothing.
    return MessageHeader(name=name, state="present", value=value)


def attachments(message: EmailMessage) -> tuple[Attachment, ...]:
    """Every non-body part the message declares, in the order the message holds them.

    The population is the message's own ``iter_attachments`` walk, so the count is a
    property of the file and not of what a caller managed to do with it. A part whose
    content cannot be decoded is still returned, with ``payload`` ``None``.
    """
    found: list[Attachment] = []
    for index, part in enumerate(message.iter_attachments(), start=1):
        assert isinstance(part, EmailMessage)
        payload: bytes | None
        try:
            content = part.get_content()
        except email.errors.MessageError, LookupError, ValueError, TypeError:
            payload = None
        else:
            payload = _as_bytes(content)
        found.append(
            Attachment(
                index=index,
                filename=(part.get_filename() or "").strip(),
                media_type=part.get_content_type(),
                payload=payload,
            )
        )
    return tuple(found)


def _as_bytes(content: object) -> bytes | None:
    if isinstance(content, bytes):
        return content
    if isinstance(content, str):
        return content.encode("utf-8")
    if isinstance(content, EmailMessage):
        return content.as_bytes()
    return None


def _body(message: EmailMessage) -> CorrespondenceBody:
    part = message.get_body(preferencelist=("plain",))
    if part is None:
        other = message.get_body(preferencelist=("html", "related"))
        if other is None:
            return CorrespondenceBody(state="absent")
        assert isinstance(other, EmailMessage)
        return CorrespondenceBody(state="not_plain_text", media_type=other.get_content_type())
    assert isinstance(part, EmailMessage)
    try:
        content = part.get_content()
    except email.errors.MessageError, LookupError, ValueError, TypeError:
        return CorrespondenceBody(state="unreadable", media_type=part.get_content_type())
    if not isinstance(content, str):
        return CorrespondenceBody(state="unreadable", media_type=part.get_content_type())
    text = content.replace("\r\n", "\n").strip("\n")
    truncated = len(text) > _MAX_BODY_CHARS
    return CorrespondenceBody(
        state="present",
        media_type=part.get_content_type(),
        text=text[:_MAX_BODY_CHARS] if truncated else text,
        characters=len(text),
        truncated=truncated,
    )


def summarize(message: EmailMessage) -> CorrespondenceSummary:
    """Build the non-authoritative summary a packet item carries."""
    parts = attachments(message)
    readable = sum(1 for part in parts if part.readable)
    warnings: list[str] = []
    unreadable = [part for part in parts if not part.readable]
    for part in unreadable:
        warnings.append(
            f"attachment {part.index} of {len(parts)} "
            f"({part.filename or 'unnamed'}, {part.media_type}) could not be decoded and was "
            "not sealed as its own item; its bytes remain inside the sealed message"
        )
    body = _body(message)
    if body.truncated:
        warnings.append(
            f"showing the first {len(body.text)} of {body.characters} character(s) of the "
            "message body; the rest is in the sealed original"
        )
    fields = {name: _header(message, header) for name, header in _SUMMARY_HEADERS}
    return CorrespondenceSummary(
        correspondence_schema=CORRESPONDENCE_SCHEMA,
        from_header=fields["from_header"],
        date_header=fields["date_header"],
        subject=fields["subject"],
        message_id=fields["message_id"],
        attachment_count=len(parts),
        attachments_readable=readable,
        attachments=tuple(
            {"index": part.index, "filename": part.filename, "media_type": part.media_type}
            for part in parts
        ),
        body=body,
        warnings=tuple(warnings),
    )


# --- reading a summary back out of a bundle -----------------------------------


@dataclass(frozen=True, slots=True)
class CorrespondenceView:
    """One bundle's correspondence block, rendered into sentences.

    Both renderers read this rather than each formatting the block themselves. #311
    was one bundle whose HTML and PDF told a recipient different things about the same
    instrument series, because the sentence existed twice; a single source is the only
    structural guarantee that cannot drift.
    """

    heading: str
    claim_note: str
    header_rows: tuple[tuple[str, str], ...]
    attachment_sentence: str
    body_heading: str
    body_text: str
    body_note: str
    warnings: tuple[str, ...]


_TEXT: dict[str, dict[str, str]] = {
    "en": {
        "heading": "Message summary (as the message states it)",
        "claim_note": (
            "Every line below is a claim made by whoever sent this message, read out of "
            "its headers. habitable does not check DKIM or any other mail signature, so "
            "none of it is verified. In particular the Date header is what the sending "
            "program wrote, not a time this packet can prove: the only time bound on this "
            "item is its RFC 3161 timestamp, reported separately."
        ),
        "from": "From (claimed)",
        "date": "Date header (claimed by the sender, not a timestamp)",
        "subject": "Subject",
        "message_id": "Message-ID",
        "absent": "not present in the message",
        "unreadable": "present, but this reader could not decode it",
        "empty": "present and empty",
        "attachments_none": "The message declares no attachments.",
        "attachments_all": (
            "The message declares {count} attachment(s), and all of them were read: "
            "{names}. Each is sealed as its own item in this packet and linked back to "
            "this message."
        ),
        "attachments_partial": (
            "The message declares {count} attachment(s), of which {readable} could be "
            "read: {names}. The rest are named in the notes below; their bytes are inside "
            "the sealed message and were not sealed as separate items."
        ),
        "body_heading": "Message body",
        "body_absent": "This message carries no body.",
        "body_not_plain_text": (
            "This message's body is {media_type}, which this packet does not render. The "
            "bytes are in the sealed original and in the .eml copy beside this packet."
        ),
        "body_unreadable": (
            "This message has a text body that could not be decoded, so none of it is "
            "shown rather than a damaged version of it. The bytes are in the sealed "
            "original."
        ),
        "body_truncated": (
            "Showing the first {shown} of {total} characters. The remainder is in the "
            "sealed original, not on this page."
        ),
    },
    "es": {
        "heading": "Resumen del mensaje (según lo indica el propio mensaje)",
        "claim_note": (
            "Cada línea siguiente es una afirmación de quien envió este mensaje, leída de "
            "sus encabezados. habitable no comprueba DKIM ni ninguna otra firma de correo, "
            "así que nada de esto está verificado. En particular, el encabezado Date es lo "
            "que escribió el programa remitente, no una hora que este expediente pueda "
            "demostrar: el único límite de tiempo de este elemento es su sello RFC 3161, "
            "que se informa por separado."
        ),
        "from": "De (afirmado)",
        "date": "Encabezado Date (afirmado por quien envía; no es un sello de tiempo)",
        "subject": "Asunto",
        "message_id": "Message-ID",
        "absent": "no está presente en el mensaje",
        "unreadable": "está presente, pero este lector no pudo descifrarlo",
        "empty": "presente y vacío",
        "attachments_none": "El mensaje no declara ningún archivo adjunto.",
        "attachments_all": (
            "El mensaje declara {count} archivo(s) adjunto(s) y se pudieron leer todos: "
            "{names}. Cada uno se sella como su propio elemento en este expediente y se "
            "enlaza con este mensaje."
        ),
        "attachments_partial": (
            "El mensaje declara {count} archivo(s) adjunto(s), de los cuales se pudieron "
            "leer {readable}: {names}. Los demás se indican en las notas siguientes; sus "
            "bytes están dentro del mensaje sellado y no se sellaron como elementos "
            "separados."
        ),
        "body_heading": "Cuerpo del mensaje",
        "body_absent": "Este mensaje no tiene cuerpo.",
        "body_not_plain_text": (
            "El cuerpo de este mensaje es {media_type}, que este expediente no representa. "
            "Los bytes están en el original sellado y en la copia .eml junto a este "
            "expediente."
        ),
        "body_unreadable": (
            "Este mensaje tiene un cuerpo de texto que no se pudo descifrar, así que no se "
            "muestra nada en lugar de una versión dañada. Los bytes están en el original "
            "sellado."
        ),
        "body_truncated": (
            "Se muestran los primeros {shown} de {total} caracteres. El resto está en el "
            "original sellado, no en esta página."
        ),
    },
}


def _text(lang: str) -> dict[str, str]:
    return _TEXT.get(lang.lower().split("-")[0], _TEXT["en"])


def _header_value_sentence(words: Mapping[str, str], state: str, value: str) -> str:
    if state == "absent":
        return words["absent"]
    if state == "unreadable":
        return words["unreadable"]
    return value or words["empty"]


def _attachment_names(entries: Sequence[Mapping[str, object]]) -> str:
    names: list[str] = []
    for entry in entries:
        raw_name = entry.get("filename")
        name = raw_name.strip() if isinstance(raw_name, str) else ""
        media_type = entry.get("media_type")
        kind = media_type if isinstance(media_type, str) and media_type else "unknown type"
        names.append(f"{name or 'unnamed'} ({kind})")
    return ", ".join(names)


def correspondence_view(block: Mapping[str, object], lang: str = "en") -> CorrespondenceView:
    """Render one ``item.correspondence`` block into the sentences both packets print.

    The block arrives from ``bundle.json`` and is read distrustfully: every field may
    be absent, null, or the wrong type, and a state this reader does not know is
    reported as unreadable rather than resolved into one it does.
    """
    words = _text(lang)
    rows: list[tuple[str, str]] = []
    for key, label in (
        ("from_header", "from"),
        ("date_header", "date"),
        ("subject", "subject"),
        ("message_id", "message_id"),
    ):
        raw = block.get(key)
        header = raw if isinstance(raw, Mapping) else {}
        state = header.get("state")
        if state not in CORRESPONDENCE_HEADER_STATES:
            state = "unreadable"
        value = header.get("value")
        rows.append(
            (
                words[label],
                _header_value_sentence(words, str(state), value if isinstance(value, str) else ""),
            )
        )

    count = _count(block.get("attachment_count"))
    readable = _count(block.get("attachments_readable"))
    raw_entries = block.get("attachments")
    entries = (
        [entry for entry in raw_entries if isinstance(entry, Mapping)]
        if (isinstance(raw_entries, list))
        else []
    )
    if count == 0:
        attachment_sentence = words["attachments_none"]
    elif readable >= count:
        attachment_sentence = words["attachments_all"].format(
            count=count, names=_attachment_names(entries)
        )
    else:
        attachment_sentence = words["attachments_partial"].format(
            count=count, readable=readable, names=_attachment_names(entries)
        )

    raw_body = block.get("body")
    body = raw_body if isinstance(raw_body, Mapping) else {}
    body_state = body.get("state")
    if body_state not in CORRESPONDENCE_BODY_STATES:
        body_state = "unreadable"
    body_text = body.get("text")
    shown = body_text if isinstance(body_text, str) and body_state == "present" else ""
    characters = _count(body.get("characters"))
    body_media_type = body.get("media_type")
    if body_state == "present":
        body_note = (
            words["body_truncated"].format(shown=len(shown), total=characters)
            if body.get("truncated") is True or characters > len(shown)
            else ""
        )
    elif body_state == "not_plain_text":
        body_note = words["body_not_plain_text"].format(
            media_type=body_media_type if isinstance(body_media_type, str) else "unknown"
        )
    elif body_state == "absent":
        body_note = words["body_absent"]
    else:
        body_note = words["body_unreadable"]

    raw_warnings = block.get("warnings")
    warnings = (
        tuple(entry for entry in raw_warnings if isinstance(entry, str))
        if isinstance(raw_warnings, list)
        else ()
    )
    return CorrespondenceView(
        heading=words["heading"],
        claim_note=words["claim_note"],
        header_rows=tuple(rows),
        attachment_sentence=attachment_sentence,
        body_heading=words["body_heading"],
        body_text=shown,
        body_note=body_note,
        warnings=warnings,
    )


def _count(value: object) -> int:
    """A non-negative integer, or 0 for anything a producer could not have meant.

    Unlike the sensor series' ``skipped_rows`` there is no "unknown" rendering to fall
    back to here: the attachment sentence has to say something. A malformed count
    reads as zero *and* the verifier refuses the packet for it, so the two halves
    together mean a nonsense inventory cannot pass silently.
    """
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return 0
    return value
