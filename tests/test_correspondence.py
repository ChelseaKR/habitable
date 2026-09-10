# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Sealed correspondence: header summary, attachment decomposition, rendering (#304).

Three claims are pinned here, in the order the issue's *Done when* states them.

1. An ``.eml`` with two attachments captures as **three** custody-bound items with
   relationships, and the packet lists all three.
2. A malformed ``.eml`` is refused **with a named error**, and nothing is sealed —
   never an empty item.
3. A header date **never appears as a timestamp anywhere**, and ``verify`` still
   requires a token.

Every count in the first is asserted against the *message's own* part walk as well as
against the items created. A loop that produced two items over a two-part message and
one that produced two over a five-part message are indistinguishable from the output
side, and only one of them has captured the evidence.
"""

from __future__ import annotations

import io
import json
from collections.abc import Callable
from html import unescape
from pathlib import Path

import pytest
from PIL import Image

from habitable.artifact import capture_artifact, capture_correspondence
from habitable.correspondence import (
    CORRESPONDENCE_BODY_STATES,
    CORRESPONDENCE_HEADER_STATES,
    CORRESPONDENCE_SCHEMA,
    attachments,
    correspondence_view,
    parse_message,
    read_message,
    summarize,
)
from habitable.errors import CaptureError
from habitable.htmlpacket import render_packet_html
from habitable.packet import build_packet
from habitable.tsa import LocalRfc3161TSA
from habitable.vault import Vault
from habitable.verify import verify_packet

_GENERATED_AT = "2026-01-02T00:10:00Z"


def _png() -> bytes:
    buffer = io.BytesIO()
    Image.new("RGB", (12, 8), (31, 78, 95)).save(buffer, format="PNG")
    return buffer.getvalue()


def _b64(payload: bytes) -> bytes:
    import base64

    return base64.encodebytes(payload)


def _message(
    *,
    headers: bytes = (
        b"From: Building Manager <manager@example-landlord.test>\r\n"
        b"Subject: Re: no heat in bedroom\r\n"
        b"Date: Fri, 02 Jan 2026 08:41:13 +0000\r\n"
        b"Message-ID: <abc@example-landlord.test>\r\n"
    ),
    body: bytes = b"A contractor is booked for Thursday morning.\r\n",
    body_type: bytes = b'text/plain; charset="utf-8"',
    parts: int = 2,
    undecodable_part: bool = False,
) -> bytes:
    """A synthetic multipart message with ``parts`` attachments."""
    out = [
        headers,
        b"MIME-Version: 1.0\r\n",
        b'Content-Type: multipart/mixed; boundary="=_b0"\r\n\r\n',
        b"--=_b0\r\n",
        b"Content-Type: " + body_type + b"\r\n",
        b"Content-Transfer-Encoding: 7bit\r\n\r\n",
        body,
    ]
    for index in range(parts):
        out += [
            b"\r\n--=_b0\r\n",
            b"Content-Type: image/png\r\n",
            b'Content-Disposition: attachment; filename="photo-%d.png"\r\n' % (index + 1),
            b"Content-Transfer-Encoding: base64\r\n\r\n",
            _b64(_png()),
        ]
    if undecodable_part:
        out += [
            b"\r\n--=_b0\r\n",
            b'Content-Type: text/plain; charset="x-nonesuch-8"\r\n',
            b'Content-Disposition: attachment; filename="notes.txt"\r\n',
            b"Content-Transfer-Encoding: 7bit\r\n\r\n",
            b"illegible\r\n",
        ]
    out.append(b"\r\n--=_b0--\r\n")
    return b"".join(out)


# --- 1. the parser, in both directions ----------------------------------------


def test_a_complete_message_summarizes_every_header_it_carries() -> None:
    summary = summarize(parse_message(_message()))
    assert summary.correspondence_schema == CORRESPONDENCE_SCHEMA
    assert summary.header_dates_are_claims is True
    assert [(h.name, h.state) for h in summary.headers] == [
        ("From", "present"),
        ("Date", "present"),
        ("Subject", "present"),
        ("Message-ID", "present"),
    ]
    assert summary.from_header.value == "Building Manager <manager@example-landlord.test>"
    assert summary.date_header.value == "Fri, 02 Jan 2026 08:41:13 +0000"
    assert summary.body.state == "present"
    assert summary.body.text == "A contractor is booked for Thursday morning."
    assert summary.warnings == ()


def test_absent_unreadable_and_empty_are_three_different_header_states() -> None:
    """The whole point of `MessageHeader.state`, and the packet's dominant defect class.

    A blank beside three filled rows reads as "the sender left it empty". Only one of
    these three actually is that.
    """
    raw = (
        b"From: a@example.test\r\n"
        # 8-bit bytes with no declared charset: present, and not decodable to text.
        b"Subject: humedad y moho en el ba\xf1o\r\n"
        b"Message-ID: \r\n"
        b"\r\nbody\r\n"
    )
    summary = summarize(parse_message(raw))
    assert summary.date_header.state == "absent", "no Date header at all"
    assert summary.subject.state == "unreadable"
    assert summary.subject.value == "", "a damaged value is not published"
    assert summary.message_id.state == "present"
    assert summary.message_id.value == "", "a sender who wrote nothing into the header"


def test_an_unparseable_date_is_text_the_sender_wrote_not_an_unreadable_header() -> None:
    """`unreadable` is about decoding, not about meaning.

    This module never turns a `Date:` header into a time, so a date that is not a
    date is simply what the sender typed. Suppressing it would delete evidence in
    the name of rigour, and the label beside it already says it proves nothing.
    """
    summary = summarize(parse_message(b"From: a@example.test\r\nDate: next Tuesday\r\n\r\nx\r\n"))
    assert summary.date_header.state == "present"
    assert summary.date_header.value == "next Tuesday"


def test_a_body_that_is_not_plain_text_is_declined_by_name_not_rendered_blank() -> None:
    summary = summarize(
        parse_message(_message(body=b"<p>hi</p>\r\n", body_type=b'text/html; charset="utf-8"'))
    )
    assert summary.body.state == "not_plain_text"
    assert summary.body.media_type == "text/html"
    assert summary.body.text == ""


def test_a_message_with_no_body_part_is_absent_and_an_empty_one_is_present() -> None:
    """Two more states that are easy to collapse and are not the same fact.

    A non-MIME message always *has* a text body, so a sender who wrote nothing sent
    an empty one -- ``present`` with zero characters. A multipart carrying only
    attachments has no body part at all, and that is ``absent``.
    """
    empty = summarize(parse_message(b"From: a@example.test\r\nSubject: x\r\n\r\n"))
    assert empty.body.state == "present"
    assert empty.body.characters == 0

    attachments_only = summarize(
        parse_message(
            b"From: a@example.test\r\nMIME-Version: 1.0\r\n"
            b'Content-Type: multipart/mixed; boundary="=_b0"\r\n\r\n'
            b"--=_b0\r\nContent-Type: image/png\r\n"
            b'Content-Disposition: attachment; filename="a.png"\r\n'
            b"Content-Transfer-Encoding: base64\r\n\r\nAAAA\r\n"
            b"--=_b0--\r\n"
        )
    )
    assert attachments_only.body.state == "absent"
    assert attachments_only.body.state in CORRESPONDENCE_BODY_STATES


def test_a_long_body_is_truncated_and_says_by_how_much() -> None:
    long_body = ("word " * 3000).encode()  # 15,000 characters
    summary = summarize(parse_message(b"From: a@example.test\r\n\r\n" + long_body))
    assert summary.body.truncated is True
    assert summary.body.characters == 15_000, "the untruncated length, beside the prefix"
    assert len(summary.body.text) == 5_000
    assert any(
        "showing the first 5000 of 15000 character(s)" in warning for warning in summary.warnings
    )
    # And the reader says the same two numbers rather than re-deriving one of them.
    assert (
        "Showing the first 5000 of 15000 characters."
        in correspondence_view(summary.to_dict(), "en").body_note
    )


# --- 2. refusal ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "raw", "expected"),
    [
        ("empty", b"", "the file is empty"),
        ("whitespace only", b"   \r\n  ", "the file is empty"),
        (
            "a JPEG, not a message",
            b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01" + b"\x00" * 40,
            "no header line at all",
        ),
        (
            "headers with no blank line before the body",
            b"From: a@example.test\r\nSubject: x\r\nthis is the body\r\n",
            "not separated from the body by a blank line",
        ),
        (
            "a multipart whose boundary never appears",
            b"From: a@example.test\r\nMIME-Version: 1.0\r\n"
            b'Content-Type: multipart/mixed; boundary="=_nope"\r\n\r\nnothing here\r\n',
            "boundary never appears",
        ),
    ],
)
def test_a_malformed_message_is_refused_with_a_named_error(
    label: str, raw: bytes, expected: str
) -> None:
    with pytest.raises(CaptureError) as excinfo:
        parse_message(raw)
    assert expected in str(excinfo.value), label


def test_the_refusal_names_the_file_so_a_reader_lands_in_the_data() -> None:
    """`parse_message` has no path to name; `read_message` does.

    A refusal that names only the fault sends the reader into this module instead of
    into their own mailbox export.
    """
    with pytest.raises(CaptureError) as excinfo:
        read_message(b"", source="landlord-reply.eml")
    assert str(excinfo.value).startswith("landlord-reply.eml: ")


def test_a_refused_message_seals_nothing_at_all(
    make_vault: Callable[..., Vault], local_tsa: LocalRfc3161TSA, tmp_path: Path
) -> None:
    """*"never captured as an empty item"* — the half a refusal alone does not prove.

    A capture that refused *after* sealing would leave an artifact with no summary and
    a custody chain that had already grown, which is exactly the state the issue names.
    """
    vault = make_vault()
    issue = vault.document.add_issue(category="heat", issue_id="i1")
    before_artifacts = len(list(vault.document.artifacts()))
    before_custody = len(vault.custody.entries)
    bad = tmp_path / "not-a-message.eml"
    bad.write_bytes(b"\xff\xd8\xff\xe0\x00\x10JFIF" + b"\x00" * 40)

    with pytest.raises(CaptureError) as excinfo:
        capture_correspondence(
            vault,
            bad,
            issue_id=issue,
            artifact_type="landlord_response",
            title="Reply",
            source_assertion="from the tenant's mailbox",
            occurred_at="2026-01-02",
            tsa=local_tsa,
        )
    assert "not-a-message.eml" in str(excinfo.value)
    assert len(list(vault.document.artifacts())) == before_artifacts
    assert len(vault.custody.entries) == before_custody


# --- 3. attachment decomposition ----------------------------------------------


def test_an_eml_with_two_attachments_captures_as_three_custody_bound_items(
    make_vault: Callable[..., Vault], local_tsa: LocalRfc3161TSA, tmp_path: Path
) -> None:
    """The issue's own acceptance criterion, with the count taken from both sides."""
    vault = make_vault()
    issue = vault.document.add_issue(category="heat", issue_id="i1")
    path = tmp_path / "reply.eml"
    path.write_bytes(_message(parts=2))

    # The population, read from the message rather than from what we produced.
    assert len(attachments(parse_message(path.read_bytes()))) == 2

    result = capture_correspondence(
        vault,
        path,
        issue_id=issue,
        artifact_type="landlord_response",
        title="Managing agent's reply",
        source_assertion="Exported by the tenant from their own mailbox",
        occurred_at="2026-01-02",
        tsa=local_tsa,
    )
    assert result.declared == 2
    assert len(result.attachments) == 2
    assert result.items == 3
    assert len(result.relationship_ids) == 2
    assert result.unreadable == ()

    ids = {a.artifact_id for a in vault.document.artifacts()}
    assert len(ids) == 3
    relationships = list(vault.document.relationships())
    assert {r.relationship_type for r in relationships} == {"supports"}
    assert {r.target_id for r in relationships} == {result.message.artifact_id}
    assert all("Attachment" in r.assertion for r in relationships)

    out = tmp_path / "packet"
    build_packet(vault, out, generated_at=_GENERATED_AT, make_pdf=False)
    bundle = json.loads((out / "bundle.json").read_text("utf-8"))
    assert len(bundle["items"]) == 3, "the packet lists all three"
    assert bundle["appendix"]["item_count"] == 3
    assert bundle["appendix"]["relationship_count"] == 2


def test_an_undecodable_attachment_is_counted_and_named_never_dropped(
    make_vault: Callable[..., Vault], local_tsa: LocalRfc3161TSA, tmp_path: Path
) -> None:
    """The two numbers. `attachments_readable < attachment_count` is a real state.

    Silently sealing one item for a two-part message would publish an inventory that
    is smaller than the evidence, and nothing downstream could tell.
    """
    vault = make_vault()
    issue = vault.document.add_issue(category="heat", issue_id="i1")
    path = tmp_path / "reply.eml"
    path.write_bytes(_message(parts=1, undecodable_part=True))

    result = capture_correspondence(
        vault,
        path,
        issue_id=issue,
        artifact_type="landlord_response",
        title="Managing agent's reply",
        source_assertion="Exported by the tenant from their own mailbox",
        occurred_at="2026-01-02",
        tsa=local_tsa,
    )
    assert result.declared == 2
    assert len(result.attachments) == 1
    assert result.items == 2
    assert len(result.unreadable) == 1
    assert "notes.txt" in result.unreadable[0]

    out = tmp_path / "packet"
    build_packet(vault, out, generated_at=_GENERATED_AT, make_pdf=False)
    bundle = json.loads((out / "bundle.json").read_text("utf-8"))
    block = next(i["correspondence"] for i in bundle["items"] if i.get("correspondence"))
    assert block["attachment_count"] == 2
    assert block["attachments_readable"] == 1
    assert len(block["attachments"]) == 2, "every declared part is listed, readable or not"
    assert any("could not be decoded" in w and "notes.txt" in w for w in block["warnings"])


def test_a_capture_is_refused_before_sealing_when_the_attachment_type_is_unknown(
    make_vault: Callable[..., Vault], local_tsa: LocalRfc3161TSA, tmp_path: Path
) -> None:
    vault = make_vault()
    issue = vault.document.add_issue(category="heat", issue_id="i1")
    path = tmp_path / "reply.eml"
    path.write_bytes(_message(parts=1))
    before = len(list(vault.document.artifacts()))
    with pytest.raises(CaptureError, match="unknown artifact type"):
        capture_correspondence(
            vault,
            path,
            issue_id=issue,
            artifact_type="landlord_response",
            title="Reply",
            source_assertion="x",
            occurred_at="2026-01-02",
            attachment_type="not_a_type",
            tsa=local_tsa,
        )
    assert len(list(vault.document.artifacts())) == before


# --- 4. a header date is never a timestamp ------------------------------------


def test_a_header_date_never_appears_as_a_timestamp_and_verify_still_wants_a_token(
    make_vault: Callable[..., Vault], tmp_path: Path
) -> None:
    """The criterion this repository's own defect class makes load-bearing.

    Captured with no TSA, so the message is *awaiting timestamp* while carrying a
    perfectly good-looking `Date:` header. If a header date could stand in for a
    time bound anywhere, this is the packet where it would.
    """
    vault = make_vault()
    issue = vault.document.add_issue(category="heat", issue_id="i1")
    path = tmp_path / "reply.eml"
    path.write_bytes(_message(parts=0))

    result = capture_correspondence(
        vault,
        path,
        issue_id=issue,
        artifact_type="landlord_response",
        title="Managing agent's reply",
        source_assertion="Exported by the tenant from their own mailbox",
        occurred_at="2026-01-02",
        tsa=None,
    )
    assert result.message.timestamped is False

    out = tmp_path / "packet"
    build_packet(vault, out, generated_at=_GENERATED_AT, make_pdf=False)
    bundle = json.loads((out / "bundle.json").read_text("utf-8"))
    item = next(i for i in bundle["items"] if i.get("correspondence"))
    header_date = item["correspondence"]["date_header"]["value"]
    assert header_date == "Fri, 02 Jan 2026 08:41:13 +0000"

    # It is in the summary, and in none of the four places a time bound lives.
    assert item["timestamp"] is None
    assert item["archive_timestamps"] == []
    assert item["additional_timestamps"] == []
    assert item["captured_at"] != header_date
    assert bundle["appendix"]["timestamped_count"] == 0

    report = verify_packet(out)
    assert report.structurally_intact
    verdict = next(v for v in report.items if v.capture_id == item["capture_id"])
    assert verdict.timestamp_present is False
    assert verdict.evidence_ready is False

    html = (out / "packet.html").read_text("utf-8")
    assert "awaiting timestamp" in html
    assert "not a timestamp" in html, "the Date row carries its own warning"


def test_the_rendered_date_row_is_labelled_a_claim_in_both_languages() -> None:
    block = summarize(parse_message(_message(parts=0))).to_dict()
    english = correspondence_view(block, "en")
    spanish = correspondence_view(block, "es")
    date_label_en = english.header_rows[1][0]
    date_label_es = spanish.header_rows[1][0]
    assert "not a timestamp" in date_label_en
    assert "no es un sello de tiempo" in date_label_es
    assert date_label_en != date_label_es, "the Spanish label is not the English one"
    assert "DKIM" in english.claim_note and "DKIM" in spanish.claim_note


# --- 5. the reader, over hostile input ----------------------------------------


def test_the_reader_reports_an_unknown_state_as_unreadable_rather_than_believing_it() -> None:
    block = summarize(parse_message(_message(parts=0))).to_dict()
    assert isinstance(block["subject"], dict)
    block["subject"]["state"] = "verified"
    view = correspondence_view(block, "en")
    assert view.header_rows[2][1] == "present, but this reader could not decode it"


def test_the_reader_survives_a_block_that_is_all_wrong_types() -> None:
    view = correspondence_view(
        {
            "from_header": "not an object",
            "attachment_count": "two",
            "attachments": {"not": "a list"},
            "body": 7,
            "warnings": "not a list",
        },
        "en",
    )
    assert view.header_rows[0][1] == "present, but this reader could not decode it"
    assert view.attachment_sentence == "The message declares no attachments."
    assert view.warnings == ()


def test_every_state_the_reader_knows_is_one_the_verifier_accepts() -> None:
    """Two vocabularies that must be one. They live in the verifier for licence
    reasons (`tests/test_guards.py` pins the Apache-2.0 subset's import closure), and
    this is the assertion that they are actually the vocabulary in use."""
    block = summarize(parse_message(_message(parts=0))).to_dict()
    assert isinstance(block["subject"], dict)
    assert block["subject"]["state"] in CORRESPONDENCE_HEADER_STATES
    assert isinstance(block["body"], dict)
    assert block["body"]["state"] in CORRESPONDENCE_BODY_STATES


# --- 6. the surrounding surfaces ----------------------------------------------


def test_a_plain_document_artifact_carries_no_correspondence_block(
    make_vault: Callable[..., Vault], local_tsa: LocalRfc3161TSA, tmp_path: Path
) -> None:
    """`null`, not absent, and not a summary of blanks for a PDF."""
    vault = make_vault()
    issue = vault.document.add_issue(category="heat", issue_id="i1")
    notice = tmp_path / "notice.pdf"
    notice.write_bytes(b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n")
    capture_artifact(
        vault,
        notice,
        issue_id=issue,
        artifact_type="utility_notice",
        title="Shutoff notice",
        source_assertion="Posted on the door",
        occurred_at="2026-01-02",
        tsa=local_tsa,
    )
    out = tmp_path / "packet"
    build_packet(vault, out, generated_at=_GENERATED_AT, make_pdf=True)
    bundle = json.loads((out / "bundle.json").read_text("utf-8"))
    assert bundle["items"][0]["correspondence"] is None
    assert (out / "packet.pdf").is_file(), (
        "a document artifact used to reach reportlab's Image(...) and kill the export"
    )


def test_a_message_sealed_before_this_existed_still_exports(
    make_vault: Callable[..., Vault], local_tsa: LocalRfc3161TSA, tmp_path: Path
) -> None:
    """`habitable artifact reply.eml` never validated, so a vault can hold an .eml
    that `capture_correspondence` would refuse today. An export must not die on
    evidence that is already sealed and already hashed: the summary is `null`, which
    is the same statement a photo item makes."""
    vault = make_vault()
    issue = vault.document.add_issue(category="heat", issue_id="i1")
    junk = tmp_path / "reply.eml"
    junk.write_bytes(b"\xff\xd8\xff\xe0\x00\x10JFIF" + b"\x00" * 40)
    capture_artifact(
        vault,
        junk,
        issue_id=issue,
        artifact_type="landlord_response",
        title="Reply",
        source_assertion="from the tenant's mailbox",
        occurred_at="2026-01-02",
        tsa=local_tsa,
    )
    out = tmp_path / "packet"
    build_packet(vault, out, generated_at=_GENERATED_AT, make_pdf=False)
    bundle = json.loads((out / "bundle.json").read_text("utf-8"))
    assert bundle["items"][0]["media_type"] == "message/rfc822"
    assert bundle["items"][0]["correspondence"] is None
    assert verify_packet(out).structurally_intact


def test_the_packet_never_publishes_the_tenants_own_filename_for_an_attachment(
    make_vault: Callable[..., Vault], local_tsa: LocalRfc3161TSA, tmp_path: Path
) -> None:
    """`tests/test_guards.py` holds the same line for captures. An attachment reaches
    the vault through a random private temporary file, and neither that name nor the
    tenant's own path for the mailbox export may reach the bundle."""
    vault = make_vault()
    issue = vault.document.add_issue(category="heat", issue_id="i1")
    path = tmp_path / "TENANT-PRIVATE-MAILBOX-9e21.eml"
    path.write_bytes(_message(parts=1))
    capture_correspondence(
        vault,
        path,
        issue_id=issue,
        artifact_type="landlord_response",
        title="Managing agent's reply",
        source_assertion="Exported by the tenant from their own mailbox",
        occurred_at="2026-01-02",
        tsa=local_tsa,
    )
    out = tmp_path / "packet"
    build_packet(vault, out, generated_at=_GENERATED_AT, make_pdf=False)
    bundle = (out / "bundle.json").read_text("utf-8")
    assert "TENANT-PRIVATE-MAILBOX-9e21" not in bundle
    assert "item-" not in bundle, "no private-temp filename leaks through an attachment"


def test_html_and_the_bundle_agree_about_the_message(
    make_vault: Callable[..., Vault], local_tsa: LocalRfc3161TSA, tmp_path: Path
) -> None:
    vault = make_vault()
    issue = vault.document.add_issue(category="heat", issue_id="i1")
    path = tmp_path / "reply.eml"
    path.write_bytes(_message(parts=2))
    capture_correspondence(
        vault,
        path,
        issue_id=issue,
        artifact_type="landlord_response",
        title="Managing agent's reply",
        source_assertion="Exported by the tenant from their own mailbox",
        occurred_at="2026-01-02",
        tsa=local_tsa,
    )
    out = tmp_path / "packet"
    build_packet(vault, out, generated_at=_GENERATED_AT, make_pdf=False)
    bundle = json.loads((out / "bundle.json").read_text("utf-8"))
    html = (out / "packet.html").read_text("utf-8")
    block = next(i["correspondence"] for i in bundle["items"] if i.get("correspondence"))
    # `unescape`, because a From header is `Name <addr>` and the renderer escapes it --
    # which is the point: bundle content is data, never markup.
    text = unescape(html)
    assert block["from_header"]["value"] in text
    assert block["body"]["text"] in text
    assert "photo-1.png (image/png), photo-2.png (image/png)" in text
    assert "&lt;manager@example-landlord.test&gt;" in html, "escaped in the raw HTML"


def test_the_spanish_packet_renders_the_summary_in_spanish(tmp_path: Path) -> None:
    """The block travels with the packet's declared language, like every other
    rendered sentence. The signed claims inside the bundle are untouched."""
    source = Path(__file__).resolve().parent / "golden" / "correspondence-packet-v4"
    bundle = json.loads((source / "bundle.json").read_text("utf-8"))
    bundle["language"] = "es"
    path = tmp_path / "packet.html"
    render_packet_html(bundle, source / "media", path)
    html = path.read_text("utf-8")
    assert "Resumen del mensaje" in html
    assert "no es un sello de tiempo" in html
    assert "Message summary (as the message states it)" not in html
