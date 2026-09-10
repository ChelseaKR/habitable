# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Regenerate the correspondence golden packet fixture.

``tests/golden/correspondence-packet-v<PACKET_VERSION>/`` is the corpus's only packet
carrying a ``correspondence`` record (issue #304). It exists for the reason
``sensor-packet-v4`` does: before it was committed no bundle in the corpus held one,
so the sealed-message surface -- header summary, attachment decomposition, body
rendering -- sat outside the compatibility guarantee that ``tests/golden/`` is.

Run it after an intentional, reviewed change to that half of the export format:

    uv run python scripts/make_golden_correspondence_packet.py

Two messages, chosen so the fixture pins the *honesty states* and not just a message
that parses:

``reply.eml``
    A complete landlord reply: every summarized header present, a plain-text body,
    and two attachments that both decode. This is the issue's own acceptance case --
    one ``.eml`` becomes three custody-bound items, joined by ``supports``
    relationships, and the packet lists all three.

``forwarded-fragment.eml``
    The complement, and the one that matters. Its ``Date:`` header is **absent**, its
    ``Subject:`` is **unreadable** (raw 8-bit bytes, no charset declared), its body is
    HTML with no plain-text alternative (**not_plain_text**), and of its two declared
    attachments **one cannot be decoded** (a ``text/plain`` part labelled with a
    charset that does not exist). Every state this format can be in that is not
    "present" occurs here, in one record, so a change that collapsed any of them into
    a blank would move these bytes.

The messages are written as literal bytes with fixed MIME boundaries rather than
built with ``EmailMessage.add_attachment``, which mints a random boundary per run and
would make the fixture unreproducible.
"""

from __future__ import annotations

import base64
import io
import shutil
import tempfile
from collections.abc import Callable
from pathlib import Path

from PIL import Image

from habitable.artifact import capture_correspondence
from habitable.packet import PACKET_VERSION, build_packet
from habitable.tsa import LocalRfc3161TSA
from habitable.vault import Vault

_FIXED_EPOCH = 1_767_312_000  # 2026-01-02T00:00:00Z — reproducible timestamps
_GENERATED_AT = "2026-01-02T00:10:00Z"
_ROOT = Path(__file__).resolve().parent.parent
_GOLDEN = _ROOT / "tests" / "golden" / f"correspondence-packet-v{PACKET_VERSION}"


def _counter_ms(start_ms: int) -> Callable[[], int]:
    state = {"t": start_ms}

    def tick() -> int:
        state["t"] += 1
        return state["t"]

    return tick


def _synthetic_png() -> bytes:
    """A never-real 24x16 image standing in for a photograph a landlord attached."""
    buffer = io.BytesIO()
    Image.new("RGB", (24, 16), (31, 78, 95)).save(buffer, format="PNG", optimize=False)
    return buffer.getvalue()


def _b64(payload: bytes) -> bytes:
    """Base64 with the standard 76-character lines, so the bytes are reproducible."""
    return base64.encodebytes(payload)


def _reply_eml() -> bytes:
    """A complete reply with two decodable attachments: the acceptance case."""
    photo = _b64(_synthetic_png())
    work_order = _b64(
        b"%PDF-1.4\n% synthetic work order, not a real document\n"
        b"1 0 obj<</Type/Catalog>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n"
    )
    return b"".join(
        [
            b"From: Building Manager <manager@example-landlord.test>\r\n",
            b"To: tenant@example.test\r\n",
            b"Subject: Re: no heat in bedroom, unit 2C\r\n",
            b"Date: Fri, 02 Jan 2026 08:41:13 +0000\r\n",
            b"Message-ID: <20260102084113.9f3a@example-landlord.test>\r\n",
            b"MIME-Version: 1.0\r\n",
            b'Content-Type: multipart/mixed; boundary="=_habitable_reply_0"\r\n',
            b"\r\n",
            b"--=_habitable_reply_0\r\n",
            b'Content-Type: text/plain; charset="utf-8"\r\n',
            b"Content-Transfer-Encoding: 7bit\r\n",
            b"\r\n",
            b"We have your notice of 28 December about the bedroom radiator.\r\n"
            b"A contractor is booked for Thursday morning. Photograph of the\r\n"
            b"boiler and the work order are attached.\r\n",
            b"\r\n",
            b"--=_habitable_reply_0\r\n",
            b"Content-Type: image/png\r\n",
            b'Content-Disposition: attachment; filename="boiler.png"\r\n',
            b"Content-Transfer-Encoding: base64\r\n",
            b"\r\n",
            photo,
            b"\r\n--=_habitable_reply_0\r\n",
            b"Content-Type: application/pdf\r\n",
            b'Content-Disposition: attachment; filename="work-order-4471.pdf"\r\n',
            b"Content-Transfer-Encoding: base64\r\n",
            b"\r\n",
            work_order,
            b"\r\n--=_habitable_reply_0--\r\n",
        ]
    )


def _fragment_eml() -> bytes:
    """The complement: absent, unreadable, not_plain_text, and an undecodable part."""
    photo = _b64(_synthetic_png())
    return b"".join(
        [
            b"From: Building Manager <manager@example-landlord.test>\r\n",
            b"To: tenant@example.test\r\n",
            # Raw 8-bit bytes with no charset declared: readable as bytes, not as
            # characters, which is what "unreadable" means here.
            b"Subject: humedad y moho en el ba\xf1o\r\n",
            # No Date: header at all. Absent is not the same fact as unreadable, and
            # neither is the same as a sender who wrote an empty value.
            b"Message-ID: <20260102091500.4c11@example-landlord.test>\r\n",
            b"MIME-Version: 1.0\r\n",
            b'Content-Type: multipart/mixed; boundary="=_habitable_fragment_0"\r\n',
            b"\r\n",
            b"--=_habitable_fragment_0\r\n",
            b'Content-Type: text/html; charset="utf-8"\r\n',
            b"Content-Transfer-Encoding: 7bit\r\n",
            b"\r\n",
            b"<html><body><p>Forwarded for your records.</p></body></html>\r\n",
            b"\r\n",
            b"--=_habitable_fragment_0\r\n",
            b"Content-Type: image/png\r\n",
            b'Content-Disposition: attachment; filename="bathroom.png"\r\n',
            b"Content-Transfer-Encoding: base64\r\n",
            b"\r\n",
            photo,
            b"\r\n--=_habitable_fragment_0\r\n",
            # A charset that does not exist. The bytes are in the sealed message and
            # this part is counted, but it cannot be decoded into content, so it is
            # named rather than sealed as its own item.
            b'Content-Type: text/plain; charset="x-nonesuch-8"\r\n',
            b'Content-Disposition: attachment; filename="notes.txt"\r\n',
            b"Content-Transfer-Encoding: 7bit\r\n",
            b"\r\n",
            b"illegible notes\r\n",
            b"\r\n--=_habitable_fragment_0--\r\n",
        ]
    )


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="golden-correspondence-packet-"))
    vault = Vault.create(
        work / "vault",
        "golden-passphrase",
        case_id="golden-correspondence-2C",
        unit="2C",
        time_source=_counter_ms(_FIXED_EPOCH * 1000),
    )
    issue = vault.document.add_issue(
        category="heat", room="bedroom", title="No heat", severity="severe"
    )
    vault.add_timeline_event(
        issue,
        event_type="notice_sent",
        text="repair notice posted and emailed to the managing agent",
        occurred_at="2025-12-28",
        source="firsthand",
    )
    vault.add_timeline_event(
        issue,
        event_type="response_received",
        text="managing agent replied by email with a photograph and a work order",
        occurred_at="2026-01-02",
        source="message",
    )

    tsa = LocalRfc3161TSA("golden-tsa", time_source=lambda: _FIXED_EPOCH)
    for name, body, title in (
        ("reply.eml", _reply_eml(), "Managing agent's reply of 2 January"),
        (
            "forwarded-fragment.eml",
            _fragment_eml(),
            "Forwarded message fragment, undated",
        ),
    ):
        path = work / name
        path.write_bytes(body)
        result = capture_correspondence(
            vault,
            path,
            issue_id=issue,
            artifact_type="landlord_response",
            title=title,
            source_assertion="Exported by the tenant from their own mailbox",
            occurred_at="2026-01-02",
            issuer="Building Manager (asserted by the sender's From header)",
            tsa=tsa,
        )
        print(
            f"{name}: {len(result.attachments)} of {result.declared} declared attachment(s) "
            f"sealed; {result.items} item(s)"
        )

    out = work / "packet"
    build_packet(vault, out, generated_at=_GENERATED_AT, make_pdf=False)

    # Commit only the verifiable, self-contained subset (mirrors the other fixtures).
    # The README is written by hand and is not regenerated, so it is preserved.
    readme = _GOLDEN / "README.md"
    kept_readme = readme.read_bytes() if readme.is_file() else None
    if _GOLDEN.exists():
        shutil.rmtree(_GOLDEN)
    (_GOLDEN / "media").mkdir(parents=True)
    if kept_readme is not None:
        readme.write_bytes(kept_readme)
    shutil.copy(out / "bundle.json", _GOLDEN / "bundle.json")
    shutil.copy(out / "bundle.sig.json", _GOLDEN / "bundle.sig.json")
    for media_file in sorted((out / "media").iterdir()):
        shutil.copy(media_file, _GOLDEN / "media" / media_file.name)

    print(f"wrote {_GOLDEN.relative_to(_ROOT)} (packet_version={PACKET_VERSION})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
