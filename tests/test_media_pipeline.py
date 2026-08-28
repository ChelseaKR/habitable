# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""EXP-07: the real audio/video evidence pipeline.

Exercises the full temporal-media path end to end -- capture, metadata-strip,
poster-frame extraction, packetize, verify -- plus the accessible HTML/PDF
rendering (transcript + poster frame). These tests require a real ffmpeg/ffprobe
on PATH and skip cleanly when it is absent (R-03: the media toolchain is an
optional dependency, never bundled).
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest

from habitable.canonical import JSONValue
from habitable.capture import capture
from habitable.config import SharingPolicy
from habitable.media import (
    extract_poster_frame,
    ffmpeg_available,
    make_shared_media_copy,
    probe_metadata,
)
from habitable.packet import build_packet
from habitable.tsa import LocalRfc3161TSA
from habitable.vault import Vault

# ffmpeg/ffprobe is an optional dependency (R-03), never bundled; the video/audio
# tests skip cleanly when it is absent rather than failing CI on machines without it.
requires_ffmpeg = pytest.mark.skipif(not ffmpeg_available(), reason="ffmpeg/ffprobe not installed")


@requires_ffmpeg
def test_probe_metadata_reports_location(make_mp4: Callable[..., Path]) -> None:
    with_loc = probe_metadata(make_mp4("loc.mp4", with_location=True))
    assert with_loc.has_location
    without = probe_metadata(make_mp4("plain.mp4", with_location=False))
    assert not without.has_location


@requires_ffmpeg
def test_make_shared_media_copy_strips_metadata(
    make_mp4: Callable[..., Path], tmp_path: Path
) -> None:
    from habitable.config import SharingPolicy

    source = make_mp4("threat.mp4", with_location=True, duration=2.0)
    dest = tmp_path / "shared.mp4"
    report = make_shared_media_copy(source, dest, SharingPolicy())
    assert dest.exists()
    # The shared copy must no longer disclose the source's embedded location.
    assert not probe_metadata(dest).has_location
    assert "gps" in report.removed
    assert report.source_had_location


@requires_ffmpeg
def test_poster_frame_extraction(make_mp4: Callable[..., Path], tmp_path: Path) -> None:
    poster = tmp_path / "poster.jpg"
    assert extract_poster_frame(make_mp4("clip.mp4", duration=2.0), poster)
    assert poster.exists() and poster.stat().st_size > 0


@requires_ffmpeg
def test_video_captures_packetizes_and_verifies(
    make_vault: Callable[..., Vault],
    make_mp4: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    vault = make_vault()
    issue = vault.document.add_issue(
        category="threat", room="hallway", title="Recorded threat", issue_id="i1"
    )
    transcript = "Landlord, 2026-06-01: 'I'm not fixing that, deal with it.'"
    capture(
        vault,
        make_mp4("threat.mp4", with_location=True, duration=2.0),
        issue_id=issue,
        tsa=local_tsa,
        transcript=transcript,
    )

    out = tmp_path / "packet"
    result = build_packet(vault, out, generated_at="2026-01-02T00:10:00Z")
    assert result.item_count == 1 and result.timestamped_count == 1

    bundle = json.loads((out / "bundle.json").read_text())
    item = bundle["items"][0]
    assert item["media_type"] == "video/mp4"
    assert item["transcript"] == transcript
    # A poster frame was extracted and bound in custody.
    assert item["poster_name"]
    assert (out / "media" / item["poster_name"]).exists()
    # The shared copy no longer leaks the source location.
    assert not probe_metadata(out / "media" / item["shared_name"]).has_location

    from habitable.verify import verify_packet

    report = verify_packet(out, trusted_certs=[local_tsa.certificate])
    assert report.ok and report.signature_ok and report.custody_ok
    assert report.verified_items == 1


@requires_ffmpeg
def test_audio_captures_and_verifies_with_transcript(
    make_vault: Callable[..., Vault],
    make_wav: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    vault = make_vault()
    issue = vault.document.add_issue(
        category="noise", room="unit", title="Furnace failing to ignite", issue_id="i1"
    )
    capture(
        vault,
        make_wav("furnace.wav"),
        issue_id=issue,
        tsa=local_tsa,
        transcript="Furnace clicks repeatedly without igniting.",
    )
    out = tmp_path / "packet"
    build_packet(vault, out, generated_at="2026-01-02T00:10:00Z")
    bundle = json.loads((out / "bundle.json").read_text())
    item = bundle["items"][0]
    assert item["media_type"] == "audio/wav"
    # Audio has no poster frame; the transcript is its accessible fallback.
    assert not item["poster_name"]
    assert item["transcript"]

    from habitable.verify import verify_packet

    report = verify_packet(out, trusted_certs=[local_tsa.certificate])
    assert report.ok and report.verified_items == 1


@requires_ffmpeg
def test_html_and_pdf_render_transcript_and_poster(
    make_vault: Callable[..., Vault],
    make_mp4: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    vault = make_vault()
    issue = vault.document.add_issue(
        category="threat", room="hallway", title="Recorded threat", issue_id="i1"
    )
    transcript = "Landlord refuses repair on camera."
    capture(
        vault, make_mp4("t.mp4", duration=2.0), issue_id=issue, tsa=local_tsa, transcript=transcript
    )
    out = tmp_path / "packet"
    build_packet(vault, out, generated_at="2026-01-02T00:10:00Z")

    html = (out / "packet.html").read_text()
    assert "Transcript" in html and transcript in html
    assert "Poster frame from evidence video" in html
    # The video is offered as a hash-verifiable download, never auto-embedded.
    assert "Download the video" in html
    # The PDF was produced.
    assert (out / "packet.pdf").exists()


def test_missing_ffmpeg_refuses_share_cleanly(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Without ffmpeg, sharing must raise a clear CaptureError -- never silently
    emit an unstripped copy."""
    from habitable import media
    from habitable.config import SharingPolicy
    from habitable.errors import CaptureError

    monkeypatch.setattr(media, "ffmpeg_available", lambda: False)
    src = tmp_path / "x.mp4"
    src.write_bytes(b"not-real-video")
    with pytest.raises(CaptureError, match="ffmpeg is not installed"):
        make_shared_media_copy(src, tmp_path / "out.mp4", SharingPolicy())
    # And poster extraction degrades to False rather than raising.
    assert extract_poster_frame(src, tmp_path / "poster.jpg") is False


@pytest.mark.parametrize(
    "failure",
    [subprocess.TimeoutExpired("ffmpeg", 120), OSError("cannot execute ffmpeg")],
)
def test_ffmpeg_process_failure_refuses_share_cleanly(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    failure: BaseException,
) -> None:
    from habitable import media
    from habitable.config import SharingPolicy
    from habitable.errors import CaptureError

    monkeypatch.setattr(media, "ffmpeg_available", lambda: True)
    monkeypatch.setattr(subprocess, "run", lambda *_a, **_kw: (_ for _ in ()).throw(failure))
    src = tmp_path / "x.mp4"
    src.write_bytes(b"not-real-video")
    destination = tmp_path / "out.mp4"

    with pytest.raises(CaptureError, match="ffmpeg could not strip metadata"):
        make_shared_media_copy(src, destination, SharingPolicy())
    assert not destination.exists()


def test_ffmpeg_available_is_boolean() -> None:
    assert isinstance(ffmpeg_available(), bool)


class TestPacketDisclosureMatchesWhatActuallyHappened:
    """Issue #211: the packet's headline metadata claim contradicted its own items.

    `packet.py::_disclosures` built the prominent "What this packet discloses"
    line purely from the configured `SharingPolicy`. Under a deliberate
    retain-metadata policy it said, of the whole packet:

        shared-copy policy permits embedded metadata, including location, to be
        retained

    But `media.make_shared_media_copy` runs ffmpeg with `-map_metadata -1`
    *unconditionally* — the still-image retention policy does not reach it — so
    every video and audio item in that same packet had all container metadata,
    GPS included, removed. Each item's own `stripped` field recorded the truth
    (`"all-container-metadata"`); only the summary a reader actually reads was
    wrong, inside a signed bundle whose Hard Rule #4 is that it "records its
    metadata handling".

    The concrete harm runs the surprising way round: a tenant who chose that
    policy *specifically to keep* a video's embedded GPS as evidence was told by
    their own packet that they had it.

    Tested against `_disclosures` directly rather than through a real export, so
    the assertion holds on a machine with no ffmpeg — which is exactly the
    machine where the video path is least exercised.
    """

    @staticmethod
    def _items(*stripped: str) -> list[dict[str, object]]:
        return [
            {"record_kind": "capture", "media_type": "video/mp4", "stripped": s, "sensor": None}
            for s in stripped
        ]

    @staticmethod
    def _disclose(items: list[dict[str, object]], policy: SharingPolicy) -> tuple[str, ...]:
        from habitable.disclosure import scope_statement
        from habitable.packet import _disclosures

        return _disclosures(
            cast("list[dict[str, JSONValue]]", items),
            policy,
            scope_statement("en", scope_type="unit"),
            include_originals=False,
            awaiting=0,
            total=len(items),
        )

    def test_retain_policy_does_not_claim_location_kept_in_a_stripped_video(self) -> None:
        notes = self._disclose(
            self._items("all-container-metadata"),
            SharingPolicy(strip_location=False, strip_all_metadata=False),
        )
        joined = " ".join(notes)
        # The retain claim must never stand as a whole-packet statement again. It is
        # matched as a complete note, because the corrected sentence legitimately
        # starts with the same words and then scopes itself.
        assert (
            "shared-copy policy permits embedded metadata, including location, to be retained"
            not in notes
        )
        assert "retained in still-image shared copies" in joined
        # ...and the packet must say what actually happened to the video.
        assert "video" in joined.casefold() or "audio" in joined.casefold()
        assert "all" in joined.casefold() and "strip" in joined.casefold()

    def test_a_still_only_packet_still_states_the_retain_policy_plainly(self) -> None:
        """The fix must not over-correct into claiming a strip that did not happen.

        With no video or audio item present, nothing was force-stripped, and the
        disclosure has to keep saying so — under-claiming disclosure is the same
        class of error as over-claiming it, pointed the other way.
        """
        stills: list[dict[str, object]] = [
            {
                "record_kind": "capture",
                "media_type": "image/jpeg",
                "stripped": "none",
                "sensor": None,
            }
        ]
        joined = " ".join(self._disclose(stills, SharingPolicy(False, False)))
        assert "retained" in joined
        assert "video" not in joined.casefold()

    def test_the_strip_location_branch_is_scoped_when_video_is_present(self) -> None:
        """The middle branch already said "still-image", but stopped short.

        It scoped its GPS claim correctly and then added "other embedded metadata
        may be retained" without scoping *that*, which is the same defect one
        clause along: for the video item, no other embedded metadata was retained.
        """
        joined = " ".join(
            self._disclose(
                self._items("all-container-metadata", "gps"),
                SharingPolicy(strip_location=True, strip_all_metadata=False),
            )
        )
        assert "still-image" in joined
        assert "video" in joined.casefold() or "audio" in joined.casefold()

    def test_strip_all_policy_is_unchanged(self) -> None:
        joined = " ".join(
            self._disclose(self._items("all-container-metadata"), SharingPolicy(True, True))
        )
        assert "all embedded metadata stripped from supported shared media" in joined
