# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""E-07/E-08: externally demonstrable no-plaintext-to-relay and the data-flow X-ray."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from habitable import prove
from habitable import sync as sync_mod
from habitable.cli import main
from habitable.prove import (
    ProveReport,
    data_flow_xray,
    format_report,
    prove_no_plaintext,
)
from habitable.vault import Vault


def test_prove_no_plaintext_is_clean(tmp_path: Path) -> None:
    report = prove_no_plaintext(tmp_path / "capture")

    assert isinstance(report, ProveReport)
    assert report.clean
    assert report.exit_code == 0
    assert report.hits == ()
    assert report.bytes_captured > 0
    assert report.frame_count > 0
    # "Every documented marker was actually searched" is what this used to
    # claim, over `marker_names` -- the *declared* set. `_scan` skips a marker
    # whose value is empty, so the two are different lists and the comment was
    # false of the assertion below it. Assert the searched set instead.
    assert report.unsearchable == ()
    assert report.searched_names == report.marker_names
    assert len(report.searched_names) >= 8
    assert "note-text" in report.searched_names
    assert "device-fingerprint" in report.searched_names

    # The capture file exists, holds the wire bytes, and greps clean.
    raw = report.capture_path.read_bytes()
    assert len(raw) == report.bytes_captured
    assert prove._MARKER_TITLE.encode() not in raw
    assert prove._MARKER_NOTE.encode() not in raw
    assert prove._MARKER_PASSPHRASE.encode() not in raw


def test_report_text_lists_markers_and_result(tmp_path: Path) -> None:
    text = format_report(prove_no_plaintext(tmp_path / "cap"))
    assert "PASS" in text
    assert "bytes captured on the wire" in text
    assert "tcpdump" in text
    for name in ("note-text", "device-fingerprint", "raw-image-bytes"):
        assert name in text


def test_prove_detects_a_deliberate_plaintext_leak(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If sealing is bypassed so plaintext hits the wire, the check must fail."""
    real_export = sync_mod.export_message

    def leaky_export(vault: Vault, recipient: object) -> bytes:
        sealed = real_export(vault, recipient)  # type: ignore[arg-type]
        # A bug that leaks a distinctive plaintext marker onto the wire.
        return b"LEAK:" + prove._MARKER_NOTE.encode() + b":" + sealed

    monkeypatch.setattr("habitable.sync.export_message", leaky_export)

    report = prove_no_plaintext(tmp_path / "leak")
    assert not report.clean
    assert report.exit_code == 1
    leaked = {name for name, _ in report.hits}
    assert "note-text" in leaked
    # The leak is visible in the raw capture file too.
    assert prove._MARKER_NOTE.encode() in report.capture_path.read_bytes()


def test_cli_prove_exit_zero_and_report(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["prove-no-plaintext", "--capture-dir", str(tmp_path / "cli-cap")])
    out = capsys.readouterr().out
    assert code == 0
    assert "prove-no-plaintext" in out
    assert "markers searched" in out
    assert "PASS" in out


def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make any outbound HTTP call blow up, so we can assert none happens."""

    def _boom(*_a: object, **_k: object) -> object:
        raise AssertionError("data-flow X-ray must not touch the network")

    monkeypatch.setattr("urllib.request.urlopen", _boom)


def test_xray_lists_all_components_without_network(
    make_vault: Callable[..., Vault], monkeypatch: pytest.MonkeyPatch
) -> None:
    _no_network(monkeypatch)
    vault = make_vault("A")
    vault.document.add_issue(category="mold", room="bath", title="leak", issue_id="i1")

    text = data_flow_xray(vault)

    for component in ("on-device capture", "RFC 3161 timestamp", "relay sync", "packet export"):
        assert component in text
    assert "no telemetry" in text
    assert "sealed blobs" in text
    assert "SHA-256 hash only" in text


def test_cli_status_xray_no_network(
    make_vault: Callable[..., Vault],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _no_network(monkeypatch)
    vault = make_vault("A")
    code = main(["status", "--vault", str(vault.path), "--passphrase", "test-passphrase", "--xray"])
    out = capsys.readouterr().out
    assert code == 0
    assert "data-flow X-ray" in out
    assert "relay sync (optional)" in out


# --------------------------------------------------------------------------- #
# A marker nobody looked for cannot count toward a PASS.                        #
# --------------------------------------------------------------------------- #
def test_a_marker_that_could_not_be_searched_sinks_the_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`_scan` skips an empty needle, and the skip used to be silent.

    Skipping is correct — ``b"" in blob`` is true of every blob, so an empty
    marker would report a hit against everything. What was wrong is that the
    name still appeared in the report's "markers searched" count and under
    "each must be absent from every captured byte", and ``clean`` was true
    because ``hits`` was empty. Two of the nine markers are derived at runtime
    from the fabricated vault (``raw-image-bytes`` and ``base64-image-bytes``),
    so one can be emptied by a change upstream of this function, and this is
    the project's externally demonstrable privacy proof.
    """
    real_markers = prove._markers

    def one_marker_empty(vault: Vault, image_bytes: bytes) -> dict[str, bytes]:
        markers = real_markers(vault, image_bytes)
        markers["raw-image-bytes"] = b""
        return markers

    monkeypatch.setattr(prove, "_markers", one_marker_empty)
    report = prove_no_plaintext(tmp_path / "capture")

    assert report.hits == ()  # nothing leaked...
    assert report.unsearchable == ("raw-image-bytes",)  # ...but one was never looked for
    assert not report.clean
    assert report.exit_code == 1
    assert "raw-image-bytes" not in report.searched_names
    assert len(report.searched_names) == len(report.marker_names) - 1


def test_the_report_says_which_marker_it_could_not_search(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_markers = prove._markers

    def one_marker_empty(vault: Vault, image_bytes: bytes) -> dict[str, bytes]:
        markers = real_markers(vault, image_bytes)
        markers["node-id"] = b""
        return markers

    monkeypatch.setattr(prove, "_markers", one_marker_empty)
    text = format_report(prove_no_plaintext(tmp_path / "capture"))

    assert "PASS" not in text
    assert "could NOT be searched" in text
    assert "node-id was never searched for" in text
    # The heading over the bullet list says "each must be absent from every
    # captured byte". A marker nobody searched for must not be under it -- that
    # sentence is the claim this run cannot make about it.
    assert "    · node-id" not in text
    assert "    ? node-id" in text
    assert "    · note-text" in text  # the ones that *were* searched still are
    # The count is the searched set over the declared set, not the declared set
    # printed twice.
    assert "markers searched           : 8 of 9" in text


def test_an_ordinary_run_still_reports_pass_over_every_marker(tmp_path: Path) -> None:
    """The complement. Without it, a check that always failed would satisfy the
    two tests above, and the proof this command exists to give would be gone."""
    report = prove_no_plaintext(tmp_path / "capture")
    text = format_report(report)
    assert report.clean and report.exit_code == 0
    assert report.unsearchable == ()
    assert "RESULT: PASS" in text
    assert "could NOT be searched" not in text
    assert f"markers searched           : {len(report.marker_names)} of " in text
