# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Parity gate: the in-browser verifier must agree with the Python verifier.

The zero-install verifier page (``site/verify/``) is a JavaScript port of the
Apache-2.0 verification subset. A second implementation is a correctness
liability (EXP-05), so this suite pins it to the same contract the Python
verifier is pinned to — ``docs/verifier-decision-table.md`` — by running both
over the golden corpus, freshly-built packets (RFC 3161 and dev tokens,
awaiting items, embedded originals), and hostile mutations, and requiring the
same verdict on every check.

Marked ``browser``: needs Playwright + Chromium (like the axe scans); skips
cleanly where they are unavailable, and runs for real in the a11y/browser CI job.
"""

from __future__ import annotations

import base64
import json
import shutil
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("playwright.sync_api")

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import Page, sync_playwright

from habitable.capture import capture
from habitable.errors import VerificationError
from habitable.packet import build_packet
from habitable.tsa import DevTSA, LocalRfc3161TSA
from habitable.vault import Vault
from habitable.verify import VerificationReport, verify_packet

_REPO = Path(__file__).resolve().parent.parent
_VERIFY_PAGE = _REPO / "site" / "verify" / "index.html"
_GOLDEN = Path(__file__).resolve().parent / "golden" / "packet-v1"

pytestmark = pytest.mark.browser


@pytest.fixture(scope="module")
def page() -> Iterator[Page]:
    with sync_playwright() as p:
        try:
            browser = p.chromium.launch()
        except PlaywrightError as exc:  # browser binary not installed
            pytest.skip(f"Chromium not available for the web-verifier parity gate: {exc}")
        try:
            page = browser.new_page()
            page.goto(_VERIFY_PAGE.as_uri(), wait_until="load")
            yield page
        finally:
            browser.close()


def _js_verify(page: Page, packet_dir: Path) -> dict[str, Any]:
    """Run the page's verifier over the packet directory's files."""
    entries = [
        {
            "path": str(path.relative_to(packet_dir)).replace("\\", "/"),
            "b64": base64.b64encode(path.read_bytes()).decode("ascii"),
        }
        for path in sorted(packet_dir.rglob("*"))
        if path.is_file()
    ]
    result: dict[str, Any] = page.evaluate(
        """
        async (entries) => {
          const files = entries.map((e) => ({
            path: e.path,
            bytes: Uint8Array.from(atob(e.b64), (c) => c.charCodeAt(0)),
          }));
          return await window.HabitableVerifier.verifyPacket(files);
        }
        """,
        entries,
    )
    return result


def _python_report(packet_dir: Path) -> VerificationReport:
    return verify_packet(packet_dir)


def _assert_parity(
    js: dict[str, Any], py: VerificationReport, *, compare_notes: bool = True
) -> None:
    assert "error" not in js, js
    assert js["ok"] == py.ok
    assert js["signature_ok"] == py.signature_ok
    assert js["custody_ok"] == py.custody_ok
    assert js["custody_length"] == py.custody_length
    assert js["verified_items"] == py.verified_items
    assert js["item_count"] == len(py.items)
    assert js["problems"] == list(py.problems)
    assert js["summary"] == py.summary()
    assert js["browser_limits"] == []  # every check must have actually run
    assert len(js["items"]) == len(py.items)
    for js_item, py_item in zip(js["items"], py.items, strict=True):
        assert js_item["capture_id"] == py_item.capture_id
        assert js_item["content_hash"] == py_item.content_hash
        assert js_item["ok"] == py_item.ok
        assert js_item["timestamp_verified"] == py_item.timestamp_verified
        assert js_item["gen_time"] == py_item.gen_time
        assert js_item["tsa_name"] == py_item.tsa_name
        assert js_item["shared_media_ok"] == py_item.shared_media_ok
        assert js_item["custody_binding_ok"] == py_item.custody_binding_ok
        assert js_item["original_fixity_ok"] == py_item.original_fixity_ok
        assert js_item["verified_authorities"] == list(py_item.verified_authorities)
        if compare_notes:
            assert js_item["notes"] == list(py_item.notes)


def test_golden_packet_parity(page: Page) -> None:
    """Both verifiers call the committed golden packet intact, check for check."""
    py = _python_report(_GOLDEN)
    assert py.ok  # the corpus contract, restated here so parity means something
    _assert_parity(_js_verify(page, _GOLDEN), py)


def test_fresh_rfc3161_packet_with_originals_parity(
    page: Page,
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    vault = make_vault()
    issue = vault.document.add_issue(category="mold", title="Mold", issue_id="i1")
    capture(vault, make_jpeg("a.jpg", with_location=True), issue_id=issue, tsa=local_tsa)
    capture(vault, make_jpeg("b.jpg", color=(10, 90, 30)), issue_id=issue, tsa=local_tsa)
    out = tmp_path / "packet"
    build_packet(vault, out, include_originals=True, generated_at="2026-01-02T00:10:00Z")

    py = _python_report(out)
    assert py.ok and all(item.original_fixity_ok is True for item in py.items)
    _assert_parity(_js_verify(page, out), py)


def test_dev_token_packet_parity(
    page: Page,
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    dev_tsa: DevTSA,
    tmp_path: Path,
) -> None:
    """The Ed25519 dev-token path verifies identically in both implementations."""
    vault = make_vault()
    issue = vault.document.add_issue(category="heat", title="No heat", issue_id="i1")
    capture(vault, make_jpeg("a.jpg"), issue_id=issue, tsa=dev_tsa)
    out = tmp_path / "packet"
    build_packet(vault, out, generated_at="2026-01-02T00:10:00Z")

    py = _python_report(out)
    assert py.ok
    _assert_parity(_js_verify(page, out), py)


def test_awaiting_timestamp_packet_parity(
    page: Page,
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    """A degraded (awaiting-timestamp) packet is NOT intact in both, identically."""
    vault = make_vault()
    issue = vault.document.add_issue(category="mold", title="Mold", issue_id="i1")
    capture(vault, make_jpeg("a.jpg"), issue_id=issue, tsa=local_tsa)
    capture(vault, make_jpeg("b.jpg", color=(10, 90, 30)), issue_id=issue, tsa=None)
    out = tmp_path / "packet"
    build_packet(vault, out, generated_at="2026-01-02T00:10:00Z")

    py = _python_report(out)
    assert not py.ok and py.signature_ok and py.custody_ok
    assert any("awaiting timestamp" in note for item in py.items for note in item.notes)
    _assert_parity(_js_verify(page, out), py)


def _mutated_golden(tmp_path: Path, mutate: Callable[[Path], object]) -> Path:
    dst = tmp_path / "mutated"
    shutil.copytree(_GOLDEN, dst)
    mutate(dst)
    return dst


def _edit_bundle(packet: Path, edit: Callable[[dict[str, Any]], None]) -> None:
    bundle_path = packet / "bundle.json"
    bundle = json.loads(bundle_path.read_text())
    edit(bundle)
    bundle_path.write_text(json.dumps(bundle))


def test_tampered_media_parity(page: Page, tmp_path: Path) -> None:
    def mutate(packet: Path) -> None:
        media = next((packet / "media").iterdir())
        data = bytearray(media.read_bytes())
        data[100] ^= 0xFF
        media.write_bytes(bytes(data))

    packet = _mutated_golden(tmp_path, mutate)
    py = _python_report(packet)
    assert not py.ok and not py.items[0].shared_media_ok
    _assert_parity(_js_verify(page, packet), py)


def test_tampered_custody_parity(page: Page, tmp_path: Path) -> None:
    def mutate(packet: Path) -> None:
        _edit_bundle(packet, lambda b: b["custody_proof"]["entries"][1].update(action="viewed"))

    packet = _mutated_golden(tmp_path, mutate)
    py = _python_report(packet)
    assert not py.ok and not py.custody_ok and not py.signature_ok
    # Note text for a re-serialized bundle can differ; the verdicts must not.
    _assert_parity(_js_verify(page, packet), py, compare_notes=False)


def test_future_version_parity(page: Page, tmp_path: Path) -> None:
    def mutate(packet: Path) -> None:
        _edit_bundle(packet, lambda b: b.update(packet_version=999))

    packet = _mutated_golden(tmp_path, mutate)
    py = _python_report(packet)
    assert not py.ok and any("newer than supported" in p for p in py.problems)
    _assert_parity(_js_verify(page, packet), py)


def test_missing_signature_parity(page: Page, tmp_path: Path) -> None:
    packet = _mutated_golden(tmp_path, lambda p: (p / "bundle.sig.json").unlink())
    py = _python_report(packet)
    assert not py.ok and not py.signature_ok
    _assert_parity(_js_verify(page, packet), py)


def test_missing_bundle_is_could_not_verify(page: Page, tmp_path: Path) -> None:
    """Python raises VerificationError; the page reports a clean 'could not verify'."""
    packet = _mutated_golden(tmp_path, lambda p: (p / "bundle.json").unlink())
    with pytest.raises(VerificationError):
        verify_packet(packet)
    js = _js_verify(page, packet)
    assert js.get("error", "").startswith("no bundle.json")


def test_invalid_bundle_json_is_could_not_verify(page: Page, tmp_path: Path) -> None:
    packet = _mutated_golden(tmp_path, lambda p: (p / "bundle.json").write_bytes(b"{not json"))
    with pytest.raises(VerificationError):
        verify_packet(packet)
    js = _js_verify(page, packet)
    assert js.get("error", "").startswith("bundle is not valid JSON")


def test_page_end_to_end_with_file_picker(page: Page) -> None:
    """The real UI path: choose the golden packet's files, read the verdict."""
    files = [str(path) for path in sorted(_GOLDEN.rglob("*")) if path.is_file()]
    page.set_input_files("#files-input", files)
    page.wait_for_selector('#result[data-state="intact"]', timeout=15000)
    assert page.locator("#verdict").inner_text() == "Packet intact"
    assert "packet intact" in page.locator("#summary").inner_text()
    report = json.loads(page.locator("#report-json").inner_text())
    assert report["ok"] is True and report["browser_limits"] == []
