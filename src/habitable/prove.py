# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Make the "ciphertext-only to relay" invariant externally demonstrable.

Two things live here, both fully local and network-free beyond a loopback relay:

- :func:`prove_no_plaintext` (E-07) fabricates a synthetic case seeded with
  distinctive plaintext *markers* — note text, an issue title, a source filename,
  the vault passphrase, the encrypted clock ``node_id``, and the raw image
  bytes — then runs a *real* sync round-trip through an in-process relay while a
  wire-tap records every byte that crosses the transport, verbatim, to a capture
  file. It then greps the captured bytes (raw, base64-encoded, and base64-decoded)
  for every marker. A single hit fails the check. The user can re-run the grep by
  hand with ``xxd``/``grep`` against the same file, and repeat it against a real
  remote relay with ``tcpdump`` (see ``docs/prove-no-plaintext.md``).

- :func:`data_flow_xray` (E-08) renders a per-component table of exactly what each
  part of habitable would expose externally, derived from the user's *own* vault
  (item counts, configured authorities). It performs no network calls and emits no
  telemetry — it is a personal, on-device data-flow X-ray.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path

from .capture import capture
from .demo import _make_photos
from .pairing import accept_pairing_material, create_pairing_material
from .relay import RelayStore, make_server
from .sync import RelayClient, sync
from .tsa import DevTSA
from .vault import Vault

__all__ = [
    "TCPDUMP_INSTRUCTIONS",
    "ProveReport",
    "data_flow_xray",
    "format_report",
    "prove_no_plaintext",
]

# Distinctive, easily-grepped plaintext markers seeded into the synthetic case.
# Fixed strings are exported so tests (and skeptics) can grep for them directly;
# node_id/fingerprint markers are derived at runtime from the fabricated vault.
_MARKER_NOTE = "PLAINTEXT-XRAY-note-black-mold-spreading-after-roof-leak"
_MARKER_TITLE = "PLAINTEXT-XRAY-title-uninhabitable-unit-4B-mold"
_MARKER_FILENAME = "PLAINTEXT-XRAY-ceiling-leak-source.jpg"
_MARKER_PASSPHRASE = "PLAINTEXT-XRAY-passphrase-must-never-leave-device"  # noqa: S105
_CASE_ID = "PLAINTEXT-XRAY-case-4B"
_CHANNEL = "prove-no-plaintext-room"


@dataclass(frozen=True, slots=True)
class ProveReport:
    """The outcome of a :func:`prove_no_plaintext` run."""

    capture_path: Path
    bytes_captured: int
    frame_count: int
    marker_names: tuple[str, ...]
    hits: tuple[tuple[str, str], ...]  # (marker_name, direction) for each plaintext hit

    @property
    def clean(self) -> bool:
        """True when no marker was found anywhere in the captured wire bytes."""
        return not self.hits

    @property
    def exit_code(self) -> int:
        return 0 if self.clean else 1


class _WireTap:
    """Wraps a transport, recording every byte it moves, verbatim, to a file.

    The capture file is the raw concatenation of every blob sent to or fetched from
    the relay — exactly what crosses the transport — so it can be inspected with
    ``xxd`` and ``grep`` with nothing added or reframed. Frames are also kept in
    memory so the scan can test each blob's base64-encoded and -decoded forms too.
    """

    def __init__(self, inner: RelayClient, capture_path: Path) -> None:
        self._inner = inner
        self._path = capture_path
        self.frames: list[tuple[str, bytes]] = []
        self._handle = capture_path.open("wb")

    def post(self, channel: str, blob: bytes) -> None:
        self._record("sent", blob)
        self._inner.post(channel, blob)

    def fetch(self, channel: str) -> list[bytes]:
        blobs = self._inner.fetch(channel)
        for blob in blobs:
            self._record("recv", blob)
        return blobs

    def _record(self, direction: str, blob: bytes) -> None:
        raw = bytes(blob)
        self.frames.append((direction, raw))
        self._handle.write(raw)
        self._handle.flush()

    def close(self) -> None:
        self._handle.close()

    @property
    def bytes_captured(self) -> int:
        return sum(len(blob) for _, blob in self.frames)


def _markers(vault: Vault, image_bytes: bytes) -> dict[str, bytes]:
    """Every plaintext that must NEVER appear on the wire to the relay."""
    return {
        "note-text": _MARKER_NOTE.encode(),
        "issue-title": _MARKER_TITLE.encode(),
        "source-filename": _MARKER_FILENAME.encode(),
        "vault-passphrase": _MARKER_PASSPHRASE.encode(),
        "case-id": _CASE_ID.encode(),
        "node-id": vault.document.clock.node_id.encode(),
        "device-fingerprint": vault.identity.public().fingerprint.encode(),
        "raw-image-bytes": image_bytes[:64],
        "base64-image-bytes": base64.b64encode(image_bytes)[:64],
    }


def _forms(blob: bytes) -> list[bytes]:
    """A blob as it might reveal plaintext: raw, base64-encoded, base64-decoded."""
    forms = [blob, base64.b64encode(blob)]
    with contextlib.suppress(binascii.Error, ValueError):
        forms.append(base64.b64decode(blob, validate=False))
    return forms


def _scan(
    frames: list[tuple[str, bytes]], markers: dict[str, bytes]
) -> tuple[tuple[str, str], ...]:
    hits: list[tuple[str, str]] = []
    for name, needle in markers.items():
        if not needle:
            continue
        for direction, blob in frames:
            if any(needle in form for form in _forms(blob)):
                hits.append((name, direction))
                break
    return tuple(hits)


def prove_no_plaintext(capture_dir: Path | None = None) -> ProveReport:
    """Run a real sync round-trip through an in-process relay and audit the wire.

    Everything is synthetic and offline: a loopback relay, an offline dev timestamp
    authority, and a fabricated case. The returned :class:`ProveReport` says how
    many bytes were captured, which markers were searched, and any hits (there must
    be none). The capture file is left on disk for independent inspection.
    """
    work = Path(tempfile.mkdtemp(prefix="habitable-prove-"))
    out_dir = Path(capture_dir) if capture_dir is not None else work
    out_dir.mkdir(parents=True, exist_ok=True)
    capture_path = out_dir / "relay-wire-capture.bin"

    store = RelayStore()
    server = make_server("127.0.0.1", 0, store)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    tap: _WireTap | None = None
    try:
        # Fabricate images with demo's helper, then give one a distinctive source
        # filename so we can prove even the vault-only filename never crosses.
        photos = _make_photos(work / "phone")
        marker_photo = photos[0].with_name(_MARKER_FILENAME)
        photos[0].rename(marker_photo)
        photos[0] = marker_photo

        tsa = DevTSA("prove-dev-tsa")
        alice = Vault.create(work / "alice", _MARKER_PASSPHRASE, case_id=_CASE_ID, unit="4B")
        bob = Vault.create(work / "bob", "prove-bob-passphrase", case_id=_CASE_ID, unit="4B")
        pairing = create_pairing_material(alice, bob.identity.public())
        accept_pairing_material(bob, pairing)

        issue = alice.document.add_issue(
            category="mold", room="bathroom", title=_MARKER_TITLE, severity="high"
        )
        alice.document.add_timeline_entry(issue, "observed", _MARKER_NOTE)
        alice.save()
        for photo in photos:
            capture(alice, photo, issue_id=issue, tsa=tsa)
        image_bytes = photos[0].read_bytes()

        markers = _markers(alice, image_bytes)

        client = RelayClient(f"http://127.0.0.1:{port}")
        tap = _WireTap(client, capture_path)
        # A real round-trip: Alice posts (sealed to Bob) and Bob syncs back.
        sync(alice, bob.identity.public(), tap, channel=_CHANNEL)
        sync(bob, alice.identity.public(), tap, channel=_CHANNEL)
        tap.close()

        hits = _scan(tap.frames, markers)
        return ProveReport(
            capture_path=capture_path,
            bytes_captured=tap.bytes_captured,
            frame_count=len(tap.frames),
            marker_names=tuple(markers),
            hits=hits,
        )
    finally:
        if tap is not None:
            tap.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


TCPDUMP_INSTRUCTIONS = """\
Repeat this against a real, remote relay (see docs/prove-no-plaintext.md):

  # 1. On the relay host, capture the traffic to a file while you sync:
  sudo tcpdump -i any -s 0 -w relay.pcap 'tcp port 8787'

  # 2. From your device, run a real sync through that relay:
  habitable sync --vault ./vault --peer <PEER-ID> --channel <ROOM> \\
      --relay http://<relay-host>:8787

  # 3. Stop tcpdump, then grep the raw capture for any of YOUR plaintext
  #    (a note you wrote, your unit number, a filename). It must not appear:
  strings relay.pcap | grep -i 'my-unit-4B'      # expect: no output
  tshark -r relay.pcap -T fields -e data | xxd   # inspect the bytes yourself

Over TLS the app-layer bytes are wrapped a second time; terminate TLS at the relay
(or capture on the loopback side) to inspect the habitable ciphertext directly."""


def format_report(report: ProveReport) -> str:
    """A human-readable summary of a prove run (used by the CLI and tests)."""
    lines = [
        "habitable prove-no-plaintext — synthetic case, in-process relay, no real data",
        "",
        f"  bytes captured on the wire : {report.bytes_captured}",
        f"  wire frames recorded       : {report.frame_count}",
        f"  markers searched           : {len(report.marker_names)}",
        f"  plaintext hits             : {len(report.hits)}",
        f"  capture file               : {report.capture_path}",
        "",
        "  markers (each must be absent from every captured byte):",
    ]
    lines.extend(f"    · {name}" for name in report.marker_names)
    lines.append("")
    if report.clean:
        lines.append("  RESULT: PASS — no plaintext marker reached the relay (ciphertext only).")
        lines.append("")
        lines.append("  Verify it yourself:")
        lines.append(f"    xxd {report.capture_path} | less")
        lines.append(f"    grep -a '{_MARKER_TITLE}' {report.capture_path}   # expect: no output")
    else:
        lines.append("  RESULT: FAIL — plaintext reached the relay:")
        lines.extend(
            f"    ✗ {name} appeared in a {direction} frame" for name, direction in report.hits
        )
    lines.append("")
    lines.append(TCPDUMP_INSTRUCTIONS)
    return "\n".join(lines)


def data_flow_xray(vault: Vault) -> str:
    """A fully-local, telemetry-free per-component view of what leaves the device.

    Every figure is read from the user's own vault; this function makes no network
    calls and records nothing. It is a personal data-flow X-ray (E-08).
    """
    captures = vault.document.captures()
    issues = vault.document.issues()
    timestamped = sum(1 for c in captures if vault.get_token(c.capture_id) is not None)
    authorities = vault.config.timestamp_authorities
    tsa_names = ", ".join(t.name for t in authorities) if authorities else "none configured"
    unit = vault.document.get_meta("unit") or vault.document.case_id

    rows = [
        (
            "on-device capture",
            "nothing",
            f"seal + SHA-256 run locally; {len(captures)} sealed originals stay in the vault",
        ),
        (
            "RFC 3161 timestamp",
            "a SHA-256 hash only",
            f"{timestamped}/{len(captures)} items stamped · authorities: {tsa_names}",
        ),
        (
            "relay sync (optional)",
            "sealed blobs + a mailbox id",
            f"{len(captures)} captures would sync as ciphertext sealed to a chosen peer; "
            "the relay also sees the room id and byte counts",
        ),
        (
            "packet export",
            "a full plaintext packet (you initiate)",
            f"{len(issues)} issues / {len(captures)} items; only when you run "
            "`habitable export`, with location stripped from shared copies",
        ),
    ]

    comp_w = max(len(r[0]) for r in rows)
    leaves_w = max(len(r[1]) for r in rows)
    header = f"  {'component'.ljust(comp_w)}  {'leaves the device'.ljust(leaves_w)}  details"
    rule = f"  {'-' * comp_w}  {'-' * leaves_w}  {'-' * 7}"
    lines = [
        f"data-flow X-ray for case {unit} — fully local, no network calls, no telemetry",
        "",
        header,
        rule,
    ]
    lines.extend(
        f"  {comp.ljust(comp_w)}  {leaves.ljust(leaves_w)}  {detail}"
        for comp, leaves, detail in rows
    )
    lines.append("")
    lines.append(
        "  Prove the relay row for real: `habitable prove-no-plaintext` "
        "(see docs/prove-no-plaintext.md)."
    )
    return "\n".join(lines)
