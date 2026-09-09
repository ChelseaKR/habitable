# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""RR-07: "is this case safely on more than one device?"

The answer is built from receipts a peer signed, never from the pairing list,
and every unmeasurable input -- a missing observation, a peer clock in the
future, a transport nobody recorded -- must be reported as unmeasurable rather
than as a value.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest

from habitable.canonical import JSONValue, canonical_json
from habitable.cli import main
from habitable.crypto import PublicIdentity
from habitable.errors import SyncError
from habitable.packet import build_packet
from habitable.pairing import accept_pairing_material, create_pairing_material
from habitable.sync import (
    LocalDirTransport,
    PaddingTransport,
    export_message,
    import_messages,
    sync,
    transport_label,
)
from habitable.syncstate import CLOCK_SKEW_TOLERANCE_MS, redundancy_from_peers
from habitable.vault import Vault
from habitable.verify import verify_packet

# The same fixed epoch the rest of the suite pins to, kept local rather than
# imported from conftest: `tests/` is not a package, so a relative import here
# works only by accident of rootdir configuration.
_BASE_MS = 1_767_312_000 * 1000


def counter_clock(start_ms: int) -> Callable[[], int]:
    """A deterministic millisecond clock advancing 1 ms per read."""
    state = {"t": start_ms}

    def tick() -> int:
        state["t"] += 1
        return state["t"]

    return tick


def _pair(tmp_path: Path, *, skew_ms: int = 0) -> tuple[Vault, Vault]:
    """Two paired vaults on the same case with clocks I control exactly.

    The shared ``make_vault`` fixture spaces each vault's clock 1000 s apart,
    which is past the skew tolerance -- fine for the code, useless for a test
    that needs to distinguish "the peer's clock is a little off" from "the
    peer's clock is not usable". So this builds the pair by hand.
    """
    a = Vault.create(
        tmp_path / "a",
        "pw-a",
        case_id="case-4B",
        unit="4B",
        time_source=counter_clock(_BASE_MS),
    )
    b = Vault.create(
        tmp_path / "b",
        "pw-b",
        case_id="case-4B",
        unit="4B",
        time_source=counter_clock(_BASE_MS + skew_ms),
    )
    # One signed, sealed invitation authorizes both directions: the issuer
    # allowlists the recipient, and accepting allowlists the issuer.
    accept_pairing_material(b, create_pairing_material(a, b.identity.public()))
    return a, b


def _round_trip(a: Vault, b: Vault, *, transport: str | None = "file") -> None:
    """a -> b, then b -> a, so ``a`` ends up holding b's signed receipt.

    Driven through ``export_message``/``import_messages`` rather than
    :func:`sync`, because a mailbox exchange needs a fourth leg before the
    receipt b queues on import actually rides back: b's outbound message is
    built *before* it imports a's. :func:`test_a_directory_sync_records_the_file_transport`
    drives the real transport end to end.
    """
    import_messages(b, [export_message(a, b.identity.public())], transport=transport)
    import_messages(a, [export_message(b, a.identity.public())], transport=transport)


def _sole_peer_record(vault: Vault, peer: PublicIdentity) -> dict[str, JSONValue]:
    record = vault.sync_peer(peer)
    assert record is not None
    assert len(record.verified_receipts) == 1
    return next(iter(record.verified_receipts.values()))


# --- pairing is not a copy -------------------------------------------------------


def test_a_paired_peer_that_never_synced_is_not_a_copy(tmp_path: Path) -> None:
    """The defect this feature exists to avoid.

    Counting the pairing list would answer "this case is on 2 devices" for a
    vault whose peer has never received a single byte.
    """
    a, _b = _pair(tmp_path)

    redundancy = a.sync_redundancy()

    assert redundancy.paired_count == 1
    assert redundancy.confirmed_count == 0
    assert redundancy.device_count == 1
    assert redundancy.single_device is True
    assert redundancy.last_peer is None
    assert redundancy.last_observed_at_ms is None


def test_a_returned_receipt_makes_the_case_two_devices(tmp_path: Path) -> None:
    a, b = _pair(tmp_path)
    a.document.add_issue(category="mold", room="bath", issue_id="i1")
    a.save()

    _round_trip(a, b)

    redundancy = a.sync_redundancy()
    assert redundancy.confirmed_count == 1
    assert redundancy.device_count == 2
    assert redundancy.single_device is False
    peer = redundancy.last_peer
    assert peer is not None
    assert peer.fingerprint == b.identity.public().fingerprint
    assert peer.confirmed is True
    assert peer.custody_head is not None


def test_both_devices_confirm_each_other_after_a_reciprocal_exchange(tmp_path: Path) -> None:
    a, b = _pair(tmp_path)
    a.document.add_issue(category="mold", room="bath", issue_id="i1")
    a.save()

    _round_trip(a, b)
    # One more leg: a's own receipt for b's message rides back on a's next delta.
    import_messages(b, [export_message(a, b.identity.public())], transport="file")

    assert a.sync_redundancy().device_count == 2
    assert b.sync_redundancy().device_count == 2


def test_a_tampered_receipt_is_refused_and_never_counted(tmp_path: Path) -> None:
    """A receipt whose signed payload was edited must not become a device."""
    a, b = _pair(tmp_path)
    transport = LocalDirTransport(tmp_path / "mbox")
    sync(a, b.identity.public(), transport, channel="room")
    import_messages(b, transport.fetch("room"))

    peer = b.sync_peer(a.identity.public())
    assert peer is not None
    message_id, receipt = next(iter(peer.pending_receipts.items()))
    payload = cast(dict[str, JSONValue], receipt["payload"])
    # Assert the edit actually changes the payload. The first version of this
    # test wrote 64 zeros into `custody_head_after_import` -- which is exactly
    # what an empty custody log already reports -- so the "tampered" receipt was
    # byte-identical, verified correctly, and the test read as a passing guard.
    before = payload["custody_head_after_import"]
    payload["custody_head_after_import"] = "f" * 64
    assert payload["custody_head_after_import"] != before
    peer.pending_receipts[message_id] = receipt
    b.save()

    reply = export_message(b, a.identity.public())
    with pytest.raises(SyncError, match="signature is invalid"):
        import_messages(a, [reply])
    assert a.sync_redundancy().single_device is True


# --- the receipt stayed compatible in both directions ----------------------------


def test_a_receipt_without_the_watermark_still_validates(tmp_path: Path) -> None:
    """A peer on the previous build signs a payload with no watermark.

    The field is additive and the protocol tag is unchanged, so this must be
    accepted -- otherwise the field is a silent protocol break that only shows
    up when half a union has updated.
    """
    a, b = _pair(tmp_path)
    outbound = export_message(a, b.identity.public())
    import_messages(b, [outbound])

    peer = b.sync_peer(a.identity.public())
    assert peer is not None
    message_id, receipt = next(iter(peer.pending_receipts.items()))
    payload = cast(dict[str, JSONValue], receipt["payload"])
    assert "importer_hlc_watermark" in payload
    del payload["importer_hlc_watermark"]
    # Re-sign, because the old build signed a payload that never had the field --
    # this is a compatibility test, not a tampering test.
    receipt["signature_b64"] = base64.b64encode(b.identity.sign(canonical_json(payload))).decode(
        "ascii"
    )
    peer.pending_receipts[message_id] = receipt
    b.save()

    assert import_messages(a, [export_message(b, a.identity.public())]).receipts_received == 1
    holding = a.sync_redundancy().peers[0]
    assert holding.confirmed is True
    assert holding.claimed_clock_state == "absent"


def test_a_receipt_carrying_an_unknown_field_still_validates(tmp_path: Path) -> None:
    """The reverse direction: a future build adds another field to the payload.

    Validation reads named fields and re-canonicalizes the payload as received,
    so an unknown key must ride through rather than being rejected as malformed.
    """
    a, b = _pair(tmp_path)
    outbound = export_message(a, b.identity.public())
    import_messages(b, [outbound])

    peer = b.sync_peer(a.identity.public())
    assert peer is not None
    message_id, receipt = next(iter(peer.pending_receipts.items()))
    payload = cast(dict[str, JSONValue], receipt["payload"])
    payload["some_field_from_a_later_build"] = "value"
    receipt["signature_b64"] = base64.b64encode(b.identity.sign(canonical_json(payload))).decode(
        "ascii"
    )
    peer.pending_receipts[message_id] = receipt
    b.save()

    assert import_messages(a, [export_message(b, a.identity.public())]).receipts_received == 1
    assert a.sync_redundancy().device_count == 2


# --- the two clocks stay apart ---------------------------------------------------


def test_the_recorded_time_is_this_device_s_clock_not_the_peer_s(tmp_path: Path) -> None:
    """The peer signs its own watermark; it does not set our clock."""
    skew = 60_000  # inside tolerance, so the peer's claim is usable and still different
    a, b = _pair(tmp_path, skew_ms=skew)
    _round_trip(a, b)

    peer = a.sync_redundancy().last_peer
    assert peer is not None
    assert peer.observed_at_ms is not None
    # Our own clock started at _BASE_MS and ticks 1 ms per read.
    assert _BASE_MS <= peer.observed_at_ms < _BASE_MS + skew
    assert peer.claimed_clock_state == "present"
    assert peer.claimed_clock_ms is not None
    assert peer.claimed_clock_ms > peer.observed_at_ms


def test_the_skew_tolerance_is_five_minutes() -> None:
    """Pinned by value, because no property test can catch a wrong constant.

    A tolerance raised past the skew the test below uses would make that test
    pass with a future clock accepted, and nothing else in the suite would
    notice.
    """
    assert CLOCK_SKEW_TOLERANCE_MS == 300_000


def test_a_peer_clock_far_in_the_future_is_unusable_not_fresh(tmp_path: Path) -> None:
    """A future timestamp is a broken clock, not a recent sync.

    Without this, a peer whose clock is wrong (or lying) reads as permanently
    up to date, because a negative age satisfies every "younger than" test.

    The skew is a literal hour rather than ``CLOCK_SKEW_TOLERANCE_MS + n``:
    written against the constant, raising the constant raises the fixture with
    it and the test can never fail, however wrong the tolerance becomes.
    """
    a, b = _pair(tmp_path, skew_ms=3_600_000)
    _round_trip(a, b)

    peer = a.sync_redundancy().last_peer
    assert peer is not None
    assert peer.claimed_clock_state == "ahead"
    assert peer.claimed_clock_ms is None
    # Still a real copy: the signature is valid, only the peer's clock is not.
    assert peer.confirmed is True
    assert a.sync_redundancy().device_count == 2


@pytest.mark.parametrize(
    ("watermark", "expected"),
    [
        (None, "absent"),
        (12345, "malformed"),
        ("not-an-hlc", "malformed"),
        ("000000000000001.000000", "malformed"),
        ("abc.000000.node", "malformed"),
        ("000000000000001.xyz.node", "malformed"),
        ("-000000000000001.000000.node", "malformed"),
        ("000000000000001.000000.", "malformed"),
    ],
)
def test_an_unusable_watermark_is_named_never_guessed(
    tmp_path: Path, watermark: object, expected: str
) -> None:
    a, b = _pair(tmp_path)
    _round_trip(a, b)

    receipt = _sole_peer_record(a, b.identity.public())
    payload = cast(dict[str, JSONValue], receipt["payload"])
    if watermark is None:
        del payload["importer_hlc_watermark"]
    else:
        payload["importer_hlc_watermark"] = cast(JSONValue, watermark)

    peer = a.sync_redundancy().last_peer
    assert peer is not None
    assert peer.claimed_clock_state == expected
    assert peer.claimed_clock_ms is None


# --- absence is never rendered as a value ----------------------------------------


def test_a_receipt_with_no_recorded_observation_reports_no_time(tmp_path: Path) -> None:
    """A vault written before observations existed still knows it has a copy."""
    a, b = _pair(tmp_path)
    _round_trip(a, b)
    record = a.sync_peer(b.identity.public())
    assert record is not None
    record.receipt_observations.clear()

    redundancy = a.sync_redundancy()
    assert redundancy.confirmed_count == 1
    assert redundancy.device_count == 2
    assert redundancy.last_observed_at_ms is None
    assert redundancy.last_peer is None
    assert redundancy.peers[0].observed_at_ms is None


@pytest.mark.parametrize("bad", [True, False, 0, -1, "1767312000000", None, {"ms": 1}])
def test_an_unusable_observation_is_not_a_timestamp(tmp_path: Path, bad: object) -> None:
    """``True`` is an ``int`` in Python; a bool must not read as a millisecond."""
    a, b = _pair(tmp_path)
    _round_trip(a, b)
    record = a.sync_peer(b.identity.public())
    assert record is not None
    message_id = next(iter(record.receipt_observations))
    record.receipt_observations[message_id] = {"observed_at_ms": cast(JSONValue, bad)}

    assert a.sync_redundancy().peers[0].observed_at_ms is None
    assert a.sync_redundancy().last_observed_at_ms is None


@pytest.mark.parametrize("bad", ["", 7, None])
def test_an_unusable_transport_is_omitted_not_invented(tmp_path: Path, bad: object) -> None:
    a, b = _pair(tmp_path)
    _round_trip(a, b)
    record = a.sync_peer(b.identity.public())
    assert record is not None
    message_id = next(iter(record.receipt_observations))
    record.receipt_observations[message_id] = {
        "observed_at_ms": _BASE_MS,
        "transport": cast(JSONValue, bad),
    }

    assert a.sync_redundancy().peers[0].transport is None


def test_no_peers_at_all_is_one_device_and_zero_paired(tmp_path: Path) -> None:
    vault = Vault.create(
        tmp_path / "solo", "pw", case_id="c", unit="1", time_source=counter_clock(_BASE_MS)
    )
    redundancy = vault.sync_redundancy()
    assert redundancy.paired_count == 0
    assert redundancy.device_count == 1
    assert redundancy.single_device is True


def test_redundancy_is_ordered_by_fingerprint_not_dict_order() -> None:
    """Two peers must render in a stable order across runs and processes."""
    from habitable.syncstate import PeerAuthorization

    peers = {
        "ffff-0000-0000-0000": PeerAuthorization("id-f", "p1", b"\x01" * 32),
        "0000-ffff-ffff-ffff": PeerAuthorization("id-0", "p2", b"\x02" * 32),
    }
    holdings = redundancy_from_peers(peers, now_ms=_BASE_MS).peers
    assert [holding.fingerprint for holding in holdings] == [
        "0000-ffff-ffff-ffff",
        "ffff-0000-0000-0000",
    ]


# --- persistence ------------------------------------------------------------------


def test_observations_survive_save_and_reopen(tmp_path: Path) -> None:
    a, b = _pair(tmp_path)
    _round_trip(a, b)
    before = a.sync_redundancy().last_peer
    assert before is not None

    reopened = Vault.open(tmp_path / "a", "pw-a", time_source=counter_clock(_BASE_MS))
    after = reopened.sync_redundancy().last_peer

    assert after is not None
    assert after.fingerprint == before.fingerprint
    assert after.observed_at_ms == before.observed_at_ms
    assert after.transport == before.transport


# --- transports name themselves ---------------------------------------------------


def test_a_directory_sync_records_the_file_transport(tmp_path: Path) -> None:
    """The real transport, end to end, naming itself through :func:`sync`."""
    a, b = _pair(tmp_path)
    transport = LocalDirTransport(tmp_path / "mbox")
    sync(a, b.identity.public(), transport, channel="room")
    # b's outbound delta is built before it imports, so the receipt it queues
    # here does not ride until the next leg.
    sync(b, a.identity.public(), transport, channel="room")
    sync(b, a.identity.public(), transport, channel="room")
    sync(a, b.identity.public(), transport, channel="room")

    peer = a.sync_redundancy().last_peer
    assert peer is not None
    assert peer.confirmed is True
    assert peer.transport == "file"


def test_padding_reports_the_route_it_wraps_not_itself(tmp_path: Path) -> None:
    inner = LocalDirTransport(tmp_path / "mbox")
    assert transport_label(PaddingTransport(inner)) == "file"


def test_a_transport_with_no_label_records_none() -> None:
    class Nameless:
        def post(self, channel: str, blob: bytes) -> None: ...

        def fetch(self, channel: str) -> list[bytes]:
            return []

    assert transport_label(Nameless()) is None
    assert transport_label(object()) is None


def test_a_non_string_label_is_refused(tmp_path: Path) -> None:
    class Numbered(LocalDirTransport):
        label = 7  # type: ignore[assignment]

    assert transport_label(Numbered(tmp_path / "mbox")) is None


def test_import_without_a_transport_records_no_transport(tmp_path: Path) -> None:
    """``import_messages`` is a public entry point; a caller may not know."""
    a, b = _pair(tmp_path)
    _round_trip(a, b, transport=None)

    peer = a.sync_redundancy().last_peer
    assert peer is not None
    assert peer.observed_at_ms is not None
    assert peer.transport is None


# --- the surfaces -----------------------------------------------------------------


def test_status_says_this_device_only_before_any_sync(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    a, _b = _pair(tmp_path)
    assert main(["status", "--vault", str(a.path), "--passphrase", "pw-a"]) == 0
    out = capsys.readouterr().out
    assert "this device only" in out
    assert "1 peer is paired" in out
    assert "on 2 devices" not in out


def test_status_says_this_device_only_in_spanish(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    a, _b = _pair(tmp_path)
    monkeypatch.setenv("HABITABLE_LANG", "es")
    assert main(["status", "--vault", str(a.path), "--passphrase", "pw-a"]) == 0
    out = capsys.readouterr().out
    assert "solo este dispositivo" in out
    assert "hay 1 dispositivo vinculado" in out


def test_status_names_the_confirming_peer_and_the_transport(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    a, b = _pair(tmp_path, skew_ms=1000)
    _round_trip(a, b)
    assert main(["status", "--vault", str(a.path), "--passphrase", "pw-a"]) == 0
    out = capsys.readouterr().out
    assert "on 2 devices" in out
    assert b.identity.public().fingerprint in out
    assert "a file or removable drive" in out
    assert "no usable clock" not in out


def test_status_flags_a_peer_whose_own_clock_is_unusable(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Reached through a missing watermark, not a skewed one, and here is why.

    ``main`` reopens the vault with the real ``wall_clock_ms``, so a fixture's
    fixed-epoch watermark is always in the past relative to today and can never
    trip the "ahead" branch through the CLI. A watermark this build did not
    write -- a peer on an older release -- reaches the same branch and does not
    depend on what day the suite runs.
    """
    a, b = _pair(tmp_path)
    _round_trip(a, b)
    receipt = _sole_peer_record(a, b.identity.public())
    payload = cast(dict[str, JSONValue], receipt["payload"])
    assert "importer_hlc_watermark" in payload
    del payload["importer_hlc_watermark"]
    a.save()

    assert main(["status", "--vault", str(a.path), "--passphrase", "pw-a"]) == 0
    out = capsys.readouterr().out
    assert "on 2 devices" in out
    assert "no usable clock of its own" in out


def test_status_prints_no_date_when_no_time_was_recorded(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The epoch must never stand in for an unrecorded observation."""
    a, b = _pair(tmp_path)
    _round_trip(a, b)
    record = a.sync_peer(b.identity.public())
    assert record is not None
    record.receipt_observations.clear()
    a.save()

    assert main(["status", "--vault", str(a.path), "--passphrase", "pw-a"]) == 0
    out = capsys.readouterr().out
    assert "recorded no time for it" in out
    assert "1970" not in out


def test_appserver_status_reports_the_redundancy_facts(tmp_path: Path) -> None:
    a, b = _pair(tmp_path, skew_ms=1000)
    _round_trip(a, b)

    payload = _app_status(a)
    assert payload["devices"] == 2
    assert payload["confirmed_devices"] == 1
    assert payload["paired_devices"] == 1
    assert payload["single_device"] is False
    assert payload["last_peer"] == b.identity.public().fingerprint
    assert payload["last_transport"] == "file"
    assert payload["last_peer_clock"] == "present"
    assert isinstance(payload["last_observed_at_ms"], int)


def test_appserver_status_reports_null_rather_than_epoch(tmp_path: Path) -> None:
    a, b = _pair(tmp_path)
    _round_trip(a, b)
    record = a.sync_peer(b.identity.public())
    assert record is not None
    record.receipt_observations.clear()

    payload = _app_status(a)
    assert payload["devices"] == 2
    assert payload["last_observed_at_ms"] is None
    assert payload["last_peer"] is None
    assert payload["last_transport"] is None


def _app_status(vault: Vault) -> dict[str, object]:
    import threading

    from habitable.appserver import AppServer

    server = AppServer(vault, None, vault.path, threading.Lock())
    status = server.status()
    # Round-trip through JSON: the app reads this over HTTP, so anything that
    # cannot survive serialization is not actually reported.
    return cast(dict[str, object], json.loads(json.dumps(status))["sync"])


# --- the packet says it too, in a count and never a name (issue #297) -------------


def _bundle_of(vault: Vault, out: Path) -> dict[str, JSONValue]:
    build_packet(vault, out, generated_at="2026-01-02T00:10:00Z", make_pdf=False)
    loaded = json.loads((out / "bundle.json").read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return cast("dict[str, JSONValue]", loaded)


def _redundancy_of(bundle: dict[str, JSONValue]) -> dict[str, JSONValue]:
    appendix = bundle["appendix"]
    assert isinstance(appendix, dict)
    field = appendix["redundancy"]
    assert isinstance(field, dict)
    return cast("dict[str, JSONValue]", field)


def test_a_packet_from_a_lone_device_states_one_device(tmp_path: Path) -> None:
    """A paired peer that has never synced does not become a copy in the packet either.

    This is the same defect `test_a_paired_peer_that_never_synced_is_not_a_copy`
    refuses on the CLI, asserted at the surface that actually leaves the device.
    """
    a, _b = _pair(tmp_path)
    a.document.add_issue(category="mold", room="bath", issue_id="i1")
    a.save()

    redundancy = _redundancy_of(_bundle_of(a, tmp_path / "packet-alone"))

    assert redundancy["state"] == "this_device_only"
    assert redundancy["device_count"] == 1
    assert redundancy["acknowledged_by"] == 0
    assert redundancy["identities_included"] is False
    assert "as_of" not in redundancy


def test_a_packet_after_a_round_trip_states_two_devices_and_when(tmp_path: Path) -> None:
    a, b = _pair(tmp_path)
    a.document.add_issue(category="mold", room="bath", issue_id="i1")
    a.save()
    _round_trip(a, b)

    out = tmp_path / "packet-two"
    bundle = _bundle_of(a, out)
    redundancy = _redundancy_of(bundle)

    assert redundancy["state"] == "acknowledged"
    assert redundancy["device_count"] == 2
    assert redundancy["acknowledged_by"] == 1
    as_of = redundancy["as_of"]
    assert isinstance(as_of, str) and as_of.endswith("Z")
    assert not as_of.startswith("1970")

    html = (out / "packet.html").read_text(encoding="utf-8")
    assert "Copies of this case" in html
    assert "2 devices" in html
    assert as_of in html


def test_the_packet_counts_devices_and_never_names_one(tmp_path: Path) -> None:
    """The scope note this feature was deferred behind, asserted rather than reviewed.

    A peer fingerprint in a packet is a map of who is organizing in a building,
    in a document whose whole purpose is to be handed to the other side. The
    check is over the *whole* packet -- bundle and rendering -- rather than over
    the redundancy object, because the field being absent from one object proves
    nothing about the artifact.
    """
    a, b = _pair(tmp_path)
    a.document.add_issue(category="mold", room="bath", issue_id="i1")
    a.save()
    _round_trip(a, b)
    fingerprint = b.identity.public().fingerprint
    assert fingerprint, "the peer has no fingerprint; this check would pass on nothing"

    out = tmp_path / "packet-anonymous"
    _bundle_of(a, out)
    for name in ("bundle.json", "packet.html"):
        assert fingerprint not in (out / name).read_text(encoding="utf-8"), name


def test_a_count_this_device_cannot_date_is_carried_without_a_date(tmp_path: Path) -> None:
    """Confirmed by signature, with no local record of when it arrived.

    The vault reports ``last_observed_at_ms is None`` here rather than an epoch,
    and the packet has to preserve that: a device count dated 1970-01-01 is a
    redundancy claim a reader would rightly discount, over data that is current.
    """
    a, b = _pair(tmp_path)
    a.document.add_issue(category="mold", room="bath", issue_id="i1")
    a.save()
    _round_trip(a, b)
    record = a.sync_peer(b.identity.public())
    assert record is not None
    record.receipt_observations.clear()
    assert a.sync_redundancy().last_observed_at_ms is None

    out = tmp_path / "packet-undated"
    redundancy = _redundancy_of(_bundle_of(a, out))
    assert redundancy["state"] == "acknowledged"
    assert redundancy["device_count"] == 2
    assert "as_of" not in redundancy
    html = (out / "packet.html").read_text(encoding="utf-8")
    assert "1970" not in html
    assert "recorded no time" in html


def test_the_verifier_reads_the_device_count_a_real_export_writes(tmp_path: Path) -> None:
    """The producer and the verifier, on the same packet, end to end.

    The unit tests in `test_packet_verify.py` hand `_verify_appendix_redundancy`
    shapes by hand, which proves the rule and not the wiring. This runs the whole
    path over a vault with a paired-but-unsynced peer -- the state whose numbers
    are easiest to get wrong -- and requires the verifier to accept what
    `build_packet` actually wrote.
    """
    a, _b = _pair(tmp_path)
    a.document.add_issue(category="mold", room="bath", issue_id="i1")
    a.save()

    out = tmp_path / "packet-verified"
    _bundle_of(a, out)
    report = verify_packet(out)
    assert not [problem for problem in report.problems if "redundancy" in problem], report.problems
