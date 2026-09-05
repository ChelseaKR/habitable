# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Fields a human reads must be fields the verifier checks (issues #278, #281).

Two positions in a packet were displayed to a recipient and bound by nothing the
standalone verifier looked at:

* ``custody_proof.length`` — checked by ``sync._custody_from_proof`` since it was
  written, ignored by ``verify._verify_custody`` (which compared only the head and
  returned the *recomputed* length), and rendered straight to a reader by
  ``bundleview``. Two readers of one structure, held to two standards, and the
  weaker one was the standalone verifier.
* ``items[*].timestamp.tsa_name`` — the authority name a verification report
  displays. The custody chain already commits the same name in a ``timestamped``
  entry's ``tsa`` detail; nothing compared them.

Neither was an acceptance bypass: both sit inside the self-attesting-signature
residual ``docs/tamper-challenge.md`` §4 concedes, and every break below has to
re-sign to be worth anything. What is asserted here is that the verifier now
*refuses* the inconsistent packet rather than displaying the unchecked half of
it — and, just as importantly, that the pristine packet still passes and that a
rewriter who keeps both statements consistent is still (documented) missed. A
guard that cannot fail proves nothing; so does one that fails on honest input.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from habitable.capture import capture
from habitable.packet import build_packet
from habitable.tsa import LocalRfc3161TSA
from habitable.vault import Vault
from habitable.verify import VerificationReport, verify_packet

GENESIS = "0" * 64


# --------------------------------------------------------------------------- #
# The rewriter's toolkit: the published algorithms, reimplemented.             #
# --------------------------------------------------------------------------- #
def _canonical(obj: object) -> bytes:
    """`docs/crypto-spec.md` canonical JSON: sorted keys, no spaces, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _entry_hash(entry: dict[str, Any], prev_hash: str) -> str:
    """`CustodyEntry.public_payload` as published in `docs/crypto-spec.md` §6.2."""
    payload = {
        "seq": entry["seq"],
        "action": entry["action"],
        "item_id": entry["item_id"],
        "hlc": entry["hlc"],
        "actor_commitment": entry["actor_commitment"],
        "details": {k: entry["details"][k] for k in sorted(entry["details"])},
        "prev_hash": prev_hash,
    }
    return hashlib.sha256(_canonical(payload)).hexdigest()


def _relink(bundle: dict[str, Any], *, fix_summary: bool = True) -> None:
    """Renumber, relink and rehash the chain so it walks cleanly after an edit.

    ``fix_summary`` is what separates a careful rewriter from a careless one: the
    real ``CustodyLog.integrity_proof`` always republishes ``length`` beside
    ``head_hash``, so a rewriter reimplementing it faithfully republishes both.
    """
    entries = bundle["custody_proof"]["entries"]
    prev = GENESIS
    for index, entry in enumerate(entries, start=1):
        entry["seq"] = index
        entry["prev_hash"] = prev
        entry["entry_hash"] = _entry_hash(entry, prev)
        prev = entry["entry_hash"]
    bundle["custody_proof"]["head_hash"] = prev
    if fix_summary:
        bundle["custody_proof"]["length"] = len(entries)


def _resign(packet_dir: Path, bundle: dict[str, Any]) -> None:
    """Write the rewritten bundle and sign it with a key the rewriter just made.

    A packet's signature carries its own verifying key (FIX-05), so with no pin
    supplied this restores ``signature_ok`` and leaves only the commitments
    *inside* the bundle to refuse it. That is the whole point: every refusal
    asserted below is a refusal on content.
    """
    raw = _canonical(bundle)
    (packet_dir / "bundle.json").write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()
    key = Ed25519PrivateKey.generate()
    (packet_dir / "bundle.sig.json").write_text(
        json.dumps(
            {
                "bundle_sha256": digest,
                "producer_fingerprint": bundle.get("producer_fingerprint", ""),
                "sign_public": base64.b64encode(key.public_key().public_bytes_raw()).decode(),
                "signature": base64.b64encode(key.sign(digest.encode("ascii"))).decode(),
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def _rewrite(
    packet_dir: Path, mutate: Callable[[dict[str, Any]], None], *, fix_summary: bool = True
) -> dict[str, Any]:
    bundle: dict[str, Any] = json.loads((packet_dir / "bundle.json").read_text(encoding="utf-8"))
    mutate(bundle)
    _relink(bundle, fix_summary=fix_summary)
    _resign(packet_dir, bundle)
    return bundle


# --------------------------------------------------------------------------- #
# Fixtures                                                                     #
# --------------------------------------------------------------------------- #
@pytest.fixture
def packet(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> Path:
    """A clean, evidence-ready packet: two captures under one issue."""
    vault = make_vault()
    issue = vault.document.add_issue(
        category="mold", room="bathroom", title="Ceiling leak", issue_id="i1"
    )
    capture(vault, make_jpeg("a.jpg", color=(120, 30, 30)), issue_id=issue, tsa=local_tsa)
    capture(vault, make_jpeg("b.jpg", color=(30, 90, 140)), issue_id=issue, tsa=local_tsa)
    out = tmp_path / "packet"
    build_packet(vault, out, generated_at="2026-01-02T00:10:00Z", make_pdf=False, tsa=local_tsa)
    return out


def _verdict(packet_dir: Path, tsa: LocalRfc3161TSA) -> VerificationReport:
    return verify_packet(packet_dir, trusted_certs=[tsa.certificate])


# --------------------------------------------------------------------------- #
# The control. Without it every "not accepted" below is vacuous.               #
# --------------------------------------------------------------------------- #
def test_the_untouched_packet_is_still_evidence_ready(
    packet: Path, local_tsa: LocalRfc3161TSA
) -> None:
    report = _verdict(packet, local_tsa)
    assert report.evidence_ready and report.status == "evidence_ready"
    assert report.custody_ok and not report.problems


def test_a_faithfully_relinked_and_resigned_packet_is_still_accepted(
    packet: Path, local_tsa: LocalRfc3161TSA
) -> None:
    """The toolkit itself must not be what the refusals below are detecting.

    A rewrite that changes nothing, relinked and re-signed with a fresh key, has
    to come back evidence-ready — otherwise every assertion in this module would
    pass for the wrong reason.
    """
    _rewrite(packet, lambda bundle: None)
    assert _verdict(packet, local_tsa).evidence_ready


# --------------------------------------------------------------------------- #
# #278 — the declared custody length                                           #
# --------------------------------------------------------------------------- #
def test_a_declared_custody_length_that_lies_is_refused(
    packet: Path, local_tsa: LocalRfc3161TSA
) -> None:
    """The planted break: entries untouched, only the number a reader is shown."""
    honest = json.loads((packet / "bundle.json").read_text(encoding="utf-8"))
    entries = len(honest["custody_proof"]["entries"])
    assert honest["custody_proof"]["length"] == entries

    def overstate(bundle: dict[str, Any]) -> None:
        bundle["custody_proof"]["length"] = entries + 7

    _rewrite(packet, overstate, fix_summary=False)
    report = _verdict(packet, local_tsa)
    # The signature verifies again: the refusal is on the packet's own contents.
    assert report.signature_ok
    assert not report.custody_ok
    assert not report.structurally_intact and report.status == "integrity_failed"
    # The recomputed length is what the report still carries -- the declared one
    # is checked, never believed.
    assert report.custody_length == entries


@pytest.mark.parametrize(
    ("label", "value"),
    [
        ("absent", None),
        ("a string", "5"),
        # `True == 1` in Python: a boolean must not be allowed to spell a count.
        ("a boolean", True),
        ("a list", []),
    ],
)
def test_a_custody_length_that_is_not_a_matching_integer_is_refused(
    packet: Path, local_tsa: LocalRfc3161TSA, label: str, value: object
) -> None:
    """An absent or wrong-typed summary is not a matching summary."""

    def mangle(bundle: dict[str, Any]) -> None:
        if value is None:
            del bundle["custody_proof"]["length"]
        else:
            bundle["custody_proof"]["length"] = value

    _rewrite(packet, mangle, fix_summary=False)
    report = _verdict(packet, local_tsa)
    assert report.signature_ok, label
    assert not report.custody_ok, label


def test_deleting_an_item_and_its_custody_entries_is_now_caught_if_the_summary_is_left_stale(
    packet: Path, local_tsa: LocalRfc3161TSA
) -> None:
    """The gap the length check actually closes, and the one it does not.

    ``docs/tamper-challenge.md`` §4 records "evidence item deleted" as MISSED
    with nothing asserted. Half of that is now false: a rewriter who drops an
    item, drops its custody entries and relinks the chain -- but republishes the
    head without republishing the length beside it -- is refused, because the
    summary and the entries no longer agree.

    The other half stands, and is asserted here so nobody reads the first half as
    more than it is: the same deletion with the summary republished *properly* is
    still accepted with nothing asserted. The answer to that one remains the pin
    or a required seal, exactly as the challenge document says.
    """

    def drop_the_last_item(bundle: dict[str, Any]) -> None:
        removed = bundle["items"].pop()["capture_id"]
        bundle["custody_proof"]["entries"] = [
            entry for entry in bundle["custody_proof"]["entries"] if entry["item_id"] != removed
        ]
        bundle["appendix"]["item_count"] = len(bundle["items"])

    careless = json.loads((packet / "bundle.json").read_text(encoding="utf-8"))
    _rewrite(packet, drop_the_last_item, fix_summary=False)
    caught = _verdict(packet, local_tsa)
    assert caught.signature_ok and not caught.custody_ok
    assert not caught.evidence_ready

    # Same edit, summary republished the way `integrity_proof` republishes it.
    (packet / "bundle.json").write_bytes(_canonical(careless))
    _rewrite(packet, drop_the_last_item, fix_summary=True)
    missed = _verdict(packet, local_tsa)
    assert missed.evidence_ready, (
        "the documented residual closed silently: re-read tamper-challenge.md §4"
    )


# --------------------------------------------------------------------------- #
# #281 — the authority name a verdict displays                                 #
# --------------------------------------------------------------------------- #
def _custody_tsa_names(bundle: dict[str, Any]) -> list[str]:
    return [
        entry["details"]["tsa"]
        for entry in bundle["custody_proof"]["entries"]
        if entry["action"] == "timestamped" and "tsa" in entry["details"]
    ]


def test_the_packet_commits_the_authority_name_in_two_places(packet: Path) -> None:
    """The premise of the cross-check, asserted rather than assumed.

    If a future export stops writing the ``tsa`` detail, the check below silently
    stops applying and takes its coverage with it. This fails first instead.
    """
    bundle = json.loads((packet / "bundle.json").read_text(encoding="utf-8"))
    assert _custody_tsa_names(bundle) == ["test-rfc3161", "test-rfc3161"]
    assert [item["timestamp"]["tsa_name"] for item in bundle["items"]] == [
        "test-rfc3161",
        "test-rfc3161",
    ]


def test_relabelling_the_authority_the_verdict_displays_is_refused(
    packet: Path, local_tsa: LocalRfc3161TSA
) -> None:
    """The planted break: only the display label moves. Nothing cryptographic does.

    The token still verifies against its own digest and still chains to the
    supplied anchor -- which is the point. "This token is from FreeTSA" is the
    sentence a recipient quotes, and until this check it was the sentence with
    nothing behind it.
    """

    def relabel(bundle: dict[str, Any]) -> None:
        bundle["items"][0]["timestamp"]["tsa_name"] = "FreeTSA"

    _rewrite(packet, relabel)
    report = _verdict(packet, local_tsa)

    assert report.signature_ok and report.custody_ok
    # The timestamp itself is untouched and still passes every check it ever did.
    assert report.items[0].timestamp_verified
    assert report.items[0].timestamp_authority_trusted
    # ...and the packet is still refused, on the contradiction, not on the token.
    assert any("no custody entry attests" in problem for problem in report.problems), (
        report.problems
    )
    assert "'FreeTSA'" in " ".join(report.problems)
    assert not report.structurally_intact and not report.evidence_ready


def test_an_emptied_authority_label_is_refused_too(
    packet: Path, local_tsa: LocalRfc3161TSA
) -> None:
    """Erasing the name is a rewrite like any other, not an opt-out of the check."""
    _rewrite(packet, lambda bundle: bundle["items"][0]["timestamp"].update({"tsa_name": ""}))
    report = _verdict(packet, local_tsa)
    assert report.signature_ok
    assert any("no custody entry attests" in problem for problem in report.problems)
    assert not report.structurally_intact


def test_relabelling_both_statements_consistently_is_still_missed(
    packet: Path, local_tsa: LocalRfc3161TSA
) -> None:
    """The honest limit. This is a consistency check, not an attestation of who signed.

    A rewriter who re-signs can move both committed statements together, and the
    label is a producer-configured nickname either way -- the identity a recipient
    can rely on is the signing certificate, reached with ``trusted_certs``. Stated
    here so the check is not mistaken for more than it is.
    """

    def relabel_everywhere(bundle: dict[str, Any]) -> None:
        item = bundle["items"][0]
        item["timestamp"]["tsa_name"] = "FreeTSA"
        for entry in bundle["custody_proof"]["entries"]:
            if entry["item_id"] == item["capture_id"] and "tsa" in entry["details"]:
                entry["details"]["tsa"] = "FreeTSA"

    _rewrite(packet, relabel_everywhere)
    assert _verdict(packet, local_tsa).evidence_ready


def test_an_item_whose_custody_attests_no_authority_is_not_accused(
    packet: Path, local_tsa: LocalRfc3161TSA
) -> None:
    """The guard, and why it has to be there.

    ``sync`` imports a peer's timestamp tokens and appends no ``timestamped``
    custody entry of its own, so a received capture reaches export with a token
    and nothing in this vault's chain that names its authority. There is no
    second statement to compare against, and demanding one would refuse honest
    packets -- ``tests/test_sync_security.py`` exports exactly that packet and
    requires it to stay intact. An item with nothing committed is skipped.
    """

    def strip_the_committed_names(bundle: dict[str, Any]) -> None:
        for entry in bundle["custody_proof"]["entries"]:
            entry["details"].pop("tsa", None)

    bundle = _rewrite(packet, strip_the_committed_names)
    assert _custody_tsa_names(bundle) == []
    assert _verdict(packet, local_tsa).evidence_ready


def test_a_malformed_item_does_not_stop_the_cross_check_or_crash_it(
    packet: Path, local_tsa: LocalRfc3161TSA
) -> None:
    """Hostile input reaches this check like every other: as a verdict, not an exception.

    An entry in ``items`` that is not an object is already a `problems` entry
    ([§1](../docs/verifier-decision-table.md)); the authority cross-check has to
    step over it rather than trip on it, and still refuse the relabelled item
    beside it.
    """

    def wreck_one_and_relabel_the_other(bundle: dict[str, Any]) -> None:
        bundle["items"][0]["timestamp"]["tsa_name"] = "FreeTSA"
        bundle["items"][1] = 12345

    _rewrite(packet, wreck_one_and_relabel_the_other)
    report = _verdict(packet, local_tsa)
    assert "malformed item in bundle" in report.problems
    assert any("no custody entry attests" in problem for problem in report.problems)
    assert not report.structurally_intact
