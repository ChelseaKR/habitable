# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""The adversarial battery behind the public tamper-evidence challenge.

`docs/tamper-challenge.md` publishes a table of what `verify_packet` catches and
what it does not. This module *is* that table, executed. Every row is a real
attack carried out against a real packet, and the assertions record the measured
verdict — including the verdicts that are **misses**.

Two rules keep this file honest:

1. **Misses are asserted as misses.** A gap that is merely described in prose
   rots silently. A gap asserted as `evidence_ready is True` fails loudly the day
   somebody closes it, which forces the doc and the challenge spec to be updated
   in the same commit. If a test here starts failing because an attack is now
   caught, that is good news — move the row and update `docs/tamper-challenge.md`.
2. **The attacker uses published information only.** The custody hash is
   recomputed from the construction in `docs/crypto-spec.md` §6.2 rather than by
   importing `habitable.evidence`, because the threat is an outsider with a copy
   of the packet and the spec — not someone with privileged access.

The headline result: without `expected_producer_key`, the bundle signature is
self-attesting (unimplemented **FIX-05**, `docs/ideation/02-large-scale-fixes.md`).
An attacker rewrites `bundle.json`, recomputes the whole custody chain, signs with
a fresh key, and writes their own `sign_public`. Everything the RFC 3161 tokens do
not directly bind is theirs to change.

**What changed with the packet seal** (ADR 0011). A sealed packet carries an RFC 3161
token over the SHA-256 of the whole `bundle.json`, so every rewrite above breaks a
signature the attacker cannot mint. Their remaining move is to *delete* the seal, which
is why the residual rows below are about deletion and about re-sealing with an authority
the recipient happens to trust. Both are asserted here as misses, with the flag that
catches each one asserted alongside.
"""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding

from habitable.capture import capture
from habitable.cli import main
from habitable.errors import TimestampError
from habitable.packet import build_packet
from habitable.tsa import DevTSA, LocalRfc3161TSA, TimestampInfo
from habitable.vault import Vault
from habitable.verify import _seal_deadline_problems, verify_packet

GENESIS = "0" * 64


# --------------------------------------------------------------------------- #
# The attacker's toolkit: published algorithms, reimplemented.                 #
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


def _rebuild_custody(bundle: dict[str, Any]) -> None:
    """Relink and rehash the whole chain so it walks cleanly after edits."""
    prev = GENESIS
    for entry in bundle["custody_proof"]["entries"]:
        entry["prev_hash"] = prev
        entry["entry_hash"] = _entry_hash(entry, prev)
        prev = entry["entry_hash"]
    bundle["custody_proof"]["head_hash"] = prev


def _resign(
    packet_dir: Path,
    bundle: dict[str, Any],
    *,
    keep_fingerprint: bool = True,
    reseal_with: LocalRfc3161TSA | None = None,
    keep_seal: bool = False,
) -> None:
    """Write the rewritten bundle and sign it with a key the attacker just made.

    ``keep_seal`` retains the genuine authority seal (the naive attacker, who keeps
    the unforgeable material exactly as they keep the genuine item token).
    ``reseal_with`` mints a fresh seal from an authority the attacker can reach.
    Neither by default: a plain re-sign simply drops the seal, which is the
    attacker's cheapest move.
    """
    old_sig: dict[str, Any] = {}
    signature_path = packet_dir / "bundle.sig.json"
    if signature_path.is_file():
        old_sig = json.loads(signature_path.read_text())
    raw = _canonical(bundle)
    (packet_dir / "bundle.json").write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()
    key = Ed25519PrivateKey.generate()
    fingerprint = bundle.get("producer_fingerprint", "") if keep_fingerprint else "ffff-ffff"
    doc: dict[str, Any] = {
        "bundle_sha256": digest,
        "producer_fingerprint": fingerprint,
        "sign_public": base64.b64encode(key.public_key().public_bytes_raw()).decode(),
        "signature": base64.b64encode(key.sign(digest.encode("ascii"))).decode(),
    }
    if keep_seal and "packet_seal" in old_sig:
        doc["packet_seal"] = old_sig["packet_seal"]
    if reseal_with is not None:
        doc["packet_seal"] = reseal_with.stamp(digest).to_dict()
    signature_path.write_text(json.dumps(doc, indent=2), encoding="utf-8")


def _rewrite(packet_dir: Path, mutate: Callable[[dict[str, Any]], None], **resign: Any) -> None:
    """Apply `mutate`, relink custody, and re-sign with a foreign key."""
    bundle = json.loads((packet_dir / "bundle.json").read_text())
    mutate(bundle)
    _rebuild_custody(bundle)
    _resign(packet_dir, bundle, **resign)


def _retarget_custody_detail(bundle: dict[str, Any], old: str, new: str) -> int:
    """Point every custody detail that commits `old` at `new` instead."""
    touched = 0
    for entry in bundle["custody_proof"]["entries"]:
        for field, value in list(entry["details"].items()):
            if value == old:
                entry["details"][field] = new
                touched += 1
    return touched


# --------------------------------------------------------------------------- #
# Fixtures                                                                     #
# --------------------------------------------------------------------------- #
@pytest.fixture
def challenge_packet(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> Path:
    """A clean, evidence-ready packet: two captures under one issue."""
    vault = make_vault()
    issue = vault.document.add_issue(
        category="mold",
        room="bathroom",
        title="Ceiling leak",
        description="Original description as captured.",
        issue_id="i1",
    )
    # Distinct colours: identical bytes would collapse to one hash and make the
    # per-item custody bindings ambiguous.
    capture(vault, make_jpeg("a.jpg", color=(120, 30, 30)), issue_id=issue, tsa=local_tsa)
    capture(vault, make_jpeg("b.jpg", color=(30, 90, 140)), issue_id=issue, tsa=local_tsa)
    out = tmp_path / "packet"
    build_packet(vault, out, generated_at="2026-01-02T00:10:00Z", make_pdf=False, tsa=local_tsa)
    return out


@pytest.fixture
def genuine_key(challenge_packet: Path) -> str:
    """The producer key a recipient would pin, read from the authentic packet."""
    key = json.loads((challenge_packet / "bundle.sig.json").read_text())["sign_public"]
    assert isinstance(key, str)
    return key


def _verdict(packet_dir: Path, tsa: LocalRfc3161TSA, **kwargs: Any) -> Any:
    return verify_packet(packet_dir, trusted_certs=[tsa.certificate], **kwargs)


def test_the_untouched_packet_is_evidence_ready(
    challenge_packet: Path, local_tsa: LocalRfc3161TSA, genuine_key: str
) -> None:
    """Baseline. Everything below is measured against this."""
    report = _verdict(challenge_packet, local_tsa)
    assert report.evidence_ready and report.status == "evidence_ready"
    assert not report.producer_key_pinned

    pinned = _verdict(challenge_packet, local_tsa, expected_producer_key=genuine_key)
    assert pinned.evidence_ready and pinned.producer_key_pinned


# --------------------------------------------------------------------------- #
# Caught with no pin at all.                                                   #
# --------------------------------------------------------------------------- #
def test_media_bitflip_without_resigning_is_caught(
    challenge_packet: Path, local_tsa: LocalRfc3161TSA
) -> None:
    target = next((challenge_packet / "media").glob("*.jpg"))
    raw = bytearray(target.read_bytes())
    raw[len(raw) // 2] ^= 0x01
    target.write_bytes(bytes(raw))
    assert not _verdict(challenge_packet, local_tsa).evidence_ready


def test_media_truncation_without_resigning_is_caught(
    challenge_packet: Path, local_tsa: LocalRfc3161TSA
) -> None:
    target = next((challenge_packet / "media").glob("*.jpg"))
    raw = target.read_bytes()
    target.write_bytes(raw[: len(raw) // 2])
    assert not _verdict(challenge_packet, local_tsa).evidence_ready


def test_bundle_edit_without_resigning_is_caught(
    challenge_packet: Path, local_tsa: LocalRfc3161TSA
) -> None:
    bundle = json.loads((challenge_packet / "bundle.json").read_text())
    bundle["unit"] = "999-FAKE"
    (challenge_packet / "bundle.json").write_bytes(_canonical(bundle))
    report = _verdict(challenge_packet, local_tsa)
    assert not report.signature_ok and not report.evidence_ready


def test_custody_entry_deleted_is_caught_even_after_resigning(
    challenge_packet: Path, local_tsa: LocalRfc3161TSA
) -> None:
    """Deleting an entry without renumbering breaks the strict `seq` walk."""

    def drop(bundle: dict[str, Any]) -> None:
        del bundle["custody_proof"]["entries"][1]

    bundle = json.loads((challenge_packet / "bundle.json").read_text())
    drop(bundle)
    _rebuild_custody(bundle)  # relink hashes but leave the seq gap
    _resign(challenge_packet, bundle)
    assert not _verdict(challenge_packet, local_tsa).custody_ok


def test_content_hash_change_is_caught_by_the_timestamp_token(
    challenge_packet: Path, local_tsa: LocalRfc3161TSA
) -> None:
    """The one thing a re-signing attacker cannot forge: the TSA's signature."""
    _rewrite(challenge_packet, lambda b: b["items"][0].__setitem__("content_hash", "0" * 64))
    report = _verdict(challenge_packet, local_tsa)
    assert report.signature_ok and report.custody_ok  # the rewrite itself is clean
    assert not report.evidence_ready  # but the token no longer matches


def test_timestamp_token_removal_is_caught(
    challenge_packet: Path, local_tsa: LocalRfc3161TSA
) -> None:
    _rewrite(challenge_packet, lambda b: b["items"][0].__setitem__("timestamp", None))
    report = _verdict(challenge_packet, local_tsa)
    assert not report.evidence_ready and report.status == "timestamp_missing"


def test_attacker_minted_authority_is_not_trusted(
    challenge_packet: Path, local_tsa: LocalRfc3161TSA
) -> None:
    """Re-stamping with the attacker's own TSA loses the pinned anchor."""
    evil = LocalRfc3161TSA("attacker-authority")
    bundle = json.loads((challenge_packet / "bundle.json").read_text())
    token = evil.stamp(bundle["items"][0]["content_hash"])
    bundle["items"][0]["timestamp"] = {
        "kind": token.kind,
        "tsa_name": token.tsa_name,
        "token_b64": base64.b64encode(token.data).decode(),
    }
    _rebuild_custody(bundle)
    _resign(challenge_packet, bundle)
    report = _verdict(challenge_packet, local_tsa)
    assert not report.evidence_ready
    assert not report.timestamp_authority_trusted


# --------------------------------------------------------------------------- #
# MISSED without a pin. These assertions document open gaps (FIX-05).          #
# If one starts failing, the gap closed — update docs/tamper-challenge.md.     #
# --------------------------------------------------------------------------- #
def _narrative_edit(bundle: dict[str, Any]) -> None:
    bundle["issues"][0]["description"] = "TAMPERED: a condition that was never documented."


def _drop_last_item(bundle: dict[str, Any]) -> None:
    removed = bundle["items"].pop()
    capture_id = removed["capture_id"]
    bundle["custody_proof"]["entries"] = [
        e for e in bundle["custody_proof"]["entries"] if e["item_id"] != capture_id
    ]
    for index, entry in enumerate(bundle["custody_proof"]["entries"], start=1):
        entry["seq"] = index
    appendix = bundle.get("appendix")
    if isinstance(appendix, dict) and "item_count" in appendix:
        appendix["item_count"] = len(bundle["items"])


def _move_capture_date(bundle: dict[str, Any]) -> None:
    bundle["items"][0]["captured_at"] = "2025-06-01T09:05:00Z"


def _swap_identity(bundle: dict[str, Any]) -> None:
    bundle["unit"] = "9Z (substituted)"
    bundle["case_id"] = "a-different-case"


@pytest.mark.parametrize(
    ("name", "mutate"),
    [
        ("narrative rewritten", _narrative_edit),
        ("evidence item deleted", _drop_last_item),
        ("capture date moved", _move_capture_date),
        ("unit and case identity swapped", _swap_identity),
    ],
)
def test_rewrite_and_foreign_resign_is_MISSED_without_a_pin_or_a_seal_requirement(
    challenge_packet: Path,
    local_tsa: LocalRfc3161TSA,
    genuine_key: str,
    name: str,
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    """Documented gap: anything no RFC 3161 token binds is the attacker's to change.

    Two things make these detectable, so each case is asserted three ways: the
    out-of-band key pin (which needs a key the recipient already trusts), and
    requiring the authority seal (which needs no secret at all — the attacker had
    to delete the seal to rewrite the bundle, and asking for it notices).
    """
    _rewrite(challenge_packet, mutate)

    unasserted = _verdict(challenge_packet, local_tsa)
    assert unasserted.evidence_ready, f"{name}: expected a documented MISS with nothing asserted"
    assert unasserted.signature_ok and unasserted.custody_ok
    assert not unasserted.seal.present, "the rewrite drops the seal it cannot re-mint"

    pinned = _verdict(challenge_packet, local_tsa, expected_producer_key=genuine_key)
    assert not pinned.evidence_ready, f"{name}: the pin must catch this"
    assert "packet signing key does not match the pinned producer key" in pinned.problems

    sealed = _verdict(challenge_packet, local_tsa, require_packet_seal=True)
    assert not sealed.evidence_ready, f"{name}: requiring the seal must catch this"
    assert any("no authority seal" in problem for problem in sealed.problems)


def _substitute_the_photograph(packet_dir: Path, **resign: Any) -> str:
    """Replace the visible image and rewrite everything that records its hash.

    Returns the genuine item timestamp token, which the attacker keeps: it binds
    `content_hash`, the hash of original bytes a default packet does not ship, so
    it constrains nothing a recipient can open.
    """
    bundle = json.loads((packet_dir / "bundle.json").read_text())
    item = bundle["items"][0]
    assert item["has_original"] is False, "this gap is about packets without originals"
    genuine_token = str(item["timestamp"]["token_b64"])

    substitute = packet_dir / "media" / item["shared_name"]
    substitute.write_bytes(b"\xff\xd8\xff\xe0 not the photograph that was captured \xff\xd9")
    new_hash = hashlib.sha256(substitute.read_bytes()).hexdigest()
    assert _retarget_custody_detail(bundle, item["shared_hash"], new_hash) >= 1
    item["shared_hash"] = new_hash

    _rebuild_custody(bundle)
    _resign(packet_dir, bundle, **resign)
    return genuine_token


def test_substituting_the_photograph_is_MISSED_without_a_pin_or_a_seal_requirement(
    challenge_packet: Path, local_tsa: LocalRfc3161TSA, genuine_key: str
) -> None:
    """The sharpest form of the gap, and the one that matters most.

    The RFC 3161 token binds `content_hash` — the *original* bytes. In a default
    packet those bytes are not present (`has_original` is false), so the token
    constrains nothing a recipient can check. The image actually rendered into
    `packet.html` and `packet.pdf` is bound only by `shared_hash`, which lives in
    the rewritable bundle. So the picture can be replaced outright while the
    genuine, unforgeable timestamp token is retained.

    The packet seal changes what the attacker must delete, not what they must
    forge: `shared_hash` is inside the bundle, and the seal covers the bundle, so
    the substitution costs them the seal. It remains a MISS only for a recipient
    who never asks whether there was one.
    """
    genuine_token = _substitute_the_photograph(challenge_packet)

    unasserted = _verdict(challenge_packet, local_tsa)
    assert unasserted.evidence_ready, "documented MISS: the visible photo is unprotected"
    assert unasserted.items[0].timestamp_authority_trusted
    reloaded = json.loads((challenge_packet / "bundle.json").read_text())
    assert reloaded["items"][0]["timestamp"]["token_b64"] == genuine_token

    pinned = _verdict(challenge_packet, local_tsa, expected_producer_key=genuine_key)
    assert not pinned.evidence_ready

    sealed = _verdict(challenge_packet, local_tsa, require_packet_seal=True)
    assert not sealed.evidence_ready


def test_substituting_the_photograph_while_keeping_the_seal_is_CAUGHT_unasserted(
    challenge_packet: Path, local_tsa: LocalRfc3161TSA
) -> None:
    """The attacker who keeps the unforgeable material loses, with no flags at all.

    Keeping the genuine seal is the natural move — it is exactly what makes the
    item-timestamp version of this attack work. It fails here because the seal's
    imprint is the whole bundle, and the bundle changed.
    """
    _substitute_the_photograph(challenge_packet, keep_seal=True)

    report = _verdict(challenge_packet, local_tsa)
    assert not report.evidence_ready
    assert report.seal.present and not report.seal.verified
    assert any("does not cover this bundle" in problem for problem in report.problems)


def test_embedded_originals_do_not_close_the_photo_substitution_gap(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    """`--include-originals` narrows the attack but does not close it.

    With originals embedded the token *is* checkable, so replacing the original
    fails. Replacing only the shared copy still passes: nothing ties the two
    files together except a custody entry the attacker rewrites.
    """
    vault = make_vault()
    issue = vault.document.add_issue(category="mold", room="bathroom", title="Leak", issue_id="i1")
    capture(vault, make_jpeg("a.jpg"), issue_id=issue, tsa=local_tsa)
    out = tmp_path / "with-originals"
    build_packet(
        vault,
        out,
        generated_at="2026-01-02T00:10:00Z",
        include_originals=True,
        make_pdf=False,
        tsa=local_tsa,
    )
    assert _verdict(out, local_tsa, require_packet_seal=True).evidence_ready

    shared_only = tmp_path / "shared-only"
    shutil.copytree(out, shared_only)
    bundle = json.loads((shared_only / "bundle.json").read_text())
    item = bundle["items"][0]
    assert item["has_original"] is True
    target = shared_only / "media" / item["shared_name"]
    target.write_bytes(b"\xff\xd8\xff\xe0 substituted presentation copy \xff\xd9")
    new_hash = hashlib.sha256(target.read_bytes()).hexdigest()
    _retarget_custody_detail(bundle, item["shared_hash"], new_hash)
    item["shared_hash"] = new_hash
    _rebuild_custody(bundle)
    _resign(shared_only, bundle)
    assert _verdict(shared_only, local_tsa).evidence_ready, (
        "documented MISS: embedding originals does not protect the shared copy"
    )
    assert not _verdict(shared_only, local_tsa, require_packet_seal=True).evidence_ready, (
        "requiring the seal must catch the substituted shared copy"
    )

    both = tmp_path / "both"
    shutil.copytree(out, both)
    bundle = json.loads((both / "bundle.json").read_text())
    item = bundle["items"][0]
    original = next((both / "originals").iterdir())
    original.write_bytes(b"\xff\xd8\xff\xe0 substituted original \xff\xd9")
    new_content = hashlib.sha256(original.read_bytes()).hexdigest()
    _retarget_custody_detail(bundle, item["content_hash"], new_content)
    item["content_hash"] = new_content
    _rebuild_custody(bundle)
    _resign(both, bundle)
    assert not _verdict(both, local_tsa).evidence_ready, "replacing the original must be caught"


def test_producer_fingerprint_is_never_cross_checked(
    challenge_packet: Path, local_tsa: LocalRfc3161TSA
) -> None:
    """A human comparing fingerprints by eye is not protected either.

    The fingerprint is derived from `sign_public ‖ box_public` and `box_public` is
    not in the packet, so it cannot be recomputed from what a recipient holds. An
    attacker copies the string across verbatim and nothing objects.
    """
    _rewrite(challenge_packet, _narrative_edit)
    sig = json.loads((challenge_packet / "bundle.sig.json").read_text())
    bundle = json.loads((challenge_packet / "bundle.json").read_text())
    assert sig["producer_fingerprint"] == bundle["producer_fingerprint"]
    assert _verdict(challenge_packet, local_tsa).evidence_ready
    assert not _verdict(challenge_packet, local_tsa, require_packet_seal=True).evidence_ready


# --------------------------------------------------------------------------- #
# The packet seal (ADR 0011): what it binds, and what is left over.            #
# --------------------------------------------------------------------------- #
def test_the_untouched_packet_is_sealed_by_its_authority(
    challenge_packet: Path, local_tsa: LocalRfc3161TSA
) -> None:
    """Baseline for every row below."""
    report = _verdict(challenge_packet, local_tsa, require_packet_seal=True)
    assert report.evidence_ready
    seal = report.seal
    assert seal.present and seal.verified and seal.trusted and seal.ok and seal.required
    assert seal.tsa_name == local_tsa.name
    assert "countersigned by" in report.seal_statement("en")
    assert "refrendado" in report.seal_statement("es")


def test_an_unsealed_packet_says_so_and_is_still_verifiable(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    """Offline export loses the seal, not the packet. The absence is stated."""
    vault = make_vault()
    issue = vault.document.add_issue(category="mold", room="bathroom", title="Leak", issue_id="i1")
    capture(vault, make_jpeg("a.jpg"), issue_id=issue, tsa=local_tsa)
    out = tmp_path / "unsealed"
    result = build_packet(vault, out, generated_at="2026-01-02T00:10:00Z", make_pdf=False)

    assert not result.seal.sealed
    assert "no timestamp authority was supplied" in result.seal.note

    report = _verdict(out, local_tsa)
    assert report.evidence_ready, "an unsealed packet is weaker, not invalid"
    assert not report.seal.present
    assert "authority seal: none" in report.seal_statement("en")
    assert not _verdict(out, local_tsa, require_packet_seal=True).evidence_ready


def test_a_seal_from_an_unreachable_authority_degrades_instead_of_failing_the_export(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    """Export inherits capture's offline-first rule, and reports which case applied."""

    class _DeadTSA:
        name = "unreachable-authority"
        kind = "rfc3161"

        def stamp(self, digest_hex: str) -> Any:
            raise TimestampError("connection refused")

    vault = make_vault()
    issue = vault.document.add_issue(category="mold", room="bathroom", title="Leak", issue_id="i1")
    capture(vault, make_jpeg("a.jpg"), issue_id=issue, tsa=local_tsa)
    out = tmp_path / "degraded"
    result = build_packet(
        vault, out, generated_at="2026-01-02T00:10:00Z", make_pdf=False, tsa=_DeadTSA()
    )

    assert not result.seal.sealed
    assert "connection refused" in result.seal.note
    assert (out / "bundle.json").is_file()
    assert "packet_seal" not in json.loads((out / "bundle.sig.json").read_text())


def test_the_fully_rehashed_forgery_re_sealed_by_an_unanchored_authority(
    challenge_packet: Path, local_tsa: LocalRfc3161TSA
) -> None:
    """The complete attack, re-sealed: every hash rebuilt, a fresh key, a fresh seal.

    The attacker mints their seal from their own authority, which the recipient
    never anchored. That is **visible** in the report and fatal under
    `--require-packet-seal` — but with nothing asserted the verdict is still
    `evidence_ready`, because an untrusted seal, like an absent one, is reported
    rather than fatal.

    That asymmetry is deliberate and worth stating: if an untrusted seal sank the
    verdict, a producer who sealed with an authority this recipient happens not to
    trust would be worse off than one who never sealed. The rule would punish the
    more careful producer. So this row is a documented MISS in the unasserted
    column, not a catch — and `docs/tamper-challenge.md` §4 says so.
    """
    evil = LocalRfc3161TSA("attacker-authority")
    _rewrite(challenge_packet, _narrative_edit, reseal_with=evil)

    unasserted = _verdict(challenge_packet, local_tsa)
    assert unasserted.signature_ok and unasserted.custody_ok, "the rewrite is internally clean"
    assert unasserted.seal.present and unasserted.seal.verified, "the forged seal is a real token"
    assert not unasserted.seal.trusted, "but not from an authority the recipient anchored"
    assert not unasserted.seal.ok
    assert unasserted.evidence_ready, "documented MISS: an untrusted seal is reported, not fatal"

    required = _verdict(challenge_packet, local_tsa, require_packet_seal=True)
    assert not required.evidence_ready
    assert any("does not chain to a certificate you supplied" in p for p in required.problems)


def test_the_fully_rehashed_forgery_is_MISSED_when_it_can_reach_your_authority(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    tmp_path: Path,
) -> None:
    """The residual, stated as a measurement rather than a caveat.

    A public authority stamps any digest for anyone. An attacker who can reach the
    recipient's own trusted authority re-seals the rewritten bundle and passes even
    `--require-packet-seal`. What they cannot do is backdate it: the forged seal
    carries the true time of the forgery, so a recipient who names the date they
    received the packet catches it. That date is the anchor nobody has to be given.
    """
    clock = {"now": 1_767_312_000}  # the packet's export time
    reachable = LocalRfc3161TSA("public-authority", time_source=lambda: clock["now"])

    vault = make_vault()
    issue = vault.document.add_issue(category="mold", room="bathroom", title="Leak", issue_id="i1")
    capture(vault, make_jpeg("a.jpg"), issue_id=issue, tsa=reachable)
    packet = tmp_path / "packet"
    build_packet(vault, packet, generated_at="2026-01-02T00:10:00Z", make_pdf=False, tsa=reachable)
    received_on = "2026-01-03T00:00:00Z"
    assert _verdict(
        packet, reachable, require_packet_seal=True, seal_not_after=received_on
    ).evidence_ready

    clock["now"] += 30 * 24 * 3600  # a month after the recipient took delivery
    _rewrite(packet, _narrative_edit, reseal_with=reachable)

    missed = _verdict(packet, reachable, require_packet_seal=True)
    assert missed.evidence_ready, "documented MISS: a reachable authority re-seals the forgery"
    assert missed.seal.ok

    caught = _verdict(packet, reachable, require_packet_seal=True, seal_not_after=received_on)
    assert not caught.evidence_ready, "the date the recipient received it must catch this"
    assert any("after the" in problem for problem in caught.problems)


def test_stripping_the_seal_is_MISSED_unless_the_recipient_requires_one(
    challenge_packet: Path, local_tsa: LocalRfc3161TSA
) -> None:
    """The downgrade, asserted as a miss because no in-packet datum can stop it.

    Everything the bundle could say about "I should be sealed" is a field the
    attacker rewrites. Only recipient policy closes this, which is why the flag
    exists and why the CLI names the absence on every run.
    """
    signature = challenge_packet / "bundle.sig.json"
    doc = json.loads(signature.read_text())
    assert doc.pop("packet_seal", None) is not None
    signature.write_text(json.dumps(doc, indent=2), encoding="utf-8")

    assert _verdict(challenge_packet, local_tsa).evidence_ready, "documented MISS: seal stripped"
    assert not _verdict(challenge_packet, local_tsa, require_packet_seal=True).evidence_ready


def test_a_dev_seal_is_never_trusted(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    dev_tsa: DevTSA,
    tmp_path: Path,
) -> None:
    """The DevTSA rule (ADR 0008) reaches the seal too: offline convenience never
    becomes recipient-facing trust."""
    vault = make_vault()
    issue = vault.document.add_issue(category="mold", room="bathroom", title="Leak", issue_id="i1")
    capture(vault, make_jpeg("a.jpg"), issue_id=issue, tsa=local_tsa)
    out = tmp_path / "dev-sealed"
    build_packet(vault, out, generated_at="2026-01-02T00:10:00Z", make_pdf=False, tsa=dev_tsa)

    report = _verdict(out, local_tsa)
    assert report.seal.present and report.seal.verified
    assert not report.seal.trusted and report.seal.kind == "dev"
    assert "does not chain" in report.seal_statement("en")
    assert not _verdict(out, local_tsa, require_packet_seal=True).evidence_ready


@pytest.mark.parametrize(
    ("record", "expected"),
    [
        ({"kind": "rfc3161", "tsa_name": "x", "token_b64": "!!not base64!!"}, "does not cover"),
        ({"kind": "nonsense", "tsa_name": "x", "token_b64": "AAAA"}, "does not cover"),
        ({"not": "a token"}, "does not cover"),
    ],
)
def test_a_malformed_seal_is_a_problem_not_a_crash(
    challenge_packet: Path,
    local_tsa: LocalRfc3161TSA,
    record: dict[str, Any],
    expected: str,
) -> None:
    signature = challenge_packet / "bundle.sig.json"
    doc = json.loads(signature.read_text())
    doc["packet_seal"] = record
    signature.write_text(json.dumps(doc, indent=2), encoding="utf-8")

    # Caught with nothing asserted, for the same reason: a present seal is checked.
    report = _verdict(challenge_packet, local_tsa)
    assert not report.evidence_ready
    assert report.seal.present and not report.seal.verified
    assert any(expected in problem for problem in report.problems)
    assert not _verdict(challenge_packet, local_tsa, require_packet_seal=True).evidence_ready


def test_a_seal_lifted_from_another_packet_does_not_transfer(
    challenge_packet: Path,
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
) -> None:
    """A genuine, trusted, in-date seal — over somebody else's bundle."""
    vault = make_vault("donor-vault", case_id="case-donor", unit="9Z")
    issue = vault.document.add_issue(category="mold", room="bathroom", title="Leak", issue_id="i1")
    capture(vault, make_jpeg("other.jpg", color=(9, 9, 9)), issue_id=issue, tsa=local_tsa)
    donor = tmp_path / "donor"
    build_packet(vault, donor, generated_at="2026-01-02T00:10:00Z", make_pdf=False, tsa=local_tsa)

    donor_seal = json.loads((donor / "bundle.sig.json").read_text())["packet_seal"]
    signature = challenge_packet / "bundle.sig.json"
    doc = json.loads(signature.read_text())
    doc["packet_seal"] = donor_seal
    signature.write_text(json.dumps(doc, indent=2), encoding="utf-8")

    # Caught with nothing asserted: a seal that is present is always checked.
    unasserted = _verdict(challenge_packet, local_tsa)
    assert not unasserted.evidence_ready
    assert any("does not cover this bundle" in problem for problem in unasserted.problems)
    assert not _verdict(challenge_packet, local_tsa, require_packet_seal=True).evidence_ready


@pytest.mark.parametrize(
    ("not_after", "expected"),
    [
        ("not a date", "is not a valid ISO 8601 UTC instant"),
        ("2020-01-01", "after the"),
    ],
)
def test_seal_date_assertions_fail_closed(
    challenge_packet: Path, local_tsa: LocalRfc3161TSA, not_after: str, expected: str
) -> None:
    report = _verdict(challenge_packet, local_tsa, seal_not_after=not_after)
    assert not report.evidence_ready
    assert any(expected in problem for problem in report.problems)


def test_a_seal_date_asserted_against_an_unsealed_packet_fails_closed(
    challenge_packet: Path, local_tsa: LocalRfc3161TSA
) -> None:
    signature = challenge_packet / "bundle.sig.json"
    doc = json.loads(signature.read_text())
    doc.pop("packet_seal")
    signature.write_text(json.dumps(doc, indent=2), encoding="utf-8")

    report = _verdict(challenge_packet, local_tsa, seal_not_after="2030-01-01T00:00:00Z")
    assert not report.evidence_ready
    assert "seal date asserted, but this packet carries no authority seal to date" in (
        report.problems
    )


def test_an_unreadable_seal_time_is_a_problem_not_a_skipped_check() -> None:
    """Fail closed: if the deadline cannot be compared, say so — never pass quietly.

    `verify_token` normalizes `gen_time`, so this is a defensive branch reached
    directly rather than through a packet. It exists because the alternative to
    reporting an uncomparable date is silently ignoring the assertion.
    """
    info = TimestampInfo(
        kind="rfc3161",
        tsa_name="x",
        gen_time="whenever",
        digest_hex="0" * 64,
        trusted_chain=True,
    )
    problems = _seal_deadline_problems(
        info, deadline=datetime(2026, 1, 3, tzinfo=UTC), not_after="2026-01-03"
    )
    assert problems == ["packet seal carries an unreadable generation time"]


def test_a_seal_dated_on_or_before_the_deadline_passes(
    challenge_packet: Path, local_tsa: LocalRfc3161TSA
) -> None:
    """Boundary: the instant itself is inside the window, and a bare date means
    midnight UTC."""
    exact = _verdict(challenge_packet, local_tsa, seal_not_after="2026-01-02T00:00:00Z")
    assert exact.evidence_ready
    day = _verdict(challenge_packet, local_tsa, seal_not_after="2026-01-03")
    assert day.evidence_ready


def test_seal_problems_survive_an_unsupported_version(
    challenge_packet: Path, local_tsa: LocalRfc3161TSA
) -> None:
    """A version problem must not swallow the seal verdict (cf. the pin)."""
    bundle = json.loads((challenge_packet / "bundle.json").read_text())
    bundle["packet_version"] = 999
    _resign(challenge_packet, bundle)
    report = _verdict(challenge_packet, local_tsa, require_packet_seal=True)
    assert report.seal.required and not report.seal.present
    assert any("no authority seal" in problem for problem in report.problems)


def test_cli_seal_flags_pass_fail_and_explain_themselves(
    challenge_packet: Path,
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The challenge is run through the CLI, so the flags have to work there."""
    pem = tmp_path / "tsa.pem"
    pem.write_bytes(local_tsa.certificate.public_bytes(Encoding.PEM))
    base = ["verify", str(challenge_packet), "--trusted-cert", str(pem)]

    assert main([*base, "--require-packet-seal"]) == 0
    assert "countersigned by" in capsys.readouterr().out

    assert main([*base, "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["packet_seal"]["ok"] is True
    assert payload["packet_seal"]["required"] is False

    assert main([*base, "--seal-not-after", "2020-01-01"]) == 1
    assert "after the 2020-01-01 you supplied" in capsys.readouterr().err

    signature = challenge_packet / "bundle.sig.json"
    doc = json.loads(signature.read_text())
    doc.pop("packet_seal")
    signature.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    assert main([*base, "--require-packet-seal"]) == 1
    captured = capsys.readouterr()
    assert "authority seal: none" in captured.out
    assert "no authority seal over its contents" in captured.err


# --------------------------------------------------------------------------- #
# The pin itself: fails closed on every malformed input.                       #
# --------------------------------------------------------------------------- #
def test_pin_matching_the_real_key_still_passes(
    challenge_packet: Path, local_tsa: LocalRfc3161TSA, genuine_key: str
) -> None:
    report = _verdict(challenge_packet, local_tsa, expected_producer_key=f"  {genuine_key}  ")
    assert report.evidence_ready and report.producer_key_pinned


@pytest.mark.parametrize(
    ("pin", "problem"),
    [
        ("!!! not base64 !!!", "pinned producer key is not valid base64"),
        ("", "pinned producer key is empty"),
    ],
)
def test_unusable_pin_fails_closed(
    challenge_packet: Path, local_tsa: LocalRfc3161TSA, pin: str, problem: str
) -> None:
    report = _verdict(challenge_packet, local_tsa, expected_producer_key=pin)
    assert not report.evidence_ready
    assert problem in report.problems


def test_pin_against_a_packet_with_no_signature_file(
    challenge_packet: Path, local_tsa: LocalRfc3161TSA, genuine_key: str
) -> None:
    (challenge_packet / "bundle.sig.json").unlink()
    report = _verdict(challenge_packet, local_tsa, expected_producer_key=genuine_key)
    assert "producer key pinned, but this packet has no readable signing key" in report.problems


@pytest.mark.parametrize(
    "payload",
    ['["not", "an", "object"]', '{"sign_public": 42}', '{"sign_public": "not base64!"}'],
)
def test_pin_against_an_unreadable_signature_file(
    challenge_packet: Path, local_tsa: LocalRfc3161TSA, genuine_key: str, payload: str
) -> None:
    (challenge_packet / "bundle.sig.json").write_text(payload, encoding="utf-8")
    report = _verdict(challenge_packet, local_tsa, expected_producer_key=genuine_key)
    assert "producer key pinned, but this packet has no readable signing key" in report.problems


def test_cli_pin_flag_passes_fails_and_explains_itself(
    challenge_packet: Path,
    local_tsa: LocalRfc3161TSA,
    genuine_key: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The challenge is run through the CLI, so the flag has to work there."""
    pem = tmp_path / "tsa.pem"
    pem.write_bytes(local_tsa.certificate.public_bytes(Encoding.PEM))
    base = ["verify", str(challenge_packet), "--trusted-cert", str(pem)]

    assert main([*base, "--expected-producer-key", genuine_key]) == 0
    capsys.readouterr()

    assert main([*base, "--expected-producer-key", "AAAA"]) == 1
    captured = capsys.readouterr()
    assert "packet signing key does not match the pinned producer key" in captured.err

    assert main([*base, "--expected-producer-key", genuine_key, "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["producer_key_pinned"] is True


def test_cli_json_reports_an_unpinned_run_as_unpinned(
    challenge_packet: Path,
    local_tsa: LocalRfc3161TSA,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    pem = tmp_path / "tsa.pem"
    pem.write_bytes(local_tsa.certificate.public_bytes(Encoding.PEM))
    assert main(["verify", str(challenge_packet), "--trusted-cert", str(pem), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["producer_key_pinned"] is False
    assert payload["evidence_ready"] is True


def test_pin_is_reported_alongside_a_version_problem(
    challenge_packet: Path, local_tsa: LocalRfc3161TSA
) -> None:
    """An unsupported version must not swallow the pin verdict."""
    bundle = json.loads((challenge_packet / "bundle.json").read_text())
    bundle["packet_version"] = 999
    _resign(challenge_packet, bundle)
    report = _verdict(challenge_packet, local_tsa, expected_producer_key="AAAA")
    assert report.producer_key_pinned
    assert any("pinned producer key" in problem for problem in report.problems)
