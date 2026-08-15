# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""The documented sync fail-closed property, tested as an absence (issue #163).

``docs/sync-threat-model.md`` states "A validation failure cannot partially
merge the message's CRDT state" and ``docs/sync-protocol-v2.md`` §3 states "Any
failure aborts that message before merge." One signed inner field -- the
``have`` manifest -- used to be validated one line *after*
``vault.document.merge``, so for that field both sentences were false: a
malformed ``have`` raised ``SyncError`` while the recipient's case document had
already been mutated, and because the raise happened before
``mark_sync_message_seen`` / ``queue_sync_receipt``, the custody and receipt
record said the message never arrived.

These tests assert the *absence* of the merge, not the presence of the raise.
A test that only asserted "malformed ``have`` raises" passed against the buggy
code.

Stored corpus and its limit
---------------------------
``tests/golden/sync-v2-adversarial/malformed-inner-fields.json`` freezes one
malformed shape per signed inner field. It stores *mutations*, not sealed
envelope bytes: a committed ``.hsync`` blob would only open with a committed
recipient private key, which this repository does not carry. So the mutation is
frozen on disk and re-applied to a genuinely signed, genuinely sealed,
genuinely paired message at test time -- which is weaker than a byte-frozen
corpus for catching a change in the *encoder*, and exactly as strong for
catching a change in the *decoder*'s validation order, which is what issue #163
is about. Issue #163 item 3's full ask (committed envelope bytes) remains open.
"""

from __future__ import annotations

import base64
import hmac
import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, cast

import pytest

from habitable.canonical import JSONValue, canonical_json
from habitable.capture import capture
from habitable.crypto import PublicIdentity, open_sealed, seal_to
from habitable.errors import SyncError
from habitable.sync import export_message, import_messages
from habitable.tsa import LocalRfc3161TSA
from habitable.vault import Vault

CORPUS_PATH = (
    Path(__file__).parent / "golden" / "sync-v2-adversarial" / "malformed-inner-fields.json"
)

# Every key of a v2 inner payload is inside the bytes covered by the Ed25519
# signature and the pairing HMAC, so every one of them is attacker-controlled
# from the moment a paired peer is version-skewed, buggy, or compromised. The
# corpus is required to carry at least one malformed case for each; see
# `test_the_corpus_covers_every_signed_inner_field`.
_SIGNED_INNER_FIELDS = frozenset(
    {
        "protocol",
        "message_id",
        "case_id",
        "recipient",
        "state",
        "state_sha256",
        "have",
        "captures",
        "custody_proof",
        "receipts",
    }
)


def _load_corpus() -> list[dict[str, Any]]:
    raw = json.loads(CORPUS_PATH.read_text("utf-8"))
    cases = raw["cases"]
    assert isinstance(cases, list) and cases, "adversarial sync corpus is empty"
    return cast(list[dict[str, Any]], cases)


CORPUS = _load_corpus()


def _open_inner(recipient: Vault, blob: bytes) -> dict[str, JSONValue]:
    envelope = json.loads(open_sealed(recipient.identity, blob))
    inner = json.loads(base64.b64decode(envelope["inner_b64"], validate=True))
    assert isinstance(inner, dict)
    return cast(dict[str, JSONValue], inner)


def _reseal(sender: Vault, recipient: PublicIdentity, inner: Mapping[str, JSONValue]) -> bytes:
    """Re-seal a mutated inner payload with the sender's *real* identity and
    *real* pairing key, so every binding the protocol checks before this point
    genuinely passes and the message reaches the validation under test."""
    peer = sender.sync_peer(recipient)
    assert peer is not None
    inner_bytes = canonical_json(dict(inner))
    envelope: dict[str, JSONValue] = {
        "sender": sender.identity.public().encode(),
        "pairing_id": peer.pairing_id,
        "inner_b64": base64.b64encode(inner_bytes).decode("ascii"),
        "sig": base64.b64encode(sender.identity.sign(inner_bytes)).decode("ascii"),
        "mac": base64.b64encode(hmac.digest(peer.key, inner_bytes, "sha256")).decode("ascii"),
    }
    return seal_to(recipient, canonical_json(envelope))


@pytest.fixture
def paired_case(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
) -> tuple[Vault, Vault, str]:
    """A sender holding one issue and one timestamped capture the recipient has
    never seen, paired with a recipient that holds neither."""
    sender = make_vault(name="sender")
    recipient = make_vault(name="recipient")
    issue_id = sender.document.add_issue(category="mold", issue_id="only-on-the-sender")
    captured = capture(sender, make_jpeg(), issue_id=issue_id, tsa=local_tsa)
    sender.save()
    assert issue_id not in {issue.issue_id for issue in recipient.document.issues()}
    return sender, recipient, captured.capture_id


def test_the_baseline_message_really_does_merge(paired_case: tuple[Vault, Vault, str]) -> None:
    """Guards the corpus tests below: if an unmutated message did not merge,
    "the document did not change" would be trivially true for every case."""
    sender, recipient, capture_id = paired_case
    before = canonical_json(dict(recipient.document.to_state()))

    result = import_messages(recipient, [export_message(sender, recipient.identity.public())])

    assert result.messages_merged == 1
    assert canonical_json(dict(recipient.document.to_state())) != before
    assert "only-on-the-sender" in {issue.issue_id for issue in recipient.document.issues()}
    assert recipient.has_original(capture_id)


@pytest.mark.parametrize("case", CORPUS, ids=[str(case["id"]) for case in CORPUS])
def test_a_rejected_message_leaves_the_document_byte_identical(
    case: dict[str, Any], paired_case: tuple[Vault, Vault, str]
) -> None:
    """The property as documented: a validation failure cannot partially merge.

    Asserted as an absence -- the recipient's canonical CRDT state before and
    after must be byte-identical, and the sender's issue must not have appeared.
    On the pre-fix code the four ``have-*`` cases raised (so a raise-only test
    passed) while this assertion failed.
    """
    sender, recipient, capture_id = paired_case
    sender_public = sender.identity.public()
    blob = export_message(sender, recipient.identity.public())
    inner = _open_inner(recipient, blob)
    message_id = inner.get("message_id")

    if case["op"] == "delete":
        inner.pop(case["field"], None)
    else:
        inner[case["field"]] = cast(JSONValue, case["value"])
    mutated = _reseal(sender, recipient.identity.public(), inner)

    before = canonical_json(dict(recipient.document.to_state()))
    with pytest.raises(SyncError, match=case["expect_error"]):
        import_messages(recipient, [mutated])

    assert canonical_json(dict(recipient.document.to_state())) == before
    assert "only-on-the-sender" not in {issue.issue_id for issue in recipient.document.issues()}
    # A merge with no matching custody/receipt record is the specific
    # inconsistency issue #163 describes; assert the whole set stayed empty.
    assert not recipient.has_original(capture_id)
    assert recipient.pending_sync_receipts(sender_public) == ()
    assert not recipient.known_peer_captures(sender_public.fingerprint)
    if isinstance(message_id, str):
        assert not recipient.has_seen_sync_message(sender_public, message_id)


def test_a_rejected_message_can_still_be_re_sent_and_merged(
    paired_case: tuple[Vault, Vault, str],
) -> None:
    """The recovery path a fail-closed import owes the operator.

    Pre-fix, a malformed ``have`` merged the state and left the message unseen,
    so a corrected re-send merged an already-merged state. Post-fix the first
    attempt changes nothing, so the re-send is the *only* merge -- which is what
    makes "unseen" the truth rather than a second inconsistency.
    """
    sender, recipient, _ = paired_case
    blob = export_message(sender, recipient.identity.public())
    inner = _open_inner(recipient, blob)
    inner["have"] = "not-an-array"

    with pytest.raises(SyncError, match="sync have manifest must be an array"):
        import_messages(recipient, [_reseal(sender, recipient.identity.public(), inner)])
    assert not recipient.document.issues()

    result = import_messages(recipient, [blob])

    assert result.messages_merged == 1
    assert result.replays_skipped == 0
    assert "only-on-the-sender" in {issue.issue_id for issue in recipient.document.issues()}


def test_a_well_formed_have_manifest_is_still_confirmed_after_the_merge(
    paired_case: tuple[Vault, Vault, str],
) -> None:
    """Validating ``have`` before the merge must not quietly narrow what it
    confirms.

    The confirmation itself is deliberately still computed *after* the merge:
    a capture arriving in this very message is in the sender's ``have``, and
    intersecting against the pre-merge document would fail to confirm it and
    make the next export re-send bytes the peer already holds. Only the
    validation moved.
    """
    sender, recipient, capture_id = paired_case

    import_messages(recipient, [export_message(sender, recipient.identity.public())])

    assert capture_id in recipient.known_peer_captures(sender.identity.public().fingerprint)


def test_the_corpus_covers_every_signed_inner_field() -> None:
    """Turn "we forgot" into a red build.

    ``have`` was absent from ``docs/sync-protocol-v2.md`` §3's ordered
    pre-merge checklist, which is how an unordered check went unnoticed on
    review. A new signed field added without an adversarial case fails here.
    """
    covered = {str(case["field"]) for case in CORPUS}
    assert covered == set(_SIGNED_INNER_FIELDS), (
        "adversarial sync corpus and the signed inner-field list disagree: "
        f"missing {sorted(_SIGNED_INNER_FIELDS - covered)}, "
        f"unexpected {sorted(covered - _SIGNED_INNER_FIELDS)}"
    )


def test_the_signed_field_list_matches_what_export_actually_emits(
    paired_case: tuple[Vault, Vault, str],
) -> None:
    """And keep that list honest against the encoder, not just against itself."""
    sender, recipient, _ = paired_case
    inner = _open_inner(recipient, export_message(sender, recipient.identity.public()))
    assert set(inner) == set(_SIGNED_INNER_FIELDS)
