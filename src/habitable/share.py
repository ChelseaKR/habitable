# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""End-to-end-encrypted case sharing with a tenant-union organizer.

Sync (:mod:`habitable.sync`) keeps two devices on *the same* case in step. Sharing
is the one-way cousin: a tenant hands a case to an organizer who was not previously
on it, without any server ever being able to read it. The ``unit`` metadata field can be
omitted, but other full-case content can still identify the unit.
Issue-subset sharing is temporarily blocked because sync v2 carries a complete custody
proof that can reveal identifiers outside the selected subset.

Behind that hold, :func:`build_share_state` still enforces the two disclosure rules a
scoped share owes its recipient — prune the issue OR-set's removal tags to the scope,
and refuse rather than silently delete a relationship that leaves it — so that whoever
lifts the hold has to *remove* those rules to ship without them. They are unreachable
today and are pinned by direct tests rather than by the CLI path (issue #279).

How it preserves end-to-end encryption
--------------------------------------
A share is exactly a sync message, reusing the same primitives:

* The tenant builds a full-case CRDT state, optionally with the unit label redacted,
  and attaches the case's sealed originals.
* The devices first exchange signed, recipient-sealed, case-bound pairing
  material. The exact expected identity and pairing key are pinned in each
  encrypted vault; a public id alone is not authorization.
* The payload is **signed** by the tenant's device key, authenticated with the
  pairing key, and **sealed** to the
  organizer's X25519 public key (:func:`habitable.crypto.seal_to`, an ephemeral-key
  ECIES box). Only the holder of the organizer's private key can open it; a relay,
  a courier, or a cloud drive used to move the ``.share`` file sees ciphertext only.
* On receipt the organizer's device verifies the signature, checks the share is for
  the case they opened, re-checks each original's fixity, validates any RFC 3161
  token, and merges the CRDT state. Because the model is a CRDT, receiving the same
  share twice changes nothing.

Trust / key-exchange model (see ``docs/sharing-trust-model.md``)
---------------------------------------------------------------
Trust is **direct and out-of-band**, with no central directory. The organizer runs
``habitable id`` and gives the tenant their public identity; the tenant confirms the
short fingerprint over a trusted channel (in person, a verified call) before sharing
— this is the human step that defeats a man-in-the-middle. The devices then use
``sync-pair-create`` / ``sync-pair-accept`` before the tenant seals the case.
The server is never trusted: it cannot read, forge, or authorize a recipient.
"""

from __future__ import annotations

import base64
from collections.abc import Mapping
from dataclasses import dataclass

from .canonical import JSONValue
from .crypto import PublicIdentity
from .errors import ShareError
from .model import CaseDocument
from .sync import export_message, import_messages
from .vault import Vault

__all__ = [
    "ShareResult",
    "build_share_state",
    "decode_share",
    "encode_share",
    "export_share",
    "import_share",
]

#: Case metadata a *scoped* disclosure must never carry, because holding it lets the
#: recipient reconstruct information about records the scope excluded.
#:
#: ``case_salt`` is the HMAC key behind :meth:`habitable.model.CaseDocument.opaque_id`:
#: every exported identifier in the case is ``HMAC(case_salt, hlc)`` truncated to 64
#: bits. A recipient holding the salt can mint the id of *any* record whose HLC they
#: can guess or observe — including records the scope was drawn to withhold — and can
#: confirm a guess offline. For a **full-case** share the salt is load-bearing and stays:
#: ``packet.py`` derives every ``order_token`` and the whole custody-proof HLC mapping
#: from it, so a recipient without the salt would mint a *different* salt on their first
#: local edit and export packets whose ordering tokens no device can correlate with the
#: sender's. That trade is the right way round: a full-case recipient was given every
#: record the salt could name, and a scoped recipient was not.
_SCOPE_WITHHELD_META = frozenset({"case_salt"})


@dataclass(frozen=True, slots=True)
class ShareResult:
    """What a received share contributed to the organizer's vault."""

    case_id: str
    captures_imported: int
    merged: bool


def export_share(
    vault: Vault,
    recipient: PublicIdentity,
    *,
    issue_ids: set[str] | None = None,
    redact_unit: bool = False,
) -> bytes:
    """Seal a full case to ``recipient``, returning sealed bytes.

    ``issue_ids`` is retained as an API/CLI compatibility parameter, but any value
    other than ``None`` fails before state attestation or sync-message construction.
    ``redact_unit`` may still omit the ``unit`` metadata field from an otherwise
    full-case state. It is field-level omission, not an anonymity guarantee.
    The result is signed and sealed — safe to move over any untrusted channel.
    """
    if issue_ids is not None:
        raise ShareError(
            "scoped shares are temporarily blocked: sync v2 carries the complete custody "
            "chain, which can reveal identifiers outside the selected issues. Share the "
            "whole case. This is a safety hold, not an unfinished feature: restoring it needs "
            "a versioned, rehashed custody-view format that binds its own scope, plus "
            "independent crypto review (issue #262)."
        )

    vault.document.attest_unsigned_fields()
    state = build_share_state(vault.document, None, redact_meta=redact_unit)
    return export_message(vault, recipient, state=state)


def build_share_state(
    document: CaseDocument,
    issue_ids: set[str] | None,
    *,
    redact_meta: bool = False,
) -> dict[str, JSONValue]:
    """Project ``document`` to the CRDT state a share may carry, refusing dishonest scopes.

    For ``issue_ids=None`` — every share the CLI can build today — this is exactly
    :meth:`habitable.model.CaseDocument.subset_state` and nothing else happens.

    For a scope it is that projection *plus* the disclosure rules a scoped share owes
    its recipient, which the projection itself does not enforce. ``subset_state`` is a
    general CRDT projection: it filters issues, timeline entries, captures and
    artifacts to the selected set and stops there, which is correct for a projection
    and insufficient for a disclosure. The two extra obligations live here, at the
    export boundary that owns the scope decision and raises the hold above, so that
    lifting that hold cannot ship them silently:

    * **Removal tags are pruned to the scope.** ``subset_state`` filters the issue
      OR-set's ``adds`` but passes ``removes`` through whole. Those are raw HLC add
      tags for issues that were *deleted*, and an HLC carries the originating device's
      wall clock and node id — so an unfiltered ``removes`` names, and dates, issues
      the scope was drawn to exclude. Only tags belonging to a disclosed issue survive.
      The cost is that a scoped share can no longer propagate the deletion of an issue
      outside its scope; that is the correct cost, because a scoped share is not
      authoritative about records it does not carry.
    * **A cross-scope relationship is refused, never dropped.** ``subset_state`` keeps
      a relationship only when *both* endpoints are inside the scope, and drops the
      rest without saying so. A recipient then cannot distinguish a record that never
      had relationships from one whose relationships were removed, which is exactly the
      "never deletes arbitrary links" clause of issue #262's own exit criteria failing
      one layer down. Silence is the one option ADR 0018 (decision 6) rules out: the
      scope is either closed under its links or the operator is told. Closing it widens
      a disclosure, and only the tenant may choose that, so this layer refuses and names
      what widening would cost.

    Raising :class:`~habitable.errors.ShareError` is safe here because the caller has
    not yet minted a message id or touched custody: :func:`export_share` refuses a scope
    before this point, and a future caller that stops refusing still calls this before
    :func:`habitable.sync.export_message`.
    """
    state = document.subset_state(issue_ids, redact_meta=redact_meta)
    if issue_ids is None:
        return state
    _refuse_cross_scope_relationships(
        _as_object(document.to_state().get("relationships")),
        _as_object(state.get("relationships")),
        issue_ids,
    )
    _prune_out_of_scope_removals(state)
    _withhold_scope_sensitive_meta(state)
    return state


def _refuse_cross_scope_relationships(
    held: Mapping[str, JSONValue], disclosed: Mapping[str, JSONValue], issue_ids: set[str]
) -> None:
    """Refuse a scope that would have to delete a link in order to fit inside itself.

    ``held`` is every relationship the case holds; ``disclosed`` is the projection's
    surviving subset. A relationship belongs to the scope when its own ``issue_id`` is
    selected, so any such relationship missing from ``disclosed`` was dropped for its
    endpoints — and shipping the scope anyway hands the recipient a record whose links
    were removed with no record of the removal.

    Written against the two dictionaries rather than against a
    :class:`~habitable.model.CaseDocument` on purpose. Today's model makes the condition
    unreachable from any document you can construct: ``add_relationship`` and
    ``_validate_relationship`` both require every endpoint to belong to the
    relationship's own issue, so an issue-selected scope always contains the endpoints
    too. That invariant lives in ``model.py``, not here, and it is exactly one selector
    away from ending — a date-scoped export filters captures by ``captured_at`` while
    keeping its issue's relationships, and issue #262 restores ``--since`` alongside
    ``--issue``. Taking plain mappings keeps this check pinned by a direct test instead
    of resting on an invariant enforced somewhere else.
    """
    dropped = sorted(
        relationship_id
        for relationship_id, payload in held.items()
        if relationship_id not in disclosed
        and isinstance(payload, dict)
        and str(payload.get("issue_id", "")) in issue_ids
    )
    if not dropped:
        return
    named = ", ".join(dropped)
    raise ShareError(
        f"this scope cannot be shared honestly: {len(dropped)} relationship(s) inside it "
        f"({named}) point to an endpoint outside it. A scoped share must either include "
        "the endpoint — widening the disclosure, which is the tenant's decision to make "
        "and not this code's — or say that the link was removed, which sync v2 has no "
        "field for. Share the whole case, or add the endpoint's issue to the scope "
        "(issue #262, ADR 0018 decision 6)."
    )


def _prune_out_of_scope_removals(state: dict[str, JSONValue]) -> None:
    """Drop OR-set removal tags that belong to no disclosed issue.

    Every surviving tag is one of the disclosed issues' own add tags, so the add-wins
    semantics of the elements the recipient actually receives are unchanged: a tag that
    can cancel nothing in this state can only name something outside it.
    """
    issues = state.get("issues")
    if not isinstance(issues, dict):
        return
    adds = _as_object(issues.get("adds"))
    disclosed_tags = {str(tag) for tags in adds.values() if isinstance(tags, list) for tag in tags}
    removes = issues.get("removes")
    if not isinstance(removes, list):
        return
    issues["removes"] = [tag for tag in removes if str(tag) in disclosed_tags]


def _withhold_scope_sensitive_meta(state: dict[str, JSONValue]) -> None:
    """Strip the metadata registers a scoped recipient must not hold (``case_salt``)."""
    meta = state.get("meta")
    if not isinstance(meta, dict):
        return
    for key in _SCOPE_WITHHELD_META:
        meta.pop(key, None)


def _as_object(value: JSONValue | None) -> dict[str, JSONValue]:
    """Narrow a JSON member to an object, treating anything else as empty."""
    return value if isinstance(value, dict) else {}


def import_share(vault: Vault, blob: bytes) -> ShareResult:
    """Open a sealed share addressed to this device and merge it into ``vault``.

    Rejects a share addressed to a different case (the recipient must have opened a
    vault for the same ``case_id``). Signature, fixity, and timestamp checks all run
    inside :func:`habitable.sync.import_messages`; a share not addressed to this
    device (wrong key) merges nothing rather than raising.
    """
    result = import_messages(vault, [blob], require_case_id=vault.document.case_id)
    if result.messages_merged == 0:
        if result.replays_skipped:
            return ShareResult(
                case_id=vault.document.case_id,
                captures_imported=0,
                merged=True,
            )
        raise ShareError(
            "no share opened: it is not sealed to this device's key, or not a share message"
        )
    return ShareResult(
        case_id=vault.document.case_id,
        captures_imported=result.captures_imported,
        merged=True,
    )


def encode_share(blob: bytes) -> str:
    """Wrap sealed share bytes as a single base64 line for a portable ``.share`` file."""
    return base64.b64encode(blob).decode("ascii")


def decode_share(text: str) -> bytes:
    """Read sealed share bytes from a ``.share`` file produced by :func:`encode_share`."""
    try:
        return base64.b64decode(text.strip(), validate=True)
    except ValueError as exc:
        raise ShareError("share file is not valid base64") from exc
