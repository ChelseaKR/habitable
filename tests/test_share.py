# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""E2E-encrypted, redactable case sharing with an organizer."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from habitable.capture import capture
from habitable.errors import HabitableError, ShareError
from habitable.pairing import accept_pairing_material, create_pairing_material
from habitable.share import decode_share, encode_share, export_share, import_share
from habitable.tsa import LocalRfc3161TSA
from habitable.vault import Vault


def _tenant_with_two_issues(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], tsa: LocalRfc3161TSA
) -> Vault:
    vault = make_vault(name="tenant", case_id="case-4B", unit="4B")
    i1 = vault.document.add_issue(category="mold", title="Mold", issue_id="i1")
    i2 = vault.document.add_issue(category="heat", title="No heat", issue_id="i2")
    vault.document.add_timeline_entry(i1, "observed", "spreading")
    capture(vault, make_jpeg("a.jpg", with_location=True), issue_id=i1, tsa=tsa)
    capture(vault, make_jpeg("b.jpg", with_location=True), issue_id=i2, tsa=tsa)
    vault.save()
    return vault


def test_share_round_trip_full_case(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], local_tsa: LocalRfc3161TSA
) -> None:
    tenant = _tenant_with_two_issues(make_vault, make_jpeg, local_tsa)
    organizer = make_vault(name="org", case_id="case-4B", unit="")

    blob = export_share(tenant, organizer.identity.public())
    # The sealed share leaks no plaintext (issue titles, unit) to a relay/courier.
    assert b"Mold" not in blob
    assert b"No heat" not in blob

    result = import_share(organizer, blob)
    assert result.captures_imported == 2
    assert {i.issue_id for i in organizer.document.issues()} == {"i1", "i2"}
    # The unit label merged in from the (non-redacted) share.
    assert organizer.document.get_meta("unit") == "4B"
    # The originals are present and re-verify on read.
    for cap in organizer.document.captures():
        assert organizer.has_original(cap.capture_id)
        organizer.read_original(cap.capture_id, cap.content_hash)


def test_share_subset_excludes_other_issues(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], local_tsa: LocalRfc3161TSA
) -> None:
    tenant = _tenant_with_two_issues(make_vault, make_jpeg, local_tsa)
    organizer = make_vault(name="org", case_id="case-4B", unit="")

    blob = export_share(tenant, organizer.identity.public(), issue_ids={"i1"})
    import_share(organizer, blob)

    assert {i.issue_id for i in organizer.document.issues()} == {"i1"}
    # Only i1's capture crossed over; i2's evidence never left the tenant device.
    captures = organizer.document.captures()
    assert len(captures) == 1
    assert captures[0].issue_id == "i1"


def test_share_can_redact_unit_label(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], local_tsa: LocalRfc3161TSA
) -> None:
    tenant = _tenant_with_two_issues(make_vault, make_jpeg, local_tsa)
    organizer = make_vault(name="org", case_id="case-4B", unit="")

    blob = export_share(tenant, organizer.identity.public(), issue_ids={"i1"}, redact_unit=True)
    import_share(organizer, blob)
    # The unit label was withheld; the organizer still gets the issue + evidence.
    assert organizer.document.get_meta("unit") == ""
    assert {i.issue_id for i in organizer.document.issues()} == {"i1"}


def test_share_unknown_issue_is_rejected(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], local_tsa: LocalRfc3161TSA
) -> None:
    tenant = _tenant_with_two_issues(make_vault, make_jpeg, local_tsa)
    organizer = make_vault(name="org", case_id="case-4B")
    with pytest.raises(ShareError):
        export_share(tenant, organizer.identity.public(), issue_ids={"nope"})


def test_share_not_addressed_to_us_opens_nothing(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], local_tsa: LocalRfc3161TSA
) -> None:
    tenant = _tenant_with_two_issues(make_vault, make_jpeg, local_tsa)
    organizer = make_vault(name="org", case_id="case-4B")
    stranger = make_vault(name="stranger", case_id="case-4B")

    blob = export_share(tenant, organizer.identity.public())
    # Sealed to the organizer's key: the stranger cannot open it.
    with pytest.raises(ShareError):
        import_share(stranger, blob)


def test_share_for_a_different_case_is_rejected(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], local_tsa: LocalRfc3161TSA
) -> None:
    tenant = _tenant_with_two_issues(make_vault, make_jpeg, local_tsa)
    organizer = make_vault(name="org", case_id="some-other-case", unit="")

    material = create_pairing_material(tenant, organizer.identity.public())
    # Pairing itself is case-bound, so an unsafe cross-case share cannot be created.
    with pytest.raises(HabitableError):
        accept_pairing_material(organizer, material)


def test_share_import_is_idempotent(
    make_vault: Callable[..., Vault], make_jpeg: Callable[..., Path], local_tsa: LocalRfc3161TSA
) -> None:
    tenant = _tenant_with_two_issues(make_vault, make_jpeg, local_tsa)
    organizer = make_vault(name="org", case_id="case-4B", unit="")

    blob = export_share(tenant, organizer.identity.public())
    first = import_share(organizer, blob)
    second = import_share(organizer, blob)
    assert first.captures_imported == 2
    assert second.captures_imported == 0  # already held; nothing re-imported
    assert len(organizer.document.captures()) == 2


def test_share_file_encoding_round_trips() -> None:
    blob = b"\x00\x01sealed-bytes\xff"
    assert decode_share(encode_share(blob)) == blob
    with pytest.raises(ShareError):
        decode_share("not valid base64 !!!")
