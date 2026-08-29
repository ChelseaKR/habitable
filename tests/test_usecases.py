# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif

from __future__ import annotations

import json
import re
from dataclasses import replace
from datetime import date
from pathlib import Path

import pytest

from habitable.errors import HabitableError
from habitable.usecases import (
    ARTIFACT_TYPES,
    RELATIONSHIP_ENDPOINT_KINDS,
    RELATIONSHIP_TYPES,
    get_profile,
    list_profiles,
    profile_expired,
)


def test_every_built_in_profile_is_versioned_and_valid() -> None:
    profiles = list_profiles()
    assert len(profiles) == 11
    assert len({profile.profile_id for profile in profiles}) == 11
    for profile in profiles:
        assert profile.version == 1
        assert profile.name_en and profile.name_es
        assert set(profile.artifact_types) <= ARTIFACT_TYPES
        assert set(profile.relationship_types) <= RELATIONSHIP_TYPES
        payload = profile.to_json()
        assert payload["profile_id"] == profile.profile_id
        assert payload["review_state"] in {"maintainer_reviewed", "external_review_required"}


def test_sensitive_profiles_keep_external_review_gate() -> None:
    for profile_id in (
        "inspector_handoff",
        "accommodation_request",
        "public_housing_remediation",
        "health_corroboration",
        "building_pattern",
        "partner_capsule",
    ):
        assert get_profile(profile_id).external_review_required


def test_unknown_profile_fails_closed() -> None:
    with pytest.raises(HabitableError, match="unknown use-case profile"):
        get_profile("not-real")


def test_no_shipped_profile_expires_today() -> None:
    # None of the built-in profiles sets expires_at yet; this is
    # forward-looking infrastructure for jurisdiction/community profiles, not a
    # behavior change for what ships today.
    for profile in list_profiles():
        assert profile.expires_at == ""
        assert not profile_expired(profile)


def test_profile_expired_compares_calendar_dates() -> None:
    base = get_profile("repair_delivery")
    never_expires = replace(base, expires_at="")
    expires_tomorrow = replace(base, expires_at="2026-08-23")
    expires_today = replace(base, expires_at="2026-08-22")
    expired_yesterday = replace(base, expires_at="2026-08-21")
    today = date(2026, 8, 22)

    assert not profile_expired(never_expires, today=today)
    assert not profile_expired(expires_tomorrow, today=today)
    # A profile expires at the start of its named day, not partway through it.
    assert profile_expired(expires_today, today=today)
    assert profile_expired(expired_yesterday, today=today)


def test_move_out_deposit_profile_is_maintainer_reviewed_and_neutral() -> None:
    """The move-out/deposit-dispute record (ADR 0014) ships as a shipped-vocabulary
    profile, not a partner-gated one, and its disclosures refuse the two conclusions
    the workflow invites: that the landlord's itemization is accepted, and that a
    condition record settles wear and tear, damage, cost, or what is owed."""
    profile = get_profile("move_out_deposit")

    assert profile.review_state == "maintainer_reviewed"
    assert not profile.external_review_required
    assert profile.reviewed_at == "2026-08-26"
    assert profile.jurisdiction == "generic"
    # Deposit rules are jurisdiction-specific; this profile deliberately carries no
    # jurisdiction guidance, so it has nothing to go stale and sets no expiry.
    assert profile.expires_at == ""
    assert "deduction_itemization" in profile.artifact_types
    assert "deduction_for" in profile.relationship_types
    assert {"before_of", "after_of"} <= set(profile.relationship_types)

    disclosures = " ".join(profile.disclosures).casefold()
    assert "assertion" in disclosures
    assert "neither accepts nor rebuts" in disclosures
    assert "wear and tear" in disclosures
    assert "what a deposit is owed" in disclosures
    # No profile may promise or deny an outcome; these are the words that would.
    for banned in ("entitled", "must refund", "illegal", "you will", "wins"):
        assert banned not in disclosures


def test_deduction_for_cannot_link_two_deductions_or_reach_an_artifact() -> None:
    """`deduction_for` records a claim *about a documented condition*. Allowing it to
    point at another document would let a chain of itemizations be presented as though
    the record connected them, which nothing in the case model asserts."""
    pairs = RELATIONSHIP_ENDPOINT_KINDS["deduction_for"]

    assert ("artifact", "artifact") not in pairs
    assert ("capture", "issue") not in pairs
    assert pairs == frozenset(
        {
            ("artifact", "issue"),
            ("artifact", "capture"),
            ("timeline", "issue"),
            ("timeline", "capture"),
        }
    )


def test_browser_app_offers_exactly_the_registry_vocabulary() -> None:
    """`app/index.html` restates both vocabularies as `<option>` lists. An option the
    engine rejects is a dead end a tenant only discovers on submit; a registry term with
    no option is a record the browser app cannot create at all."""
    markup = (Path(__file__).resolve().parent.parent / "app" / "index.html").read_text("utf-8")
    selects = dict(
        re.findall(r'<select id="(art-type|rel-type)"[^>]*>(.*?)</select>', markup, re.S)
    )
    assert set(selects) == {"art-type", "rel-type"}, "app select ids moved; update this guard"

    assert set(re.findall(r'<option value="([^"]+)"', selects["art-type"])) == set(ARTIFACT_TYPES)
    assert set(re.findall(r'<option value="([^"]+)"', selects["rel-type"])) == set(
        RELATIONSHIP_TYPES
    )


def test_every_artifact_type_has_a_label_in_both_app_languages() -> None:
    app = Path(__file__).resolve().parent.parent / "app" / "i18n"
    for locale in ("en", "es"):
        bundle = json.loads((app / f"{locale}.json").read_text("utf-8"))
        for artifact_type in ARTIFACT_TYPES:
            key = f"artifact_{artifact_type}"
            assert bundle.get(key), f"{locale}.json: no label for {key}"
