# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif

from __future__ import annotations

import pytest

from habitable.errors import HabitableError
from habitable.usecases import ARTIFACT_TYPES, RELATIONSHIP_TYPES, get_profile, list_profiles


def test_all_ten_profiles_are_versioned_and_valid() -> None:
    profiles = list_profiles()
    assert len(profiles) == 10
    assert len({profile.profile_id for profile in profiles}) == 10
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
