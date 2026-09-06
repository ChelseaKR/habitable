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
from habitable.vault import Vault


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


def test_a_profile_declares_its_vocabulary_and_never_gates_what_can_be_recorded(
    tmp_path: Path,
) -> None:
    """ADR 0010's vocabulary is a declaration, not a constraint (issue #277).

    A profile is chosen for the workflow a tenant is *starting*; the landlord
    decides what arrives afterwards. Someone on the repair-notice profile who is
    then handed a clinician's letter must be able to record it, so the engine
    validates against the global registry and ignores the profile's list. This
    pins that, because "the declaration should constrain something" is the
    obvious reading of the old ADR wording and would fail on the person, mid-case,
    holding the document.
    """
    profile = get_profile("repair_delivery")
    outside = "clinician_letter"
    assert outside in ARTIFACT_TYPES
    assert outside not in profile.artifact_types, "pick a type this profile does not declare"

    vault = Vault.create(
        tmp_path / "vault", "correct horse battery staple", case_id="c-277", unit="4B"
    )
    vault.document.set_use_case_profile(profile.profile_id)
    issue_id = vault.document.add_issue(
        title="Damp bedroom", category="mold", severity="high", room="bedroom"
    )
    artifact_id = vault.document.add_artifact(
        issue_id=issue_id,
        artifact_type=outside,
        title="Letter from the GP",
        source="tenant copy",
        issuer="",
        occurred_at="2026-01-02",
        content_hash="0" * 64,
        media_type="text/plain",
        sealed_name="letter.txt",
    )
    assert artifact_id, "a profile blocked a record it merely does not name"
    stored = [a for a in vault.document.artifacts() if a.artifact_id == artifact_id]
    assert len(stored) == 1 and stored[0].artifact_type == outside


def test_the_plan_names_exactly_the_profiles_the_registry_calls_reviewed() -> None:
    """`docs/novel-use-cases-plan.md` enumerates the two review states by profile id.

    That enumeration is hand-maintained, and it drifted: it said "Four profiles"
    and listed four, in a paragraph that already announced `move_out_deposit` had
    shipped (issue #277, "also, minor"). Deriving both sets and both count words
    from the registry means the next profile to land fails here instead of leaving
    a reader counting wrong.

    The first cut of this guard read every backticked id in the text *before* the
    `maintainer_reviewed` marker, which swept up the `move_out_deposit` mentioned
    two sentences earlier -- so restoring the four-name list still passed. It now
    reads the parenthesised list attached to each claim, and the sabotage fails it.
    """
    plan = (Path(__file__).resolve().parent.parent / "docs" / "novel-use-cases-plan.md").read_text(
        "utf-8"
    )
    profiles = list_profiles()
    known = {profile.profile_id for profile in profiles}
    reviewed = {p.profile_id for p in profiles if p.review_state == "maintainer_reviewed"}
    gated = {p.profile_id for p in profiles if p.external_review_required}
    assert reviewed and gated, "the registry has no profiles in one of the two states"

    words = {
        1: "One",
        2: "Two",
        3: "Three",
        4: "Four",
        5: "Five",
        6: "Six",
        7: "Seven",
        8: "Eight",
        9: "Nine",
        10: "Ten",
        11: "Eleven",
        12: "Twelve",
    }
    for expected, verb, state in (
        (reviewed, "are", "maintainer_reviewed"),
        (gated, "remain", "external_review_required"),
    ):
        pattern = r"(\w+)(?: profiles)? \(([^)]*)\)\s*" + verb + r"\s*`" + state + "`"
        found = re.search(pattern, plan, re.S)
        assert found, f"the plan no longer enumerates the {state} profiles"
        count_word, listed = found.group(1), found.group(2)
        named = set(re.findall(r"`([a-z_]+)`", listed))
        assert named <= known, f"the plan names profiles that do not exist: {sorted(named - known)}"
        assert named == expected, (
            f"the plan lists {sorted(named)} as {state}; the registry says {sorted(expected)}"
        )
        assert count_word == words[len(expected)], (
            f"the plan says {count_word!r} {state} profiles; there are {len(expected)}"
        )
