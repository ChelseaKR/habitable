# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

import pytest

from habitable.cli import main
from habitable.usecases import get_profile, list_profiles
from habitable.vault import Vault


def test_cli_profile_artifact_relationship_and_handoff(
    make_vault: Callable[..., Vault], tmp_path: Path
) -> None:
    vault = make_vault()
    issue = vault.document.add_issue(category="mold", issue_id="i1")
    vault.save()
    document = tmp_path / "request.txt"
    document.write_text("Synthetic request.", encoding="utf-8")

    assert (
        main(
            [
                "profile",
                "set",
                "--vault",
                str(vault.path),
                "--passphrase",
                "test-passphrase",
                "repair_delivery",
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "artifact",
                "--vault",
                str(vault.path),
                "--passphrase",
                "test-passphrase",
                str(document),
                "--issue",
                issue,
                "--type",
                "repair_request",
                "--title",
                "Repair request",
                "--source",
                "tenant copy",
                "--occurred-at",
                "2026-01-03",
                "--no-timestamp",
            ]
        )
        == 0
    )
    reopened = Vault.open(vault.path, "test-passphrase")
    artifact_id = reopened.document.artifacts()[0].artifact_id
    assert (
        main(
            [
                "relate",
                "--vault",
                str(vault.path),
                "--passphrase",
                "test-passphrase",
                "--issue",
                issue,
                "--type",
                "documents_condition",
                "--source",
                artifact_id,
                "--target",
                issue,
            ]
        )
        == 0
    )
    packet = tmp_path / "packet"
    assert (
        main(
            [
                "export",
                "--vault",
                str(vault.path),
                "--passphrase",
                "test-passphrase",
                "--out",
                str(packet),
                "--no-pdf",
                "--dev-tsa",  # seal offline: a unit test must never call a public TSA
                "--handoff-profile",
                "repair_delivery",
            ]
        )
        == 0
    )
    assert (packet / "handoff-repair_delivery.html").exists()


def test_cli_lists_all_profiles(capsys: object) -> None:
    assert main(["profile", "list"]) == 0
    captured = capsys.readouterr()  # type: ignore[attr-defined]
    assert captured.out.count("\tv1\t") == 11
    assert "external review required" in captured.out
    assert "move_out_deposit\tv1\timplemented" in captured.out


def test_cli_profile_list_flags_an_expired_profile(
    capsys: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    expired = replace(get_profile("repair_delivery"), expires_at="2000-01-01")
    patched = tuple(
        expired if profile.profile_id == "repair_delivery" else profile
        for profile in list_profiles()
    )
    monkeypatch.setattr("habitable.cli.list_profiles", lambda: patched)

    assert main(["profile", "list"]) == 0
    captured = capsys.readouterr()  # type: ignore[attr-defined]
    assert "repair_delivery\tv1\treview expired 2000-01-01\t" in captured.out


def test_cli_status_notes_an_expired_selected_profile(
    make_vault: Callable[..., Vault], capsys: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = make_vault()
    assert (
        main(
            [
                "profile",
                "set",
                "--vault",
                str(vault.path),
                "--passphrase",
                "test-passphrase",
                "repair_delivery",
            ]
        )
        == 0
    )
    expired = replace(get_profile("repair_delivery"), expires_at="2000-01-01")
    monkeypatch.setattr("habitable.cli.get_profile", lambda profile_id: expired)

    assert main(["status", "--vault", str(vault.path), "--passphrase", "test-passphrase"]) == 0
    captured = capsys.readouterr()  # type: ignore[attr-defined]
    assert "review expired 2000-01-01; export falls back to generic" in captured.out


class TestIssueFieldVocabularies:
    """Issue #206: `issue --category`/`--severity` took any string, silently.

    `habitable timeline` constrains `--type` and `--source` to enums with an
    explicit `other` plus a required label. `habitable issue` constrained
    nothing, so `--category "typo-category-xyz" --severity "kinda bad i guess"`
    was accepted, echoed back, and exit 0 -- and because export scoping is
    blocked (#203 item 3) and there is no correction path (#203 item 2), that
    typo then rode into the exported packet with no supported way to remove it.

    Entry validation only. Categories already stored in a vault are free text and
    stay readable; nothing here touches `add_issue`, the custody chain, or the
    packet format, so old entries are grandfathered and only new CLI entries are
    checked.
    """

    @staticmethod
    def _args(vault: Vault, *extra: str) -> list[str]:
        return [
            "issue",
            "--vault",
            str(vault.path),
            "--passphrase",
            "test-passphrase",
            *extra,
        ]

    def test_a_typo_category_is_refused_and_names_the_vocabulary(
        self, make_vault: Callable[..., Vault], capsys: pytest.CaptureFixture[str]
    ) -> None:
        vault = make_vault()
        with pytest.raises(SystemExit) as exc:
            main(self._args(vault, "--category", "typo-category-xyz"))
        assert exc.value.code != 0
        message = capsys.readouterr().err
        assert "typo-category-xyz" in message
        # The error has to say what *is* accepted, or it just moves the guesswork.
        for known in ("heat", "mold", "pests", "water", "electrical", "structural"):
            assert known in message

    def test_a_typo_severity_is_refused(
        self, make_vault: Callable[..., Vault], capsys: pytest.CaptureFixture[str]
    ) -> None:
        vault = make_vault()
        with pytest.raises(SystemExit) as exc:
            main(self._args(vault, "--category", "mold", "--severity", "kinda bad i guess"))
        assert exc.value.code != 0
        assert "kinda bad i guess" in capsys.readouterr().err

    def test_every_documented_category_is_accepted(self, make_vault: Callable[..., Vault]) -> None:
        """The six categories README names must all work, or the guard is a trap."""
        vault = make_vault()
        for category in ("heat", "mold", "pests", "water", "electrical", "structural"):
            assert main(self._args(vault, "--category", category)) == 0

    def test_other_needs_a_label_and_works_with_one(
        self, make_vault: Callable[..., Vault], capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The escape hatch stays open, but it has to say what it means.

        A closed vocabulary with no `other` would be worse than free text: a
        tenant with a real condition outside the six would have to misfile it.
        """
        vault = make_vault()
        assert main(self._args(vault, "--category", "other")) == 2
        assert "--other-label" in capsys.readouterr().err

        assert main(self._args(vault, "--category", "other", "--other-label", "broken lift")) == 0

    def test_severity_other_needs_a_detail(
        self, make_vault: Callable[..., Vault], capsys: pytest.CaptureFixture[str]
    ) -> None:
        vault = make_vault()
        assert main(self._args(vault, "--category", "mold", "--severity", "other")) == 2
        assert "--severity-detail" in capsys.readouterr().err
        assert (
            main(
                self._args(
                    vault,
                    "--category",
                    "mold",
                    "--severity",
                    "other",
                    "--severity-detail",
                    "intermittent but worsening",
                )
            )
            == 0
        )

    def test_existing_free_text_categories_still_load(
        self, make_vault: Callable[..., Vault]
    ) -> None:
        """Grandfathering: validation is at CLI entry, not in the data model."""
        vault = make_vault()
        vault.document.add_issue(category="whatever-was-typed-in-2026", issue_id="old")
        vault.save()
        assert main(["status", "--vault", str(vault.path), "--passphrase", "test-passphrase"]) == 0
