# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Candidate #13: a joint submission index over separately signed packets.

The whole safety argument is that the index merges nothing and proves nothing on
its own authority, so these tests are mostly about what it refuses to do:
substitute a member quietly, absorb an extra one, survive a doctored index, or
report a missing packet as an unchanged one.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.serialization import Encoding

from habitable.canonical import canonical_json, sha256_bytes
from habitable.capture import capture
from habitable.cli import main
from habitable.errors import HabitableError
from habitable.joint import (
    JOINT_DISCLOSURES,
    JOINT_INDEX_FILE,
    JOINT_INDEX_HTML,
    JOINT_INDEX_VERSION,
    build_joint_index,
    check_joint_index,
)
from habitable.packet import build_packet
from habitable.tsa import LocalRfc3161TSA
from habitable.vault import Vault


def _submission(
    make_vault: Callable[..., Vault],
    make_jpeg: Callable[..., Path],
    local_tsa: LocalRfc3161TSA,
    root: Path,
    *,
    units: tuple[str, ...] = ("4b", "4c"),
) -> Path:
    """A submission folder: one already-exported packet per unit, nothing else.

    Each vault is a separate case with its own device identity and its own chain
    of custody, which is the situation the joint index exists for: the organizer
    was handed finished packets, not keys.
    """
    root.mkdir(parents=True, exist_ok=True)
    for unit in units:
        vault = make_vault(f"vault-{unit}", unit=unit.upper())
        issue = vault.document.add_issue(category="mold", room="bath", title="Mold")
        capture(vault, make_jpeg(f"{unit}.jpg"), issue_id=issue, tsa=local_tsa)
        build_packet(vault, root / unit, make_pdf=False)
    return root


class TestBuild:
    def test_indexes_every_packet_without_touching_it(
        self,
        make_vault: Callable[..., Vault],
        make_jpeg: Callable[..., Path],
        local_tsa: LocalRfc3161TSA,
        tmp_path: Path,
    ) -> None:
        """The index lists each packet, binds it by its own bundle digest, and
        leaves the member bytes exactly as their producer wrote them."""
        root = _submission(make_vault, make_jpeg, local_tsa, tmp_path / "submission")
        before = {unit: (root / unit / "bundle.json").read_bytes() for unit in ("4b", "4c")}

        result = build_joint_index(root, trusted_certs=[local_tsa.certificate])

        assert result.member_count == 2
        assert result.all_ready
        assert [member.path for member in result.members] == ["4b", "4c"]
        assert [member.label for member in result.members] == ["4B", "4C"]
        for member in result.members:
            assert member.bundle_sha256 == sha256_bytes(before[member.path])
        # Not one byte of any member packet moved.
        for unit, raw in before.items():
            assert (root / unit / "bundle.json").read_bytes() == raw

    def test_index_says_it_merges_nothing_and_signs_nothing(
        self,
        make_vault: Callable[..., Vault],
        make_jpeg: Callable[..., Path],
        local_tsa: LocalRfc3161TSA,
        tmp_path: Path,
    ) -> None:
        """The three claims the format rests on are written down, not implied:
        presentation only, no merged custody, and the index itself unsigned."""
        root = _submission(make_vault, make_jpeg, local_tsa, tmp_path / "submission")
        build_joint_index(root, trusted_certs=[local_tsa.certificate])

        document = json.loads((root / JOINT_INDEX_FILE).read_text(encoding="utf-8"))
        assert document["joint_index_version"] == JOINT_INDEX_VERSION
        assert document["presentation_only"] is True
        assert document["custody_merged"] is False
        assert document["index_signed"] is False
        assert document["source_of_truth"] == "each member packet's own bundle.json"
        assert document["disclosures"] == list(JOINT_DISCLOSURES)

    def test_no_new_custody_chain_or_signature_is_written(
        self,
        make_vault: Callable[..., Vault],
        make_jpeg: Callable[..., Path],
        local_tsa: LocalRfc3161TSA,
        tmp_path: Path,
    ) -> None:
        """Only two files appear beside the packets, and neither is a bundle or a
        signature: a joint index that produced either would be the merged record
        this design exists to refuse."""
        root = _submission(make_vault, make_jpeg, local_tsa, tmp_path / "submission")
        build_joint_index(root, trusted_certs=[local_tsa.certificate])

        written = sorted(child.name for child in root.iterdir() if child.is_file())
        assert written == [JOINT_INDEX_HTML, JOINT_INDEX_FILE]
        document = json.loads((root / JOINT_INDEX_FILE).read_text(encoding="utf-8"))
        assert "custody" not in document
        assert "signature" not in document

    def test_a_folder_that_is_not_a_packet_is_refused_not_skipped(
        self,
        make_vault: Callable[..., Vault],
        make_jpeg: Callable[..., Path],
        local_tsa: LocalRfc3161TSA,
        tmp_path: Path,
    ) -> None:
        """Quietly dropping a folder would produce a complete-looking table of
        contents over an incomplete submission, which is the one error nobody
        rereads the index to catch."""
        root = _submission(make_vault, make_jpeg, local_tsa, tmp_path / "submission")
        (root / "notes").mkdir()

        with pytest.raises(HabitableError, match="notes"):
            build_joint_index(root, trusted_certs=[local_tsa.certificate])

    def test_empty_submission_is_refused(self, tmp_path: Path) -> None:
        root = tmp_path / "empty"
        root.mkdir()
        with pytest.raises(HabitableError, match="no packet directories"):
            build_joint_index(root)

    def test_without_an_anchor_no_member_is_ready(
        self,
        make_vault: Callable[..., Vault],
        make_jpeg: Callable[..., Path],
        local_tsa: LocalRfc3161TSA,
        tmp_path: Path,
    ) -> None:
        """ADR 0008's fail-closed direction is not softened by bulk: with no
        trusted certificate the packets are intact but not evidence-ready, and
        the index must say so rather than rounding a batch up to ready."""
        root = _submission(make_vault, make_jpeg, local_tsa, tmp_path / "submission")

        result = build_joint_index(root)

        assert not result.all_ready
        assert result.ready_count == 0
        assert all(member.structurally_intact for member in result.members)


class TestHtml:
    def test_html_states_each_row_and_every_limit(
        self,
        make_vault: Callable[..., Vault],
        make_jpeg: Callable[..., Path],
        local_tsa: LocalRfc3161TSA,
        tmp_path: Path,
    ) -> None:
        """A recipient reading the page, on a printout or with a screen reader,
        gets the unit, a link to the packet, the digest, and the limits."""
        root = _submission(make_vault, make_jpeg, local_tsa, tmp_path / "submission")
        result = build_joint_index(root, trusted_certs=[local_tsa.certificate])

        html = result.html_path.read_text(encoding="utf-8")
        assert html.count("<h1") == 1
        assert '<html lang="en">' in html
        assert "<caption>" in html
        assert '<th scope="col">' in html
        assert '<th scope="row">4B</th>' in html
        assert 'href="4b/packet.html"' in html
        assert result.members[0].bundle_sha256 in html
        assert "merges no chain of custody" in html
        assert "this index is not" in html
        assert "does not make them one case" in html

    def test_spanish_index_is_spanish(
        self,
        make_vault: Callable[..., Vault],
        make_jpeg: Callable[..., Path],
        local_tsa: LocalRfc3161TSA,
        tmp_path: Path,
    ) -> None:
        root = _submission(make_vault, make_jpeg, local_tsa, tmp_path / "submission")
        result = build_joint_index(root, trusted_certs=[local_tsa.certificate], language="es")

        html = result.html_path.read_text(encoding="utf-8")
        assert '<html lang="es">' in html
        assert "Índice de presentación conjunta" in html
        assert "No fusiona ninguna cadena de custodia" in html


class TestCheck:
    def test_an_untouched_submission_checks_out(
        self,
        make_vault: Callable[..., Vault],
        make_jpeg: Callable[..., Path],
        local_tsa: LocalRfc3161TSA,
        tmp_path: Path,
    ) -> None:
        root = _submission(make_vault, make_jpeg, local_tsa, tmp_path / "submission")
        build_joint_index(root, trusted_certs=[local_tsa.certificate])

        check = check_joint_index(root / JOINT_INDEX_FILE, trusted_certs=[local_tsa.certificate])

        assert check.ok
        assert check.matched_count == 2
        assert check.ready_count == 2
        assert not check.unlisted

    def test_an_edited_member_bundle_fails_the_digest(
        self,
        make_vault: Callable[..., Vault],
        make_jpeg: Callable[..., Path],
        local_tsa: LocalRfc3161TSA,
        tmp_path: Path,
    ) -> None:
        """The point of recording the digest: a member rewritten after indexing
        is caught by the index even before its own signature is consulted."""
        root = _submission(make_vault, make_jpeg, local_tsa, tmp_path / "submission")
        build_joint_index(root, trusted_certs=[local_tsa.certificate])

        bundle = root / "4b" / "bundle.json"
        document = json.loads(bundle.read_text(encoding="utf-8"))
        document["issues"][0]["title"] = "Severe mold"
        bundle.write_bytes(canonical_json(document))

        check = check_joint_index(root / JOINT_INDEX_FILE, trusted_certs=[local_tsa.certificate])

        assert not check.ok
        drifted = next(member for member in check.members if member.path == "4b")
        assert not drifted.digest_matches
        assert not drifted.ok
        assert check.matched_count == 1

    def test_a_swapped_member_directory_fails_the_digest(
        self,
        make_vault: Callable[..., Vault],
        make_jpeg: Callable[..., Path],
        local_tsa: LocalRfc3161TSA,
        tmp_path: Path,
    ) -> None:
        """Substituting one household's whole packet for another's leaves both
        packets internally valid and individually verifiable. Only the index
        notices that the folder named 4B no longer holds 4B's bundle."""
        root = _submission(make_vault, make_jpeg, local_tsa, tmp_path / "submission")
        build_joint_index(root, trusted_certs=[local_tsa.certificate])

        (root / "4b" / "bundle.json").write_bytes((root / "4c" / "bundle.json").read_bytes())
        (root / "4b" / "bundle.sig.json").write_bytes(
            (root / "4c" / "bundle.sig.json").read_bytes()
        )

        check = check_joint_index(root / JOINT_INDEX_FILE, trusted_certs=[local_tsa.certificate])

        assert not check.ok
        swapped = next(member for member in check.members if member.path == "4b")
        assert not swapped.digest_matches

    def test_a_removed_member_is_missing_not_unchanged(
        self,
        make_vault: Callable[..., Vault],
        make_jpeg: Callable[..., Path],
        local_tsa: LocalRfc3161TSA,
        tmp_path: Path,
    ) -> None:
        """A member with no observed digest must never compare equal to its
        recorded one: absent is a different fact from unchanged."""
        root = _submission(make_vault, make_jpeg, local_tsa, tmp_path / "submission")
        build_joint_index(root, trusted_certs=[local_tsa.certificate])
        (root / "4b" / "bundle.json").unlink()

        check = check_joint_index(root / JOINT_INDEX_FILE, trusted_certs=[local_tsa.certificate])

        gone = next(member for member in check.members if member.path == "4b")
        assert not gone.present
        assert gone.observed_sha256 == ""
        assert not gone.digest_matches
        assert not check.ok

    def test_a_packet_added_after_indexing_is_reported_not_absorbed(
        self,
        make_vault: Callable[..., Vault],
        make_jpeg: Callable[..., Path],
        local_tsa: LocalRfc3161TSA,
        tmp_path: Path,
    ) -> None:
        """An index that ignored a folder someone dropped in afterwards would
        present a complete-looking table of contents over a set it never saw."""
        root = _submission(make_vault, make_jpeg, local_tsa, tmp_path / "submission")
        build_joint_index(root, trusted_certs=[local_tsa.certificate])
        _submission(make_vault, make_jpeg, local_tsa, root, units=("9z",))

        check = check_joint_index(root / JOINT_INDEX_FILE, trusted_certs=[local_tsa.certificate])

        assert check.unlisted == ("9z",)
        assert not check.ok

    def test_a_doctored_index_cannot_talk_its_way_to_ok(
        self,
        make_vault: Callable[..., Vault],
        make_jpeg: Callable[..., Path],
        local_tsa: LocalRfc3161TSA,
        tmp_path: Path,
    ) -> None:
        """Every verdict is recomputed from the packets, so rewriting the index's
        own recorded digest and readiness changes nothing about the answer."""
        root = _submission(make_vault, make_jpeg, local_tsa, tmp_path / "submission")
        build_joint_index(root, trusted_certs=[local_tsa.certificate])

        index_path = root / JOINT_INDEX_FILE
        document = json.loads(index_path.read_text(encoding="utf-8"))
        bundle = root / "4b" / "bundle.json"
        edited = json.loads(bundle.read_text(encoding="utf-8"))
        edited["issues"][0]["title"] = "Severe mold"
        bundle.write_bytes(canonical_json(edited))
        # The attacker updates the index to match what they just wrote, and
        # asserts readiness for good measure.
        for member in document["members"]:
            if member["path"] == "4b":
                member["bundle_sha256"] = sha256_bytes(bundle.read_bytes())
                member["evidence_ready"] = True
                member["status"] = "evidence_ready"
                member["problems"] = []
        index_path.write_bytes(canonical_json(document))

        check = check_joint_index(index_path, trusted_certs=[local_tsa.certificate])

        forged = next(member for member in check.members if member.path == "4b")
        # The digest now agrees, because the attacker made it agree. The member's
        # own producer signature is what refuses.
        assert forged.digest_matches
        assert not forged.evidence_ready
        assert not forged.ok
        assert not check.ok

    def test_an_index_naming_a_path_outside_the_submission_is_refused(
        self,
        make_vault: Callable[..., Vault],
        make_jpeg: Callable[..., Path],
        local_tsa: LocalRfc3161TSA,
        tmp_path: Path,
    ) -> None:
        """A joint index arrives from someone else. It must not be able to point
        the checker at a path of its choosing."""
        root = _submission(make_vault, make_jpeg, local_tsa, tmp_path / "submission")
        build_joint_index(root, trusted_certs=[local_tsa.certificate])

        index_path = root / JOINT_INDEX_FILE
        document = json.loads(index_path.read_text(encoding="utf-8"))
        document["members"][0]["path"] = "../elsewhere"
        index_path.write_bytes(canonical_json(document))

        check = check_joint_index(index_path, trusted_certs=[local_tsa.certificate])

        rejected = check.members[0]
        assert rejected.status == "rejected_path"
        assert not rejected.present
        assert not check.ok

    @pytest.mark.parametrize(
        ("mutate", "expected"),
        [
            (lambda doc: doc.update(joint_index_version=JOINT_INDEX_VERSION + 1), "not supported"),
            (lambda doc: doc.pop("members"), "no member list"),
        ],
    )
    def test_an_unreadable_index_fails_closed(
        self,
        make_vault: Callable[..., Vault],
        make_jpeg: Callable[..., Path],
        local_tsa: LocalRfc3161TSA,
        tmp_path: Path,
        mutate: Callable[[dict[str, object]], object],
        expected: str,
    ) -> None:
        root = _submission(make_vault, make_jpeg, local_tsa, tmp_path / "submission")
        build_joint_index(root, trusted_certs=[local_tsa.certificate])

        index_path = root / JOINT_INDEX_FILE
        document = json.loads(index_path.read_text(encoding="utf-8"))
        mutate(document)
        index_path.write_bytes(canonical_json(document))

        check = check_joint_index(index_path, trusted_certs=[local_tsa.certificate])

        assert not check.ok
        assert any(expected in problem for problem in check.problems)

    def test_a_missing_index_fails_closed(self, tmp_path: Path) -> None:
        check = check_joint_index(tmp_path / "nothing" / JOINT_INDEX_FILE)
        assert not check.ok
        assert check.problems
        assert not check.members

    def test_a_non_json_index_fails_closed(self, tmp_path: Path) -> None:
        index_path = tmp_path / JOINT_INDEX_FILE
        index_path.write_bytes(b"not json at all")
        check = check_joint_index(index_path)
        assert not check.ok
        assert any("not valid JSON" in problem for problem in check.problems)


class TestCli:
    def test_build_then_check_round_trip(
        self,
        make_vault: Callable[..., Vault],
        make_jpeg: Callable[..., Path],
        local_tsa: LocalRfc3161TSA,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        root = _submission(make_vault, make_jpeg, local_tsa, tmp_path / "submission")
        pem = tmp_path / "tsa.pem"
        pem.write_bytes(local_tsa.certificate.public_bytes(Encoding.PEM))

        assert main(["joint", "build", str(root), "--trusted-cert", str(pem)]) == 0
        built = capsys.readouterr().out
        assert "No chain of custody was merged." in built

        assert main(["joint", "check", str(root), "--trusted-cert", str(pem)]) == 0
        assert "checks out" in capsys.readouterr().out

    def test_check_exits_non_zero_on_a_changed_member(
        self,
        make_vault: Callable[..., Vault],
        make_jpeg: Callable[..., Path],
        local_tsa: LocalRfc3161TSA,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        root = _submission(make_vault, make_jpeg, local_tsa, tmp_path / "submission")
        build_joint_index(root, trusted_certs=[local_tsa.certificate])
        bundle = root / "4b" / "bundle.json"
        document = json.loads(bundle.read_text(encoding="utf-8"))
        document["issues"][0]["title"] = "Severe mold"
        bundle.write_bytes(canonical_json(document))

        assert main(["joint", "check", str(root), "--json"]) == 1
        payload = json.loads(capsys.readouterr().out)
        assert payload["ok"] is False
        assert payload["matched_count"] == 1

    def test_build_exits_non_zero_when_a_member_is_not_ready(
        self,
        make_vault: Callable[..., Vault],
        make_jpeg: Callable[..., Path],
        local_tsa: LocalRfc3161TSA,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """No anchor, so nothing is evidence-ready, so the command says so with
        its exit code exactly as `habitable verify` does."""
        root = _submission(make_vault, make_jpeg, local_tsa, tmp_path / "submission")
        assert main(["joint", "build", str(root)]) == 1
        capsys.readouterr()
