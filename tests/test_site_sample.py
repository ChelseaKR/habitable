# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Regression gate for the literal evidence packet published by GitHub Pages."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast

from cryptography import x509

from habitable.canonical import JSONValue, sha256_bytes
from habitable.exif import read_metadata
from habitable.packet import PACKET_VERSION
from habitable.verify import verify_packet

_SAMPLE = Path(__file__).resolve().parent.parent / "site" / "sample-packet"
_OPAQUE_ID = re.compile(r"^(?:issue|tl|cap|hlc)-[0-9a-f]{16}$")
_RAW_HLC = re.compile(r"\d{15}\.\d{6}\.[0-9a-f]{16}")
_SYNTHETIC_CERT = _SAMPLE / "synthetic-timestamp-authority.pem"


def _walk_keys(value: JSONValue) -> set[str]:
    collected: set[str] = set()
    if isinstance(value, Mapping):
        collected.update(str(key) for key in value)
        for nested in value.values():
            collected.update(_walk_keys(nested))
    elif isinstance(value, Sequence) and not isinstance(value, str | bytes):
        for nested in value:
            collected.update(_walk_keys(nested))
    return collected


def test_public_sample_is_current_signed_and_intact() -> None:
    report = verify_packet(_SAMPLE)
    assert report.structurally_intact, (
        f"public sample is broken: {report.summary()} {report.problems}"
    )
    assert report.status == "timestamp_authority_untrusted"
    assert not report.timestamp_authority_trusted
    assert not report.evidence_ready
    assert report.signature_ok and report.custody_ok

    bundle = json.loads((_SAMPLE / "bundle.json").read_text(encoding="utf-8"))
    # A *freshness* gate, not a compatibility pin: the sample is regenerated to
    # whatever the current version is, so a change that alters the writer and
    # the verifier together stays green here. Backward compatibility is pinned
    # by the committed-bytes corpus in tests/golden/ (issue #160), and the
    # sample also carries none of the v4-specific surfaces (no relationships,
    # no profile, no handoff view), so it is not a substitute for that fixture.
    assert bundle["packet_version"] == PACKET_VERSION
    assert bundle["appendix"]["item_count"] == len(bundle["items"]) == 3
    assert report.cryptographically_verified_items == 3
    assert report.verified_items == 0
    assert (_SAMPLE / "bundle.sig.json").is_file()
    assert (_SAMPLE / "packet.html").is_file()
    assert (_SAMPLE / "packet.pdf").is_file()
    assert "synthetic demonstration" in json.dumps(bundle).lower()


def test_public_sample_can_exercise_explicit_synthetic_cert_pinning() -> None:
    cert = x509.load_pem_x509_certificate(_SYNTHETIC_CERT.read_bytes())
    report = verify_packet(_SAMPLE, trusted_certs=[cert])
    assert report.evidence_ready, report.summary()
    assert report.verified_items == 3
    notice = (_SAMPLE / "SYNTHETIC-AUTHORITY.txt").read_text(encoding="utf-8")
    assert "does not make the timestamp authority independently trusted" in notice


def test_public_sample_exports_only_opaque_ids_and_sanitized_media() -> None:
    raw = (_SAMPLE / "bundle.json").read_text(encoding="utf-8")
    bundle = cast(dict[str, JSONValue], json.loads(raw))

    # The v1 sample leaked raw HLC/node-bearing identifiers and private source
    # filenames. Current packets keep both out while `source` carries only the
    # packet-v3 reviewed provenance vocabulary (firsthand/message/document/etc.).
    legacy_node_id = sha256_bytes(b"synthetic-demo-case" + b"public-synthetic-sample-not-secret")[
        :16
    ]
    assert _RAW_HLC.search(raw) is None
    assert legacy_node_id not in raw
    assert not ({"actor", "private_details"} & _walk_keys(bundle))
    timeline = cast(list[dict[str, JSONValue]], bundle["timeline"])
    assert {str(entry["source"]) for entry in timeline} == {
        "document",
        "firsthand",
        "message",
    }
    assert "/Users/" not in raw and "/home/" not in raw and "C:\\" not in raw

    ids: list[str] = []
    ids.extend(
        str(issue["issue_id"]) for issue in cast(list[dict[str, JSONValue]], bundle["issues"])
    )
    ids.extend(
        str(entry["entry_id"]) for entry in cast(list[dict[str, JSONValue]], bundle["timeline"])
    )
    ids.extend(
        str(entry["order_token"]) for entry in cast(list[dict[str, JSONValue]], bundle["timeline"])
    )
    ids.extend(
        str(item["capture_id"]) for item in cast(list[dict[str, JSONValue]], bundle["items"])
    )
    custody = cast(dict[str, JSONValue], bundle["custody_proof"])
    ids.extend(str(entry["hlc"]) for entry in cast(list[dict[str, JSONValue]], custody["entries"]))
    assert ids and all(_OPAQUE_ID.fullmatch(item_id) for item_id in ids)

    assert not (_SAMPLE / "originals").exists()
    disclosures = cast(list[str], bundle["disclosures"])
    assert "all embedded metadata stripped from supported shared media" in disclosures
    assert "custody identities not exported" in disclosures
    for item in cast(list[dict[str, JSONValue]], bundle["items"]):
        assert item["has_original"] is False
        media = _SAMPLE / "media" / str(item["shared_name"])
        metadata = read_metadata(media)
        assert not metadata.has_location
        assert metadata.capture_time is None
        assert not metadata.fields_present


def test_every_published_artifact_uses_only_vocabulary_the_cli_accepts() -> None:
    """Issues #237, #238 and #240, on the artifact strangers actually read.

    `site/sample-packet/` is the synthetic packet the site links and the one
    review task LA-01 (#122) asks a housing lawyer to cold-read. It was generated
    with `category="moisture"` and severities `high` and `urgent` -- one category
    and two severities that `habitable issue` refuses, sitting in the document
    the project offers as its worked example of a good record.

    Four surfaces had drifted apart in four directions at once: the CLI's enum,
    the app's Urgency menu, this generator, and `render_app_screenshots.py` --
    which seeds the app previews shown in the README, and was also seeding
    `severity="high"`. The guard scans every generator under `scripts/` rather
    than the one that was wrong, because the defect was drift between siblings
    and naming one sibling would have left the next one free to drift.
    """
    from habitable.model import ISSUE_CATEGORIES, ISSUE_SEVERITIES

    # `make_golden_packet.py` is deliberately exempt. The golden corpus pins the
    # packet *format* across versions, not the copy: its severity is arbitrary test
    # data, and bringing it in line would mean regenerating a committed
    # backward-compatibility fixture for a cosmetic reason -- or, worse, leaving the
    # generator and the fixture disagreeing. Format fixtures record what was emitted;
    # they are not exemplary artifacts and are not shown to anyone as a model record.
    exempt = {"make_golden_packet.py"}
    scripts = [
        path
        for path in sorted((Path(__file__).resolve().parent.parent / "scripts").glob("*.py"))
        if path.name not in exempt
    ]
    assert scripts, "no scripts found; this guard is reading nothing"

    # Aliases are deliberately NOT accepted here. They are normalised at CLI and app
    # entry, but these generators call `add_issue` directly -- so a seed of
    # `category="moisture"` is stored verbatim as `moisture`, a string the CLI takes
    # as input and never stores. The first cut of this guard allowed alias spellings,
    # which would have let the published sample keep demonstrating `Category:
    # moisture` to the housing lawyer reading it for review task LA-01.
    known = set(ISSUE_CATEGORIES)
    seeded_any = False
    bad: list[str] = []
    for script in scripts:
        source = script.read_text(encoding="utf-8")
        categories = re.findall(r'category="([^"]*)"', source)
        severities = re.findall(r'severity="([^"]*)"', source)
        seeded_any = seeded_any or bool(categories or severities)
        bad += [f"{script.name}: category={c!r}" for c in categories if c not in known]
        bad += [
            f"{script.name}: severity={s!r}" for s in severities if s and s not in ISSUE_SEVERITIES
        ]

    assert seeded_any, "no script seeds a case any more; this guard reads nothing"
    assert not bad, (
        "a published artifact is generated with vocabulary `habitable issue` "
        f"refuses, so it demonstrates values a tenant could not enter: {bad}"
    )
