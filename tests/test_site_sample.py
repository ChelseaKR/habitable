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
    assert "location stripped from shared copies" in disclosures
    assert "custody identities not exported" in disclosures
    for item in cast(list[dict[str, JSONValue]], bundle["items"]):
        assert item["has_original"] is False
        media = _SAMPLE / "media" / str(item["shared_name"])
        metadata = read_metadata(media)
        assert not metadata.has_location
        assert metadata.capture_time is None
        assert not metadata.fields_present
