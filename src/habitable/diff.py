# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Compare two packet exports of the same case (EXP-02).

`bundle.json` is deterministic (see :mod:`habitable.packet`): two exports of an
*unchanged* case produce byte-identical bytes. But cases change — a new capture, a
timestamp arriving for a previously-queued item, a severity edit — and a recipient
who already has an older packet (a judge, an inspector, an organizer) needs an
honest, precise answer to "what moved?" rather than having to eyeball two JSON
files or re-verify from scratch.

`diff_packets` reads only the two packet directories' `bundle.json` (never the
private vault) and reports, structurally:

* items added / removed / changed, by `capture_id`;
* issues added / removed / changed, by `issue_id`;
* disclosures added / removed;
* whether the chain of custody grew **honestly** — `old`'s custody entries must be
  an unmodified, position-for-position prefix of `new`'s entries. Growth is
  expected; a mismatch in the shared prefix means history was rewritten, which is
  reported as a problem rather than folded into an innocuous-looking "changed."

`format_diff` renders the result as short, localized (EN/ES) lines via the
:mod:`habitable.i18n` CLI catalog, in the spirit of "issue 2's severity changed;
3 captures added; nothing removed."
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from .canonical import JSONValue
from .errors import DiffError
from .i18n import cli_text, resolve_locale

if TYPE_CHECKING:
    from collections.abc import Mapping

__all__ = [
    "IssueChange",
    "ItemChange",
    "PacketDiff",
    "diff_packets",
    "format_diff",
]

_BUNDLE = "bundle.json"
_MANIFEST = "manifest.json"


@dataclass(frozen=True, slots=True)
class ItemChange:
    """One media item present in both packets with at least one differing field."""

    capture_id: str
    fields: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class IssueChange:
    """One issue present in both packets with at least one differing field."""

    issue_id: str
    fields: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PacketDiff:
    """The structural difference between two packet exports of the same case."""

    old_dir: Path
    new_dir: Path
    case_id: str
    language: str
    old_generated_at: str
    new_generated_at: str

    items_added: tuple[str, ...] = field(default_factory=tuple)
    items_removed: tuple[str, ...] = field(default_factory=tuple)
    items_changed: tuple[ItemChange, ...] = field(default_factory=tuple)

    issues_added: tuple[str, ...] = field(default_factory=tuple)
    issues_removed: tuple[str, ...] = field(default_factory=tuple)
    issues_changed: tuple[IssueChange, ...] = field(default_factory=tuple)

    disclosures_added: tuple[str, ...] = field(default_factory=tuple)
    disclosures_removed: tuple[str, ...] = field(default_factory=tuple)

    custody_length_old: int = 0
    custody_length_new: int = 0
    custody_head_old: str = ""
    custody_head_new: str = ""
    custody_prefix_intact: bool = True
    custody_divergence_index: int | None = None

    @property
    def has_changes(self) -> bool:
        return bool(
            self.items_added
            or self.items_removed
            or self.items_changed
            or self.issues_added
            or self.issues_removed
            or self.issues_changed
            or self.disclosures_added
            or self.disclosures_removed
            or self.custody_length_old != self.custody_length_new
        )

    @property
    def ok(self) -> bool:
        """False when the two exports cannot be trusted to compare cleanly."""
        return self.custody_prefix_intact


def diff_packets(old_dir: Path, new_dir: Path) -> PacketDiff:
    """Compare two packet directories that claim to export the same case.

    Raises :class:`~habitable.errors.DiffError` if either bundle is missing/
    malformed, or if the two packets report different ``case_id``s — comparing
    unrelated cases would produce a meaningless, misleading report rather than a
    clean refusal.
    """
    old_dir = Path(old_dir)
    new_dir = Path(new_dir)
    old_bundle = _load_bundle(old_dir)
    new_bundle = _load_bundle(new_dir)

    old_case = _s(old_bundle, "case_id")
    new_case = _s(new_bundle, "case_id")
    if old_case != new_case:
        raise DiffError(
            f"packets are different cases ({old_case!r} vs {new_case!r}); refusing to diff"
        )

    items_added, items_removed, items_changed = _diff_items(
        _list_of_dicts(old_bundle, "items"), _list_of_dicts(new_bundle, "items")
    )
    issues_added, issues_removed, issues_changed = _diff_issues(
        _list_of_dicts(old_bundle, "issues"), _list_of_dicts(new_bundle, "issues")
    )

    old_disclosures = set(_list_of_strs(old_bundle, "disclosures"))
    new_disclosures = set(_list_of_strs(new_bundle, "disclosures"))

    old_proof = _map(old_bundle, "custody_proof")
    new_proof = _map(new_bundle, "custody_proof")
    old_entries = _list_of_dicts(old_proof, "entries")
    new_entries = _list_of_dicts(new_proof, "entries")
    prefix_intact, divergence = _custody_prefix_check(old_entries, new_entries)

    return PacketDiff(
        old_dir=old_dir,
        new_dir=new_dir,
        case_id=new_case,
        language=_s(new_bundle, "language") or _s(old_bundle, "language"),
        old_generated_at=_manifest_generated_at(old_dir),
        new_generated_at=_manifest_generated_at(new_dir),
        items_added=items_added,
        items_removed=items_removed,
        items_changed=items_changed,
        issues_added=issues_added,
        issues_removed=issues_removed,
        issues_changed=issues_changed,
        disclosures_added=tuple(sorted(new_disclosures - old_disclosures)),
        disclosures_removed=tuple(sorted(old_disclosures - new_disclosures)),
        custody_length_old=_int(old_proof, "length"),
        custody_length_new=_int(new_proof, "length"),
        custody_head_old=_s(old_proof, "head_hash"),
        custody_head_new=_s(new_proof, "head_hash"),
        custody_prefix_intact=prefix_intact,
        custody_divergence_index=divergence,
    )


def format_diff(diff: PacketDiff, locale: str = "en") -> list[str]:
    """Render *diff* as short, localized, human-readable lines."""
    loc = resolve_locale(locale)
    lines = _format_custody_line(diff, loc)

    if not diff.has_changes:
        lines.append(cli_text("diff_no_changes", loc))
        return lines

    lines.extend(_format_item_lines(diff, loc))
    lines.extend(_format_issue_lines(diff, loc))
    lines.extend(_format_disclosure_lines(diff, loc))
    return lines


def _format_custody_line(diff: PacketDiff, loc: str) -> list[str]:
    if not diff.custody_prefix_intact:
        return [cli_text("diff_custody_diverged", loc, index=diff.custody_divergence_index)]
    if diff.custody_length_new != diff.custody_length_old:
        return [
            cli_text(
                "diff_custody_advanced",
                loc,
                old=diff.custody_length_old,
                new=diff.custody_length_new,
            )
        ]
    return []


def _format_item_lines(diff: PacketDiff, loc: str) -> list[str]:
    lines: list[str] = []
    if diff.items_added:
        lines.append(cli_text("diff_items_added", loc, count=len(diff.items_added)))
    if diff.items_removed:
        lines.append(cli_text("diff_items_removed", loc, count=len(diff.items_removed)))
    for change in diff.items_changed:
        lines.append(
            cli_text(
                "diff_item_changed_line",
                loc,
                capture_id=change.capture_id,
                fields=", ".join(change.fields),
            )
        )
    return lines


def _format_issue_lines(diff: PacketDiff, loc: str) -> list[str]:
    lines: list[str] = []
    if diff.issues_added:
        lines.append(cli_text("diff_issues_added", loc, count=len(diff.issues_added)))
    if diff.issues_removed:
        lines.append(cli_text("diff_issues_removed", loc, count=len(diff.issues_removed)))
    for change in diff.issues_changed:
        lines.append(
            cli_text(
                "diff_issue_changed_line",
                loc,
                issue_id=change.issue_id,
                fields=", ".join(change.fields),
            )
        )
    return lines


def _format_disclosure_lines(diff: PacketDiff, loc: str) -> list[str]:
    if not (diff.disclosures_added or diff.disclosures_removed):
        return []
    return [
        cli_text(
            "diff_disclosures_changed",
            loc,
            added=len(diff.disclosures_added),
            removed=len(diff.disclosures_removed),
        )
    ]


# --- comparison helpers ---------------------------------------------------------


def _diff_records_by_id(
    old_records: list[dict[str, JSONValue]], new_records: list[dict[str, JSONValue]], id_key: str
) -> tuple[tuple[str, ...], tuple[str, ...], list[tuple[str, tuple[str, ...]]]]:
    """Shared added/removed/changed logic keyed by *id_key*; changed pairs are
    ``(id, sorted differing field names)``, left for the caller to wrap in its own
    dataclass so each call site stays concretely typed under mypy --strict."""
    old_by_id = {_s(r, id_key): r for r in old_records if _s(r, id_key)}
    new_by_id = {_s(r, id_key): r for r in new_records if _s(r, id_key)}
    added = tuple(sorted(set(new_by_id) - set(old_by_id)))
    removed = tuple(sorted(set(old_by_id) - set(new_by_id)))
    changed: list[tuple[str, tuple[str, ...]]] = []
    for record_id in sorted(set(old_by_id) & set(new_by_id)):
        old_record, new_record = old_by_id[record_id], new_by_id[record_id]
        keys = set(old_record) | set(new_record)
        differing = tuple(sorted(k for k in keys if old_record.get(k) != new_record.get(k)))
        if differing:
            changed.append((record_id, differing))
    return added, removed, changed


def _diff_items(
    old_items: list[dict[str, JSONValue]], new_items: list[dict[str, JSONValue]]
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[ItemChange, ...]]:
    added, removed, changed = _diff_records_by_id(old_items, new_items, "capture_id")
    return added, removed, tuple(ItemChange(rid, fields) for rid, fields in changed)


def _diff_issues(
    old_issues: list[dict[str, JSONValue]], new_issues: list[dict[str, JSONValue]]
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[IssueChange, ...]]:
    added, removed, changed = _diff_records_by_id(old_issues, new_issues, "issue_id")
    return added, removed, tuple(IssueChange(rid, fields) for rid, fields in changed)


def _custody_prefix_check(
    old_entries: list[dict[str, JSONValue]], new_entries: list[dict[str, JSONValue]]
) -> tuple[bool, int | None]:
    """Is *old_entries* an unmodified, position-for-position prefix of *new_entries*?

    Compared by ``entry_hash`` (each entry's hash already commits to its own
    content and its predecessor's hash), so this also catches a reordering or a
    tampered `details` payload within the shared prefix, not just truncation.
    """
    common = min(len(old_entries), len(new_entries))
    for i in range(common):
        if _s(old_entries[i], "entry_hash") != _s(new_entries[i], "entry_hash"):
            return False, i
    if len(old_entries) > len(new_entries):
        # The "new" packet has fewer entries than the "old" one — custody shrank,
        # which can never happen honestly for the same case.
        return False, common
    return True, None


# --- loading ---------------------------------------------------------------------


def _load_bundle(packet_dir: Path) -> Mapping[str, JSONValue]:
    bundle_path = packet_dir / _BUNDLE
    if not bundle_path.exists():
        raise DiffError(f"no {_BUNDLE} in {packet_dir}")
    try:
        parsed = json.loads(bundle_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise DiffError(f"{bundle_path} is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise DiffError(f"{bundle_path} must be a JSON object")
    return parsed


def _manifest_generated_at(packet_dir: Path) -> str:
    """Best-effort, informational only: never fails the diff if absent/malformed."""
    manifest_path = packet_dir / _MANIFEST
    if not manifest_path.exists():
        return ""
    try:
        parsed = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError, UnicodeDecodeError:
        return ""
    return _s(parsed, "generated_at") if isinstance(parsed, dict) else ""


# --- small typed accessors (mirrors habitable.verify's parsing helpers) ----------


def _s(mapping: Mapping[str, JSONValue], key: str) -> str:
    value = mapping.get(key)
    return value if isinstance(value, str) else ""


def _int(mapping: Mapping[str, JSONValue], key: str) -> int:
    value = mapping.get(key)
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _map(mapping: Mapping[str, JSONValue], key: str) -> Mapping[str, JSONValue]:
    value = mapping.get(key)
    return value if isinstance(value, dict) else {}


def _list_of_dicts(mapping: Mapping[str, JSONValue], key: str) -> list[dict[str, JSONValue]]:
    value = mapping.get(key)
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _list_of_strs(mapping: Mapping[str, JSONValue], key: str) -> list[str]:
    value = mapping.get(key)
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]
