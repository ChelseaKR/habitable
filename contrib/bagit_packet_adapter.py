# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Chelsea Kelly-Reif
"""Package an exact Habitable packet as a strict BagIt 1.0 transfer bag.

This dependency-free adapter uses only Python's standard library plus Habitable's
published verification subset.  It first rejects unsafe filesystem objects and
ambiguous paths, then requires Habitable structural verification to pass.  The
packet's exact files are copied beneath ``data/packet/`` and covered by SHA-256
payload and tag manifests.  The copied packet and completed bag are verified again
before a single same-filesystem rename publishes the result.

BagIt detects accidental transfer corruption.  It is not secure against active
attackers who can rewrite both content and manifests; Habitable's signed packet and
independent timestamp-authority trust checks remain the security boundary.

See ``contrib/bagit-packet-adapter.md`` for the interoperability profile and CLI.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tempfile
import unicodedata
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from habitable.verify import VerificationReport, verify_packet

__all__ = [
    "BagCreationResult",
    "BagItAdapterError",
    "BagValidation",
    "create_bag",
    "validate_bag",
]

_BAGIT = "bagit.txt"
_PAYLOAD_MANIFEST = "manifest-sha256.txt"
_TAG_MANIFEST = "tagmanifest-sha256.txt"
_PAYLOAD_PREFIX = "data/packet/"
_BAGIT_BYTES = b"BagIt-Version: 1.0\nTag-File-Character-Encoding: UTF-8\n"
_DIGEST_RE = re.compile(r"^([0-9A-Fa-f]{64})[ \t]+(.+)$")
_WINDOWS_FORBIDDEN = frozenset('<>:"|?*')
_WINDOWS_RESERVED = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *(f"COM{number}" for number in range(1, 10)),
        *(f"LPT{number}" for number in range(1, 10)),
    }
)


class BagItAdapterError(ValueError):
    """A source packet, bag, or destination violates the adapter's safe profile."""


@dataclass(frozen=True)
class BagValidation:
    """Fail-closed validation result for one Habitable BagIt transfer bag."""

    bag_dir: Path
    problems: tuple[str, ...]
    payload_files: int = 0
    payload_bytes: int = 0
    tag_files: int = 0

    @property
    def ok(self) -> bool:
        return not self.problems


@dataclass(frozen=True)
class BagCreationResult:
    """A published bag and the structural packet verdict it was built from."""

    bag_dir: Path
    packet_dir: Path
    packet_report: VerificationReport
    validation: BagValidation


@dataclass(frozen=True)
class _FileEntry:
    relative: PurePosixPath
    source: Path
    device: int
    inode: int


@dataclass(frozen=True)
class _Inventory:
    directories: tuple[PurePosixPath, ...]
    files: tuple[_FileEntry, ...]


def create_bag(packet_dir: Path | str, output_dir: Path | str) -> BagCreationResult:
    """Verify and package ``packet_dir`` into a new, atomically published bag.

    The destination must not already exist.  Refusing replacement means a failed
    or racing invocation cannot delete a prior transfer bag, and successful
    publication is one rename rather than a visible partially-built directory.
    """
    source = _source_root(Path(packet_dir))
    output = Path(output_dir)
    inventory = _inventory(source, context="packet")
    _preflight_packet_references(source)
    _verify_habitable_packet(source)
    _prepare_destination(source, output)

    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        stage = Path(tempfile.mkdtemp(prefix=f".{output.name}.stage-", dir=output.parent))
    except OSError as exc:
        raise BagItAdapterError(f"cannot prepare output directory {output.parent}: {exc}") from exc
    try:
        payload_root = stage / "data" / "packet"
        payload_root.mkdir(parents=True)
        _copy_directories(payload_root, inventory.directories)
        digests, payload_bytes = _copy_files(payload_root, inventory.files, source)

        # Re-run the packet verifier over the exact copied snapshot before its
        # BagIt manifests can make that snapshot appear transfer-complete.
        copied_report = _verify_habitable_packet(payload_root)

        (stage / _BAGIT).write_bytes(_BAGIT_BYTES)
        manifest = _render_manifest(digests)
        (stage / _PAYLOAD_MANIFEST).write_bytes(manifest)
        tag_digests = {
            _BAGIT: _sha256_path(stage / _BAGIT),
            _PAYLOAD_MANIFEST: _sha256_path(stage / _PAYLOAD_MANIFEST),
        }
        (stage / _TAG_MANIFEST).write_bytes(_render_manifest(tag_digests))

        validation = validate_bag(stage)
        if not validation.ok:
            raise BagItAdapterError(
                "completed bag failed validation: " + "; ".join(validation.problems)
            )
        if validation.payload_bytes != payload_bytes:
            raise BagItAdapterError("completed bag payload byte count changed")

        # A second existence check narrows the ordinary race window.  BagIt does
        # not claim protection against an active local attacker (RFC 8493 §5.4).
        if output.exists() or output.is_symlink():
            raise BagItAdapterError(f"output already exists; refusing to replace it: {output}")
        stage.rename(output)
        published = BagValidation(
            bag_dir=output,
            problems=validation.problems,
            payload_files=validation.payload_files,
            payload_bytes=validation.payload_bytes,
            tag_files=validation.tag_files,
        )
    except OSError as exc:
        raise BagItAdapterError(f"cannot build or publish transfer bag: {exc}") from exc
    finally:
        shutil.rmtree(stage, ignore_errors=True)

    return BagCreationResult(
        bag_dir=output,
        packet_dir=output / "data" / "packet",
        packet_report=copied_report,
        validation=published,
    )


def validate_bag(bag_dir: Path | str) -> BagValidation:
    """Validate the strict Habitable transfer profile without escaping ``bag_dir``.

    This is deliberately not a general-purpose validator for every BagIt option.
    It validates the exact profile emitted by :func:`create_bag`: BagIt 1.0,
    UTF-8, SHA-256, one packet at ``data/packet/``, and a tag manifest covering
    every non-tag-manifest tag file.
    """
    root = Path(bag_dir)
    try:
        return _validate_bag(root)
    except (BagItAdapterError, OSError, UnicodeError) as exc:
        return BagValidation(bag_dir=root, problems=(str(exc),))


def _validate_bag(root: Path) -> BagValidation:
    root = _safe_directory_root(root, context="bag")
    inventory = _inventory(root, context="bag")
    actual_files = {entry.relative.as_posix(): entry.source for entry in inventory.files}
    actual_dirs = {entry.as_posix() for entry in inventory.directories}

    required = {_BAGIT, _PAYLOAD_MANIFEST, _TAG_MANIFEST}
    missing_tags = sorted(required - actual_files.keys(), key=_utf8_key)
    if missing_tags:
        raise BagItAdapterError(f"bag is missing required tag file(s): {', '.join(missing_tags)}")
    if actual_files[_BAGIT].read_bytes() != _BAGIT_BYTES:
        raise BagItAdapterError("bagit.txt is not the exact BagIt 1.0 UTF-8 declaration")

    payload_entries = _parse_manifest(actual_files[_PAYLOAD_MANIFEST], payload=True)
    tag_entries = _parse_manifest(actual_files[_TAG_MANIFEST], payload=False)

    expected_tag_paths = {_BAGIT, _PAYLOAD_MANIFEST}
    if set(tag_entries) != expected_tag_paths:
        missing = sorted(expected_tag_paths - tag_entries.keys(), key=_utf8_key)
        extra = sorted(tag_entries.keys() - expected_tag_paths, key=_utf8_key)
        details = _set_difference_details(missing, extra)
        raise BagItAdapterError(f"tag manifest does not cover the exact tag set ({details})")

    payload_paths = {path for path in actual_files if path.startswith(_PAYLOAD_PREFIX)}
    untracked_files = set(actual_files) - payload_paths - required
    if untracked_files:
        names = ", ".join(sorted(untracked_files, key=_utf8_key))
        raise BagItAdapterError(f"bag contains untracked tag file(s): {names}")
    invalid_dirs = {
        path
        for path in actual_dirs
        if path not in {"data", "data/packet"} and not path.startswith(_PAYLOAD_PREFIX)
    }
    if invalid_dirs:
        names = ", ".join(sorted(invalid_dirs, key=_utf8_key))
        raise BagItAdapterError(f"bag contains a directory outside data/packet: {names}")

    listed_payload = set(payload_entries)
    if listed_payload != payload_paths:
        missing = sorted(listed_payload - payload_paths, key=_utf8_key)
        extra = sorted(payload_paths - listed_payload, key=_utf8_key)
        details = _set_difference_details(missing, extra)
        raise BagItAdapterError(f"payload manifest and data/packet differ ({details})")

    payload_bytes = 0
    for path in sorted(payload_entries, key=_utf8_key):
        payload_path = actual_files[path]
        payload_bytes += payload_path.stat(follow_symlinks=False).st_size
        _require_digest(payload_path, payload_entries[path], label=path)
    for path in sorted(tag_entries, key=_utf8_key):
        _require_digest(actual_files[path], tag_entries[path], label=path)

    return BagValidation(
        bag_dir=root,
        problems=(),
        payload_files=len(payload_entries),
        payload_bytes=payload_bytes,
        tag_files=len(tag_entries),
    )


def _source_root(path: Path) -> Path:
    return _safe_directory_root(path, context="packet")


def _safe_directory_root(path: Path, *, context: str) -> Path:
    if path.is_symlink():
        raise BagItAdapterError(f"{context} root must not be a symlink: {path}")
    if not path.exists():
        raise BagItAdapterError(f"{context} directory does not exist: {path}")
    if not path.is_dir():
        raise BagItAdapterError(f"{context} root must be a directory: {path}")
    return path.resolve(strict=True)


def _inventory(root: Path, *, context: str) -> _Inventory:
    directories: list[PurePosixPath] = []
    files: list[_FileEntry] = []

    def walk(directory: Path, relative: PurePosixPath | None = None) -> None:
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda entry: _utf8_key(entry.name))
        except OSError as exc:
            raise BagItAdapterError(f"cannot scan {context} directory {directory}: {exc}") from exc
        for entry in entries:
            rel = PurePosixPath(entry.name) if relative is None else relative / entry.name
            path = Path(entry.path)
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise BagItAdapterError(f"cannot inspect {context} path {rel}: {exc}") from exc
            mode = metadata.st_mode
            if stat.S_ISLNK(mode):
                raise BagItAdapterError(f"{context} contains a symlink: {rel.as_posix()}")
            if stat.S_ISDIR(mode):
                directories.append(rel)
                walk(path, rel)
            elif stat.S_ISREG(mode):
                files.append(
                    _FileEntry(
                        relative=rel,
                        source=path,
                        device=metadata.st_dev,
                        inode=metadata.st_ino,
                    )
                )
            else:
                raise BagItAdapterError(f"{context} contains a non-regular file: {rel.as_posix()}")

    walk(root)
    _validate_relative_paths(
        [path.as_posix() for path in directories] + [entry.relative.as_posix() for entry in files],
        context=context,
    )
    return _Inventory(
        directories=tuple(sorted(directories, key=lambda path: _utf8_key(path.as_posix()))),
        files=tuple(sorted(files, key=lambda entry: _utf8_key(entry.relative.as_posix()))),
    )


def _validate_relative_paths(paths: Iterable[str], *, context: str) -> None:
    seen_exact: set[str] = set()
    seen_portable: dict[str, str] = {}
    for path in paths:
        _validate_relative_path(path, context=context)
        if path in seen_exact:
            raise BagItAdapterError(f"{context} contains duplicate path: {path}")
        seen_exact.add(path)
        portable = unicodedata.normalize("NFC", path).casefold()
        prior = seen_portable.get(portable)
        if prior is not None and prior != path:
            raise BagItAdapterError(
                f"{context} paths collide by case or Unicode normalization: {prior!r}, {path!r}"
            )
        seen_portable[portable] = path


def _validate_relative_path(path: str, *, context: str) -> None:
    if not path or path.startswith("/") or path.startswith("\\"):
        raise BagItAdapterError(f"{context} path must be non-empty and relative: {path!r}")
    if "\\" in path:
        raise BagItAdapterError(f"{context} path contains an ambiguous backslash: {path!r}")
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise BagItAdapterError(f"{context} path contains empty or traversal component: {path!r}")
    for component in parts:
        _validate_component(component, context=context, path=path)


def _validate_component(component: str, *, context: str, path: str) -> None:
    try:
        component.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise BagItAdapterError(f"{context} path is not valid UTF-8: {path!r}") from exc
    if component != component.strip():
        raise BagItAdapterError(f"{context} path has leading/trailing whitespace: {path!r}")
    if any(ord(character) < 32 or ord(character) == 127 for character in component):
        raise BagItAdapterError(f"{context} path contains a control character: {path!r}")
    if any(character in _WINDOWS_FORBIDDEN for character in component):
        raise BagItAdapterError(f"{context} path is not portable to Windows: {path!r}")
    if component.endswith((".", " ")):
        raise BagItAdapterError(f"{context} path has a non-portable suffix: {path!r}")
    stem = component.split(".", 1)[0].upper()
    if stem in _WINDOWS_RESERVED:
        raise BagItAdapterError(f"{context} path uses a reserved Windows name: {path!r}")


def _preflight_packet_references(root: Path) -> None:
    """Confine verifier-consumed filenames before handing it untrusted JSON."""
    bundle_path = root / "bundle.json"
    try:
        bundle = json.loads(bundle_path.read_bytes())
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise BagItAdapterError(f"cannot safely parse packet bundle.json: {exc}") from exc
    if not isinstance(bundle, dict):
        raise BagItAdapterError("packet bundle.json must contain an object")
    items = bundle.get("items")
    if not isinstance(items, list):
        return  # Habitable reports the malformed packet; no path is consumed here.
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            continue
        for field in ("shared_name", "poster_name", "capture_id"):
            value = item.get(field)
            if not isinstance(value, str) or not value:
                continue
            _validate_relative_path(value, context=f"bundle item {index} {field}")
            if "/" in value:
                raise BagItAdapterError(
                    f"bundle item {index} {field} must be one filename, not a path"
                )


def _verify_habitable_packet(root: Path) -> VerificationReport:
    try:
        report = verify_packet(root)
    except Exception as exc:
        raise BagItAdapterError(f"Habitable packet verification could not run: {exc}") from exc
    if not report.structurally_intact:
        details = list(report.problems)
        if not report.signature_ok:
            details.append("packet signature failed")
        if not report.custody_ok:
            details.append("packet custody proof failed")
        failed_items = sum(not item.structurally_intact for item in report.items)
        if failed_items:
            details.append(f"{failed_items} packet item(s) failed structural checks")
        explanation = "; ".join(details) or "unknown structural failure"
        raise BagItAdapterError(f"Habitable packet is not structurally intact: {explanation}")
    return report


def _prepare_destination(source: Path, output: Path) -> None:
    if not output.name:
        raise BagItAdapterError("output must name a new directory")
    if output.exists() or output.is_symlink():
        raise BagItAdapterError(f"output already exists; refusing to replace it: {output}")
    resolved_output = output.resolve(strict=False)
    if _contains(source, resolved_output) or _contains(resolved_output, source):
        raise BagItAdapterError("packet and output directories must not contain one another")


def _contains(parent: Path, child: Path) -> bool:
    return parent == child or parent in child.parents


def _copy_directories(payload_root: Path, directories: Sequence[PurePosixPath]) -> None:
    for relative in directories:
        (payload_root / Path(*relative.parts)).mkdir(parents=True, exist_ok=True)


def _copy_files(
    payload_root: Path, files: Sequence[_FileEntry], source_root: Path
) -> tuple[dict[str, str], int]:
    digests: dict[str, str] = {}
    total_bytes = 0
    for entry in files:
        target = payload_root / Path(*entry.relative.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        digest, size = _copy_regular_file(entry, target, source_root)
        manifest_path = _PAYLOAD_PREFIX + entry.relative.as_posix()
        digests[manifest_path] = digest
        total_bytes += size
    return digests, total_bytes


def _copy_regular_file(entry: _FileEntry, target: Path, source_root: Path) -> tuple[str, int]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(entry.source, flags)
    except OSError as exc:
        raise BagItAdapterError(f"cannot safely open packet file {entry.relative}: {exc}") from exc
    digest = hashlib.sha256()
    size = 0
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise BagItAdapterError(f"packet file changed type: {entry.relative}")
        if (metadata.st_dev, metadata.st_ino) != (entry.device, entry.inode):
            raise BagItAdapterError(f"packet file changed during packaging: {entry.relative}")
        resolved = entry.source.resolve(strict=True)
        if not _contains(source_root, resolved):
            raise BagItAdapterError(f"packet file escaped its root: {entry.relative}")
        with os.fdopen(descriptor, "rb", closefd=False) as source, target.open("xb") as destination:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
                destination.write(chunk)
                size += len(chunk)
    finally:
        os.close(descriptor)
    copied_digest = _sha256_path(target)
    if copied_digest != digest.hexdigest():
        raise BagItAdapterError(f"copied payload digest changed: {entry.relative}")
    return copied_digest, size


def _render_manifest(digests: dict[str, str]) -> bytes:
    lines = [
        f"{digests[path]}  {_encode_manifest_path(path)}\n"
        for path in sorted(digests, key=_utf8_key)
    ]
    return "".join(lines).encode("utf-8")


def _parse_manifest(path: Path, *, payload: bool) -> dict[str, str]:
    try:
        raw = path.read_bytes()
        text = raw.decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise BagItAdapterError(f"cannot read UTF-8 manifest {path.name}: {exc}") from exc
    if text.startswith("\ufeff"):
        raise BagItAdapterError(f"manifest {path.name} must not begin with a UTF-8 BOM")
    if not text or not text.endswith("\n"):
        raise BagItAdapterError(f"manifest {path.name} must be non-empty and LF-terminated")
    if "\r" in text:
        raise BagItAdapterError(f"manifest {path.name} must use deterministic LF endings")

    entries: dict[str, str] = {}
    raw_paths: list[str] = []
    for number, line in enumerate(text.splitlines(), start=1):
        digest, decoded_path = _parse_manifest_line(
            line, manifest_name=path.name, number=number, payload=payload
        )
        if decoded_path in entries:
            raise BagItAdapterError(f"duplicate path in {path.name}: {decoded_path}")
        entries[decoded_path] = digest.lower()
        raw_paths.append(decoded_path)
    _validate_relative_paths(raw_paths, context=path.name)
    return entries


def _parse_manifest_line(
    line: str, *, manifest_name: str, number: int, payload: bool
) -> tuple[str, str]:
    match = _DIGEST_RE.fullmatch(line)
    if match is None:
        raise BagItAdapterError(f"malformed {manifest_name} line {number}")
    digest, encoded_path = match.groups()
    decoded_path = _decode_manifest_path(encoded_path)
    if _encode_manifest_path(decoded_path) != encoded_path:
        raise BagItAdapterError(f"non-canonical path encoding in {manifest_name} line {number}")
    _validate_relative_path(decoded_path, context=manifest_name)
    if payload and not decoded_path.startswith(_PAYLOAD_PREFIX):
        raise BagItAdapterError(f"payload manifest path is outside data/packet: {decoded_path}")
    if not payload and decoded_path.startswith("data/"):
        raise BagItAdapterError(f"tag manifest references payload path: {decoded_path}")
    return digest, decoded_path


def _encode_manifest_path(path: str) -> str:
    return path.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _decode_manifest_path(path: str) -> str:
    decoded: list[str] = []
    index = 0
    while index < len(path):
        if path[index] != "%":
            decoded.append(path[index])
            index += 1
            continue
        token = path[index : index + 3]
        normalized = token.upper()
        if len(token) != 3 or normalized not in {"%0D", "%0A", "%25"}:
            raise BagItAdapterError(f"manifest path has invalid percent escape: {path!r}")
        decoded.append({"%0D": "\r", "%0A": "\n", "%25": "%"}[normalized])
        index += 3
    return "".join(decoded)


def _require_digest(path: Path, expected: str, *, label: str) -> None:
    actual = _sha256_path(path)
    if actual != expected:
        raise BagItAdapterError(f"SHA-256 mismatch for {label}")


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _set_difference_details(missing: Sequence[str], extra: Sequence[str]) -> str:
    details: list[str] = []
    if missing:
        details.append("missing " + ", ".join(missing))
    if extra:
        details.append("extra " + ", ".join(extra))
    return "; ".join(details) or "unknown difference"


def _utf8_key(value: str) -> bytes:
    try:
        return value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise BagItAdapterError(f"path is not valid UTF-8: {value!r}") from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create or validate a strict BagIt 1.0 transfer bag for a Habitable packet."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create", help="verify a packet and create a new transfer bag")
    create.add_argument("packet", type=Path, help="Habitable packet directory")
    create.add_argument("output", type=Path, help="new BagIt directory (must not exist)")
    validate = commands.add_parser("validate", help="validate payload and tag coverage/digests")
    validate.add_argument("bag", type=Path, help="BagIt transfer directory")
    return parser


def _main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "validate":
        validation = validate_bag(args.bag)
        if validation.ok:
            print(
                f"valid Habitable transfer bag: {validation.payload_files} payload file(s), "
                f"{validation.payload_bytes} byte(s), {validation.tag_files} digested tag file(s)"
            )
            return 0
        print("invalid Habitable transfer bag: " + "; ".join(validation.problems), file=sys.stderr)
        return 1
    try:
        result = create_bag(args.packet, args.output)
    except BagItAdapterError as exc:
        print(f"could not create Habitable transfer bag: {exc}", file=sys.stderr)
        return 1
    print(
        f"created {result.bag_dir}: {result.validation.payload_files} exact packet file(s), "
        f"{result.validation.payload_bytes} byte(s)"
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through _main in tests
    raise SystemExit(_main())
