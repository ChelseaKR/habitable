# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
"""Fail when the built distributions carry metadata PyPI would render wrongly.

This gate reads the *artifact* -- the wheel's ``*.dist-info/METADATA`` and the
sdist's ``PKG-INFO`` -- and never the field values in ``pyproject.toml``.  That
distinction is the whole point.  A sibling project in this portfolio shipped a
0.2.0 wheel with no ``Project-URL`` lines at all while ``pyproject.toml`` on the
default branch declared four of them, because the release was built from a tag
cut before that change merged; every source-level assertion in that repository
passed.  Only the built distribution knows what PyPI will be told, so only the
built distribution is admissible evidence here.

``pyproject.toml`` is read for exactly two things -- the expected version and
the expected Python floor -- and both are then used as *assertions against* the
artifact, so a stale build is a failure rather than a silent pass.

Standard library only, so it can run before the project is installed and in the
publish job, which has no development environment.

Usage::

    python scripts/check_dist_metadata.py dist
    python scripts/check_dist_metadata.py dist --wheel-only   # measure one wheel
"""

from __future__ import annotations

import argparse
import email.parser
import email.policy
import re
import sys
import tarfile
import tomllib
import zipfile
from dataclasses import dataclass
from email.message import Message
from pathlib import Path

DISTRIBUTION = "habitable"
LICENSE_EXPRESSION = "AGPL-3.0-or-later"
REQUIRED_URL_LABELS = ("Homepage", "Source", "Issues")
REPO_ROOT = Path(__file__).resolve().parent.parent

# ``![alt](target)`` and ``<img src="target">`` whose target carries no scheme.
# PyPI does not rewrite relative paths the way GitHub does: it resolves them
# against https://pypi.org/project/habitable/, where they lead nowhere.
_MD_IMAGE = re.compile(r"!\[[^\]\n]*\]\(\s*(?P<target>[^\s)]+)")
_HTML_IMAGE = re.compile(r"<img\b[^>]*?\bsrc\s*=\s*[\"'](?P<target>[^\"']+)")
_SCHEME = re.compile(r"^(?:[A-Za-z][A-Za-z0-9+.-]*:|//|#)")
_INSTALL_LINE = re.compile(rf"(?:pip|pipx|uv tool|uv pip)\s+install\b[^\n]*\b{DISTRIBUTION}\b")
_PY_CLASSIFIER = re.compile(r"^Programming Language :: Python :: (\d+)\.(\d+)$")


@dataclass(frozen=True)
class Result:
    """One named field check and what the artifact actually said."""

    name: str
    ok: bool
    detail: str


def _normalize(name: str) -> str:
    """Apply PEP 503 name normalization."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _parse(raw: bytes) -> Message:
    parser = email.parser.BytesParser(policy=email.policy.compat32)
    return parser.parsebytes(raw)


def _description(msg: Message) -> str:
    """Return the long description from the body, or the legacy header."""
    payload = msg.get_payload(decode=False)
    if isinstance(payload, str) and payload.strip():
        return payload
    return str(msg.get("Description") or "")


def _read_wheel(path: Path) -> Message:
    with zipfile.ZipFile(path) as archive:
        names = [n for n in archive.namelist() if n.endswith(".dist-info/METADATA")]
        if len(names) != 1:
            raise SystemExit(f"{path.name}: expected exactly one dist-info/METADATA, found {names}")
        return _parse(archive.read(names[0]))


def _read_sdist(path: Path) -> Message:
    with tarfile.open(path) as archive:
        names = [n for n in archive.getnames() if n.count("/") == 1 and n.endswith("/PKG-INFO")]
        if len(names) != 1:
            raise SystemExit(f"{path.name}: expected exactly one top-level PKG-INFO, found {names}")
        handle = archive.extractfile(names[0])
        if handle is None:
            raise SystemExit(f"{path.name}: PKG-INFO is not a regular file")
        with handle:
            return _parse(handle.read())


def _expected_from_source() -> tuple[str, str]:
    """Return ``(version, requires-python)`` declared in pyproject.toml."""
    data = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = data["project"]
    return str(project["version"]), str(project["requires-python"])


def _floor(requires_python: str) -> tuple[int, int]:
    match = re.search(r">=\s*(\d+)\.(\d+)", requires_python)
    if match is None:
        raise SystemExit(f"cannot read a >=X.Y floor out of requires-python {requires_python!r}")
    return int(match.group(1)), int(match.group(2))


def _check_identity(msg: Message, version: str) -> list[Result]:
    name = str(msg.get("Name") or "")
    got_version = str(msg.get("Version") or "")
    return [
        Result(
            "name is the published distribution name",
            _normalize(name) == DISTRIBUTION,
            f"Name: {name!r} (expected {DISTRIBUTION!r})",
        ),
        Result(
            "version matches the source tree",
            got_version == version,
            f"Version: {got_version!r} (pyproject says {version!r})",
        ),
    ]


def _check_python_floor(msg: Message, requires_python: str) -> list[Result]:
    got = str(msg.get("Requires-Python") or "")
    floor = _floor(requires_python)
    classifiers = [str(c) for c in (msg.get_all("Classifier") or [])]
    versions = [
        (int(m.group(1)), int(m.group(2)))
        for m in (_PY_CLASSIFIER.match(c) for c in classifiers)
        if m is not None
    ]
    below = [f"{major}.{minor}" for major, minor in versions if (major, minor) < floor]
    only = "Programming Language :: Python :: 3 :: Only"
    return [
        Result(
            "requires-python is present and matches the source tree",
            got == requires_python,
            f"Requires-Python: {got!r} (pyproject says {requires_python!r})",
        ),
        Result(
            "interpreter classifiers do not claim versions below the floor",
            bool(versions) and not below,
            f"interpreter classifiers {[f'{a}.{b}' for a, b in versions]}, "
            f"floor {floor[0]}.{floor[1]}, below the floor: {below or 'none'}",
        ),
        Result(
            "the Python-3-only classifier states the floor is a floor",
            only in classifiers,
            f"{only}: {'present' if only in classifiers else 'MISSING'}",
        ),
    ]


def _check_license(msg: Message) -> list[Result]:
    expression = str(msg.get("License-Expression") or "")
    legacy = msg.get("License")
    legacy_text = str(legacy) if legacy is not None else ""
    return [
        Result(
            "license is a PEP 639 SPDX expression",
            expression == LICENSE_EXPRESSION,
            f"License-Expression: {expression!r} (expected {LICENSE_EXPRESSION!r})",
        ),
        Result(
            "no legacy License field, and none carrying licence text",
            legacy is None,
            "License: absent"
            if legacy is None
            else f"License: present, {len(legacy_text.splitlines())} lines, "
            f"{len(legacy_text)} characters -- PyPI renders all of it",
        ),
    ]


def _check_urls(msg: Message) -> list[Result]:
    entries: dict[str, str] = {}
    for raw in msg.get_all("Project-URL") or []:
        label, _, url = str(raw).partition(",")
        entries[label.strip()] = url.strip()
    missing = [label for label in REQUIRED_URL_LABELS if label not in entries]
    unreachable = sorted(label for label, url in entries.items() if not url.startswith("https://"))
    return [
        Result(
            "every required Project-URL label is published",
            not missing,
            f"labels {sorted(entries)}; missing {missing or 'none'}",
        ),
        Result(
            "every published Project-URL is an absolute https URL",
            not unreachable,
            f"not absolute https: {unreachable or 'none'}",
        ),
    ]


def _relative_images(description: str) -> list[str]:
    targets = [m.group("target") for m in _MD_IMAGE.finditer(description)]
    targets += [m.group("target") for m in _HTML_IMAGE.finditer(description)]
    return sorted({t for t in targets if not _SCHEME.match(t)})


def _check_description(msg: Message, requires_python: str) -> list[Result]:
    description = _description(msg)
    content_type = str(msg.get("Description-Content-Type") or "")
    major, minor = _floor(requires_python)
    floor_text = f"{major}.{minor}"
    relative = _relative_images(description)
    install = _INSTALL_LINE.search(description)
    return [
        Result(
            "the rendered description declares its content type",
            content_type.startswith("text/"),
            f"Description-Content-Type: {content_type!r}",
        ),
        Result(
            "the rendered description is not empty",
            len(description.strip()) > 0,
            f"description is {len(description)} characters",
        ),
        Result(
            "the description tells a reader how to install this distribution",
            install is not None,
            f"install line: {install.group(0) if install else 'NONE FOUND'}",
        ),
        Result(
            "the description states the Python floor the resolver enforces",
            floor_text in description,
            f"{floor_text!r} {'appears' if floor_text in description else 'DOES NOT APPEAR'} "
            "in the rendered description",
        ),
        Result(
            "no image source resolves against pypi.org instead of the repository",
            not relative,
            f"relative image sources: {relative or 'none'}",
        ),
    ]


def check(msg: Message, version: str, requires_python: str) -> list[Result]:
    """Run every field check against one parsed metadata document."""
    return [
        *_check_identity(msg, version),
        *_check_python_floor(msg, requires_python),
        *_check_license(msg),
        *_check_urls(msg),
        *_check_description(msg, requires_python),
    ]


def _agreement(wheel: Message, sdist: Message) -> Result:
    """The sdist and the wheel must tell PyPI the same story."""
    fields = ("Name", "Version", "Requires-Python", "License-Expression", "License")
    disagreements = [
        field
        for field in fields
        if [str(v) for v in (wheel.get_all(field) or [])]
        != [str(v) for v in (sdist.get_all(field) or [])]
    ]
    wheel_urls = sorted(str(v) for v in (wheel.get_all("Project-URL") or []))
    sdist_urls = sorted(str(v) for v in (sdist.get_all("Project-URL") or []))
    if wheel_urls != sdist_urls:
        disagreements.append("Project-URL")
    return Result(
        "the wheel and the sdist agree on what PyPI is told",
        not disagreements,
        f"fields that disagree: {disagreements or 'none'}",
    )


def _one(paths: list[Path], kind: str) -> Path:
    if len(paths) != 1:
        raise SystemExit(f"expected exactly one {kind}, found {[p.name for p in paths]}")
    return paths[0]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dist_dir", type=Path, help="directory holding the built wheel and sdist")
    parser.add_argument(
        "--wheel-only",
        action="store_true",
        help="check a lone wheel (used to measure an already-published artifact)",
    )
    args = parser.parse_args(argv)

    version, requires_python = _expected_from_source()
    wheel_path = _one(sorted(args.dist_dir.glob("*.whl")), "wheel")
    wheel = _read_wheel(wheel_path)
    results = check(wheel, version, requires_python)
    measured = [f"wheel {wheel_path.name}"]

    if not args.wheel_only:
        sdist_path = _one(sorted(args.dist_dir.glob("*.tar.gz")), "sdist")
        sdist = _read_sdist(sdist_path)
        results.append(_agreement(wheel, sdist))
        measured.append(f"sdist {sdist_path.name}")

    print(f"checking published metadata in {', '.join(measured)}")
    for result in results:
        print(f"  [{'PASS' if result.ok else 'FAIL'}] {result.name}\n         {result.detail}")
    passed = sum(1 for r in results if r.ok)
    print(f"\nfields correct in the artifact / fields examinable: {passed}/{len(results)}")
    if passed != len(results):
        print("\nThis metadata is immutable once uploaded: a published version cannot be")
        print("edited in place, so a wrong field here can only ever be fixed by a new release.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
