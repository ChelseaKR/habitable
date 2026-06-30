<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Releasing habitable

Releases are tagged, built reproducibly, accompanied by an SBOM, and
**provenance-attested and signed** so a downloader can verify a release artifact
was built from this source by this repository's CI.

## Cutting a release

1. Ensure `main` is green: `make verify`, the `a11y` gate, and CodeQL all pass.
2. Update `CHANGELOG.md` (move `[Unreleased]` → the new version) and bump
   `version` in `pyproject.toml` (and `__version__`) if it changed.
3. Tag and push:
   ```console
   $ git tag vX.Y.Z && git push origin vX.Y.Z
   ```
4. The **`release` workflow** (`.github/workflows/release.yml`) then:
   - builds the wheel + sdist (`uv build`);
   - generates a runtime **SBOM** (CycloneDX) into `dist/sbom.cdx.json`;
   - produces a **signed build-provenance attestation** for the artifacts
     (`actions/attest-build-provenance`, Sigstore);
   - creates/updates the GitHub release and uploads `dist/*`;
   - in a separate `pypi-publish` job (scoped to `id-token: write` only),
     rebuilds the wheel + sdist from the tagged source and **publishes to PyPI
     via Trusted Publishing** (`pypa/gh-action-pypi-publish`, OIDC — no stored
     token), which also attaches PEP 740 provenance to the PyPI artifacts.

### One-time PyPI setup (before the first tag)

Trusted Publishing needs a **pending publisher** registered on PyPI once, which
CI cannot do for itself:

- project `habitable`, owner `ChelseaKR`, repository `habitable`,
  workflow `release.yml`, environment `pypi`;
- a matching GitHub Environment named `pypi` on this repo.

After that, every `vX.Y.Z` tag publishes with no API token.

## Verifying a downloaded artifact

Anyone can confirm an artifact came from this repo's CI:

```console
$ gh attestation verify habitable-X.Y.Z-py3-none-any.whl --repo ChelseaKR/habitable
```

The SBOM (`sbom.cdx.json`) lists the runtime dependency set for that release.

## Versioning contract

SemVer for the package. The **packet format** and **verification protocol** are
versioned independently and older packets must keep verifying — enforced by the
golden-packet corpus and the version-contract test (see
[`evidence-method.md`](evidence-method.md) and `tests/test_golden.py`), not by
prose.

## Not yet wired (tracked for v1.0)

- **Reproducible-build verification:** document and verify a byte-identical
  rebuild of the wheel. Until then, note that the GitHub-release artifacts and
  the PyPI artifacts are produced by two independent `uv build` invocations of
  the same tagged source, each independently attested (Sigstore build-provenance
  for the release artifacts, PEP 740 for the PyPI artifacts).
