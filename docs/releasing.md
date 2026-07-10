<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Releasing habitable

Releases are tagged, built reproducibly, accompanied by an SBOM, and carry a
**Sigstore-signed build-provenance attestation** so a downloader can verify a
release artifact was built from this source by this repository's CI. The
**release tag itself** is signed too, going forward (git tag signature,
verified by a CI guard before anything builds) — see the one-time setup below.
These are two different signatures: one over the build (always present since
v0.2.0), one over the tag identity (new; existing v0.1.0/v0.2.0 tags predate it
and are not signed).

## Cutting a release

1. Ensure `main` is green: `make verify`, the `a11y` gate, and CodeQL all pass.
2. Update `CHANGELOG.md` (move `[Unreleased]` → the new version) and bump
   `version` in `pyproject.toml`. `__version__` is derived from the installed
   distribution (`importlib.metadata.version`), so there is nothing to hand-edit
   in `src/habitable/__init__.py` — that is the point (REL-02/03: no second place
   for the version to drift).
3. Tag with a **signed, annotated tag** and push (see one-time setup below):
   ```console
   $ git tag -s vX.Y.Z -m "vX.Y.Z" && git push origin vX.Y.Z
   ```
4. The **`release` workflow** (`.github/workflows/release.yml`) first runs two
   guards, *before* building anything: the tag must be a valid signature per
   `.github/allowed_signers`, and its version must match `pyproject.toml`. It
   then re-runs `make verify` at the tagged commit — a red commit cannot ship.
   Only then does it:
   - build the wheel + sdist (`uv build`);
   - install the wheel into a clean environment and serve the packaged local app;
   - generate a runtime **SBOM** (CycloneDX) into `dist/sbom.cdx.json`;
   - produce a **signed build-provenance attestation** for the artifacts
     (`actions/attest-build-provenance`, Sigstore);
   - create/update the GitHub release and upload `dist/*`;
   - in a separate `pypi-publish` job (scoped to `contents: read` plus
     `id-token: write`),
     rebuilds the wheel + sdist from the tagged source and **publishes to PyPI
     via Trusted Publishing** (`pypa/gh-action-pypi-publish`, OIDC — no stored
     token), which also attaches PEP 740 provenance to the PyPI artifacts.

### One-time setup: signing release tags

The release workflow verifies tag signatures against `.github/allowed_signers`
using git's SSH signing format. Until a maintainer completes this setup, the tag
guard fails closed (intentional — an unsigned tag must never publish):

```console
$ ssh-keygen -t ed25519 -C "release-signing@habitable" -f ~/.ssh/habitable-release
$ git config gpg.format ssh
$ git config user.signingkey ~/.ssh/habitable-release.pub
```

Then add the matching **public** key as a line in `.github/allowed_signers`
(format documented in that file) and commit it — public keys are not secret.

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
