# SPDX-License-Identifier: AGPL-3.0-or-later
# A tiny, dependency-free image for the optional ciphertext-only sync relay.
# The relay uses only the Python standard library, so there is nothing to pip
# install — which keeps the image small and the attack surface minimal, fitting
# for a component that should never be able to read anything.
#
# Build from the repository root:
#   docker build -f relay/Dockerfile -t habitable-relay .
# Pinned by digest for reproducible, tamper-evident builds (Dependabot bumps it).
FROM python:3.14-slim@sha256:cea0e6040540fb2b965b6e7fb5ffa00871e632eef63719f0ea54bca189ce14a6

# Apply Debian security updates on top of the pinned digest.
#
# The digest pin freezes the package set at whatever upstream built the image
# with, so a base that is fully patched on the day it is published drifts out of
# date without its digest changing. CVE-2026-53615 (integer overflow in
# util-linux, HIGH) is fixed in Debian 2.41.5-0+deb13u1 and has been in
# trixie-security since before 2026-08-17, but the upstream python:3.14-slim
# image has not been rebuilt against it: the newest published digest as of
# 2026-08-17 still ships 2.41-5. Rebasing onto a fresher digest therefore
# cannot clear the finding, and it reaches nine binary packages
# (util-linux, bsdutils, mount, login, and the lib{blkid,mount,smartcols,uuid}1
# and liblastlog2-2 runtime libraries). Only an upgrade layer clears it.
#
# The cleanup below is load-bearing, not tidiness. `make relay-repro` rebuilds
# this image twice with --no-cache and compares the two OCI archives byte for
# byte. Five apt/dpkg artifacts differ between two builds that install the
# identical package set, and each was identified by bisecting the failing
# archive diff rather than guessed at:
#
#   /var/log/apt/history.log, /var/log/apt/term.log, /var/log/dpkg.log and
#   /var/log/alternatives.log record wall-clock times in every entry.
#
#   /var/cache/ldconfig/aux-cache stores each shared library's inode number
#   and ctime inside the file's own bytes. BuildKit's rewrite-timestamp
#   normalises file mtimes in the layer, so this one survives that
#   normalisation and is why removing the logs alone still failed the gate.
#
# Neither costs anything at runtime: the logs are a build record, and
# aux-cache is a cache ldconfig regenerates when it next runs.
RUN apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* \
 && rm -rf /var/log/apt /var/log/dpkg.log /var/log/alternatives.log \
 && rm -rf /var/cache/ldconfig

# Remove the base image's bundled pip.
#
# python:3.14-slim ships pip via ensurepip so the image is useful standalone,
# but this relay never runs pip — the comment above already says so. Pip
# vendors its own copies of its dependencies (see its vendor.txt) rather than
# depending on packages installed alongside it, and that vendored copy lags
# upstream: even on the current pip release, it still bundles
# msgpack 1.1.2 (GHSA-6v7p-g79w-8964, HIGH) and setuptools 70.3.0
# (CVE-2025-47273, HIGH). Neither is fixable by bumping pip's own version or
# the base digest — they are pinned inside pip's vendor tree until pip's
# maintainers refresh it. Since nothing in this image ever imports pip,
# deleting it removes the code paths those CVEs live in rather than waiting
# on an upstream release. `python3 -c "import sys"` and the relay's own
# stdlib-only imports are unaffected — verified by running the built image.
RUN rm -rf /usr/local/lib/python3.14/site-packages/pip \
           /usr/local/lib/python3.14/site-packages/pip-*.dist-info \
           /usr/local/lib/python3.14/site-packages/README.txt \
           /usr/local/lib/python3.14/ensurepip

# Run as a non-root user.
RUN useradd --system --uid 10001 --no-create-home relay

WORKDIR /opt/habitable
# Only the source tree is needed (no third-party dependencies for the relay).
COPY src/ /opt/habitable/src/

ENV PYTHONPATH=/opt/habitable/src \
    PYTHONUNBUFFERED=1 \
    HABITABLE_RELAY_HOST=0.0.0.0 \
    HABITABLE_RELAY_PORT=8787

EXPOSE 8787
USER relay

HEALTHCHECK --interval=30s --timeout=3s --start-period=3s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8787/healthz', timeout=2)"]

ENTRYPOINT ["python", "-m", "habitable.relay"]
