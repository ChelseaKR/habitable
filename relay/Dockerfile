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
# The digest pin gives a reproducible base, but it also freezes the package set
# at whatever the upstream image was built with. CVE-2026-53615 (integer
# overflow in util-linux libblkid) is fixed in Debian's 2.41.5-0+deb13u1, and
# that package is available from the security suite today, but the upstream
# python:*-slim image has not been rebuilt since. Without this step the image
# ships the vulnerable 2.41-5 no matter how recently the digest was bumped, and
# the container CVE scan fails on a finding a rebase cannot clear.
# The trailing cleanup is not tidiness. This image is verified by a
# byte-identical double rebuild (`make relay-repro`), and apt writes
# timestamped records into the image: /var/log/apt/history.log and term.log,
# /var/log/dpkg.log, and dpkg's own status backups. Those bytes differ between
# two builds seconds apart and fail the reproducibility gate even though the
# installed package set is identical. Removing them keeps both properties:
# patched packages and a reproducible image.
RUN apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* \
 && rm -rf /var/log/apt /var/log/dpkg.log /var/log/alternatives.log \
 && rm -f /var/lib/dpkg/status-old /var/lib/dpkg/available-old \
 && rm -rf /var/backups/* \
 && find /var/log -type f -name '*.log' -delete


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
