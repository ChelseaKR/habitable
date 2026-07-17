# SPDX-License-Identifier: AGPL-3.0-or-later
# A tiny, dependency-free image for the optional ciphertext-only sync relay.
# The relay uses only the Python standard library, so there is nothing to pip
# install — which keeps the image small and the attack surface minimal, fitting
# for a component that should never be able to read anything.
#
# Build from the repository root:
#   docker build -f relay/Dockerfile -t habitable-relay .
# Pinned by digest for reproducible, tamper-evident builds (Dependabot bumps it).
FROM python:3.14-slim@sha256:d3400aa122fa42cf0af0dbe8ec3091b047eac5c8f7e3539f7135e86d855dc015

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
