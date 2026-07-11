#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Chelsea Kelly-Reif
#
# Build the relay twice from the same tracked source and compare the complete
# Docker image archives byte for byte. This proves reproducibility for this pinned base,
# platform, Dockerfile, and BuildKit invocation; it does not claim that unrelated
# builder versions or CPU architectures emit the same bytes.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

for command in docker git tar cmp; do
  command -v "$command" >/dev/null || {
    echo "error: required executable not found: $command" >&2
    exit 2
  }
done
docker buildx version >/dev/null

epoch="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}"
if [[ ! "$epoch" =~ ^[0-9]+$ ]]; then
  echo "error: SOURCE_DATE_EPOCH must be an integer Unix timestamp" >&2
  exit 2
fi

tmp="$(mktemp -d "${TMPDIR:-/tmp}/habitable-relay-repro.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/context"
git archive --format=tar HEAD -- relay/Dockerfile src | tar -xf - -C "$tmp/context"

build() {
  local destination="$1"
  docker buildx build \
    --no-cache \
    --provenance=false \
    --build-arg "SOURCE_DATE_EPOCH=$epoch" \
    --file "$tmp/context/relay/Dockerfile" \
    --platform linux/amd64 \
    --output "type=docker,dest=$destination,rewrite-timestamp=true" \
    "$tmp/context"
}

echo "habitable: verifying reproducible relay image (SOURCE_DATE_EPOCH=$epoch)"
echo "  building Docker image archive #1..."
build "$tmp/relay-1.tar"
echo "  building Docker image archive #2..."
build "$tmp/relay-2.tar"

if ! cmp -s "$tmp/relay-1.tar" "$tmp/relay-2.tar"; then
  echo "FAIL: relay Docker image archives differ byte for byte" >&2
  exit 1
fi

echo "habitable: relay Docker image archive is byte-identical across clean rebuilds"
