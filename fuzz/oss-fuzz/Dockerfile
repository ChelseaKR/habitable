# SPDX-License-Identifier: Apache-2.0
# Reviewable source for OSS-Fuzz's `projects/habitable/Dockerfile` (issue #256).
# Kept in-repo next to the harnesses so a change to either is reviewed against
# the other; OSS-Fuzz builds from its own copy of this file.
FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:21f6fab17ace4dc76e1c56de91ee95d3d03da021df94b41056ba036f6c6f55e9

# The verification subset only (`canonical`, `crypto`, `errors`, `evidence`,
# `timeline`, `tsa`, `verify`). It is already kept dependency-light and
# byte-compilable on older interpreters for the `verifier-portability` CI job,
# which is exactly what makes it buildable here without dragging the vault, sync
# and relay layers -- and their AGPL-only dependencies -- into the image.
RUN git clone --depth 1 https://github.com/ChelseaKR/habitable habitable
COPY build.sh $SRC/
WORKDIR $SRC/habitable
