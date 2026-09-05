# SPDX-License-Identifier: Apache-2.0
# Reviewable source for OSS-Fuzz's `projects/habitable/Dockerfile` (issue #256).
# Kept in-repo next to the harnesses so a change to either is reviewed against
# the other; OSS-Fuzz builds from its own copy of this file.
FROM gcr.io/oss-fuzz-base/base-builder-python

# The verification subset only (`canonical`, `crypto`, `errors`, `evidence`,
# `timeline`, `tsa`, `verify`). It is already kept dependency-light and
# byte-compilable on older interpreters for the `verifier-portability` CI job,
# which is exactly what makes it buildable here without dragging the vault, sync
# and relay layers -- and their AGPL-only dependencies -- into the image.
RUN git clone --depth 1 https://github.com/ChelseaKR/habitable habitable
COPY build.sh $SRC/
WORKDIR $SRC/habitable
