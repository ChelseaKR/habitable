#!/bin/bash -eu
# SPDX-License-Identifier: Apache-2.0
# Reviewable source for OSS-Fuzz's `projects/habitable/build.sh` (issue #256).
# OSS-Fuzz builds from its own copy; this is the one that gets reviewed, and
# `tests/test_verify_fuzz.py` pins that it still names every harness in fuzz/.

# Runtime dependencies of the verification subset, installed directly rather
# than through `pip install .`. The project declares `requires-python = ">=3.14"`
# for the full application, which the OSS-Fuzz Python base image does not ship;
# the *subset* has a floor of 3.12 (canonical.py uses PEP 695 `type` statements)
# and is pinned to that floor by the `verifier-portability` job in CI. Installing
# the two runtime deps and putting src/ on the path is therefore not a shortcut
# around the version declaration -- it is the subset's real, tested contract.
python3 -m pip install --upgrade "cryptography>=44" "asn1crypto>=1.5"

export PYTHONPATH="$SRC/habitable/src:${PYTHONPATH:-}"

for harness in "$SRC"/habitable/fuzz/fuzz_*.py; do
  name=$(basename "$harness" .py)

  # `compile_python_fuzzer` is `pyinstaller --onefile`, which bundles imported
  # modules and NOT data files, and forwards any extra arguments straight to
  # PyInstaller. Both harnesses seed from the committed golden fixtures --
  # fuzz_verify_packet copies a whole packet at import time, before
  # `atheris.Setup` -- so without this the compiled target dies of
  # FileNotFoundError on startup and fuzzes nothing at all, in an image where
  # nobody is watching a console. It is invisible locally because the clone is
  # right there. `--add-data` puts the tree inside the binary; `golden_root()`
  # in each harness reads it back out of `sys._MEIPASS`, and falls back to the
  # checkout so the same file still runs from a working copy.
  compile_python_fuzzer "$harness" \
    --add-data "$SRC/habitable/tests/golden:habitable-golden"

  # Each harness ships its own seed corpus as code, so the seeds are reviewed
  # in the same diff as the harness and cannot drift from it. Materialise them
  # here into the zip libFuzzer picks up.
  seed_dir="$WORK/$name-seeds"
  rm -rf "$seed_dir"
  mkdir -p "$seed_dir"
  python3 - "$harness" "$seed_dir" <<'PY'
import hashlib
import importlib.util
import sys
from pathlib import Path

harness_path, seed_dir = Path(sys.argv[1]), Path(sys.argv[2])
spec = importlib.util.spec_from_file_location(harness_path.stem, harness_path)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
for payload in module.seed_corpus():
    (seed_dir / hashlib.sha256(payload).hexdigest()).write_bytes(payload)
PY
  (cd "$seed_dir" && zip -q -r "$OUT/${name}_seed_corpus.zip" .)
done
