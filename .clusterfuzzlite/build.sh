#!/bin/bash -eu
# Build the VersionSec fuzz harnesses.
#
# Runtime dependencies are installed from the same hash-locked file CI uses, so
# the fuzzing environment cannot silently resolve a different httpx or pydantic
# than the one under test. The project itself is installed with --no-deps
# because its dependencies are already pinned above.

pip3 install --require-hashes -r requirements/runtime.txt
# The project itself, from the checked-out source rather than an index. There
# is no artifact to hash here; --no-deps keeps the pinned layer above intact.
pip3 install --no-deps .

for harness in "$SRC"/versionsec/fuzz/fuzz_*.py; do
  name=$(basename "$harness" .py)
  compile_python_fuzzer "$harness"

  seed_dir="$SRC/versionsec/fuzz/corpus/$name"
  if [ -d "$seed_dir" ]; then
    zip -j "$OUT/${name}_seed_corpus.zip" "$seed_dir"/* >/dev/null
  fi
done
