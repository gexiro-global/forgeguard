# Fuzzing and property-based testing

VersionSec parses files it did not produce. An operator hands it a config or
runner snapshot as JSON, and the tool must either reject that input cleanly or
produce a report that serialises in three formats. Both halves are tested
adversarially, from two directions.

## Two complementary layers

| Layer | Tool | Where it runs | What it attacks |
| --- | --- | --- | --- |
| Coverage-guided fuzzing | Atheris + libFuzzer | ClusterFuzzLite, on pull requests and nightly | raw bytes into the parsers and exporters |
| Property-based testing | Hypothesis | the normal `pytest` suite, every push and PR | invariants over generated *valid* snapshots |

The fuzzers explore what happens at and below the validator boundary. The
property tests explore what must hold above it, for every snapshot that parses.
Neither replaces the other.

## The harnesses

`fuzz/fuzz_config_snapshot.py`, `fuzz/fuzz_runner_snapshot.py` and
`fuzz/fuzz_report_export.py`.

Rejecting malformed input is the documented contract, so `ValidationError`,
`ValueError` and `UnicodeDecodeError` are expected and swallowed. Anything else
escaping the harness is a finding. A snapshot that parsed must additionally
review and serialise without raising, and the export harness asserts the two
properties the formats promise: `render_json` output is ASCII-safe and
re-parsable, and the SARIF structure stays JSON-serialisable.

Seed corpora live in `fuzz/corpus/<harness>/`. They pair the real examples from
`examples/` with near-miss inputs (`{}`, schema-id only), so the mutator starts
both inside and just outside the accepted shape.

## Why ClusterFuzzLite and not a plain runner step

Atheris needs libFuzzer from clang and has no wheel for the CI platform. A plain
`pip install atheris` on `ubuntu-latest` fails with:

```
RuntimeError: Failed to find libFuzzer; set either $CLANG_BIN to point to your
Clang binary, or $LIBFUZZER_LIB to point directly to your libFuzzer .a file.
```

This was confirmed before choosing the approach. The ClusterFuzzLite base image
(`gcr.io/oss-fuzz-base/base-builder-python`) already ships clang, libFuzzer and
Atheris, so the harnesses are built there instead.

The build installs runtime dependencies from the same hash-locked
`requirements/runtime.txt` that CI uses, then the project with `--no-deps`. The
fuzzing environment therefore cannot silently resolve a different `httpx` or
`pydantic` than the one under test.

## Pinning

The ClusterFuzzLite base image is pinned by digest, not by the `latest` tag, so
the fuzzing toolchain cannot change under a build. To move to a newer base:

```bash
docker pull gcr.io/oss-fuzz-base/base-builder-python
docker inspect gcr.io/oss-fuzz-base/base-builder-python --format '{{index .RepoDigests 0}}'
```

Put the resulting digest in `.clusterfuzzlite/Dockerfile` and rebuild.
`tests/test_dependency_pinning.py` fails if any `FROM` loses its digest.

The `pip3 install --no-deps .` in `build.sh` is deliberately unhashed: it
installs the checked-out source, not an index artifact, exactly like the
`dist/*.whl` step in CI. OpenSSF Scorecard still reports it under
`Pinned-Dependencies`; that report is accurate about what it sees and wrong
about the risk, because there is no downloaded artifact to pin.

## Running locally

```bash
docker build -f .clusterfuzzlite/Dockerfile -t versionsec-cflite .

mkdir -p /tmp/cf_out /tmp/cf_work
docker run --rm -e FUZZING_LANGUAGE=python -e SANITIZER=address \
  -e OUT=/out -e WORK=/work \
  -v /tmp/cf_out:/out -v /tmp/cf_work:/work \
  versionsec-cflite bash -c 'bash $SRC/build.sh'

# then run one harness against its seed corpus
mkdir -p /tmp/corp && unzip -o /tmp/cf_out/fuzz_config_snapshot_seed_corpus.zip -d /tmp/corp
docker run --rm --network=none -v /tmp/cf_out:/out -v /tmp/corp:/corp \
  versionsec-cflite /out/fuzz_config_snapshot /corp -max_total_time=180
```

`--network=none` is deliberate: these harnesses exercise offline parsing only
and must never reach a network during execution.

The property tests need nothing special:

```bash
python -m pytest tests/test_property_snapshots.py
```

## Properties the Hypothesis tests hold

Generated over valid snapshots, 150 examples each, bounded so CI stays
predictable:

- every review serialises to JSON, SARIF and Markdown, and the JSON stays ASCII;
- an unspecified policy never yields a pass/warn verdict, only `INFO`;
- a finding that is not `ASSESSED` is never presented with a verdict;
- an operator-supplied snapshot never sets `product_confirmed`;
- review is deterministic for a fixed `now`;
- a runner review emits each `FG-RUNNER-*` check exactly once;
- `execution_engine: host` never produces a container verdict, because there is
  no container to judge;
- a snapshot outside the freshness window is never `ASSESSED`.

## Known limitations

- **Corpus is not persisted between runs.** ClusterFuzzLite can store a growing
  corpus in a separate storage repository; that is not configured, so each run
  starts from the committed seeds. Coverage per run is therefore bounded.
- **This does not raise the OpenSSF Scorecard `Fuzzing` check on its own merit
  as a Python fuzzer.** Scorecard detects language-level fuzz functions only for
  Go, Haskell, JavaScript/TypeScript and Erlang. It detects this integration
  because `.clusterfuzzlite/` is present, not because it evaluated the
  harnesses. The harnesses are here to find defects, not to move a score.
