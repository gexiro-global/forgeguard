# Dependency pinning

Every package this project installs from an index is pinned to an exact version
and to a set of SHA-256 hashes. `pip` is always invoked with `--require-hashes`,
so an artifact whose bytes do not match a recorded hash is refused before it is
unpacked.

## Layers

| Input | Lock | Used by |
| --- | --- | --- |
| `requirements/runtime.in` | `requirements/runtime.txt` | the built wheel's own dependencies, installed into the clean smoke environment |
| `requirements/dev.in` | `requirements/dev.txt` | the CI test job (includes the runtime layer) |
| `requirements/build.in` | `requirements/build.txt` | the CI build job and the ForgeGuard bridge build |
| `requirements/fuzz.in` | `requirements/fuzz.txt` | fuzzing and property-based testing (includes the runtime layer) |

`dev.in` and `fuzz.in` start with `-r runtime.in` so that a single hash-locked
file installs everything those jobs need, and so the runtime layer can never be
resolved to two different versions in two different jobs.

## The project itself is never resolved from an index

CI installs the dependency layer first and then adds the project with
`--no-deps`:

```bash
python -m pip install --require-hashes -r requirements/dev.txt
python -m pip install --no-deps -e .
```

`pip check` afterwards proves the locked versions still satisfy the ranges
declared in `pyproject.toml`. The same pattern installs the built wheel in the
smoke environment, so `dist/*.whl` is the only unhashed input and it is a local
artifact this workflow just built, not an index download.

## Regenerating a lock

Resolve on **Python 3.11**, the lowest version the project supports. A lock
resolved on 3.12 is not valid on 3.11: `jaraco-context` pulls in
`backports.tarfile` only below 3.12, and `--require-hashes` then rejects the
install because that package has no recorded hash.

```bash
python3.11 -m venv /tmp/lockenv
/tmp/lockenv/bin/pip install 'pip<25.1' 'pip-tools==7.5.1'

/tmp/lockenv/bin/pip-compile --generate-hashes --allow-unsafe --strip-extras \
  --output-file requirements/dev.txt requirements/dev.in
```

`pip-tools` 7.5.1 needs `pip < 25.1`; newer pip removed
`pip._internal.utils.compat.stdlib_pkgs`, which `piptools.sync` imports.

After regenerating, verify the lock on **both** supported interpreters:

```bash
for py in python3.11 python3.12; do
  rm -rf /tmp/check && $py -m venv /tmp/check
  /tmp/check/bin/pip install --require-hashes -r requirements/dev.txt
done
```

When a version in `requirements/dev.in` changes, change the matching pin in the
`dev` extra of `pyproject.toml` too. `tests/test_dependency_pinning.py` fails if
the two disagree.

## What the drift guard enforces

`tests/test_dependency_pinning.py` runs in the normal suite, offline, and fails
if any of the following stops being true:

- every layer has both an input and a lock;
- every requirement in every lock carries at least one `--hash=sha256:`;
- every pin declared in a `.in` appears at the same version in its `.txt`;
- the runtime layer resolves to identical versions inside `dev.txt` and `fuzz.txt`;
- the `dev` extra in `pyproject.toml` matches `requirements/dev.in`;
- no workflow contains a `pip install` without `--require-hashes` (index fetch)
  or `--no-deps` (local artifact).

Each of those was confirmed by deliberately breaking it and observing the
matching test fail.

## Scope

Hash pinning covers packages installed from an index. GitHub Actions are pinned
separately, by full commit SHA, in the workflow files themselves.
