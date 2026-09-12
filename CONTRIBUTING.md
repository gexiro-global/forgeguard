# Contributing

## Development setup

Install the same hash-locked dependency set CI uses, then the project itself
without re-resolving anything:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r requirements/dev.txt
python -m pip install --no-deps -e .
```

`pip install -e ".[dev]"` still works for a quick local environment, but it
resolves dependencies fresh and so does not reproduce what CI installs. Prefer
the locked form when reproducing a CI failure.

Python 3.11 and 3.12 are both supported and both are tested.

## What CI will run against your change

Run all of it locally first. `ruff` is the most common surprise, because a
formatting difference fails the build exactly like a broken test:

```bash
ruff check .
ruff format --check .
python -m compileall versionsec
python -m pytest -q --cov=versionsec --cov-fail-under=91.28
python -m pip check
```

On top of that, every pull request also runs CodeQL (Python and Actions),
GitHub Dependency Review, and ClusterFuzzLite against the code the pull request
changed. See [docs/FUZZING.md](docs/FUZZING.md).

## Tests are part of the change, not a follow-up

A behaviour change without a test that would have failed before it is not
ready. Put the test in the same pull request.

- Deterministic logic and explicit evidence fields over clever inference.
- Cover scoring, CLI behaviour and endpoint allowlists directly.
- Keep examples and fixtures synthetic. Never commit a real host, token or
  credential, not even redacted.
- If the change affects snapshot parsing or report serialisation, consider
  whether it belongs as an invariant in `tests/test_property_snapshots.py`
  rather than as one more example.

## Changing a dependency

Dependencies are version-pinned and hash-pinned. Editing a `requirements/*.txt`
by hand will fail CI. Follow
[docs/DEPENDENCY_PINNING.md](docs/DEPENDENCY_PINNING.md): edit the `.in`,
regenerate on Python 3.11, verify the lock installs on 3.11 **and** 3.12, and
keep the `dev` extra in `pyproject.toml` in step with `requirements/dev.in`.

## Scope boundaries

VersionSec is a defensive tool that reviews one explicitly authorized instance,
read-only. Out of scope for v0.x, and rejected on sight:

- exploit payloads or proof-of-exploitation behaviour;
- discovery of third-party or unspecified hosts;
- retrieval of protected artifacts;
- any write path, state-changing probe or destructive action;
- a PASS conclusion that the supplied evidence does not actually support.

That last one matters as much as the others. A check that reports PASS from
evidence it did not verify is a defect, not a feature.

## How your change gets accepted

See [docs/REVIEW.md](docs/REVIEW.md) for what review means here, what a change
is judged against, and an honest statement of the project's current review
limits.
