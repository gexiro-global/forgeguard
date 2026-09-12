## Summary

What changes, and why it is needed.

## Verification

Run these locally before opening the pull request; CI runs the same commands.

- [ ] `ruff check .` and `ruff format --check .`
- [ ] `python -m compileall versionsec`
- [ ] `python -m pytest -q --cov=versionsec --cov-fail-under=91.28`
- [ ] `python -m pip check`

## Tests

- [ ] This change adds or updates a test that would have failed before it.
- [ ] Or: this change cannot affect behaviour (docs, comments, metadata only).

## Evidence honesty

- [ ] Every conclusion this change produces follows from evidence the tool
      actually collected; nothing claims more certainty than its source supports.
- [ ] Any new or changed finding text states its limits, and reports
      `INDETERMINATE` rather than guessing.

## Scope and safety

- [ ] This concerns my own or an explicitly authorized instance.
- [ ] VersionSec stays read-only: no write path, no state-changing probe.
- [ ] No third-party discovery and no protected artifact retrieval.
- [ ] No real host, token, credential or customer data in code, tests, fixtures
      or this description.

## Dependencies

- [ ] No dependency changed.
- [ ] Or: the `.in` was edited, the lock regenerated on Python 3.11 and verified
      to install on 3.11 and 3.12, and `pyproject.toml`'s `dev` extra kept in
      step. See `docs/DEPENDENCY_PINNING.md`.

## Release impact

- [ ] No effect on versioning, packaging, workflows or published artifacts.
- [ ] Or: `docs/RELEASE_CHECKLIST.md` was followed and the affected items are
      called out below.
