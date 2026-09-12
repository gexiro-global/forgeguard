# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project adheres to semantic versioning.

## [0.7.2] - 2026-09-12

A metadata and documentation patch. No scanning, configuration-review,
runner-review, scoring, schema, finding-ID or compatibility behaviour changed.
0.7.1 remains functionally valid; 0.7.2 is the preferred current release because
its distribution metadata and public documentation are fully corrected.

### Fixed

- Documentation links in the PyPI long description. The README is published as the
  long description, and PyPI renders it on its own domain, so a relative link such
  as `[MIGRATION.md](MIGRATION.md)` resolved to
  `https://pypi.org/project/versionsec/MIGRATION.md` and returned 404. Fifteen
  links were affected, including `MIGRATION.md`, `LICENSE`, `AUTHORIZED_USE.md`
  and every document under `docs/`. They are now absolute canonical GitHub URLs,
  which render correctly on both surfaces. The 0.7.1 distribution metadata is
  immutable and keeps the relative links; that is why this release exists.
- `docs/INTEGRATION_TESTING.md` named a wheel filename from before the rebrand, so
  the documented command asked the lab for a file no build produces.

### Added

- `tests/test_long_description_links.py`: the README is checked for relative links,
  for repository documents linked through anything other than the canonical blob
  URL, and for links that point at paths which no longer exist. The check is
  structural and needs no network access, so this class of defect cannot return
  unnoticed.

### Changed

- `forgeguard` compatibility bridge moves to 0.7.2 and pins `versionsec==0.7.2`.
  It remains metadata-only: no code of its own, and the `forgeguard` command and
  `import forgeguard` continue to resolve to the same implementation.
- Release checklist records that the repository social preview carries the version
  number and can only be refreshed through the GitHub web UI, since no API exposes
  it.

## [0.7.1] - 2026-09-11

### Fixed

- `versionsec --version` and `forgeguard --version` exited with code 2 and
  `Error: No such option: --version` in 0.7.0. Both now exit 0 and print a deterministic
  version line. **0.7.0 is superseded**; only the version flag was affected, scanning,
  configuration review and runner review behaved correctly in 0.7.0.

### Added

- `--version` on the canonical and the compatibility entrypoint. Canonical output is
  `VersionSec <version>`; the legacy entrypoint appends `(forgeguard compatibility CLI)` so
  it identifies itself without presenting ForgeGuard as the current brand.
- `tests/test_release_contract.py`: the documented release-contract commands are now executed
  as real subprocesses against installed console scripts, in the source environment and in
  clean virtual environments built from the wheel and from the sdist. The 0.7.0 defect existed
  because the suite asserted `__version__` and used in-process runners, which cannot observe a
  missing CLI option.

## [0.7.0] - 2026-09-11

**ForgeGuard is now VersionSec.** Releases up to and including 0.6.0 were published as
`forgeguard` and are unchanged; the entries below them in this file are historical and
deliberately still say ForgeGuard.

- Rename the product to VersionSec: canonical distribution `versionsec`, canonical import
  `versionsec`, canonical CLI `versionsec`, canonical site <https://versionsec.com>,
  canonical repository `gexiro-global/versionsec`.
- Keep every existing capability: Gitea and Forgejo providers, read-only bounded live
  assessment, offline configuration review, offline runner review with the eight
  `FG-RUNNER-*` checks, Markdown/JSON/SARIF exports, deterministic completeness semantics
  and the existing qualification targets.
- Compatibility, all covered by `tests/test_migration_0_7.py`: `import forgeguard` and
  `import forgeguard.cli` resolve to the same module objects as `versionsec.*`; the
  `forgeguard` console script remains installed and runs the canonical CLI; the legacy
  import path is silent so automation does not break; `forgeguard==0.7.0` is published as a
  thin bridge depending on `versionsec==0.7.0` with no duplicated implementation.
- Environment variables: canonical `VERSIONSEC_TOKEN`, legacy `FORGEGUARD_TOKEN` still
  accepted, canonical wins deterministically when both are set.
- Deliberately unchanged for consumer compatibility: all `FG-*` finding identifiers and the
  machine-readable schema identifiers `forgeguard.assessment.v1`,
  `forgeguard.config-snapshot.v1`, `forgeguard.runner-snapshot.v1`,
  `forgeguard.scan-result.v0.3`. Human-facing branding (report title, Markdown header and
  footer, SARIF driver name, User-Agent) now reads VersionSec.
- Add `MIGRATION.md`.

## [0.6.0] - 2026-09-11

Control Plane Hardening.

- Add `forgeguard runner review`: an offline, zero-network assessment of one
  operator-declared Gitea or Forgejo Actions runner's security posture, validated
  against a new closed schema `forgeguard.runner-snapshot.v1`
  (`forgeguard/schemas/runner-snapshot-v1.json`). It never reads runner credentials,
  `.runner` files, Docker/registry secrets, or repository secrets, and refuses any
  field outside the closed schema without echoing the rejected input.
- Add eight provider-aware checks: `FG-RUNNER-VERSION`, `FG-RUNNER-EXECUTION`,
  `FG-RUNNER-PRIVILEGED`, `FG-RUNNER-VOLUMES`, `FG-RUNNER-DOCKER`, `FG-RUNNER-NETWORK`,
  `FG-RUNNER-EPHEMERAL`, `FG-RUNNER-PLUGIN`. Severity depends on the declared
  `workload_trust` (trusted-only vs mixed-untrusted), never on runner version alone.
  When `execution_engine=host`, the four container-specific checks correctly report
  `not_applicable` instead of re-penalizing one root cause five times.
- Runner qualification targets: Gitea Runner 3.4.2 and Forgejo Runner 13.0.0 / 13.1.0,
  each independently verified via the exact, checksum-verified official release binary's
  own `--version` and `generate-config` output — see [docs/UPSTREAM.md](docs/UPSTREAM.md).
- `forgeguard.config-snapshot.v1` is unchanged; 0.5.0 config-review snapshots remain valid.
- Add `docs/RUNNER_REVIEW.md`; update README, CHECKS.md, PROVIDERS.md, UPSTREAM.md.

## [0.5.0] - 2026-09-11

- Complete the R01 qualification contract: the manifest must carry all of G01-G15 (each PASS) and a closed set of hash-bound evidence categories; the preflight compares the exact source ref and run attempt, requires the manifest hash, enforces an exact two-file set, and shares a no-network publisher-stub handoff (`promote_handoff`) used by both the workflow and tests.
- Extract an importable R05 config-qualification contract (`tools/config_contract.py`) that asserts finding statuses against an independent oracle, completeness/assessed, request_count, and the exit code of every export format; the lab and tests share it.
- Enforce and verify lab cleanup: `tools/lab_cleanup.py` removes run-owned resources and confirms absence (distinguishing an unreachable daemon), `tools/tls_lab.py` writes `cleanup/tls-cleanup.json` and fails on any lingering resource.
- README/version updated to the candidate; regenerate goldens (version-only diff).

## [0.5.0rc3] - Unreleased

- Release promotion no longer rebuilds: `release.yml` downloads the exact frozen artifacts of a referenced completed+successful trusted push run, and the preflight binds them to a qualification manifest (run/attempt/ref/SHA/version/digests) before any upload (R01-C).
- Separate `prepared` from `publish_allowed`: a correct `publish=false` dispatch is a successful prepare-only (exit 0, no upload); only real validation failures refuse (R01-A).
- The preflight actually runs `gh attestation verify` on the exact wheel and sdist and enforces repo/signer-workflow/source-digest/subject; the manual `attestation_verified` boolean is removed as a sufficient condition (R01-B).
- Restore two independent lab findings invariants: public variants reject any unexpected warn/fail (only Gitea 1.26.4 `FG-CVE-78433=fail` excepted), and all four Gitea 1.26.4 variants require that finding while private stays incomplete with exit 4 (R02-A/B).
- Add a real per-container configuration read-back to the lab: read the closed key list from each container's written `app.ini`, compare to the declared fixture, snapshot the measured data, and run `config review` on the installed wheel with per-finding assertions (R05).
- Add a set-based dependency inventory/audit reconciliation helper and test (missing/unexpected/version-mismatch), so audit completeness is verified by set rather than count (E-FINAL).
- Bump candidate to 0.5.0rc3.

## [0.5.0rc2] - Unreleased

- Separate release preparation from PyPI publication: `release.yml` now prepares and qualifies candidates on every trigger but uploads only on an explicit manual `workflow_dispatch` with `publish=true`, an approved data-validated preflight, and independently verified attestations; `id-token: write` is scoped to the publish job and the `release` trigger can no longer reach publishing (R01).
- Assert real CLI exit codes against a pre-declared oracle in the integration lab and add a Docker-free unit test of the qualification helper (R02).
- Add real-engine golden regression across both providers, including material-change and snapshot-provenance guards (R03).
- Add numeric `assess_score` oracle tests with permutation invariance and incomplete-dominates-confirmed behaviour (R04).
- Bind each advisory catalog record to exact frozen single-record source bytes via a structured provenance manifest, correcting the prior collection-listing hash ambiguity, and verify it offline (R06).
- Derive packaging version expectations from the trusted manifest instead of hardcoding; bump candidate to 0.5.0rc2.

## [0.5.0rc1] - Unreleased

- Add separate Gitea and Forgejo providers with explicit identity/version provenance.
- Add closed offline configuration snapshots, including provider-specific MFA settings.
- Add minimal/standard/extended scopes, dry-run and public/private/unspecified policy.
- Add finite, hashed advisory catalogs and explicit unknown future/backport handling.
- Add assessment JSON Schema and offline SARIF 2.1.0 export/validation.
- Enforce response streaming limits, deadlines, cookie separation and no token over HTTP.
- Use scoring algorithm 2 with grouped penalties and partial-evidence completeness; scores are not comparable with 0.2.2.
- Add atomic no-clobber output and documented exit codes 0/2/3/4/5.

## [Unreleased maintenance before 0.5]

- Link the official ForgeGuard product page and authorized commercial-intake path.
- Link private vulnerability reporting directly from the security policy.
- Add complete project metadata links for documentation, issues, and the changelog.
- Refresh the pinned GitHub Actions and build-backend maintenance dependencies.
- Enable GitHub private vulnerability reporting and CodeQL default setup, and strengthen `main` branch protection without imposing a single-maintainer review deadlock.

## [0.2.2] - 2026-08-20

- Narrow the implemented product scope to self-hosted Gitea and require explicit trusted `--product gitea` confirmation before Gitea-specific advisory conclusions.
- Fail safe when a Forgejo marker conflicts with a Gitea declaration.
- Correct CVE-2026-27771 to an affected/fixed/unknown Gitea version-advisory check, independent of registry and sign-in responses, using authoritative `CWE-862`.
- Make `FG-VER` informational and score the affected-version root fact only once through `FG-CVE-27771`.
- Add explicit assessment completeness: indeterminate core evidence emits `value: null`, `grade: "N/A"`, and `assessed: false`.
- Classify only explicit HTTP 401/403 access-control responses as PASS; 404, redirects, 429, 5xx, unclassified statuses and network failures remain INFO/UNDETERMINED.
- Align distribution, runtime, JSON, and User-Agent versions through installed package metadata.
- Reject credential-bearing, query-bearing, fragment-bearing, dot-segment, non-HTTP(S), and hostless target URLs.
- Prefer `FORGEGUARD_TOKEN`, warn on legacy `--token`, and retain token non-disclosure regression tests.
- Expand CI with Ruff, format, dependency, build, Twine, exact-wheel install, and built-wheel CLI gates.
- Restore the Apache-2.0 SPDX license expression and mechanically regenerate synthetic examples under schema `forgeguard.scan-result.v0.3`.
- Give `FG-SIGNIN` and `FG-ANON` disjoint browser/API evidence ownership so no request or score penalty is duplicated.
- Treat only an explicit non-empty remote version string as anonymous disclosure evidence.
- Harden Markdown rendering, dual-output collision refusal, and bounded iterative URL decoding against report and path ambiguity.
- Make the release workflow fail closed on the Python 3.11/3.12 quality matrix and the exact wheel that would be published.

## [0.2.1] - 2026-08-10

- Pin CI actions, restrict CI permissions, and ship explicit typing/license metadata.
- Bound every runtime, build, and development dependency to a tested next-major ceiling and
  add complete license, audience, Python, security-topic, and typed-package classifiers.

## [0.2.0] - 2026-06-12

### Added

- Initial public-prep package for ForgeGuard by Gexiro.
- Read-only checks for forge version and patch currency.
- Initial CVE-2026-27771 posture inference; its overbroad semantics are corrected and
  superseded by 0.2.2.
- Anonymous registry, sign-in, and anonymous surface posture checks.
- Deterministic scoring with severity weights and `WARN_FACTOR = 0.35`.
- Synthetic before/after example reports.
