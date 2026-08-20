# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project adheres to semantic versioning.

## [Unreleased]

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
