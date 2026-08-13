# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project adheres to semantic versioning.

## [Unreleased]

- No unreleased changes.

## [0.2.2] - 2026-08-13

- Narrow the implemented product scope to self-hosted Gitea and fail safe for explicit Forgejo version strings.
- Correct CVE-2026-27771 to an affected/fixed/unknown Gitea version-advisory check, independent of registry and sign-in responses.
- Use precise observed-response wording for registry, sign-in, and anonymous checks.
- Align distribution, runtime, JSON, and User-Agent versions through installed package metadata.
- Reject credential-bearing, query-bearing, fragment-bearing, non-HTTP(S), and hostless target URLs.
- Prefer `FORGEGUARD_TOKEN`, warn on legacy `--token`, and add token non-disclosure regression tests.
- Restore the Apache-2.0 SPDX license expression and update synthetic examples and public documentation.

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
