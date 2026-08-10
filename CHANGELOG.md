# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project adheres to semantic versioning.

## [Unreleased]

- Pin CI actions, restrict CI permissions, and ship explicit typing/license metadata.
- Bound every runtime, build, and development dependency to a tested next-major ceiling and
  add complete license, audience, Python, security-topic, and typed-package classifiers.

## [0.2.0] - 2026-06-12

### Added

- Initial public-prep package for ForgeGuard by Gexiro.
- Read-only checks for forge version and patch currency.
- CVE-2026-27771 posture inference for vulnerable, mitigated, exposed, and patched states.
- Anonymous registry, sign-in, and anonymous surface posture checks.
- Deterministic scoring with severity weights and `WARN_FACTOR = 0.35`.
- Synthetic before/after example reports.
