# VersionSec

> **VersionSec was formerly ForgeGuard.** Releases up to and including 0.6.0 were published
> as `forgeguard` and remain available and unchanged. From 0.7.0 the canonical name is
> VersionSec (`pip install versionsec`). `forgeguard==0.7.2` is a compatibility bridge and
> the `forgeguard` CLI/import keep working. Stable `FG-*` finding IDs are unchanged.
> See [MIGRATION.md](https://github.com/gexiro-global/versionsec/blob/main/MIGRATION.md).

[![CI](https://github.com/gexiro-global/versionsec/actions/workflows/ci.yml/badge.svg)](https://github.com/gexiro-global/versionsec/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/versionsec.svg)](https://pypi.org/project/versionsec/)
[![Python](https://img.shields.io/pypi/pyversions/versionsec.svg)](https://pypi.org/project/versionsec/)
[![License: Apache-2.0](https://img.shields.io/pypi/l/versionsec.svg)](https://github.com/gexiro-global/versionsec/blob/main/LICENSE)

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/gexiro-global/versionsec/badge)](https://scorecard.dev/viewer/?uri=github.com/gexiro-global/versionsec)
[Security and trust evidence](https://github.com/gexiro-global/versionsec/blob/main/docs/SECURITY-TRUST.md) documents the project's policies and automated checks. No certification or badge level is claimed.

Read-only posture assessment for one explicitly authorized self-hosted Gitea or Forgejo instance, or an explicitly supplied anonymized configuration snapshot.

## Current release — 0.7.2

A metadata and documentation patch. Documentation links embedded in the published package description are now absolute canonical URLs, so they resolve from PyPI as well as from GitHub. 0.7.1 fixed the `--version` flag. Neither release changed scanning, configuration review, runner review, scoring, schemas, finding IDs or the compatibility surface. See [CHANGELOG.md](https://github.com/gexiro-global/versionsec/blob/main/CHANGELOG.md).

## VersionSec — 0.7.0

The ForgeGuard → VersionSec rebrand. No capability was removed: the separate Gitea or Forgejo providers, read-only live posture assessment, offline configuration review, offline runner review, Markdown/JSON/SARIF exports and deterministic completeness semantics all carry over unchanged. Canonical CLI is `versionsec`, canonical import is `versionsec`; the `forgeguard` CLI and `import forgeguard` continue to work through a compatibility shim that resolves to the same implementation. Machine-readable schema identifiers (`forgeguard.assessment.v1`, `forgeguard.config-snapshot.v1`, `forgeguard.runner-snapshot.v1`) and all `FG-*` finding IDs are deliberately unchanged so existing report consumers keep working. See [MIGRATION.md](https://github.com/gexiro-global/versionsec/blob/main/MIGRATION.md).

## Control Plane Hardening — 0.6.0

Adds an offline runner posture review (`versionsec runner review`) for the trust boundaries that matter most to a Gitea or Forgejo administrator: execution engine isolation, privileged mode, host volume mounts, Docker socket exposure, job network mode, ephemeral registration, and the experimental Forgejo plugin engine. Runner review is zero-network, evaluates only an explicitly supplied `forgeguard.runner-snapshot.v1` snapshot, and never reads runner credentials, `.runner` files, or Docker/registry secrets. Runner qualification targets are Gitea Runner 3.4.2 and Forgejo Runner 13.0.0 / 13.1.0 — see [upstream evidence](https://github.com/gexiro-global/versionsec/blob/main/docs/UPSTREAM.md) and [runner review](https://github.com/gexiro-global/versionsec/blob/main/docs/RUNNER_REVIEW.md).

## Multi-Forge Support — 0.5.0

Adds Gitea or Forgejo as separate providers, with operator-declared product identity, finite provider-specific advisory catalogs, exposure intent, request profiles, offline configuration review of an explicitly supplied snapshot, and JSON/Markdown/SARIF exports. It does not scan application source code or private artifact contents.

Qualification targets are Gitea 1.26.4 / 1.27.3 and Forgejo 15.0.8 / 16.0.4 — these are the exact tested targets, not a universal support promise; see [release notes](https://github.com/gexiro-global/versionsec/blob/main/docs/RELEASE_CANDIDATE_0_5.md) and the CI evidence linked from the release.

## Install

```bash
python -m pip install versionsec
```

Or pin the exact release:

```bash
python -m pip install versionsec==0.7.2
```

## Usage

```bash
versionsec providers
versionsec checks
versionsec scan --url https://git.example.com/team --authorized --product forgejo --profile standard --policy public --dry-run
versionsec scan --url https://git.example.com/team --authorized --product forgejo --profile standard --policy public --format json
versionsec config review --snapshot anonymized-snapshot.json --policy private --format json
versionsec runner review --snapshot runner-snapshot.json --format json
```

Use minimal for one version request, standard for five bounded existing requests, or extended for those requests plus root. The profiles change scope, not aggressiveness. Exposure intent (public/private/unspecified) is independent; unspecified is the default.

The operator declares product identity. Compatible APIs and inventory versions alone do not identify a product. Opposing markers, conflicting versions, unknown syntax and unsupported evidence remain explicitly incomplete. No Gitea advisory is applied to Forgejo.

## Evidence boundaries

HTTP 200 on a checked path is only a status observation, not proof of repository readability, private data access or loaded configuration. Public-by-design status observations are informational. Private intent creates a bounded review warning. HTTP 401/403 may support denial on that path only. Errors, redirects, 404, 429, malformed version JSON, timeouts and truncation remain incomplete.

Incomplete assessments have null score, N/A grade and assessed=false, even when another check warns. Skipped checks remain listed. Scoring version 2 is not comparable with 0.2.2 scores. No score is security certification or a claim of no vulnerabilities.

Offline review performs zero requests and evaluates only the supplied snapshot. It supports a closed key list for registration, sign-in, new-repository privacy and product-specific MFA. It never reads app.ini, production files, tokens, databases or private keys. See [config review](https://github.com/gexiro-global/versionsec/blob/main/docs/CONFIG_REVIEW.md).

## Transport and reports

One target, GET only, finite allowlist, no retries or redirects, serial requests, at most 12 requests, 10 seconds each and 60 seconds overall. Responses are streamed with a 256 KiB decompressed limit. HTTPS verifies certificates; --ca-bundle explicitly supplies a private CA. Ambient proxy/CA settings are ignored. HTTP never transmits a token. Anonymous requests do not inherit authentication or cookies.

Prefer VERSIONSEC_TOKEN for the optional version-read token. The legacy --token option warns because shell history/process listings may retain it. Reports do not contain the token.

Use --format md,json,sarif with --out reports/result.md for separate files. The directory must exist. Existing files, symlinks and collisions are refused, and writes are atomic. Multiple formats require files; single machine-readable stdout is clean.

JSON uses forgeguard.assessment.v1 with a packaged schema. SARIF 2.1.0 is schema-validated against frozen OASIS errata01. No source locations are invented. No DevGuard or GitHub Code Scanning importer integration is claimed.

## Documentation

- [Migration and exit codes](https://github.com/gexiro-global/versionsec/blob/main/docs/MIGRATION_0_5.md)
- [Security model](https://github.com/gexiro-global/versionsec/blob/main/docs/SECURITY_MODEL.md) and [authorized use](https://github.com/gexiro-global/versionsec/blob/main/AUTHORIZED_USE.md)
- [Scoring](https://github.com/gexiro-global/versionsec/blob/main/docs/SCORING.md), [checks](https://github.com/gexiro-global/versionsec/blob/main/docs/CHECKS.md), [upstream evidence](https://github.com/gexiro-global/versionsec/blob/main/docs/UPSTREAM.md)
- [Provider guide](https://github.com/gexiro-global/versionsec/blob/main/docs/PROVIDERS.md), [runner review](https://github.com/gexiro-global/versionsec/blob/main/docs/RUNNER_REVIEW.md) and [integration lab](https://github.com/gexiro-global/versionsec/blob/main/docs/INTEGRATION_TESTING.md)
- [Candidate notes](https://github.com/gexiro-global/versionsec/blob/main/docs/RELEASE_CANDIDATE_0_5.md) and [release checklist](https://github.com/gexiro-global/versionsec/blob/main/docs/RELEASE_CHECKLIST.md)

Historical 0.2.2 before/after examples remain in examples/ for migration context. Current examples use the golden- prefix and are synthetic offline fixtures, not production scans.

## Commercial hardening

Gexiro offers a paid Hardening Report for authorized Gitea operators who want human review of bounded evidence, explicit limitations, prioritized findings, and a practical remediation plan.

A Remediation Sprint is a separate engagement: scope and acceptance criteria are frozen first, changes begin only after explicit approval, and the result includes before/after verification. Scope expansion, third-party targets, and remote changes require separate written authorization.

VersionSec remains usable as a free OSS CLI without a hosted account or control plane. Heavy SaaS and recurring monitoring are not offered at this stage.

[Request a scoped VersionSec Hardening Report](mailto:contact@gexiro.com?subject=VersionSec%20Hardening%20Report)

## License

Apache-2.0. See [LICENSE](https://github.com/gexiro-global/versionsec/blob/main/LICENSE).

Built and maintained by [Gexiro Global Enterprises Ltd](https://gexiro.com).

Part of the [Gexiro open-source toolkit](https://github.com/gexiro-global).

VersionSec by Gexiro

Not affiliated with Gitea, Forgejo, Codeberg, GitHub, or GitLab.
