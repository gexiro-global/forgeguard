# forgeguard

[![CI](https://github.com/gexiro-global/forgeguard/actions/workflows/ci.yml/badge.svg)](https://github.com/gexiro-global/forgeguard/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/forgeguard.svg)](https://pypi.org/project/forgeguard/)
[![Python](https://img.shields.io/pypi/pyversions/forgeguard.svg)](https://pypi.org/project/forgeguard/)
[![License: Apache-2.0](https://img.shields.io/pypi/l/forgeguard.svg)](https://github.com/gexiro-global/forgeguard/blob/main/LICENSE)

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/gexiro-global/forgeguard/badge)](https://scorecard.dev/viewer/?uri=github.com/gexiro-global/forgeguard)
[Security and trust evidence](docs/SECURITY-TRUST.md) documents the project's policies and automated checks. No certification or badge level is claimed.

Read-only posture assessment for one explicitly authorized self-hosted Gitea or Forgejo instance, or an explicitly supplied anonymized configuration snapshot.

## Control Plane Hardening — 0.6.0

Adds an offline runner posture review (`forgeguard runner review`) for the trust boundaries that matter most to a Gitea or Forgejo administrator: execution engine isolation, privileged mode, host volume mounts, Docker socket exposure, job network mode, ephemeral registration, and the experimental Forgejo plugin engine. Runner review is zero-network, evaluates only an explicitly supplied `forgeguard.runner-snapshot.v1` snapshot, and never reads runner credentials, `.runner` files, or Docker/registry secrets. Runner qualification targets are Gitea Runner 3.4.2 and Forgejo Runner 13.0.0 / 13.1.0 — see [upstream evidence](docs/UPSTREAM.md) and [runner review](docs/RUNNER_REVIEW.md).

## Multi-Forge Support — 0.5.0

Adds Gitea or Forgejo as separate providers, with operator-declared product identity, finite provider-specific advisory catalogs, exposure intent, request profiles, offline configuration review of an explicitly supplied snapshot, and JSON/Markdown/SARIF exports. It does not scan application source code or private artifact contents.

Qualification targets are Gitea 1.26.4 / 1.27.3 and Forgejo 15.0.8 / 16.0.4 — these are the exact tested targets, not a universal support promise; see [release notes](docs/RELEASE_CANDIDATE_0_5.md) and the CI evidence linked from the release.

## Install

```bash
python -m pip install forgeguard
```

Or pin the exact release:

```bash
python -m pip install forgeguard==0.6.0
```

## Usage

```bash
forgeguard providers
forgeguard checks
forgeguard scan --url https://git.example.com/team --authorized --product forgejo --profile standard --policy public --dry-run
forgeguard scan --url https://git.example.com/team --authorized --product forgejo --profile standard --policy public --format json
forgeguard config review --snapshot anonymized-snapshot.json --policy private --format json
forgeguard runner review --snapshot runner-snapshot.json --format json
```

Use minimal for one version request, standard for five bounded existing requests, or extended for those requests plus root. The profiles change scope, not aggressiveness. Exposure intent (public/private/unspecified) is independent; unspecified is the default.

The operator declares product identity. Compatible APIs and inventory versions alone do not identify a product. Opposing markers, conflicting versions, unknown syntax and unsupported evidence remain explicitly incomplete. No Gitea advisory is applied to Forgejo.

## Evidence boundaries

HTTP 200 on a checked path is only a status observation, not proof of repository readability, private data access or loaded configuration. Public-by-design status observations are informational. Private intent creates a bounded review warning. HTTP 401/403 may support denial on that path only. Errors, redirects, 404, 429, malformed version JSON, timeouts and truncation remain incomplete.

Incomplete assessments have null score, N/A grade and assessed=false, even when another check warns. Skipped checks remain listed. Version 2 scores are not comparable with 0.2.2. No score is security certification or a claim of no vulnerabilities.

Offline review performs zero requests and evaluates only the supplied snapshot. It supports a closed key list for registration, sign-in, new-repository privacy and product-specific MFA. It never reads app.ini, production files, tokens, databases or private keys. See [config review](docs/CONFIG_REVIEW.md).

## Transport and reports

One target, GET only, finite allowlist, no retries or redirects, serial requests, at most 12 requests, 10 seconds each and 60 seconds overall. Responses are streamed with a 256 KiB decompressed limit. HTTPS verifies certificates; --ca-bundle explicitly supplies a private CA. Ambient proxy/CA settings are ignored. HTTP never transmits a token. Anonymous requests do not inherit authentication or cookies.

Prefer FORGEGUARD_TOKEN for the optional version-read token. The legacy --token option warns because shell history/process listings may retain it. Reports do not contain the token.

Use --format md,json,sarif with --out reports/result.md for separate files. The directory must exist. Existing files, symlinks and collisions are refused, and writes are atomic. Multiple formats require files; single machine-readable stdout is clean.

JSON uses forgeguard.assessment.v1 with a packaged schema. SARIF 2.1.0 is schema-validated against frozen OASIS errata01. No source locations are invented. No DevGuard or GitHub Code Scanning importer integration is claimed.

## Documentation

- [Migration and exit codes](docs/MIGRATION_0_5.md)
- [Security model](docs/SECURITY_MODEL.md) and [authorized use](AUTHORIZED_USE.md)
- [Scoring](docs/SCORING.md), [checks](docs/CHECKS.md), [upstream evidence](docs/UPSTREAM.md)
- [Provider guide](docs/PROVIDERS.md), [runner review](docs/RUNNER_REVIEW.md) and [integration lab](docs/INTEGRATION_TESTING.md)
- [Candidate notes](docs/RELEASE_CANDIDATE_0_5.md) and [release checklist](docs/RELEASE_CHECKLIST.md)

Historical 0.2.2 before/after examples remain in examples/ for migration context. Current examples use the golden- prefix and are synthetic offline fixtures, not production scans.

## Commercial hardening

Gexiro offers a paid Hardening Report for authorized Gitea operators who want human review of bounded evidence, explicit limitations, prioritized findings, and a practical remediation plan.

A Remediation Sprint is a separate engagement: scope and acceptance criteria are frozen first, changes begin only after explicit approval, and the result includes before/after verification. Scope expansion, third-party targets, and remote changes require separate written authorization.

ForgeGuard remains usable as a free OSS CLI without a hosted account or control plane. Heavy SaaS and recurring monitoring are not offered at this stage.

[Request a scoped ForgeGuard Hardening Report](mailto:contact@gexiro.com?subject=ForgeGuard%20Hardening%20Report)

## License

Apache-2.0. See [LICENSE](LICENSE).

Built and maintained by [Gexiro Global Enterprises Ltd](https://gexiro.com).

Part of the [Gexiro open-source toolkit](https://github.com/gexiro-global).

ForgeGuard by Gexiro

Not affiliated with Gitea, Forgejo, Codeberg, GitHub, or GitLab.
