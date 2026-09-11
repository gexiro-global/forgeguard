# Roadmap

## 0.6.0 Control Plane Hardening

Adds offline runner posture review (`versionsec runner review`): execution engine isolation,
privileged mode, host volume mounts, Docker socket exposure, job network mode, ephemeral
registration, and the experimental Forgejo plugin engine. Closes the "explicitly scoped
runner/token controls" item named as future work in 0.5's own entry below. See
[docs/RUNNER_REVIEW.md](docs/RUNNER_REVIEW.md) and [CHANGELOG.md](CHANGELOG.md).

Under consideration, not committed: widening the runner qualification matrix to additional
point releases once each can be fully qualified; SSRF/outbound mirror-hardening config posture
(`[migrations]` ALLOWED_DOMAINS/BLOCKED_DOMAINS/ALLOW_LOCALNETWORKS); additional advisory catalog
records with authoritative, reproducibly-frozen sources. No SaaS, hosted control plane, or
general compliance certification is planned.

## 0.5.0 implementation

Separate Gitea/Forgejo providers, bounded profiles, exposure policy, offline configuration snapshots, finite advisory catalogs and versioned JSON/SARIF exports are implemented in the candidate. Qualification and delivery gates remain tracked in the PR and candidate notes.

Future work: additional qualified releases, reviewed advisory coverage, explicitly scoped runner/token controls. No SaaS, automatic remediation, customer-code scanning or additional forge provider is part of this milestone.

## Historical 0.2.2 roadmap

# Roadmap

Items below are planned and are not implemented in VersionSec 0.2.2 unless stated otherwise.

## Truth-correct current scope

VersionSec 0.2.2 supports one authorized, operator-confirmed self-hosted Gitea target with version/advisory posture, explicit completeness, and limited read-only HTTP observations.

A compatible version endpoint is not product detection. The operator supplies `--product gitea` from trusted inventory. Without that confirmation, Gitea-specific advisory posture remains indeterminate and the assessment is ungraded.

## Future product targets

### Forgejo support

Forgejo requires a separate implementation milestone with:

- product-specific detection or trusted Forgejo declaration;
- Forgejo version semantics;
- an authoritative Forgejo advisory source;
- Forgejo-specific regression tests.

Until those gates exist, Forgejo receives no Gitea version or advisory conclusion.

### Registration posture

A future registration check requires a separately reviewed safe evidence model. Registration posture is not implemented in 0.2.2.

## Later controls

- Runner posture.
- Token-configuration posture.
- TLS posture.
- Optional operator-reviewed remediation notes.
- Supply-chain, SBOM, and OSV enrichment.

Monitoring, alerting, and issue emission require separate product and authorization decisions and are not part of 0.2.2.
