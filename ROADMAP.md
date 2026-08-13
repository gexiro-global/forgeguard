# Roadmap

Items below are planned and are not implemented in ForgeGuard 0.2.2 unless stated otherwise.

## Truth-correct current scope

ForgeGuard 0.2.2 supports one authorized self-hosted Gitea target with version/advisory posture and limited read-only HTTP observations.

## Future product targets

### Forgejo support

Forgejo requires a separate implementation milestone with:

- product-specific detection;
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
