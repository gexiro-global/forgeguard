# Security and trust evidence

This page is an evidence index, not a certification. The evidence does not prove the project is vulnerability-free, does not establish a SLSA level, and does not imply OpenSSF affiliation or endorsement. Tool output describes observed posture; it is not proof of compromise or absence of compromise.

- [Security policy](../SECURITY.md), [security model](SECURITY_MODEL.md) and [authorized-use boundary](../AUTHORIZED_USE.md)
- [Contribution process](../CONTRIBUTING.md), [governance](../GOVERNANCE.md), [maintainers](../MAINTAINERS.md) and [support](../SUPPORT.md)
- CI runs lint, format, compile, tests, dependency checks and exact-wheel smoke checks.
- GitHub default CodeQL setup is active; dependency review, Dependabot, secret scanning and OpenSSF Scorecard supplement it.
- Third-party actions are pinned to immutable commit SHAs with version comments.

The Scorecard badge is intentionally withheld until a successful default-branch run has produced a public API result. `.bestpractices.json` contains evidence-backed automation proposals only; it is not an OpenSSF Best Practices or OSPS Baseline claim. A human must review any badge submission.
