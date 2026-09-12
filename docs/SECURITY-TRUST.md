# Security and trust evidence

This page is an evidence index, not a certification. The evidence does not prove the
project is vulnerability-free, does not establish a SLSA level, and does not imply
OpenSSF affiliation or endorsement. Tool output describes observed posture; it is not
proof of compromise or absence of compromise.

- [Security policy](../SECURITY.md), [security model](SECURITY_MODEL.md) and [authorized-use boundary](../AUTHORIZED_USE.md)
- [Contribution process](../CONTRIBUTING.md), [governance](../GOVERNANCE.md), [maintainers](../MAINTAINERS.md) and [support](../SUPPORT.md)
- CI runs lint, format, compile, tests, dependency checks and exact-wheel smoke checks.
- GitHub default CodeQL setup is active; dependency review, Dependabot, secret scanning and OpenSSF Scorecard supplement it.
- Third-party actions are pinned to immutable commit SHAs with version comments.

## OpenSSF Scorecard

Scorecard is an automated assessment of selected repository practices at a point in
time, for one commit, under the permissions the analysis had. It is not a
certification and not an audit.

**Current result, published by the official service**

| Field | Value |
|---|---|
| Score | **7.3 / 10** |
| Measured | 2026-09-12T09:01:29Z |
| Commit | `7fff4d6de1f9421497f1e3bc65ab9ad0df926b50` |
| Tool | Scorecard v5.3.0 (`c22063e786c11f9dd714d777a687ff7c4599b600`) |
| Source | [api.scorecard.dev](https://api.scorecard.dev/projects/github.com/gexiro-global/versionsec) · [viewer](https://scorecard.dev/viewer/?uri=github.com/gexiro-global/versionsec) |

The same run in CI reported the same score for the same commit, so the CI measurement
and the published result agree.

**Earlier measurement, kept for history:** 6.5 on 2026-09-04T13:39:26Z for commit
`fa48e28109ad45ffb222bf8423d437daa92f5cc1`. That predates the ForgeGuard → VersionSec
rename and the 0.7.x releases. Scores from different commits, tool versions or
permission sets are not directly comparable, and a higher number is not by itself
evidence of improved security.

### Checks that do not score full marks, and why

These are reported as measured. None of them is removed from this page.

| Check | Score | What it actually means here |
|---|---|---|
| Branch-Protection | -1 | Not a finding. The analysis token could not read the protection settings. Verified directly: `main` requires 5 status checks with strict mode, blocks force pushes and deletions, requires conversation resolution, and **enforces the rules on administrators**. |
| Code-Review | 0 | Accurate. 0 of 14 changesets carried an approving review. This is a single-maintainer project with no second human reviewer; PRs and green CI are not a substitute, and no reviewer is going to be invented to raise the number. |
| Contributors | 0 | Accurate. The repository has one human contributor plus Dependabot, so there is no organisational diversity to detect. |
| Signed-Releases | 0 | Detection limit, not a missing signature. The check looks for `*.sig`, `*.asc`, `*.intoto.jsonl` and similar **among the release assets**. This project's provenance lives in GitHub's attestation store instead, and in PyPI's PEP 740 records. Both verify — see below. |
| Fuzzing | 0 | Accurate. There is no fuzzing integration. Absence of fuzzing is not a discovered vulnerability, and a placeholder harness would not change that. |
| CII-Best-Practices | 0 | Accurate. No OpenSSF Best Practices Badge project exists for this repository — see below. |
| Pinned-Dependencies | 7 | Partly accurate. Every third-party GitHub Action is pinned to a commit SHA. The deduction is for `pip install` steps in CI that install by version without `--require-hashes`. Hash-pinned CI installs are tracked as separate hardening, not claimed as done. |

`Vulnerabilities: 10` means no advisory was matched at scan time against the sources
the check consults. It is not a statement that the software has no vulnerabilities.

## OpenSSF Best Practices Badge and OSPS Baseline

**Status: not registered.** Searching the official portal on 2026-09-12 for
`versionsec`, `forgeguard` and `gexiro`, and by repository URL for both the current
and the former repository name, returned no project. The same query API returns
results for known projects, so this is a real absence and not a failed lookup.

There is therefore no badge level to report, and nothing was lost in the rename.

`.bestpractices.json` in this repository holds evidence-backed proposals for OSPS
Baseline criteria. It is a working document. It is not a submission, not an awarded
badge, and not a claim that Baseline is met. Any submission needs a human to check
each answer against real evidence first.

## Release provenance

What exists, and what it proves:

- Each published wheel and sdist carries a Sigstore attestation produced by this
  repository's own CI. Verify with
  `gh attestation verify <file> --repo gexiro-global/versionsec`.
- PyPI records PEP 740 provenance naming the Trusted Publisher that uploaded each
  file: `release.yml` for `versionsec`, `release-bridge.yml` for the `forgeguard`
  compatibility bridge.
- Publishing uses Trusted Publishing (OIDC). No long-lived PyPI API token exists.

What this does **not** establish: it is not a SLSA level claim, not an audit, and not
evidence that the code is free of vulnerabilities. It binds specific bytes to the
workflow and commit that produced them.

Release tags are annotated and **unsigned**. A signed merge commit is a different
object from a signed tag, and neither is the same as an artifact attestation. No
signing identity exists for this project, and none was improvised.

## Known limitations

- Single maintainer: no independent human code review, no organisational diversity.
- No fuzzing integration.
- CI installs build tooling by version, not by hash.
- Scans and tests are bounded by their scope, tool version, date and advisory data.
