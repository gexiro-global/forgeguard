# Security and trust evidence

This page is an evidence index, not a certification. The evidence does not prove the
project is vulnerability-free, does not establish a SLSA level, and does not imply
OpenSSF affiliation or endorsement. Tool output describes observed posture; it is not
proof of compromise or absence of compromise.

- [Security policy](../SECURITY.md), [security model](SECURITY_MODEL.md) and [authorized-use boundary](../AUTHORIZED_USE.md)
- [Contribution process](../CONTRIBUTING.md), [governance](../GOVERNANCE.md), [maintainers](../MAINTAINERS.md) and [support](../SUPPORT.md)
- CI runs lint, format, compile, tests with a coverage floor, dependency checks and exact-wheel smoke checks.
- Every dependency installed from an index is version-pinned and hash-pinned; CI installs run under `--require-hashes` ([dependency pinning](DEPENDENCY_PINNING.md)).
- Snapshot parsing and report serialisation are fuzzed with Atheris via ClusterFuzzLite, and covered by Hypothesis property tests ([fuzzing](FUZZING.md)).
- GitHub default CodeQL setup is active; dependency review, Dependabot, secret scanning and OpenSSF Scorecard supplement it.
- Third-party actions are pinned to immutable commit SHAs with version comments.

## OpenSSF Scorecard

Scorecard is an automated assessment of selected repository practices at a point in
time, for one commit, under the permissions the analysis had. It is not a
certification and not an audit.

**Current result, published by the official service**

| Field | Value |
|---|---|
| Score | **7.9 / 10** |
| Measured | 2026-09-12T18:29:10Z |
| Commit | `8373303c0cdecd11616b830817cdde17e28653a5` |
| Tool | Scorecard v5.3.0 (`c22063e786c11f9dd714d777a687ff7c4599b600`) |
| Source | [api.scorecard.dev](https://api.scorecard.dev/projects/github.com/gexiro-global/versionsec) · [viewer](https://scorecard.dev/viewer/?uri=github.com/gexiro-global/versionsec) |

The same run in CI reported the same score for the same commit, so the CI measurement
and the published result agree.

**Earlier measurements, kept for history:**

| Score | Date | Commit | Context |
|---|---|---|---|
| 6.5 | 2026-09-04T13:39:26Z | `fa48e281` | before the ForgeGuard → VersionSec rename |
| 7.3 | 2026-09-12T09:01:29Z | `7fff4d6d` | after 0.7.2, before dependency hash-pinning and fuzzing |
| 7.9 | 2026-09-12T18:29:10Z | `8373303c` | current |

The 7.3 → 7.9 movement came from two specific changes, not from tuning: `Fuzzing`
went 0 → 10 when a real ClusterFuzzLite integration landed, and
`Pinned-Dependencies` went 7 → 9 when every index install moved to
`--require-hashes`. Scores from different commits, tool versions or permission sets
are not directly comparable, and a higher number is not by itself evidence of
improved security.

### Checks that do not score full marks, and why

These are reported as measured. None of them is removed from this page.

| Check | Score | What it actually means here |
|---|---|---|
| Branch-Protection | -1 | Not a finding. The analysis token could not read the protection settings. Verified directly: `main` requires 5 status checks with strict mode, blocks force pushes and deletions, requires conversation resolution, and **enforces the rules on administrators**. |
| Code-Review | 0 | Accurate. 0 of 14 changesets carried an approving review. This is a single-maintainer project with no second human reviewer; PRs and green CI are not a substitute, and no reviewer is going to be invented to raise the number. |
| Contributors | 0 | Accurate. The repository has one human contributor plus Dependabot, so there is no organisational diversity to detect. |
| Signed-Releases | 0 | Detection limit, not a missing signature. The check looks for `*.sig`, `*.asc`, `*.intoto.jsonl` and similar **among the release assets**. This project's provenance lives in GitHub's attestation store instead, and in PyPI's PEP 740 records. Both verify — see below. |
| CII-Best-Practices | 2 | Accurate. A Best Practices project exists and is in progress; 2 is the score for in-progress. **No badge has been earned** — see below. |
| Pinned-Dependencies | 9 | Accurate, and the remainder is a detection limit. Every third-party Action is pinned by commit SHA, every index install runs under `--require-hashes`, and the fuzzing base image is pinned by digest. The one remaining deduction is `pip3 install --no-deps .` in the fuzzing build, which installs the checked-out source rather than a downloaded artifact; there is nothing to hash. |

`Vulnerabilities: 10` means no advisory was matched at scan time against the sources
the check consults. It is not a statement that the software has no vulnerabilities.

## OpenSSF Best Practices Badge and OSPS Baseline

**Status: registered and in progress. No badge has been earned.**

| Field | Value |
|---|---|
| Project | [14605](https://www.bestpractices.dev/en/projects/14605) |
| Series | Metal / Passing |
| Progress | 96% of the 67 Passing criteria |
| Badge level | `in_progress` — **not** `passing` |
| Registered | 2026-09-12 |

The remaining two criteria, `know_secure_design` and `know_common_errors`, are
personal attestations about a primary developer's knowledge. They can only be
answered by that person and are deliberately left unanswered until they are.

Until the public entry shows `passing`, the correct description of this project is
"working towards the OpenSSF Best Practices passing badge". Any wording that implies
the badge has been awarded is false.

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
  This is the largest remaining gap; [REVIEW.md](REVIEW.md) states what the automated
  gates do and do not compensate for.
- Fuzzing runs on changed code per pull request and nightly, but the corpus is not
  persisted between runs, so coverage per run is bounded.
- Release tags are unsigned; provenance lives in artifact attestations instead.
- No OpenSSF Best Practices badge has been earned.
- Scans and tests are bounded by their scope, tool version, date and advisory data.
