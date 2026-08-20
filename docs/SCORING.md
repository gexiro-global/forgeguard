# Scoring

ForgeGuard scoring is deterministic and does not use AI. Risk and evidence completeness are separate concepts.

## Assessment core

The core scored checks are:

- `FG-CVE-27771`, including product confirmation and Gitea advisory eligibility;
- `FG-REG`;
- `FG-SIGNIN`;
- `FG-ANON`.

`FG-VER` is informational product/version evidence. It never adds a second penalty for the same CVE version threshold.

Every core finding has an evidence state:

- `assessed`: enough evidence exists for PASS, WARN, or FAIL;
- `indeterminate`: evidence is absent, ambiguous, unsupported, or failed;
- `informational`: context that does not independently determine the core posture.

## Incomplete assessment

If any core check is missing or indeterminate:

```json
{
  "value": null,
  "grade": "N/A",
  "assessed": false
}
```

Missing evidence is not converted to score zero, risk, PASS, or A. `incomplete_checks` lists the unresolved core finding IDs. Subscores for unresolved domains are also `null`/N/A.

A normal A–F grade is emitted only when all core checks are assessed.

## Severity weights

| Severity | FAIL penalty |
|---|---:|
| Critical | -40 |
| High | -20 |
| Medium | -10 |
| Low | -4 |
| Info | 0 |

A WARN finding subtracts `int(weight * WARN_FACTOR)`.

`WARN_FACTOR = 0.35`

## Grade thresholds

| Score | Grade |
|---:|:---|
| 90–100 | A |
| 75–89 | B |
| 60–74 | C |
| 40–59 | D |
| 0–39 | F |

These thresholds apply only to a complete assessment.

## Current domains

- `patch`: CVE-2026-27771 version/advisory posture for confirmed Gitea.
- `registry`: independent OCI registry-root response posture.
- `auth`: repository-browser posture from `FG-SIGNIN` and API posture from `FG-ANON`, using disjoint endpoint ownership.

No empty future domain is displayed as 100.

## No correlated double counting

For confirmed Gitea 1.26.1:

- `FG-VER` records the observed version as informational evidence;
- `FG-CVE-27771` produces one FAIL/HIGH penalty;
- with every other core check assessed and passing, the result is 80/B.

The same product/version root fact is not penalized twice.

Authentication findings follow the same rule. `FG-SIGNIN` owns only
`/explore/repos`; `FG-ANON` owns only the repository-search and user-search API
paths. One endpoint/status observation therefore contributes at most one penalty.

## Limit

A complete score still covers only the checks implemented in the installed ForgeGuard version. It is not a security certification, vulnerability oracle, complete hardening assessment, exploitability result, compromise determination, registration assessment, or private-package-access assessment.
