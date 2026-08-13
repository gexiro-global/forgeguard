# Scoring

ForgeGuard scoring is deterministic and does not use AI.

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

## Current domains

- `patch`: Gitea patch currency.
- `registry`: independent OCI registry-root posture plus CVE version posture.
- `auth`: observed sign-in and anonymous responses on checked paths.
- `runner`: reserved for future checks and currently receives no findings.

The CVE result is based only on Gitea version/advisory posture. Registry and sign-in responses do not change it.

The synthetic affected-version example contains two related HIGH FAIL findings, `FG-VER` and `FG-CVE-27771`, and therefore scores 60. Future versions may deduplicate related controls after an explicit scoring design review.

## Limit

A score covers only the checks implemented in the installed ForgeGuard version. It is not a complete hardening, exploitability, compromise, registration, or private-package-access assessment.
