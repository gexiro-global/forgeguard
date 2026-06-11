# Scoring

ForgeGuard scoring is deterministic and does not use AI.

## Severity Weights

| Severity | Penalty |
|----------|--------:|
| Critical | -40 |
| High | -20 |
| Medium | -10 |
| Low | -4 |
| Info | 0 |

`FAIL` findings subtract the full severity penalty. `WARN` findings subtract `int(weight * WARN_FACTOR)`.

`WARN_FACTOR = 0.35`

## Grade Thresholds

| Score | Grade |
|------:|:------|
| 90-100 | A |
| 75-89 | B |
| 60-74 | C |
| 40-59 | D |
| 0-39 | F |

## Subscores

Subscores group findings by posture domain:

- `patch`: version and fixed-release posture.
- `registry`: registry exposure and CVE-2026-27771 posture.
- `auth`: sign-in and anonymous surface posture.
- `runner`: reserved for future runner checks.

Future versions may add optional domain de-duplication when multiple findings describe the same underlying control.
