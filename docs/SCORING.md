# Scoring version 2

Observation, policy result, completeness and severity are separate fields.
Scoring is deterministic and never uses AI.

Every selected required finding must have sufficient evidence. Missing,
unsupported, conflicted, errored or truncated evidence yields null value, N/A
grade and assessed=false, listing unresolved IDs. An existing warning cannot hide
another missing observation. Skipped controls are listed separately and are not
assessed as safe. An empty assessment is incomplete.

For complete assessments, FAIL weights remain critical 40, high 20, medium 10,
low 4 and info 0. WARN subtracts int(weight * 0.35).
Within each penalty group only the greatest penalty applies. All version
advisories share one group; browser/API observations share anonymous-access.
Registry root remains an independent observation. Disclosure and header presence
have no penalty.

Grades: A >=90, B >=75, C >=60, D >=40, F below 40.
Public and unspecified intent do not penalize intended anonymous HTTP 200.
Private intent treats it as a bounded review warning, not proof of private-data
access. A status may come from a proxy, login page or empty API.
Offline private intent evaluates only declared snapshot configuration.

Score version 2 and old scores are not directly comparable. Even 100/A refers
only to complete selected conditions and finite catalog evidence, not security
certification, absence of vulnerabilities, compromise or a comprehensive audit.
