# ForgeGuard by Gexiro - https://git.example.com

Read-only security posture and supply-chain visibility for self-hosted Gitea.

**Product:** gitea 1.26.1  |  **Score:** 80/100 (B)
**Product confirmation:** True (operator-declared)
**Scope:** own-instance | authorized | read-only | single target | **Scan:** fg_example_affected_pre_update

**Summary:** critical 0 | high 1 | medium 0 | low 0 | info 0 | pass 4

## Top actions
- **P1 - Upgrade Gitea to >=1.26.2** - the confirmed version is within the affected range for CVE-2026-27771; this version result does not prove exploitability.

## Interpretation
- FG-VER is informational version evidence. FG-CVE-27771 is the only finding that scores the CVE affected-version condition.
- PASS means evidence supports only the named checked condition; it is not a claim that the whole instance is secure.
- INFO / UNDETERMINED means evidence was insufficient. If any core check is undetermined, the assessment is N/A rather than an A-F grade.
- Registry-root and anonymous-access checks are independent HTTP observations; they do not prove CVE exploitability or private artifact access.

## Sub-scores
| Domain | Score |
|--------|------:|
| patch | 80 |
| registry | 100 |
| auth | 100 |

## Findings
### FG-CVE-27771 - CVE-2026-27771 version posture
- **State:** FAIL / HIGH
- **Evidence state:** assessed
- **Rationale:** Installed Gitea version is within the affected range for CVE-2026-27771. This version check does not prove exploitability or data exposure.
- **Action:** Upgrade Gitea to >=1.26.2 or a newer currently supported security release.
- **Refs:** CVE-2026-27771, https://blog.gitea.com/release-of-1.26.2/
- **CWE:** CWE-862
- **Evidence:** `{'product': 'gitea', 'product_confirmed': True, 'product_source': 'operator-declared', 'version': '1.26.1', 'affected_through': '1.26.1', 'first_fixed_in': '1.26.2'}`

### FG-VER - Confirmed Gitea version observed
- **State:** PASS - version observed
- **Evidence state:** informational
- **Rationale:** Gitea 1.26.1 was observed for an operator-confirmed Gitea target. CVE risk is scored separately by FG-CVE-27771.
- **Evidence:** `{'product': 'gitea', 'product_confirmed': True, 'product_source': 'operator-declared', 'version': '1.26.1'}`

### FG-SIGNIN - Explicit access-control responses observed on checked paths
- **State:** PASS
- **Evidence state:** assessed
- **Rationale:** Both checked paths returned HTTP 401 or 403 to anonymous requests; no specific REQUIRE_SIGNIN_VIEW configuration value was inferred.
- **Evidence:** `{'anon_api': 403, 'anon_explore': 403}`

### FG-REG - Explicit registry-root access-control response observed
- **State:** PASS
- **Evidence state:** assessed
- **Rationale:** The anonymous /v2/ request returned HTTP 403, an explicit authentication or access-denial response. No artifact access was attempted.
- **Evidence:** `{'anon_v2_http': 403}`

### FG-ANON - Explicit access-control responses observed on anonymous checks
- **State:** PASS
- **Evidence state:** assessed
- **Rationale:** Every checked endpoint returned HTTP 401 or 403 to the anonymous request. No global sign-in configuration was inferred.
- **Evidence:** `{'checked': {'/api/v1/repos/search?limit=1': 403, '/explore/repos': 403, '/api/v1/users/search?limit=1': 403}}`

---
ForgeGuard by Gexiro | own/authorized Gitea instances only | read-only
