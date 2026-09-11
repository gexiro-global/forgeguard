# VersionSec by Gexiro - https://git.example.com

Read-only security posture and supply-chain visibility for self-hosted Gitea.

**Product:** gitea 1.26.2  |  **Score:** 100/100 (A)
**Product confirmation:** True (operator-declared)
**Scope:** own-instance | authorized | read-only | single target | **Scan:** fg\_example\_patched\_post\_update

**Summary:** critical 0 | high 0 | medium 0 | low 0 | info 0 | pass 5

## Top actions
- None - no FAIL or WARN findings and all core checks were assessed.

## Interpretation
- FG-VER is informational version evidence. FG-CVE-27771 is the only finding that scores the CVE affected-version condition.
- PASS means evidence supports only the named checked condition; it is not a claim that the whole instance is secure.
- INFO / UNDETERMINED means evidence was insufficient. If any core check is undetermined, the assessment is N/A rather than an A-F grade.
- Registry-root and anonymous-access checks are independent HTTP observations; they do not prove CVE exploitability or private artifact access.

## Sub-scores
| Domain | Score |
|--------|------:|
| patch | 100 |
| registry | 100 |
| auth | 100 |

## Findings
### FG-VER - Confirmed Gitea version observed
- **State:** PASS - version observed
- **Evidence state:** informational
- **Rationale:** Gitea 1.26.2 was observed for an operator-confirmed Gitea target. CVE risk is scored separately by FG-CVE-27771.
- **Evidence:** {'product': 'gitea', 'product\_confirmed': True, 'product\_source': 'operator-declared', 'version': '1.26.2'}

### FG-SIGNIN - Explicit access-control response observed on browsing path
- **State:** PASS
- **Evidence state:** assessed
- **Rationale:** The checked repository browsing path returned HTTP 401 or 403 to an anonymous request; no specific REQUIRE\_SIGNIN\_VIEW configuration value was inferred.
- **Evidence:** {'anon\_explore': 403}

### FG-REG - Explicit registry-root access-control response observed
- **State:** PASS
- **Evidence state:** assessed
- **Rationale:** The anonymous /v2/ request returned HTTP 403, an explicit authentication or access-denial response. No artifact access was attempted.
- **Evidence:** {'anon\_v2\_http': 403}

### FG-CVE-27771 - CVE-2026-27771 version posture
- **State:** PASS - at or above first fixed release
- **Evidence state:** assessed
- **Rationale:** Installed Gitea 1.26.2 is at or above the first release containing the fix for CVE-2026-27771.
- **Refs:** CVE-2026-27771, https://blog.gitea.com/release-of-1.26.2/
- **CWE:** CWE-862
- **Evidence:** {'product': 'gitea', 'product\_confirmed': True, 'product\_source': 'operator-declared', 'version': '1.26.2', 'affected\_through': '1.26.1', 'first\_fixed\_in': '1.26.2'}

### FG-ANON - Explicit access-control responses observed on API checks
- **State:** PASS
- **Evidence state:** assessed
- **Rationale:** Every checked API endpoint returned HTTP 401 or 403 to the anonymous request. No global sign-in configuration was inferred.
- **Evidence:** {'checked': {'/api/v1/repos/search?limit=1': 403, '/api/v1/users/search?limit=1': 403}}

---
VersionSec by Gexiro | own/authorized Gitea instances only | read-only
