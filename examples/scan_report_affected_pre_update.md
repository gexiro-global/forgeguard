# ForgeGuard by Gexiro - https://git.example.com

Read-only security posture and supply-chain visibility for self-hosted Gitea.

**Product:** gitea 1.26.1  |  **Score:** 60/100 (C)
**Scope:** own-instance | authorized | read-only | single target | **Scan:** fg_example_affected_pre_update

**Summary:** critical 0 | high 2 | medium 0 | low 0 | pass 3

## Top actions
- **P1 - Upgrade Gitea to >=1.26.2** - the installed version is within the affected range for CVE-2026-27771; this version result does not prove exploitability.

## Interpretation
- FG-VER and FG-CVE-27771 report Gitea version posture against the first fixed release.
- Registry-root and anonymous-access checks are independent HTTP observations; they do not prove CVE exploitability or private artifact access.
- PASS means the checked condition passed; it is not a claim that the whole instance is secure.

## Sub-scores
| Domain | Score |
|--------|------:|
| patch | 80 |
| registry | 80 |
| auth | 100 |
| runner | 100 |

## Findings
### FG-VER - Gitea patch-currency gap
- **State:** FAIL / HIGH
- **Rationale:** Installed Gitea 1.26.1 is below the first release containing the fix for CVE-2026-27771.
- **Action:** Upgrade Gitea to >=1.26.2 or a newer currently supported security release.
- **Refs:** CVE-2026-27771
- **Evidence:** `{'version': '1.26.1', 'first_fixed_in': '1.26.2'}`

### FG-CVE-27771 - CVE-2026-27771 version posture
- **State:** FAIL / HIGH
- **Rationale:** Installed Gitea version is within the affected range for CVE-2026-27771. This version check does not prove exploitability or data exposure.
- **Action:** Upgrade Gitea to >=1.26.2 or a newer currently supported security release.
- **Refs:** CVE-2026-27771, https://blog.gitea.com/release-of-1.26.2/
- **Evidence:** `{'product': 'gitea', 'version': '1.26.1', 'affected_through': '1.26.1', 'first_fixed_in': '1.26.2'}`

### FG-SIGNIN - Checked repository/API surfaces appear access-controlled
- **State:** PASS
- **Rationale:** Anonymous requests returned access-control or sign-in redirect responses on the checked paths; no specific configuration key was read.
- **Evidence:** `{'anon_api': 403, 'anon_explore': 302}`

### FG-REG - OCI registry root did not return HTTP 200 anonymously
- **State:** PASS
- **Rationale:** The anonymous /v2/ request returned HTTP 403; no package, manifest, or blob access was attempted.
- **Evidence:** `{'anon_v2_http': 403}`

### FG-ANON - No anonymous HTTP 200 observed on checked endpoints
- **State:** PASS
- **Rationale:** None of the three checked endpoints returned HTTP 200 to an anonymous request.
- **Evidence:** `{'checked': {'/api/v1/repos/search?limit=1': 403, '/explore/repos': 302, '/api/v1/users/search?limit=1': 403}}`

---
ForgeGuard by Gexiro | own/authorized Gitea instances only | read-only
