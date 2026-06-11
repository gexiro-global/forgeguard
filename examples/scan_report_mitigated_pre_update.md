# ForgeGuard by Gexiro - https://git.example.com

Read-only security posture and supply-chain visibility for self-hosted Gitea/Forgejo.

**Forge:** gitea 1.25.3  |  **Score:** 66/100 (C)
**Scope:** own-instance | authorized | read-only | single target | **Scan:** fg_example_pre_update

**Summary:** critical 1 | high 1 | medium 0 | low 0 | pass 3

## Top actions
- **P1 - Update Gitea to >=1.26.2** - CVE-2026-27771 window present, mitigation active, code-level fix missing.

## Interpretation
- FG-VER reports patch currency: vulnerable version, patched, or unknown.
- FG-CVE-27771 reports exposure posture: active exposure, mitigated posture, patched, or unknown.
- A mitigated posture still needs the code-level update because mitigation is not the patch.

## Sub-scores
| Domain | Score |
|--------|------:|
| patch | 80 |
| registry | 86 |
| auth | 100 |
| runner | 100 |

## Findings
### FG-VER - Vulnerable version: patch-currency gap
**State:** FAIL / HIGH  
**Rationale:** Running 1.25.3 < 1.26.2: the code-level fix for CVE-2026-27771 is missing.  
**Action:** Update Gitea to >= 1.26.2.  
**Refs:** CVE-2026-27771  
**Evidence:** `{'version': '1.25.3', 'fixed_in': '1.26.2'}`

### FG-CVE-27771 - CVE-2026-27771 exposure posture
**State:** WARN / CRITICAL CVE - mitigated but unpatched  
**Rationale:** Mitigated posture: vulnerable version remains, but anonymous /v2/ access is denied or sign-in is enforced.  
**Action:** Update Gitea to >= 1.26.2; keep sign-in enforcement until patched.  
**Refs:** CVE-2026-27771, https://blog.gitea.com/release-of-1.26.2/  
**Evidence:** `{'version': '1.25.3', 'anon_v2_http': 403, 'signin_required_inferred': True, 'registry_anon_open': False}`

### FG-SIGNIN - Anonymous access requires sign-in
**State:** PASS  
**Rationale:** REQUIRE_SIGNIN_VIEW appears enforced; anonymous browsing/API access is denied.  
**Evidence:** `{'anon_api': 403, 'anon_explore': 302}`

### FG-REG - Container registry not anonymously reachable
**State:** PASS  
**Rationale:** Anonymous /v2/ access is denied.  
**Evidence:** `{'anon_v2_http': 403}`

### FG-ANON - No anonymously readable surfaces detected
**State:** PASS  
**Rationale:** Probed endpoints all require authentication.  
**Evidence:** `{'probed': ['/api/v1/repos/search?limit=1', '/explore/repos', '/api/v1/users/search?limit=1']}`

---
ForgeGuard by Gexiro | own/authorized instances only | read-only by default
