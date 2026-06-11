# ForgeGuard by Gexiro - https://git.example.com

Read-only security posture and supply-chain visibility for self-hosted Gitea/Forgejo.

**Forge:** gitea 1.26.2  |  **Score:** 100/100 (A)
**Scope:** own-instance | authorized | read-only | single target | **Scan:** fg_example_post_update

**Summary:** critical 0 | high 0 | medium 0 | low 0 | pass 5

## Top actions
- None - all checks pass.

## Interpretation
- FG-VER reports patch currency: vulnerable version, patched, or unknown.
- FG-CVE-27771 reports exposure posture: active exposure, mitigated posture, patched, or unknown.
- A mitigated posture still needs the code-level update because mitigation is not the patch.

## Sub-scores
| Domain | Score |
|--------|------:|
| patch | 100 |
| registry | 100 |
| auth | 100 |
| runner | 100 |

## Findings
### FG-VER - Patched: version is at or above the fixed release
**State:** PASS - patched  
**Rationale:** Running 1.26.2 (>= 1.26.2).  
**Evidence:** `{'version': '1.26.2', 'fixed_in': '1.26.2'}`

### FG-SIGNIN - Anonymous access requires sign-in
**State:** PASS  
**Rationale:** REQUIRE_SIGNIN_VIEW appears enforced; anonymous browsing/API access is denied.  
**Evidence:** `{'anon_api': 403, 'anon_explore': 302}`

### FG-REG - Container registry not anonymously reachable
**State:** PASS  
**Rationale:** Anonymous /v2/ access is denied.  
**Evidence:** `{'anon_v2_http': 403}`

### FG-CVE-27771 - CVE-2026-27771 exposure posture
**State:** PASS - patched  
**Rationale:** Patched: 1.26.2 is at or above 1.26.2.  
**Action:** Update Gitea to >= 1.26.2; keep REQUIRE_SIGNIN_VIEW=true until patched.  
**Refs:** CVE-2026-27771, https://blog.gitea.com/release-of-1.26.2/  
**Evidence:** `{'version': '1.26.2', 'anon_v2_http': 403, 'signin_required_inferred': True, 'registry_anon_open': False}`

### FG-ANON - No anonymously readable surfaces detected
**State:** PASS  
**Rationale:** Probed endpoints all require authentication.  
**Evidence:** `{'probed': ['/api/v1/repos/search?limit=1', '/explore/repos', '/api/v1/users/search?limit=1']}`

---
ForgeGuard by Gexiro | own/authorized instances only | read-only by default
