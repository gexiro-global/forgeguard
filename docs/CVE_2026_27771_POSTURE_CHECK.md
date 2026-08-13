# CVE-2026-27771 Version Posture Check

ForgeGuard treats CVE-2026-27771 as a Gitea version/advisory posture check, not an exploit or exposure test.

## Official baseline

- [Gitea 1.26.2 release notes](https://blog.gitea.com/release-of-1.26.2/)
- [CVE-2026-27771 CNA record](https://cveawg.mitre.org/api/cve/CVE-2026-27771)
- [GHSA-8qw8-rq86-9pc2](https://github.com/go-gitea/gitea/security/advisories/GHSA-8qw8-rq86-9pc2)

The project baseline is:

- affected Gitea versions: up to and including `1.26.1`;
- first Gitea release containing the fix: `1.26.2`;
- authoritative weakness classification: `CWE-862` (Missing Authorization).

## Product confirmation

The baseline is applied only when trusted operator inventory confirms Gitea through `--product gitea`.

The safe version endpoint can supply version evidence, but a generic semantic version is not product identity. `--known-version` also supplies only a version; it does not confirm Gitea.

An explicit Forgejo marker conflicts with a Gitea declaration and fails safe as unsupported. No Gitea PASS or FAIL is emitted.

## Result semantics

| State | Status | Evidence state | Meaning |
|---|---|---|---|
| Confirmed Gitea <=1.26.1 | FAIL / HIGH | assessed | Gitea is within the affected version range. |
| Confirmed Gitea >=1.26.2 | PASS / INFO | assessed | Gitea is at or above the first release containing the fix. |
| Confirmed Gitea version unknown/unparseable | INFO / MEDIUM | indeterminate | Version posture cannot be determined. |
| Product unknown or unsupported | INFO | indeterminate | The Gitea baseline is not applied. |

If the CVE finding is indeterminate, the final assessment is N/A rather than an A–F grade.

A FAIL result does not prove exploitability, compromise, or data exposure. A PASS result does not claim that the entire instance is secure or that it is on a currently supported release line.

## Scoring boundary

`FG-VER` records informational version evidence and carries no penalty for this CVE threshold. `FG-CVE-27771` is the only finding that penalizes the affected-version condition.

## Independent checks

The anonymous OCI `/v2/` registry-root response, sign-in responses, and anonymous repository/API responses do not change the CVE verdict. They are independent posture observations.

ForgeGuard does not use registry-root reachability or inferred sign-in behavior as proof of exposure or mitigation for CVE-2026-27771.

## Artifact boundary

ForgeGuard does not request Composer source links, private package content, OCI manifests, OCI blobs, layers, or repository content. It performs no exploitation.
