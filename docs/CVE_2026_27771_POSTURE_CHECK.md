# CVE-2026-27771 Version Posture Check

ForgeGuard treats CVE-2026-27771 as a Gitea version/advisory posture check, not an exploit or exposure test.

## Official baseline

- [Gitea 1.26.2 release notes](https://blog.gitea.com/release-of-1.26.2/)
- [CVE-2026-27771 record](https://www.cve.org/CVERecord?id=CVE-2026-27771)

The project baseline is:

- affected Gitea versions: up to and including `1.26.1`;
- first Gitea release containing the fix: `1.26.2`.

ForgeGuard can obtain a version from the authorized `/api/v1/version` endpoint or from `--known-version` supplied from trusted operator inventory.

## Result semantics

| State | Status | Meaning |
|---|---|---|
| Gitea version <=1.26.1 | FAIL / HIGH | Installed Gitea is within the affected version range. |
| Gitea version >=1.26.2 | PASS / INFO | Installed Gitea is at or above the first release containing the fix. |
| Gitea version unknown/unparseable | INFO / MEDIUM | Version posture cannot be determined. |
| Product unsupported | INFO | The Gitea baseline is not applied. |

A FAIL result does not prove exploitability, compromise, or data exposure. A PASS result does not claim that the entire instance is secure or that it is on a currently supported release line.

## Independent checks

The anonymous OCI `/v2/` registry-root response, homepage response, sign-in responses, and anonymous repository/API responses do not change the CVE verdict. They are independent posture observations.

ForgeGuard does not use registry-root reachability or inferred sign-in behavior as proof of exposure or mitigation for CVE-2026-27771.

## Product boundary

ForgeGuard 0.2.2 applies this baseline only to Gitea. A version string explicitly marked as Forgejo is treated as unsupported and receives no Gitea affected/fixed conclusion.

## Artifact boundary

ForgeGuard does not request Composer source links, private package content, OCI manifests, OCI blobs, layers, or repository content. It performs no exploitation.
