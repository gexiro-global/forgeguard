# CVE-2026-27771 Posture Check

CVE-2026-27771 is treated by ForgeGuard as a patch-currency and exposure-posture check, not an exploit check.

Public references:

- [Gitea 1.26.2 release notes](https://blog.gitea.com/release-of-1.26.2/)
- [CVE-2026-27771 record](https://www.cve.org/CVERecord?id=CVE-2026-27771)

## Version Window

- Vulnerable window: Gitea versions before `1.26.2`.
- Patched window: Gitea versions at or after `1.26.2`.

ForgeGuard may use `/api/v1/version`, an authenticated version read, or `--known-version` from local operator inventory.

## Safe Inference Model

ForgeGuard uses:

- `GET /api/v1/version` for version discovery when allowed.
- `GET /v2/` for registry root response posture.
- `GET /` for sign-in enforcement inference.

It stops at auth response codes and registry root response codes. It does not follow registry artifact paths.

## Four Posture States

| State | Meaning |
|-------|---------|
| Vulnerable version | Version is below `1.26.2`; code-level fix is missing. |
| Mitigated posture | Version is below `1.26.2`, but sign-in enforcement or denied `/v2/` root access reduces anonymous exposure. |
| Exposed posture | Version is below `1.26.2` and the registry root appears anonymously reachable without a sign-in signal. |
| Patched | Version is `1.26.2` or newer. |

## Why ForgeGuard Does Not Pull Artifacts

The purpose of ForgeGuard is defensive posture inference for authorized operators. Pulling protected package contents, manifests, or layers would cross from posture checking into artifact access. ForgeGuard v0.2 therefore uses only root and metadata response signals and never requests actual package or container contents.
