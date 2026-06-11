# Before And After Example

This is a synthetic narrative for `https://git.example.com`.

## Before

The instance reports Gitea `1.25.3`. ForgeGuard identifies a patch-currency gap because the version is below `1.26.2`. The `/v2/` registry root returns an authorization-denied response, so the CVE-2026-27771 posture is classified as mitigated rather than exposed.

Result: `66/100 (C)`

Primary action: update Gitea to `1.26.2` or newer and keep sign-in enforcement in place until the update is complete.

## After

The instance reports Gitea `1.26.2`. ForgeGuard identifies the fixed release, the registry root is not anonymously reachable, and the anonymous browsing/API surfaces require sign-in.

Result: `100/100 (A)`

The update closes the code-level patch-currency gap shown in the before report.
