# Affected-Version And Patched-Version Example

This is a synthetic narrative for `https://git.example.com`. It contains no live scan data.

## Before: affected version

The synthetic instance reports Gitea `1.26.1`. ForgeGuard reports that this version is within the affected range for CVE-2026-27771 and below the first fixed release.

Result: `60/100 (C)`

Primary action: upgrade Gitea to `1.26.2` or a newer currently supported security release.

This is a version/advisory result. It does not prove exploitation or data exposure.

## After: first fixed release

The synthetic instance reports Gitea `1.26.2`. ForgeGuard reports that this version is at the first release containing the fix. The independent registry-root and checked anonymous paths also return non-200 access-control responses.

Result: `100/100 (A)`

The update closes the version-based patch-currency gap for this CVE. A 100 score covers only ForgeGuard's limited checks and is not a complete security guarantee.
