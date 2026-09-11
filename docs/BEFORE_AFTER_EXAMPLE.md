# Affected-Version And Patched-Version Example

This is a synthetic narrative for `https://git.example.com`. It contains no live scan data. Both cases use trusted operator product confirmation and explicit HTTP 401/403 access-control responses so every core check is assessed.

## Before: affected version

The synthetic instance is operator-confirmed as Gitea and reports version `1.26.1`.

- `FG-VER`: informational PASS recording the version.
- `FG-CVE-27771`: FAIL/HIGH, the single penalty for the affected version.
- `FG-REG`, `FG-SIGNIN`, `FG-ANON`: narrowly scoped PASS from explicit 401/403 evidence.

Result: `80/100 (B)`

Primary action: upgrade Gitea to `1.26.2` or a newer currently supported security release.

This is a version/advisory result. It does not prove exploitation or data exposure.

## After: first fixed release

The synthetic instance is operator-confirmed as Gitea and reports version `1.26.2`. VersionSec reports that this version is at the first release containing the fix. The independent checked paths return explicit access-control responses.

Result: `100/100 (A)`

The update closes the version-based CVE finding. A 100 score covers only VersionSec's limited assessed checks and is not a complete security guarantee.

## Incomplete contrast

If product identity, version, registry, sign-in, or anonymous core evidence is indeterminate, VersionSec reports `N/A` with `assessed: false`; it never substitutes `100/A` for missing evidence.
