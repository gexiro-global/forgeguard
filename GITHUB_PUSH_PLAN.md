# GitHub Push Plan

Target organization: `gexiro-global`

Target repository: `forgeguard`

## Constraints

- No publish action is part of this preparation stage.
- No credentials are included in this plan.
- No remote is configured by this package-preparation step.

## Recommended Private Staging Process

1. An authorized human creates `gexiro-global/forgeguard` as a private repository.
2. Enable branch protection for the default branch.
3. Enable GitHub security features available for the repository.
4. Add the remote locally only after the repository exists.
5. Push the committed package to the private repository.
6. Confirm GitHub Actions CI passes on Python 3.11 and 3.12.
7. Confirm the community profile shows README, license, security policy, issue templates, and PR template.
8. Run an independent OPSEC review against the private repository contents.
9. Tag only after review approval.
10. Make the repository public only after explicit final GO.

## Exact Final-GO Process

1. Reviewer signs off on `RELEASE_READINESS_REPORT.md` and `OPSEC_SCAN_RESULTS.md`.
2. Release owner approves private staging push.
3. Push to the private repository.
4. Wait for CI and repository security checks.
5. Reviewer repeats OPSEC and package inspection from the private repository.
6. Release owner issues explicit final GO for public visibility.
7. Change repository visibility to public.
8. Create the release/tag and attach artifacts only under a separate release approval.
