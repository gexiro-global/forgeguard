# ForgeGuard 0.5.0rc1 — Multi-Forge Preview

Candidate scope: Gitea and Forgejo provider implementations, finite version
advisory catalogs, policy intent, profiles, closed offline configuration snapshots,
versioned evidence JSON and SARIF 2.1.0.

Qualification targets: Gitea 1.26.4 and 1.27.3; Forgejo 15.0.8 and 16.0.4.
These are exact implementation targets. Consult the final PR verification and
integration evidence before treating a target as tested. No claim is made for all
releases in a branch.

The Forgejo catalog currently proves only the exact fixed releases for the
2026-09-10 template-initialization security change. Upstream release notes do not
establish the affected introduction boundary; older versions remain undetermined.
No CVE identifier is invented. Gitea retains FG-CVE-27771 and adds FG-CVE-78433.

Gitea 1.26.4 is the previous generally maintained release line, not a line
receiving current security fixes. Its known version advisory is expected to fail.
The official release-management policy describes current and previous maintenance;
SECURITY.md restricts security fixes to the newest release and main. See UPSTREAM.md.

No release/tag/PyPI publication or main merge is part of this candidate.
Attestation implementation, generation and verification are separate gates.
A draft PR remains required while any mandatory gate is incomplete.
No importer integration, security certification, platform-wide compatibility,
Windows/macOS execution, or universal zero-false-positive claim is made.
