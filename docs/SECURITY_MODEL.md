# Security Model

ForgeGuard 0.2.2 is a read-only, GET-only posture self-check for one self-hosted Gitea instance.

## Scope

- One target URL per invocation.
- Own or explicitly authorized Gitea instances only.
- No write-path checks, issue creation, remote mutation, target discovery, or mass scanning.
- Forgejo is not a supported product in 0.2.2.
- Registration posture is not implemented.

## Target URL boundary

A target must:

- use HTTP or HTTPS;
- include a hostname;
- contain no embedded username/password;
- contain no query or fragment.

A legal Gitea sub-path is preserved. Unsafe URLs are rejected before the HTTP client is created or a report is written.

## Allowlisted endpoints

- `/api/v1/version`
- `/v2/`
- `/`
- `/api/v1/repos/search?limit=1`
- `/explore/repos`
- `/api/v1/users/search?limit=1`

Every request path is checked at runtime. Non-allowlisted paths are refused before a network call.

## Authentication

Prefer `FORGEGUARD_TOKEN` for an optional token. The token is used only for the authenticated version read. Anonymous posture checks remain anonymous. Redirect following is disabled.

The legacy `--token` option remains available with a warning because command-line values may be visible in shell history or process listings. Token values are not fields in reports.

## Advisory boundary

CVE-2026-27771 is evaluated only from confirmed Gitea version posture. Registry-root and sign-in responses do not affect that result.

## Registry and data boundary

ForgeGuard stops at the OCI registry root and status-code evidence. It does not request private package contents, Composer source links, OCI manifests, blobs, layers, repository contents, or protected artifacts.
