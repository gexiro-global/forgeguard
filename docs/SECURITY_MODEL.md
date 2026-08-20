# Security Model

ForgeGuard 0.2.2 is a read-only, GET-only posture self-check for one self-hosted target.

## Scope

- One target URL per invocation.
- Own or explicitly authorized instances only.
- Gitea-specific conclusions require trusted `--product gitea` confirmation.
- No write-path checks, issue creation, remote mutation, target discovery, or mass scanning.
- Forgejo is not a supported product in 0.2.2.
- Registration posture is not implemented.

## Authorization metadata

A new `Target` defaults to `authorized: false`. The high-level CLI sets it true only after the required `--authorized` affirmation passes. Low-level Python clients cannot enforce legal authorization; the metadata represents the executed workflow truthfully.

## Product boundary

Product identity starts as `unknown`. A generic version response or `--known-version` does not establish Gitea. The operator declaration `--product gitea` is trusted inventory input.

An explicit Forgejo version marker overrides a conflicting Gitea declaration and prevents a Gitea advisory PASS or FAIL.

## Target URL boundary

A target must:

- use HTTP or HTTPS;
- include a hostname;
- contain no embedded username/password;
- contain no query or fragment;
- contain no decoded `.` or `..` segment or backslash separator across up to eight decoding layers;
- avoid excessive nested percent-encoding.

A legal subpath is preserved. Unsafe URLs are rejected before the HTTP client is created or a report is written.

## Allowlisted endpoints

- `/api/v1/version`
- `/v2/`
- `/`
- `/api/v1/repos/search?limit=1`
- `/explore/repos`
- `/api/v1/users/search?limit=1`

Every request path is checked at runtime. Non-allowlisted paths are refused before a network call.

`FG-SIGNIN` owns the browser observation at `/explore/repos`. `FG-ANON`
owns the two API-search observations. No endpoint/status observation is requested
or scored twice.

## Authentication

Prefer `FORGEGUARD_TOKEN` for an optional token. The token is used only for the authenticated version read. Anonymous posture checks remain anonymous. Redirect following is disabled.

The legacy `--token` option remains available with a warning because command-line values may be visible in shell history or process listings. Token values are not fields in reports.

## Report integrity

Markdown rendering treats target, scan, finding, rationale, remediation, reference,
and evidence values as untrusted. Control characters become visible escapes,
Markdown metacharacters are escaped, and raw HTML is neutralized. JSON preserves
the original structured values under JSON escaping.

## HTTP evidence taxonomy

- 200 records anonymous readability/reachability and produces a bounded warning.
- 401/403 are explicit authentication/access-denial evidence and may produce a narrowly scoped PASS.
- 404, redirects, 429, 5xx, unclassified statuses and network failures are INFO/UNDETERMINED.
- ForgeGuard does not infer a global sign-in configuration from these responses.

## Advisory and completeness boundary

CVE-2026-27771 is evaluated only from operator-confirmed Gitea version posture. Registry-root and sign-in responses do not affect that result. `FG-VER` is informational; only `FG-CVE-27771` scores the CVE affected-version condition.

If any core check is indeterminate, the assessment is N/A rather than A–F. Missing evidence is not interpreted as either risk or security.

## Registry and data boundary

ForgeGuard stops at the OCI registry root and status-code evidence. It does not request private package contents, Composer source links, OCI manifests, blobs, layers, repository contents, or protected artifacts.
