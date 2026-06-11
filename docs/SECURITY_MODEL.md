# Security Model

ForgeGuard v0.2 is read-only and GET-only.

## Scope

- One target URL per scan.
- Own or explicitly authorized instances only.
- No write-path checks in v0.2.
- No issue creation or remote mutation in v0.2.

## Allowlisted Endpoints

ForgeGuard v0.2 uses only safe posture endpoints:

- `/api/v1/version`
- `/v2/`
- `/`
- `/api/v1/repos/search?limit=1`
- `/explore/repos`
- `/api/v1/users/search?limit=1`

## Authentication

Anonymous checks are used for posture inference. If supplied, the optional API token is used only for authenticated version reads.

## Registry Boundary

ForgeGuard stops at the registry root response. It does not request package contents, OCI manifests, OCI layers, or protected artifacts.
