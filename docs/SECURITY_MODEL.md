# Security model — 0.5 preview

ForgeGuard assesses one explicitly authorized base URL or one operator-supplied
offline snapshot. It performs no discovery, exploitation, auth bypass, writes,
account creation, private content retrieval or automatic remediation.

Product identity is an operator declaration, separate from version evidence.
A compatible API does not identify Gitea or Forgejo. Opposing markers in inventory
or observations and conflicting versions stop dependent inference. Catalog
version ranges are finite and provider-specific. Vendor/backport uncertainty
never becomes fixed or affected automatically.

## HTTP boundary

Central transport enforces the existing finite GET allowlist:
`/api/v1/version`, `/explore/repos`, `/v2/`,
`/api/v1/repos/search?limit=1`, `/api/v1/users/search?limit=1`, `/`.
No private repository contents, OCI manifests, blobs, layers or attachments.
No new enumeration endpoints are introduced.

Minimal uses one version request; standard five existing requests; extended also
reads root. Plans are independent of exposure intent. Dry-run performs no DNS or
HTTP. Profile limits are below the hard ceiling of 12 requests.
One request at a time, no retries, at most 10 seconds per request, 60 seconds
overall, and at most 256 KiB after decompression while streaming. Errors and
truncation preserve incompleteness.

Redirects are not followed. The validated base origin and legal subpath are
preserved. Embedded credentials, queries, fragments, dot segments, backslashes
and excessive nested encodings are refused. Loopback/private addresses remain
valid for an operator's own instances.

HTTPS verifies certificates. `--ca-bundle` explicitly selects trust for a private
CA; disabling verification is not supported. HTTP never transmits a token.
Ambient proxy and CA environment variables are ignored through trust_env=false;
proxy configuration is not supported by this preview.

Only the version request may authenticate, using FORGEGUARD_TOKEN preferably.
The legacy token argument warns on stderr. Anonymous and authenticated clients
have separate state and discard cookies before/after requests.
Bodies from status-only controls are discarded without retaining names or data.
Only a bounded version field and closed-value header summaries survive.
Raw arbitrary headers, cookies and server exception details do not enter reports.

HTTP 401/403 confirms only denial on the named path. HTTP 200 confirms status,
not repository contents, private-data access or runtime settings. Redirects,
404, 429, 5xx, timeouts, malformed version JSON and truncated bodies are incomplete.
CSP/HSTS presence is informational; no full CSP/TLS audit is claimed.

## Offline and output boundary

Configuration review accepts a closed, anonymized JSON schema, never raw server
configuration. Snapshot declarations do not establish runtime behavior, existing
repository visibility or completed MFA enrollment. Missing keys and stale or
unsupported snapshots stay unknown.

Export is offline. Markdown neutralizes untrusted text. JSON/SARIF use serializers.
Output collisions, existing files and symlinks are rejected; atomic writes do not
overwrite input or an existing report. Reports may contain operator-provided
aliases/provenance; the operator must sanitize these inputs before sharing.
