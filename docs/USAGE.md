# Usage

ForgeGuard by Gexiro runs read-only posture checks against one explicitly authorized self-hosted Gitea instance.

## List checks

```bash
python -m forgeguard checks
```

## Scan

```bash
forgeguard scan --url https://git.example.com --authorized
```

A Gitea sub-path is supported:

```bash
forgeguard scan --url https://git.example.com/gitea --authorized
```

Write Markdown and JSON:

```bash
forgeguard scan \
  --url https://git.example.com \
  --authorized \
  --format md,json \
  --out ./reports/scan_report.md
```

## Token input

Preferred:

```bash
FORGEGUARD_TOKEN='replace-with-authorized-token' \
  forgeguard scan --url https://git.example.com --authorized
```

The backward-compatible `--token` option emits a security warning because command-line values can be visible in shell history or process listings. Tokens are not written to Markdown or JSON reports.

## Flags

- `--url`: base URL of one authorized Gitea instance.
- `--authorized`: required operator affirmation of authorization.
- `--token`: legacy optional token input for the authenticated version read; prefer `FORGEGUARD_TOKEN`.
- `--known-version`: Gitea version from trusted local inventory.
- `--scan-id`: identifier embedded in output artifacts.
- `--out`: output Markdown path; JSON uses the same path with `.json`.
- `--format`: `md`, `json`, or `md,json`.

Target URLs using non-HTTP(S) schemes, missing a hostname, or containing credentials, a query, or a fragment are refused without echoing the sensitive URL.

## Output limits

Markdown is intended for operator review. JSON uses the `forgeguard.scan-result.v0.2` schema.

Findings describe Gitea version posture and exact checked HTTP response behavior. They do not prove exploitability, compromise, private artifact access, a specific configuration key, or complete security.

## Authorization

ForgeGuard refuses a scan unless `--authorized` is supplied. This is a workflow guardrail, not a legal authorization mechanism.
