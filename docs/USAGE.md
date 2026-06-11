# Usage

ForgeGuard by Gexiro runs read-only posture checks against one authorized self-hosted Gitea or Forgejo instance.

## List Checks

```bash
python -m forgeguard checks
```

## Scan

```bash
forgeguard scan --url https://git.example.com --authorized
```

Write a Markdown report:

```bash
forgeguard scan --url https://git.example.com --authorized --out ./reports/scan_report.md
```

Write Markdown and JSON:

```bash
forgeguard scan --url https://git.example.com --authorized --format md,json --out ./reports/scan_report.md
```

## Flags

- `--url`: base URL of your authorized Gitea or Forgejo instance.
- `--authorized`: required affirmation that you own or are authorized to assess the target.
- `--token`: optional API token for authenticated version reads when anonymous metadata is hidden.
- `--known-version`: local inventory version to use when the API version endpoint is blocked.
- `--scan-id`: identifier embedded in output artifacts.
- `--out`: output Markdown path; JSON output uses the same path with `.json`.
- `--format`: comma-separated output list, currently `md`, `json`, or `md,json`.

## Output Formats

Markdown is intended for operator review. JSON follows the `forgeguard.scan-result.v0.2` schema represented by `forgeguard.models.ScanResult`.

## Authorization

ForgeGuard refuses scans unless `--authorized` is supplied. This is a workflow guardrail, not a legal authorization mechanism.
