# Usage

ForgeGuard by Gexiro runs read-only posture checks against one explicitly authorized self-hosted target.

## List checks

```bash
python -m forgeguard checks
```

## Confirmed Gitea scan

Use `--product gitea` only when trusted operator inventory confirms the authorized target is Gitea:

```bash
forgeguard scan \
  --url https://git.example.com \
  --authorized \
  --product gitea
```

A legal subpath is supported:

```bash
forgeguard scan \
  --url https://git.example.com/team/gitea \
  --authorized \
  --product gitea
```

Write Markdown and JSON:

```bash
forgeguard scan \
  --url https://git.example.com \
  --authorized \
  --product gitea \
  --format md,json \
  --out ./reports/scan_report.md
```

This writes `scan_report.md` and `scan_report.json`. If both requested formats
resolve to one path, ForgeGuard refuses before scanning or writing.

A trusted inventory version can be supplied when the endpoint is hidden:

```bash
forgeguard scan \
  --url https://git.example.com \
  --authorized \
  --product gitea \
  --known-version 1.26.2
```

`--known-version` without `--product gitea` does not confirm the product and therefore cannot produce a Gitea advisory grade.

## Token input

Preferred:

```bash
FORGEGUARD_TOKEN='replace-with-authorized-token' \
  forgeguard scan \
  --url https://git.example.com \
  --authorized \
  --product gitea
```

The backward-compatible `--token` option emits a security warning because command-line values can be visible in shell history or process listings. Tokens are not written to Markdown or JSON reports.

## Flags

- `--url`: base URL of one authorized target.
- `--authorized`: required operator affirmation of authorization.
- `--product gitea`: trusted operator declaration that enables Gitea-specific advisory conclusions.
- `--token`: legacy optional token input for the authenticated version read; prefer `FORGEGUARD_TOKEN`.
- `--known-version`: version from trusted local inventory; does not establish product identity.
- `--scan-id`: identifier embedded in output artifacts.
- `--out`: output Markdown path; JSON replaces its suffix with `.json`. A collision is refused.
- `--format`: `md`, `json`, or `md,json`.

Target URLs using non-HTTP(S) schemes, missing a hostname, containing credentials/query/fragment, decoded `.`/`..` segments, or backslash separators are refused without echoing sensitive input. Validation iteratively decodes up to eight layers and refuses excessive nested encoding.

## Output and schema

Markdown is intended for operator review. JSON uses `forgeguard.scan-result.v0.3`.

Dynamic Markdown values are rendered on one line with control characters, Markdown metacharacters, and raw HTML neutralized. JSON retains the original structured evidence.

A complete assessment has an integer `value`, A–F `grade`, and `assessed: true`. If a core check is indeterminate, `value` is `null`, `grade` is `"N/A"`, `assessed` is `false`, and `incomplete_checks` identifies the gap.

Findings describe exact, bounded evidence. They do not prove exploitability, compromise, private artifact access, a specific configuration key, or complete security.

## Authorization

ForgeGuard refuses a CLI scan unless `--authorized` is supplied. Target metadata defaults to `authorized: false` and is set true only by the high-level authorized CLI path. This is a truthful workflow guardrail, not a legal authorization mechanism or DRM.
