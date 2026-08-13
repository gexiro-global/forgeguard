# forgeguard

[![CI](https://github.com/gexiro-global/forgeguard/actions/workflows/ci.yml/badge.svg)](https://github.com/gexiro-global/forgeguard/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/forgeguard.svg)](https://pypi.org/project/forgeguard/)
[![Python](https://img.shields.io/pypi/pyversions/forgeguard.svg)](https://pypi.org/project/forgeguard/)
[![License: Apache-2.0](https://img.shields.io/pypi/l/forgeguard.svg)](https://github.com/gexiro-global/forgeguard/blob/main/LICENSE)

Read-only security posture self-check for one explicitly authorized self-hosted Gitea instance.

ForgeGuard gives Gitea operators repeatable evidence about version posture, the fixed-version baseline for CVE-2026-27771, anonymous OCI registry-root reachability, and anonymous responses on a small allowlist of repository/API paths. It uses no exploit probes, performs no internet-wide discovery, and does not request private package contents, manifests, or blobs.

## Supported scope in 0.2.2

ForgeGuard 0.2.2 supports self-hosted Gitea. Forgejo is not currently supported: a version string explicitly marked as Forgejo fails safe as an unsupported product, and ForgeGuard does not apply Gitea version or advisory conclusions to it.

One invocation accepts one target URL and refuses to run without the operator's `--authorized` affirmation.

## What it checks

- Gitea version and patch posture against the first release containing the fix for CVE-2026-27771.
- CVE-2026-27771 affected/fixed/unknown version posture for confirmed Gitea.
- Anonymous OCI `/v2/` registry-root response posture as an independent observation.
- Observed access-control responses on two checked repository/API paths.
- Anonymous HTTP 200 responses on three explicitly allowlisted repository/API paths.
- Markdown and JSON evidence with deterministic scoring.

## Evidence limits

- A CVE version result does not prove exploitability, compromise, or data exposure.
- OCI `/v2/` HTTP 200 does not prove access to private packages, manifests, or blobs.
- Sign-in and anonymous findings describe only the checked paths and status codes; ForgeGuard does not claim that a specific Gitea configuration key is set.
- A PASS finding is not a claim that the whole instance is secure.
- Registration posture is not checked in 0.2.2.
- Forgejo-specific detection, version semantics, advisory sources, and tests are planned work, not current capability.

## What it does not do

- No mass scanning or target discovery.
- No exploit proof of concept.
- No unauthenticated third-party assessment.
- No private repository, package, blob, manifest, or layer retrieval.
- No state-changing remote requests.
- No AI in scoring.
- No guarantee of complete security.

## Install

```bash
python -m pip install forgeguard
```

Or install the latest source revision:

```bash
python -m pip install "git+https://github.com/gexiro-global/forgeguard.git"
```

For local development:

```bash
git clone https://github.com/gexiro-global/forgeguard.git
cd forgeguard
python -m pip install -e ".[dev]"
```

## Quickstart

```bash
mkdir -p reports
forgeguard scan \
  --url https://git.example.com \
  --authorized \
  --out ./reports/scan_report.md
```

Use a version from trusted operator inventory when the authorized version endpoint is intentionally hidden:

```bash
forgeguard scan \
  --url https://git.example.com/gitea \
  --authorized \
  --known-version 1.26.2 \
  --format md,json \
  --out ./reports/scan_report.md
```

Target URLs must use HTTP or HTTPS, include a hostname, and contain no embedded credentials, query, or fragment. A legal Gitea sub-path is preserved.

## Token handling

Prefer an environment variable so the token is not placed directly in shell history or process arguments:

```bash
FORGEGUARD_TOKEN='replace-with-authorized-token' \
  forgeguard scan --url https://git.example.com --authorized
```

The backward-compatible `--token` option remains available, but ForgeGuard emits a security warning because command-line values may be visible in shell history or process listings. Tokens are used only for the authorized version read and are not included in Markdown or JSON reports.

## Synthetic before/after

The synthetic example compares an affected Gitea version with the first fixed release. It does not claim that ForgeGuard tested exploitation or private data access.

**Before** — Gitea `1.26.1`, within the affected version range:

```text
# ForgeGuard by Gexiro - https://git.example.com
Product: gitea 1.26.1 | Score: 60/100 (C)
Summary: critical 0 | high 2 | medium 0 | low 0 | pass 3
Top action: P1 - Upgrade Gitea to >=1.26.2
```

**After** — Gitea `1.26.2`, at the first fixed release:

```text
# ForgeGuard by Gexiro - https://git.example.com
Product: gitea 1.26.2 | Score: 100/100 (A)
Summary: critical 0 | high 0 | medium 0 | low 0 | pass 5
Top action: None - no FAIL or WARN findings.
```

| Finding | Affected version (1.26.1) | First fixed release (1.26.2) |
|---|---|---|
| FG-VER — patch currency | FAIL / HIGH | **PASS** |
| FG-CVE-27771 — version posture | FAIL / HIGH | **PASS** |
| FG-SIGNIN / FG-REG / FG-ANON | PASS | PASS |
| **Score** | **60/100 (C)** | **100/100 (A)** |

Full synthetic artifacts:

- [Affected version Markdown](examples/scan_report_affected_pre_update.md)
- [Affected version JSON](examples/scan_result_affected_pre_update.json)
- [First fixed release Markdown](examples/scan_report_patched_post_update.md)
- [First fixed release JSON](examples/scan_result_patched_post_update.json)

## Scoring

Scoring is deterministic and does not use AI. FAIL findings subtract the full severity weight: critical 40, high 20, medium 10, low 4. WARN findings subtract `int(weight * 0.35)`. Grades are A at 90+, B at 75+, C at 60+, D at 40+, and F below 40.

The score summarizes only ForgeGuard's limited checks. It is not a complete hardening or compromise assessment.

## Security and ethics

Run ForgeGuard only on a Gitea instance you own or are explicitly authorized to assess. ForgeGuard uses read-only HTTP GET requests to an exact allowlist and stops at version, root-response, and status-code evidence.

See [Authorized Use](AUTHORIZED_USE.md), [Security Policy](SECURITY.md), and [Security Model](docs/SECURITY_MODEL.md).

## Roadmap

Forgejo support and registration posture are future, product-specific work and are not implemented in 0.2.2. See [ROADMAP.md](ROADMAP.md).

## License

Apache-2.0. See [LICENSE](LICENSE).

Built and maintained by [Gexiro Global Enterprises Ltd](https://gexiro.com).

Part of the [Gexiro open-source toolkit](https://github.com/gexiro-global).

ForgeGuard by Gexiro

Not affiliated with Gitea, Forgejo, Codeberg, GitHub, or GitLab.
