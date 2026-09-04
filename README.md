# forgeguard

[![CI](https://github.com/gexiro-global/forgeguard/actions/workflows/ci.yml/badge.svg)](https://github.com/gexiro-global/forgeguard/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/forgeguard.svg)](https://pypi.org/project/forgeguard/)
[![Python](https://img.shields.io/pypi/pyversions/forgeguard.svg)](https://pypi.org/project/forgeguard/)
[![License: Apache-2.0](https://img.shields.io/pypi/l/forgeguard.svg)](https://github.com/gexiro-global/forgeguard/blob/main/LICENSE)

[Security and trust evidence](docs/SECURITY-TRUST.md) documents the project's policies and automated checks. No certification or badge level is claimed.

Read-only security posture self-check for one explicitly authorized self-hosted Gitea instance.

ForgeGuard gives Gitea operators repeatable evidence about version posture, the fixed-version baseline for CVE-2026-27771, anonymous OCI registry-root behavior, and anonymous responses on a small allowlist of repository/API paths. It uses no exploit probes, performs no internet-wide discovery, and does not request private package contents, manifests, or blobs.

Official product page: [gexiro.com/forgeguard](https://gexiro.com/forgeguard)

## Supported scope in 0.2.2

ForgeGuard 0.2.2 supports self-hosted Gitea. Gitea-specific conclusions require the trusted operator declaration `--product gitea`; a compatible version endpoint or `--known-version` alone does not confirm product identity.

Forgejo is not supported. An explicit Forgejo version marker overrides a conflicting Gitea declaration and fails safe as unsupported. ForgeGuard does not apply Gitea version or advisory conclusions to that target.

One invocation accepts one target URL and refuses to run without the operator's `--authorized` affirmation.

## What it checks

- Informational product/version evidence.
- CVE-2026-27771 affected/fixed/unknown version posture for operator-confirmed Gitea.
- Anonymous OCI `/v2/` registry-root response posture as an independent observation.
- Repository browsing posture on the allowlisted `/explore/repos` path.
- Anonymous HTTP responses on the two allowlisted repository and user-search API paths.
- Non-overlapping score ownership between the browsing and API observations.
- Markdown and JSON evidence with deterministic scoring and explicit completeness.

## Evidence and completeness semantics

- `PASS` means evidence supports only the named checked condition.
- `WARN` or `FAIL` means the named observation produced an actionable result.
- `INFO / UNDETERMINED` means evidence was insufficient or ambiguous.
- If any core check is undetermined, the final assessment is `value: null`, `grade: "N/A"`, `assessed: false` rather than a normal A–F grade.
- HTTP 404, redirects, 429, 5xx and network failures do not become PASS.
- A CVE version result does not prove exploitability, compromise, or data exposure.
- OCI `/v2/` HTTP 200 does not prove access to private packages, manifests, or blobs.
- ForgeGuard does not infer `REQUIRE_SIGNIN_VIEW` or any specific configuration key from HTTP behavior.
- Registration posture is not checked in 0.2.2.

## What it does not do

- No mass scanning or target discovery.
- No exploit proof of concept.
- No unauthenticated third-party assessment.
- No private repository, package, blob, manifest, or layer retrieval.
- No state-changing remote requests.
- No AI in scoring.
- No security certification, vulnerability oracle, or guarantee of complete security.

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

Raw source-tree execution can inherit metadata from a different installed ForgeGuard distribution. Install the source/editable package before relying on runtime version metadata.

## Quickstart

```bash
mkdir -p reports
forgeguard scan \
  --url https://git.example.com \
  --authorized \
  --product gitea \
  --out ./reports/scan_report.md
```

Use a version from trusted operator inventory when the authorized version endpoint is intentionally hidden:

```bash
forgeguard scan \
  --url https://git.example.com/gitea \
  --authorized \
  --product gitea \
  --known-version 1.26.2 \
  --format md,json \
  --out ./reports/scan_report.md
```

`--out` names the Markdown artifact. JSON replaces that suffix with `.json`;
ForgeGuard refuses a dual-format invocation if both names resolve to the same file.

Omitting `--product` keeps the product unknown and prevents a Gitea-specific A–F grade, even if a generic version value is returned.

Target URLs must use HTTP or HTTPS, include a hostname, and contain no embedded credentials, query, fragment, decoded `.`/`..` segment, or backslash separator at any of eight decoded layers. Excessive nested encoding is refused. Legal subpaths such as `/team/gitea` are preserved.

## Token handling

Prefer an environment variable so the token is not placed directly in shell history or process arguments:

```bash
FORGEGUARD_TOKEN='replace-with-authorized-token' \
  forgeguard scan \
  --url https://git.example.com \
  --authorized \
  --product gitea
```

The backward-compatible `--token` option remains available, but ForgeGuard emits a security warning because command-line values may be visible in shell history or process listings. Tokens are used only for the authorized version read and are not included in Markdown or JSON reports.

## Synthetic before/after

The synthetic example uses an operator-confirmed Gitea target and explicit 401/403 access-control observations. It does not claim that ForgeGuard tested exploitation or private data access.

**Before** — Gitea `1.26.1`, within the affected version range:

```text
Product: gitea 1.26.1 | Score: 80/100 (B)
Summary: critical 0 | high 1 | medium 0 | low 0 | pass 4
Top action: P1 - Upgrade Gitea to >=1.26.2
```

**After** — Gitea `1.26.2`, at the first fixed release:

```text
Product: gitea 1.26.2 | Score: 100/100 (A)
Summary: critical 0 | high 0 | medium 0 | low 0 | pass 5
Top action: None - no FAIL or WARN findings and all core checks were assessed.
```

| Finding | Affected version (1.26.1) | First fixed release (1.26.2) |
|---|---|---|
| FG-VER — version evidence | PASS / informational | PASS / informational |
| FG-CVE-27771 — version posture | FAIL / HIGH | PASS |
| FG-SIGNIN / FG-REG / FG-ANON | PASS | PASS |
| Assessment | complete | complete |
| **Score** | **80/100 (B)** | **100/100 (A)** |

Full mechanically generated artifacts:

- [Affected version Markdown](examples/scan_report_affected_pre_update.md)
- [Affected version JSON](examples/scan_result_affected_pre_update.json)
- [First fixed release Markdown](examples/scan_report_patched_post_update.md)
- [First fixed release JSON](examples/scan_result_patched_post_update.json)

## Scoring

Scoring is deterministic and does not use AI. `FG-VER` is informational. `FG-CVE-27771` is the only finding that penalizes the CVE affected-version condition, so the same version fact is not counted twice.

Likewise, `FG-SIGNIN` owns only the browser path and `FG-ANON` owns only the API paths, so one HTTP observation cannot be charged twice.

FAIL findings subtract the full severity weight: critical 40, high 20, medium 10, low 4. WARN findings subtract `int(weight * 0.35)`. A–F grades are emitted only when every core check is assessed. Otherwise the assessment is N/A, not zero and not A.

The score summarizes only ForgeGuard's limited checks. It is not a complete hardening, exploitability, compromise, registration, or private-artifact assessment. See [Scoring](docs/SCORING.md).

## Security and ethics

Run ForgeGuard only on a Gitea instance you own or are explicitly authorized to assess. ForgeGuard uses read-only HTTP GET requests to an exact allowlist and stops at version, root-response, and status-code evidence.

See [Authorized Use](AUTHORIZED_USE.md), [Security Policy](SECURITY.md), and [Security Model](docs/SECURITY_MODEL.md).

## Commercial hardening

Gexiro offers a paid Hardening Report for authorized Gitea operators who want human review of bounded evidence, explicit limitations, prioritized findings, and a practical remediation plan.

A Remediation Sprint is a separate engagement: scope and acceptance criteria are frozen first, changes begin only after explicit approval, and the result includes before/after verification. Scope expansion, third-party targets, and remote changes require separate written authorization.

ForgeGuard remains usable as a free OSS CLI without a hosted account or control plane. Heavy SaaS and recurring monitoring are not offered at this stage.

[Request a scoped ForgeGuard Hardening Report](mailto:contact@gexiro.com?subject=ForgeGuard%20Hardening%20Report)

## Roadmap

Forgejo support and registration posture are future, product-specific work and are not implemented in 0.2.2. See [ROADMAP.md](ROADMAP.md).

## License

Apache-2.0. See [LICENSE](LICENSE).

Built and maintained by [Gexiro Global Enterprises Ltd](https://gexiro.com).

Part of the [Gexiro open-source toolkit](https://github.com/gexiro-global).

ForgeGuard by Gexiro

Not affiliated with Gitea, Forgejo, Codeberg, GitHub, or GitLab.
