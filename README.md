<!-- Badges placeholder: CI, package version, license -->

# ForgeGuard by Gexiro

Read-only security posture self-check for self-hosted Gitea and Forgejo.

ForgeGuard helps operators of self-hosted Gitea/Forgejo instances understand patch currency, registry exposure, anonymous access posture, and basic security configuration without exploit probes or internet-wide scanning. It is intended to close a visibility gap after self-hosting: operators need quick, repeatable evidence about whether one authorized forge is patched and whether anonymous surfaces look intentionally constrained.

## What It Checks In v0.2

- Forge version and patch currency against the fixed Gitea 1.26.2 release for CVE-2026-27771.
- CVE-2026-27771 posture using safe root response inference.
- Anonymous registry posture via safe `/v2/` response inference.
- Sign-in and anonymous access posture.
- Basic registry exposure.

## What It Does NOT Do

- No mass scanning.
- No exploit PoC.
- No private blob or manifest retrieval.
- No unauthenticated third-party probing.
- No AI code review.
- No guarantee of full security.

## Install

```bash
python -m pip install forgeguard
```

For local development:

```bash
python -m pip install -e ".[dev]"
```

## Quickstart

```bash
forgeguard scan --url https://git.example.com --authorized --out ./reports/scan_report.md
```

Use `--known-version` when your version endpoint is intentionally hidden:

```bash
forgeguard scan --url https://git.example.com --authorized --known-version 1.26.2 --format md,json --out ./reports/scan_report.md
```

## Sample Output

Synthetic pre-update example:

```text
# ForgeGuard by Gexiro - https://git.example.com

Read-only security posture and supply-chain visibility for self-hosted Gitea/Forgejo.

Forge: gitea 1.25.3 | Score: 66/100 (C)
Summary: critical 1 | high 1 | medium 0 | low 0 | pass 3
```

See `examples/scan_report_mitigated_pre_update.md` and `examples/scan_report_patched_post_update.md` for complete synthetic reports.

## Scoring

ForgeGuard scoring is deterministic and does not use AI. Findings subtract fixed penalties from 100: critical -40, high -20, medium -10, low -4. Warning findings use `WARN_FACTOR = 0.35`, so a critical warning subtracts 14 points. Grades are A at 90+, B at 75+, C at 60+, D at 40+, and F below 40.

## Security And Ethics

Run ForgeGuard only on instances you own or are explicitly authorized to assess. ForgeGuard v0.2 uses read-only HTTP GET checks and stops at posture signals; it does not request package contents or registry artifacts. Reports are posture evidence, not proof of compromise.

See `AUTHORIZED_USE.md` and `SECURITY.md`.

## Roadmap

- v0.3: runner, token, and TLS posture checks.
- v0.4: optional issue emitter and AI remediation notes.
- v1: supply-chain, SBOM, and OSV enrichment.
- Later: semantic code intelligence.

## Responsible Disclosure

To report a vulnerability in ForgeGuard itself, see `SECURITY.md`.

ForgeGuard by Gexiro

Not affiliated with Gitea, Forgejo, Codeberg, GitHub, or GitLab.
