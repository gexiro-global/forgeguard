from __future__ import annotations

from .models import Finding, ScanResult, Status
from .scoring import priority_key


def _finding_by_id(findings: list[Finding], finding_id: str) -> Finding | None:
    return next((finding for finding in findings if finding.id == finding_id), None)


def _finding_label(finding: Finding) -> str:
    if finding.id == "FG-CVE-27771" and finding.status == Status.WARN and finding.severity.value == "critical":
        return "WARN / CRITICAL CVE - mitigated but unpatched"
    if finding.id == "FG-CVE-27771" and finding.status == Status.FAIL:
        return "FAIL / CRITICAL CVE - active exposure"
    if finding.status == Status.PASS:
        return "PASS - patched" if finding.id in {"FG-VER", "FG-CVE-27771"} else "PASS"
    return f"{finding.status.value.upper()} / {finding.severity.value.upper()}"


def _evidence_summary(finding: Finding) -> str:
    keys = {
        "FG-VER": ("version", "fixed_in"),
        "FG-CVE-27771": ("version", "anon_v2_http", "signin_required_inferred", "registry_anon_open"),
        "FG-SIGNIN": ("anon_api", "anon_explore"),
        "FG-REG": ("anon_v2_http",),
        "FG-ANON": ("open", "probed"),
    }.get(finding.id)
    if keys is None:
        data = finding.evidence
    else:
        data = {key: finding.evidence[key] for key in keys if key in finding.evidence}
    return str(data)


def _top_actions(findings: list[Finding]) -> list[str]:
    actionable = [finding for finding in findings if finding.status in (Status.FAIL, Status.WARN)]
    version = _finding_by_id(actionable, "FG-VER")
    cve = _finding_by_id(actionable, "FG-CVE-27771")
    actions: list[str] = []
    consumed: set[str] = set()
    if version is not None and cve is not None:
        actions.append(
            "- **P1 - Update Gitea to >=1.26.2** - CVE-2026-27771 window present, "
            "mitigation active, code-level fix missing."
        )
        consumed.update({"FG-VER", "FG-CVE-27771"})
    for index, finding in enumerate(
        sorted((f for f in actionable if f.id not in consumed), key=priority_key, reverse=True),
        start=2 if actions else 1,
    ):
        remediation = finding.remediation or "Review finding evidence and decide operator action."
        actions.append(f"- **P{index} - {finding.title}** - {remediation}")
        if len(actions) >= 5:
            break
    return actions


def render_markdown(result: ScanResult) -> str:
    findings = sorted(result.findings, key=priority_key, reverse=True)
    summary = result.summary
    out: list[str] = []
    out.append(f"# ForgeGuard by Gexiro - {result.target.url}")
    out.append("")
    out.append("Read-only security posture and supply-chain visibility for self-hosted Gitea/Forgejo.")
    out.append("")
    out.append(f"**Forge:** {result.target.forge} {result.target.version or '(unknown)'}  |  "
               f"**Score:** {result.score.value}/100 ({result.score.grade})")
    out.append(f"**Scope:** {result.target.scope} | authorized | read-only | single target | **Scan:** {result.scan_id}")
    out.append("")
    out.append(f"**Summary:** critical {summary.get('critical', 0)} | high {summary.get('high', 0)} | "
               f"medium {summary.get('medium', 0)} | low {summary.get('low', 0)} | pass {summary.get('pass', 0)}")
    out.append("")
    out.append("## Top actions")
    top_actions = _top_actions(findings)
    if not top_actions:
        out.append("- None - all checks pass.")
    else:
        out.extend(top_actions)
    out.append("")
    out.append("## Interpretation")
    out.append("- FG-VER reports patch currency: vulnerable version, patched, or unknown.")
    out.append("- FG-CVE-27771 reports exposure posture: active exposure, mitigated posture, patched, or unknown.")
    out.append("- A mitigated posture still needs the code-level update because mitigation is not the patch.")
    out.append("")
    out.append("## Sub-scores")
    out.append("| Domain | Score |")
    out.append("|--------|------:|")
    for key in ("patch", "registry", "auth", "runner"):
        out.append(f"| {key} | {result.score.sub.get(key, '-')} |")
    out.append("")
    out.append("## Findings")
    for finding in findings:
        out.append(f"### {finding.id} - {finding.title}")
        out.append(f"**State:** {_finding_label(finding)}  ")
        out.append(f"**Rationale:** {finding.rationale}  ")
        if finding.remediation:
            out.append(f"**Action:** {finding.remediation}  ")
        if finding.references:
            out.append(f"**Refs:** {', '.join(finding.references)}  ")
        out.append(f"**Evidence:** `{_evidence_summary(finding)}`")
        out.append("")
    out.append("---")
    out.append("ForgeGuard by Gexiro | own/authorized instances only | read-only by default")
    return "\n".join(out)
