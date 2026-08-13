from __future__ import annotations

from .models import Finding, ScanResult, Status
from .scoring import priority_key


def _finding_by_id(findings: list[Finding], finding_id: str) -> Finding | None:
    return next((finding for finding in findings if finding.id == finding_id), None)


def _finding_label(finding: Finding) -> str:
    if finding.status == Status.PASS:
        if finding.id in {"FG-VER", "FG-CVE-27771"}:
            return "PASS - at or above first fixed release"
        return "PASS"
    return f"{finding.status.value.upper()} / {finding.severity.value.upper()}"


def _evidence_summary(finding: Finding) -> str:
    keys = {
        "FG-VER": ("product", "version", "first_fixed_in"),
        "FG-CVE-27771": ("product", "version", "affected_through", "first_fixed_in"),
        "FG-SIGNIN": ("anon_api", "anon_explore"),
        "FG-REG": ("anon_v2_http",),
        "FG-ANON": ("open", "checked"),
    }.get(finding.id)
    if keys is None:
        data = finding.evidence
    else:
        data = {key: finding.evidence[key] for key in keys if key in finding.evidence}
    return str(data)


def _top_actions(findings: list[Finding]) -> list[str]:
    actionable = [
        finding for finding in findings if finding.status in (Status.FAIL, Status.WARN)
    ]
    version = _finding_by_id(actionable, "FG-VER")
    cve = _finding_by_id(actionable, "FG-CVE-27771")
    actions: list[str] = []
    consumed: set[str] = set()
    if version is not None and cve is not None:
        actions.append(
            "- **P1 - Upgrade Gitea to >=1.26.2** - the installed version is within the "
            "affected range for CVE-2026-27771; this version result does not prove exploitability."
        )
        consumed.update({"FG-VER", "FG-CVE-27771"})
    for index, finding in enumerate(
        sorted(
            (finding for finding in actionable if finding.id not in consumed),
            key=priority_key,
            reverse=True,
        ),
        start=2 if actions else 1,
    ):
        remediation = (
            finding.remediation or "Review finding evidence and decide operator action."
        )
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
    out.append(
        "Read-only security posture and supply-chain visibility for self-hosted Gitea."
    )
    out.append("")
    out.append(
        f"**Product:** {result.target.forge} {result.target.version or '(unknown)'}  |  "
        f"**Score:** {result.score.value}/100 ({result.score.grade})"
    )
    out.append(
        f"**Scope:** {result.target.scope} | authorized | read-only | single target | "
        f"**Scan:** {result.scan_id}"
    )
    out.append("")
    out.append(
        f"**Summary:** critical {summary.get('critical', 0)} | "
        f"high {summary.get('high', 0)} | medium {summary.get('medium', 0)} | "
        f"low {summary.get('low', 0)} | pass {summary.get('pass', 0)}"
    )
    out.append("")
    out.append("## Top actions")
    top_actions = _top_actions(findings)
    if not top_actions:
        out.append("- None - no FAIL or WARN findings.")
    else:
        out.extend(top_actions)
    out.append("")
    out.append("## Interpretation")
    out.append(
        "- FG-VER and FG-CVE-27771 report Gitea version posture against the first fixed release."
    )
    out.append(
        "- Registry-root and anonymous-access checks are independent HTTP observations; "
        "they do not prove CVE exploitability or private artifact access."
    )
    out.append(
        "- PASS means the checked condition passed; it is not a claim that the whole instance is secure."
    )
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
        out.append(f"- **State:** {_finding_label(finding)}")
        out.append(f"- **Rationale:** {finding.rationale}")
        if finding.remediation:
            out.append(f"- **Action:** {finding.remediation}")
        if finding.references:
            out.append(f"- **Refs:** {', '.join(finding.references)}")
        out.append(f"- **Evidence:** `{_evidence_summary(finding)}`")
        out.append("")
    out.append("---")
    out.append("ForgeGuard by Gexiro | own/authorized Gitea instances only | read-only")
    return "\n".join(out)
