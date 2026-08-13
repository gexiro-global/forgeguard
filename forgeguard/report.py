from __future__ import annotations

from .models import EvidenceState, Finding, ScanResult, Status
from .scoring import priority_key


def _finding_label(finding: Finding) -> str:
    if finding.status == Status.PASS:
        if finding.id == "FG-CVE-27771":
            return "PASS - at or above first fixed release"
        if finding.id == "FG-VER":
            return "PASS - version observed"
        return "PASS"
    if (
        finding.status == Status.INFO
        and finding.evidence_state == EvidenceState.INDETERMINATE
    ):
        return "INFO / UNDETERMINED"
    if (
        finding.status == Status.INFO
        and finding.evidence_state == EvidenceState.INFORMATIONAL
    ):
        return "INFO / INFORMATIONAL"
    return f"{finding.status.value.upper()} / {finding.severity.value.upper()}"


def _evidence_summary(finding: Finding) -> str:
    keys = {
        "FG-VER": (
            "product",
            "product_confirmed",
            "product_source",
            "version",
        ),
        "FG-CVE-27771": (
            "product",
            "product_confirmed",
            "product_source",
            "version",
            "affected_through",
            "first_fixed_in",
        ),
        "FG-SIGNIN": ("anon_api", "anon_explore"),
        "FG-REG": ("anon_v2_http",),
        "FG-ANON": ("open", "checked"),
    }.get(finding.id)
    if keys is None:
        data = finding.evidence
    else:
        data = {key: finding.evidence[key] for key in keys if key in finding.evidence}
    return str(data)


def _top_actions(findings: list[Finding], incomplete_checks: list[str]) -> list[str]:
    actions: list[str] = []
    if incomplete_checks:
        checks = ", ".join(incomplete_checks)
        actions.append(
            "- **P1 - Complete assessment evidence** - the assessment is ungraded "
            f"because these core checks are indeterminate: {checks}."
        )
    actionable = [
        finding for finding in findings if finding.status in (Status.FAIL, Status.WARN)
    ]
    for finding in sorted(actionable, key=priority_key, reverse=True):
        index = len(actions) + 1
        if finding.id == "FG-CVE-27771" and finding.status == Status.FAIL:
            actions.append(
                f"- **P{index} - Upgrade Gitea to >=1.26.2** - the confirmed version "
                "is within the affected range for CVE-2026-27771; this version result "
                "does not prove exploitability."
            )
        else:
            remediation = (
                finding.remediation
                or "Review finding evidence and decide operator action."
            )
            actions.append(f"- **P{index} - {finding.title}** - {remediation}")
        if len(actions) >= 5:
            break
    return actions


def render_markdown(result: ScanResult) -> str:
    findings = sorted(result.findings, key=priority_key, reverse=True)
    summary = result.summary
    if result.score.assessed:
        score_display = f"{result.score.value}/100 ({result.score.grade})"
    else:
        score_display = "N/A (assessment incomplete)"
    out: list[str] = []
    out.append(f"# ForgeGuard by Gexiro - {result.target.url}")
    out.append("")
    out.append(
        "Read-only security posture and supply-chain visibility for self-hosted Gitea."
    )
    out.append("")
    out.append(
        f"**Product:** {result.target.forge} {result.target.version or '(unknown)'}  |  "
        f"**Score:** {score_display}"
    )
    out.append(
        f"**Product confirmation:** {result.target.product_confirmed} "
        f"({result.target.product_source})"
    )
    authorization = "authorized" if result.target.authorized else "not affirmed"
    out.append(
        f"**Scope:** {result.target.scope} | {authorization} | read-only | single target | "
        f"**Scan:** {result.scan_id}"
    )
    out.append("")
    out.append(
        f"**Summary:** critical {summary.get('critical', 0)} | "
        f"high {summary.get('high', 0)} | medium {summary.get('medium', 0)} | "
        f"low {summary.get('low', 0)} | info {summary.get('info', 0)} | "
        f"pass {summary.get('pass', 0)}"
    )
    out.append("")
    out.append("## Top actions")
    top_actions = _top_actions(findings, result.score.incomplete_checks)
    if not top_actions:
        out.append(
            "- None - no FAIL or WARN findings and all core checks were assessed."
        )
    else:
        out.extend(top_actions)
    out.append("")
    out.append("## Interpretation")
    out.append(
        "- FG-VER is informational version evidence. FG-CVE-27771 is the only finding "
        "that scores the CVE affected-version condition."
    )
    out.append(
        "- PASS means evidence supports only the named checked condition; it is not a "
        "claim that the whole instance is secure."
    )
    out.append(
        "- INFO / UNDETERMINED means evidence was insufficient. If any core check is "
        "undetermined, the assessment is N/A rather than an A-F grade."
    )
    out.append(
        "- Registry-root and anonymous-access checks are independent HTTP observations; "
        "they do not prove CVE exploitability or private artifact access."
    )
    out.append("")
    out.append("## Sub-scores")
    out.append("| Domain | Score |")
    out.append("|--------|------:|")
    for key in ("patch", "registry", "auth"):
        value = result.score.sub.get(key)
        out.append(f"| {key} | {value if value is not None else 'N/A'} |")
    out.append("")
    out.append("## Findings")
    for finding in findings:
        out.append(f"### {finding.id} - {finding.title}")
        out.append(f"- **State:** {_finding_label(finding)}")
        out.append(f"- **Evidence state:** {finding.evidence_state.value}")
        out.append(f"- **Rationale:** {finding.rationale}")
        if finding.remediation:
            out.append(f"- **Action:** {finding.remediation}")
        if finding.references:
            out.append(f"- **Refs:** {', '.join(finding.references)}")
        if finding.cwe:
            out.append(f"- **CWE:** {finding.cwe}")
        out.append(f"- **Evidence:** `{_evidence_summary(finding)}`")
        out.append("")
    out.append("---")
    out.append("ForgeGuard by Gexiro | own/authorized Gitea instances only | read-only")
    return "\n".join(out)
