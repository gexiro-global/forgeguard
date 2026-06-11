from __future__ import annotations

from .models import Finding, Score, Severity, Status

# Deterministic scoring for ForgeGuard by Gexiro.
# The tool does not infer risk with AI; operators can adjust these constants if
# their environment needs a different calibration.
SEVERITY_WEIGHT: dict[Severity, int] = {
    Severity.critical: 40,
    Severity.high: 20,
    Severity.medium: 10,
    Severity.low: 4,
    Severity.info: 0,
}
WARN_FACTOR = 0.35

_SUBSCORE_BUCKETS: dict[str, list[str]] = {
    "patch": ["FG-VER"],
    "registry": ["FG-REG", "FG-CVE-27771"],
    "auth": ["FG-SIGNIN", "FG-ANON", "FG-VER-DISCLOSE"],
    "runner": ["FG-ACT"],
}


def finding_penalty(finding: Finding) -> int:
    weight = SEVERITY_WEIGHT.get(finding.severity, 0)
    if finding.status == Status.FAIL:
        return weight
    if finding.status == Status.WARN:
        return int(weight * WARN_FACTOR)
    return 0


def priority_key(finding: Finding) -> tuple[int, int, str]:
    status_rank = {
        Status.FAIL: 2,
        Status.WARN: 1,
        Status.INFO: 0,
        Status.PASS: 0,
    }
    return (finding_penalty(finding), status_rank.get(finding.status, 0), finding.id)


def grade_for(value: int) -> str:
    if value >= 90:
        return "A"
    if value >= 75:
        return "B"
    if value >= 60:
        return "C"
    if value >= 40:
        return "D"
    return "F"


def _subscores(findings: list[Finding]) -> dict[str, int]:
    out: dict[str, int] = {}
    for name, ids in _SUBSCORE_BUCKETS.items():
        value = 100
        for finding in findings:
            if any(finding.id.startswith(check_id) for check_id in ids):
                value -= finding_penalty(finding)
        out[name] = max(0, value)
    return out


def score_findings(findings: list[Finding]) -> Score:
    value = max(0, 100 - sum(finding_penalty(finding) for finding in findings))
    return Score(value=value, grade=grade_for(value), sub=_subscores(findings))
