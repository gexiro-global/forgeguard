from __future__ import annotations

from .models import EvidenceState, Finding, Score, Severity, Status

# Deterministic scoring for VersionSec by Gexiro.
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

CORE_CHECK_IDS = ("FG-CVE-27771", "FG-REG", "FG-SIGNIN", "FG-ANON")

_SUBSCORE_BUCKETS: dict[str, tuple[str, ...]] = {
    "patch": ("FG-CVE-27771",),
    "registry": ("FG-REG",),
    "auth": ("FG-SIGNIN", "FG-ANON", "FG-VER-DISCLOSE"),
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


def _subscores(findings: list[Finding]) -> dict[str, int | None]:
    out: dict[str, int | None] = {}
    by_id = {finding.id: finding for finding in findings}
    for name, ids in _SUBSCORE_BUCKETS.items():
        selected = [by_id[check_id] for check_id in ids if check_id in by_id]
        required = [check_id for check_id in ids if check_id in CORE_CHECK_IDS]
        if any(
            check_id not in by_id
            or by_id[check_id].evidence_state != EvidenceState.ASSESSED
            for check_id in required
        ):
            out[name] = None
            continue
        out[name] = max(0, 100 - sum(finding_penalty(item) for item in selected))
    return out


def score_findings(findings: list[Finding]) -> Score:
    by_id = {finding.id: finding for finding in findings}
    incomplete = [
        check_id
        for check_id in CORE_CHECK_IDS
        if check_id not in by_id
        or by_id[check_id].evidence_state != EvidenceState.ASSESSED
    ]
    if incomplete:
        return Score(
            value=None,
            grade="N/A",
            assessed=False,
            sub=_subscores(findings),
            incomplete_checks=incomplete,
        )
    value = max(0, 100 - sum(finding_penalty(finding) for finding in findings))
    return Score(
        value=value,
        grade=grade_for(value),
        assessed=True,
        sub=_subscores(findings),
    )
