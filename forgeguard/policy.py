from .assessment import EvidenceFinding
from .models import EvidenceState, Score
from .scoring import finding_penalty, grade_for


def assess_score(findings: list[EvidenceFinding]) -> Score:
    incomplete = sorted(
        f.id
        for f in findings
        if f.evidence_state == EvidenceState.INDETERMINATE
        or f.applicability == "undetermined"
    )
    if not findings:
        incomplete = ["FG-COVERAGE"]
    if incomplete:
        return Score(
            value=None, grade="N/A", assessed=False, incomplete_checks=incomplete
        )
    groups: dict[str, int] = {}
    for f in findings:
        groups[f.penalty_group] = max(
            groups.get(f.penalty_group, 0), finding_penalty(f)
        )
    value = max(0, 100 - sum(groups.values()))
    return Score(value=value, grade=grade_for(value), assessed=True)
