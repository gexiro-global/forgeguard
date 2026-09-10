import hashlib

from ..models import Status
from .json import report_data


def to_sarif(result):
    data = report_data(result)
    findings = sorted(result.findings, key=lambda f: f.id)
    rules = [
        {
            "id": f.id,
            "shortDescription": {"text": f.title},
            "fullDescription": {"text": f.rationale or f.title},
            "help": {"text": f.remediation or "Review the limited evidence."},
            "properties": {"references": sorted(f.references)},
        }
        for f in findings
    ]
    results = []
    for index, f in enumerate(findings):
        if f.status not in (Status.WARN, Status.FAIL):
            continue
        fingerprint = hashlib.sha256(
            (
                result.target.url + "\0" + f.id + "\0" + data.get("policy", "legacy")
            ).encode()
        ).hexdigest()
        results.append(
            {
                "ruleId": f.id,
                "ruleIndex": index,
                "level": "error" if f.status == Status.FAIL else "warning",
                "message": {"text": f.rationale or f.title},
                "partialFingerprints": {"forgeguard/v1": fingerprint},
                "properties": {
                    "evidence_state": f.evidence_state.value,
                    "versionOnly": getattr(f, "scope", None) == "version",
                },
            }
        )
    return {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ForgeGuard",
                        "version": result.tool["version"],
                        "informationUri": "https://github.com/gexiro-global/forgeguard",
                        "rules": rules,
                    }
                },
                "results": results,
                "invocations": [{"executionSuccessful": True}],
                "properties": {
                    "assessmentComplete": result.score.assessed,
                    "incompleteChecks": result.score.incomplete_checks,
                    "skippedChecks": data.get("skipped_checks", []),
                    "profile": data.get("profile", "legacy"),
                    "policy": data.get("policy", "unspecified"),
                    "limitations": data.get("limitations", []),
                    "catalog": data.get("catalog", {}),
                },
            }
        ],
    }
