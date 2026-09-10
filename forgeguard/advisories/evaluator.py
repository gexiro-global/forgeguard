import hashlib
import json
from importlib.resources import files

from ..assessment import EvidenceFinding, Identity
from ..models import EvidenceState, Severity, Status
from ..providers.base import release_version
from .models import Advisory


def catalog(product: str) -> tuple[list[Advisory], dict]:
    if product not in {"gitea", "forgejo"}:
        return [], {"version": "2026-09-10.1", "coverage": "unknown product"}
    data = (
        files("forgeguard")
        .joinpath("advisories", "catalog", product + ".json")
        .read_bytes()
    )
    payload = json.loads(data)
    records = [Advisory.model_validate(x) for x in payload["records"]]
    if any(r.product != product for r in records) or len(
        {r.id for r in records}
    ) != len(records):
        raise ValueError("Invalid provider catalog")
    return records, {
        "version": payload["version"],
        "verified_at": payload["verified_at"],
        "sha256": hashlib.sha256(data).hexdigest(),
        "coverage": "Curated records only; absence is not evidence of safety.",
    }


def evaluate(record: Advisory, identity: Identity) -> EvidenceFinding:
    version = release_version(identity.normalized_version)
    outcome = "undetermined"
    reason = "Product/version conflict, unsupported syntax, or version outside catalog evidence."
    if (
        identity.declared_product == record.product
        and not identity.product_conflict
        and not identity.version_conflict
        and version is not None
        and not record.conditions
    ):
        if any(x.contains(version) for x in record.affected):
            outcome = "affected"
        elif any(x.contains(version) for x in record.fixed):
            outcome = "fixed"
        if outcome != "undetermined":
            reason = (
                "Version is within the catalog's explicit " + outcome + " interval."
            )
    return EvidenceFinding(
        id=record.id,
        title=record.title,
        scope="version",
        source="catalog:" + record.product,
        observed={
            "version": identity.normalized_version,
            "record_version": record.record_version,
            "outcome": outcome,
        },
        evidence={"outcome": outcome},
        expected="Version within the explicit fixed range for this advisory.",
        status=Status.FAIL
        if outcome == "affected"
        else Status.PASS
        if outcome == "fixed"
        else Status.INFO,
        severity=Severity(record.severity) if outcome == "affected" else Severity.info,
        evidence_state=EvidenceState.INDETERMINATE
        if outcome == "undetermined"
        else EvidenceState.ASSESSED,
        applicability="undetermined" if outcome == "undetermined" else "applicable",
        reason=reason,
        rationale=reason
        + " Version assessment does not prove exploitability. "
        + record.limitations,
        remediation="Review the upstream advisory and upgrade within a supported line."
        if outcome != "fixed"
        else "",
        references=sorted(record.sources),
        penalty_group="version-advisories",
    )
