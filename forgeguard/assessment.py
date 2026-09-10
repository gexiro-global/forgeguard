from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .models import Finding, ScanResult

Intent = Literal["public", "private", "unspecified"]
Profile = Literal["minimal", "standard", "extended"]


class EvidenceFinding(Finding):
    check_version: str = "1"
    scope: Literal["http", "version", "operator-snapshot"]
    source: str
    observed: dict = Field(default_factory=dict)
    expected: str
    applicability: Literal[
        "applicable", "undetermined", "not_applicable", "skipped_by_profile"
    ]
    reason: str
    penalty_group: str


class Identity(BaseModel):
    model_config = ConfigDict(extra="forbid")
    declared_product: str | None
    declared_version_marker: str | None = None
    observed_product_marker: str | None
    product_source: str
    declared_version: str | None
    observed_version: str | None
    normalized_version: str | None
    product_conflict: bool
    version_conflict: bool
    support: Literal["qualified", "unsupported", "unknown"]
    provider_revision: str | None


class Assessment(ScanResult):
    schema_id: Literal["forgeguard.assessment.v1"] = "forgeguard.assessment.v1"
    profile: str
    profile_version: Literal["1"] = "1"
    policy: Intent
    policy_version: Literal["1"] = "1"
    scoring_version: Literal["2"] = "2"
    identity: Identity
    catalog: dict
    findings: list[EvidenceFinding]
    skipped_checks: list[str]
    request_count: int
    limitations: list[str]
    run: dict[str, str] = Field(default_factory=dict)

    def normalized(self) -> dict:
        result = self.model_dump(mode="json")
        result.pop("run")
        result.pop("scan_id")
        return result
