from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field

from .version import __version__


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class Status(str, Enum):
    FAIL = "fail"
    WARN = "warn"
    PASS = "pass"
    INFO = "info"


class EvidenceState(str, Enum):
    ASSESSED = "assessed"
    INDETERMINATE = "indeterminate"
    INFORMATIONAL = "informational"


class Finding(BaseModel):
    id: str
    title: str
    severity: Severity
    status: Status
    evidence: dict = Field(default_factory=dict)
    rationale: str = ""
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    cwe: str | None = None
    evidence_state: EvidenceState = EvidenceState.ASSESSED


class Target(BaseModel):
    url: str
    forge: str = "unknown"
    version: str | None = None
    authorized: bool = False
    scope: str = "own-instance"
    product_confirmed: bool = False
    product_source: str = "unconfirmed"


class Score(BaseModel):
    value: int | None
    grade: str
    assessed: bool = True
    max: int = 100
    sub: dict[str, int | None] = Field(default_factory=dict)
    incomplete_checks: list[str] = Field(default_factory=list)


def _default_tool_metadata() -> dict[str, str]:
    return {
        "name": "ForgeGuard",
        "brand": "by Gexiro",
        "version": __version__,
        "schema": "forgeguard.scan-result.v0.3",
        "positioning": "Read-only security posture and supply-chain visibility for self-hosted Gitea.",
    }


class ScanResult(BaseModel):
    tool: dict[str, str] = Field(default_factory=_default_tool_metadata)
    scan_id: str
    target: Target
    score: Score
    findings: list[Finding] = Field(default_factory=list)
    summary: dict[str, int] = Field(default_factory=dict)
