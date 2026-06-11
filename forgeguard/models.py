from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


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


class Target(BaseModel):
    url: str
    forge: str = "unknown"
    version: str | None = None
    authorized: bool = True
    scope: str = "own-instance"


class Score(BaseModel):
    value: int
    grade: str
    max: int = 100
    sub: dict[str, int] = Field(default_factory=dict)


def _default_tool_metadata() -> dict[str, str]:
    return {
        "name": "ForgeGuard",
        "brand": "by Gexiro",
        "version": "0.2.0",
        "schema": "forgeguard.scan-result.v0.2",
        "positioning": "Read-only security posture and supply-chain visibility for self-hosted Gitea/Forgejo.",
    }


class ScanResult(BaseModel):
    tool: dict[str, str] = Field(default_factory=_default_tool_metadata)
    scan_id: str
    target: Target
    score: Score
    findings: list[Finding] = Field(default_factory=list)
    summary: dict[str, int] = Field(default_factory=dict)
