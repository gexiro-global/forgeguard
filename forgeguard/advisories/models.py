from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..providers.base import release_version


class Interval(BaseModel):
    model_config = ConfigDict(extra="forbid")
    lower: str
    upper: str

    @model_validator(mode="after")
    def validate_bounds(self):
        low, high = release_version(self.lower), release_version(self.upper)
        if low is None or high is None or low > high:
            raise ValueError("Invalid inclusive advisory interval")
        return self

    def contains(self, version: tuple[int, int, int]) -> bool:
        return release_version(self.lower) <= version <= release_version(self.upper)


class Advisory(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    product: Literal["gitea", "forgejo"]
    record_version: int = 1
    title: str
    sources: list[str]
    source_sha256: list[str]
    verified_at: str
    affected: list[Interval]
    fixed: list[Interval]
    severity: Literal["critical", "high", "medium", "low", "info"]
    severity_source: str
    limitations: str
    applicability: str
    retrieval_url: str = ""
    selected_record_id: str = ""
    selected_record_location: str = ""
    conditions: dict[str, bool] = Field(default_factory=dict)

    @model_validator(mode="after")
    def disjoint_ranges(self):
        for a in self.affected:
            for b in self.fixed:
                if not (
                    release_version(a.upper) < release_version(b.lower)
                    or release_version(b.upper) < release_version(a.lower)
                ):
                    raise ValueError("Overlapping affected/fixed intervals")
        return self
