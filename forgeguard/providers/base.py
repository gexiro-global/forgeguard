from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol

from ..safety import SAFE_GET_PATHS

VERSION_PATH = "/api/v1/version"
STANDARD_PATHS = (
    VERSION_PATH,
    "/explore/repos",
    "/v2/",
    "/api/v1/repos/search?limit=1",
    "/api/v1/users/search?limit=1",
)


def release_version(raw: str | None) -> tuple[int, int, int] | None:
    """Only final upstream semver; metadata is retained separately, not ordered."""
    match = re.fullmatch(
        r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?",
        raw or "",
    )
    return tuple(map(int, match.groups())) if match else None


@dataclass(frozen=True)
class RunnerInfo:
    product: str
    qualified_versions: tuple[str, ...]
    config_source: str
    security_source: str


@dataclass(frozen=True)
class Setting:
    key: str
    values: tuple[object, ...]
    default: object
    source: str


class ForgeProvider(Protocol):
    id: str
    revision: str
    qualified_versions: tuple[str, ...]
    config_source: str
    api_source: str
    settings: tuple[Setting, ...]
    runner: RunnerInfo

    def request_plan(self, profile: str) -> tuple[str, ...]: ...
    def normalize_version(self, raw: str | None) -> tuple[int, int, int] | None: ...


class ProviderBase:
    id: str
    revision = "1"

    def request_plan(self, profile: str) -> tuple[str, ...]:
        plans = {
            "minimal": (VERSION_PATH,),
            "standard": STANDARD_PATHS,
            "extended": (*STANDARD_PATHS, "/"),
        }
        paths = plans[profile]
        if not set(paths) <= SAFE_GET_PATHS:
            raise ValueError("Provider request plan exceeds central allowlist")
        return paths

    def normalize_version(self, raw: str | None) -> tuple[int, int, int] | None:
        if raw and "+" in raw and raw.split("+", 1)[1] != self.id:
            return None
        return release_version(raw)


def common_settings(source: str) -> tuple[Setting, ...]:
    return tuple(
        Setting(k, (False, True), False, source)
        for k in (
            "service.DISABLE_REGISTRATION",
            "service.REGISTER_EMAIL_CONFIRM",
            "service.REGISTER_MANUAL_CONFIRM",
            "service.REQUIRE_SIGNIN_VIEW",
            "repository.FORCE_PRIVATE",
        )
    ) + (
        Setting(
            "repository.DEFAULT_PRIVATE", ("last", "private", "public"), "last", source
        ),
    )
