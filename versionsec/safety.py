from __future__ import annotations

# VersionSec by Gexiro - read-only safety allowlist.
# Every network read MUST target one of these exact paths. ForgeClient enforces
# this at runtime so a future code change cannot turn VersionSec into a probe.
SAFE_GET_PATHS = frozenset(
    {
        "/api/v1/version",
        "/v2/",
        "/",
        "/api/v1/repos/search?limit=1",
        "/explore/repos",
        "/api/v1/users/search?limit=1",
    }
)
