from __future__ import annotations

# ForgeGuard by Gexiro - read-only safety allowlist.
# Every network read MUST target one of these exact paths. ForgeClient enforces
# this at runtime so a future code change cannot turn ForgeGuard into a probe.
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
