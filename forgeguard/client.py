from __future__ import annotations

import httpx

from .safety import SAFE_GET_PATHS

_UA = "ForgeGuard-by-Gexiro/0.2 (read-only; own-authorized-only)"


class ForgeClient:
    """GET-only async HTTP client for one Gitea/Forgejo instance.

    Anonymous probes do not follow redirects. A redirect to sign-in is itself a
    posture signal. The authenticated client is only used when a token is supplied.
    Every request path is checked against SAFE_GET_PATHS; a non-allowlisted path
    is refused before any network call so the tool cannot be repurposed as a probe.
    """

    def __init__(self, base_url: str, token: str | None = None, timeout: float = 10.0,
                 verify: bool = True) -> None:
        self.base = base_url.rstrip("/")
        self.has_token = bool(token)
        self._anon = httpx.AsyncClient(timeout=timeout, follow_redirects=False,
                                       headers={"User-Agent": _UA}, verify=verify)
        auth_headers = {"User-Agent": _UA}
        if token:
            auth_headers["Authorization"] = f"token {token}"
        self._auth = httpx.AsyncClient(timeout=timeout, follow_redirects=False,
                                       headers=auth_headers, verify=verify)

    async def get(self, path: str, *, auth: bool = False) -> httpx.Response | None:
        if path not in SAFE_GET_PATHS:
            raise ValueError(f"Refusing non-allowlisted read-only path: {path}")
        client = self._auth if auth else self._anon
        try:
            return await client.get(self.base + path)
        except httpx.HTTPError:
            return None

    async def aclose(self) -> None:
        await self._anon.aclose()
        await self._auth.aclose()
