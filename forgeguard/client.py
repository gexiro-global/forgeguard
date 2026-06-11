from __future__ import annotations

import httpx

_UA = "ForgeGuard-by-Gexiro/0.2 (read-only; own-authorized-only)"


class ForgeClient:
    """GET-only async HTTP client for one Gitea/Forgejo instance.

    Anonymous probes do not follow redirects. A redirect to sign-in is itself a
    posture signal. The authenticated client is only used when a token is supplied.
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
        client = self._auth if auth else self._anon
        try:
            return await client.get(self.base + path)
        except httpx.HTTPError:
            return None

    async def aclose(self) -> None:
        await self._anon.aclose()
        await self._auth.aclose()
