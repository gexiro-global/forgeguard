from __future__ import annotations

import asyncio
import json
import time
from urllib.parse import urlsplit

import httpx

from .safety import SAFE_GET_PATHS
from .urls import normalize_target_url
from .version import __version__

_UA = f"ForgeGuard-by-Gexiro/{__version__} (read-only; own-authorized-only)"


class ForgeClient:
    """One origin, serial GETs, no retries, redirects, cookies or ambient proxies."""

    def __init__(
        self,
        base_url: str,
        token: str | None = None,
        timeout: float = 10.0,
        verify: bool | str = True,
        request_budget: int = 12,
        total_timeout: float = 60.0,
        body_limit: int = 262144,
    ) -> None:
        self.base = normalize_target_url(base_url)
        if verify is False:
            raise ValueError("Certificate verification cannot be disabled")
        if not 0 < timeout <= 10 or not 0 < total_timeout <= 60:
            raise ValueError("Timeout exceeds transport bounds")
        if not 1 <= request_budget <= 12 or not 1 <= body_limit <= 262144:
            raise ValueError("Request or body budget exceeds transport bounds")
        if isinstance(verify, str):
            import ssl

            verify = ssl.create_default_context(cafile=verify)
        self.has_token = bool(token) and urlsplit(self.base).scheme == "https"
        self._token = token if self.has_token else None
        self._timeout = timeout
        self._deadline = time.monotonic() + total_timeout
        self._budget = request_budget
        self._limit = body_limit
        self.request_count = 0
        self.observations: dict[str, dict] = {}
        self._lock = asyncio.Lock()
        headers = {"User-Agent": _UA}
        self._anon = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            headers=headers,
            verify=verify,
            trust_env=False,
        )
        self._auth = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            headers=headers,
            verify=verify,
            trust_env=False,
        )

    async def get(self, path: str, *, auth: bool = False) -> httpx.Response | None:
        if path not in SAFE_GET_PATHS:
            raise ValueError("Refusing non-allowlisted read-only path")
        if auth and path != "/api/v1/version":
            raise ValueError("Authentication is limited to the version read")
        async with self._lock:
            remaining = self._deadline - time.monotonic()
            if self.request_count >= self._budget or remaining <= 0:
                self.observations[path] = {"error": "budget_exhausted"}
                return None
            self.request_count += 1
            client = self._auth if auth and self.has_token else self._anon
            client.cookies.clear()
            headers = (
                {"Authorization": f"token {self._token}"}
                if auth and self.has_token
                else {}
            )
            try:
                async with asyncio.timeout(min(remaining, self._timeout)):
                    async with client.stream(
                        "GET", self.base + path, headers=headers
                    ) as response:
                        data = bytearray()
                        size = 0
                        async for chunk in response.aiter_bytes():
                            size += len(chunk)
                            if size > self._limit:
                                self.observations[path] = {
                                    "error": "body_limit",
                                    "status": response.status_code,
                                }
                                return None
                            if path == "/api/v1/version":
                                data.extend(chunk)
                        content_type = (
                            response.headers.get("content-type", "")
                            .split(";")[0]
                            .strip()
                            .lower()
                        )
                        # Only closed-value summaries survive. Bodies, cookies, URLs,
                        # arbitrary headers and user/repository names are never retained.
                        obs = {
                            "status": response.status_code,
                            "complete": True,
                            "html": content_type == "text/html",
                            "json": content_type == "application/json",
                            "https": urlsplit(self.base).scheme == "https",
                            "nosniff": response.headers.get(
                                "x-content-type-options", ""
                            ).lower()
                            == "nosniff",
                            "frame_policy": response.headers.get(
                                "x-frame-options", ""
                            ).upper()
                            in {"DENY", "SAMEORIGIN"},
                            "hsts_present": "strict-transport-security"
                            in response.headers,
                            "csp_present": "content-security-policy"
                            in response.headers,
                        }
                        self.observations[path] = obs
                        payload = {}
                        if path == "/api/v1/version" and response.status_code == 200:
                            try:
                                parsed = json.loads(data)
                                raw = (
                                    parsed.get("version")
                                    if isinstance(parsed, dict)
                                    else None
                                )
                                if isinstance(raw, str) and 0 < len(raw.strip()) <= 128:
                                    raw = raw.strip()
                                    if self._token and self._token in raw:
                                        obs["error"] = "invalid_version"
                                        obs["complete"] = False
                                    else:
                                        payload["version"] = raw
                                else:
                                    obs["error"] = "invalid_version"
                                    obs["complete"] = False
                            except (ValueError, UnicodeError):
                                obs["error"] = "invalid_json"
                                obs["complete"] = False
                        return httpx.Response(response.status_code, json=payload)
            except (httpx.HTTPError, TimeoutError):
                self.observations[path] = {"error": "transport"}
                return None
            finally:
                client.cookies.clear()

    async def aclose(self) -> None:
        await self._anon.aclose()
        await self._auth.aclose()
