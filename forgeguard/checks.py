from __future__ import annotations

import re

from .client import ForgeClient
from .models import Finding, Severity, Status, Target

FIXED_VERSION = "1.26.2"
SAFE_ANON_PATHS = (
    "/api/v1/version",
    "/v2/",
    "/",
    "/api/v1/repos/search?limit=1",
    "/explore/repos",
    "/api/v1/users/search?limit=1",
)


def _semver(version: str | None) -> tuple[int, int, int] | None:
    match = re.match(r"(\d+)\.(\d+)\.(\d+)", version or "")
    return tuple(int(part) for part in match.groups()) if match else None  # type: ignore[return-value]


def _is_vulnerable(version: str | None) -> bool | None:
    parsed, fixed = _semver(version), _semver(FIXED_VERSION)
    return None if parsed is None else parsed < fixed


async def _detect(client: ForgeClient, known_version: str | None) -> tuple[Target, bool]:
    target = Target(url=client.base, forge="unknown", version=known_version)
    anon_disclosed = False
    response = await client.get("/api/v1/version", auth=client.has_token)
    if response is not None and response.status_code == 200:
        try:
            target.version = response.json().get("version", target.version)
        except Exception:  # noqa: BLE001 - tolerate non-JSON server responses
            pass
        if not client.has_token:
            anon_disclosed = True
    if target.version:
        target.forge = "gitea"
    return target, anon_disclosed


async def check_version(client: ForgeClient, target: Target, anon_disclosed: bool) -> list[Finding]:
    findings: list[Finding] = []
    vulnerable_version = _is_vulnerable(target.version)
    if target.version is None:
        findings.append(Finding(id="FG-VER", title="Forge version undetermined", severity=Severity.medium,
                                status=Status.INFO, evidence={"version": None},
                                rationale="Version is not available from the safe API path and no local version was supplied.",
                                remediation="Re-run with --token or --known-version to enable patch-currency checks."))
    elif vulnerable_version:
        findings.append(Finding(id="FG-VER", title="Vulnerable version: patch-currency gap",
                                severity=Severity.high, status=Status.FAIL,
                                evidence={"version": target.version, "fixed_in": FIXED_VERSION},
                                rationale=f"Running {target.version} < {FIXED_VERSION}: the code-level fix for CVE-2026-27771 is missing.",
                                remediation=f"Update Gitea to >= {FIXED_VERSION}.", references=["CVE-2026-27771"]))
    else:
        findings.append(Finding(id="FG-VER", title="Patched: version is at or above the fixed release",
                                severity=Severity.info, status=Status.PASS,
                                evidence={"version": target.version, "fixed_in": FIXED_VERSION},
                                rationale=f"Running {target.version} (>= {FIXED_VERSION})."))
    if anon_disclosed:
        findings.append(Finding(id="FG-VER-DISCLOSE", title="Version disclosed to anonymous users",
                                severity=Severity.low, status=Status.WARN,
                                evidence={"endpoint": "/api/v1/version"},
                                rationale="Exact version is readable without authentication, which increases targeting context.",
                                remediation="Set REQUIRE_SIGNIN_VIEW=true to hide metadata from anonymous users."))
    return findings


async def check_cve_27771(client: ForgeClient, target: Target) -> list[Finding]:
    vulnerable_version = _is_vulnerable(target.version)
    v2_response = await client.get("/v2/")
    anon_v2 = v2_response.status_code if v2_response is not None else None
    home_response = await client.get("/")
    home = home_response.status_code if home_response is not None else None
    signin_required = (home in (401, 403)) or (anon_v2 in (401, 403))
    registry_anon_open = anon_v2 == 200
    evidence = {
        "version": target.version,
        "anon_v2_http": anon_v2,
        "signin_required_inferred": signin_required,
        "registry_anon_open": registry_anon_open,
    }
    if vulnerable_version is False:
        status, severity, rationale = (
            Status.PASS,
            Severity.info,
            f"Patched: {target.version} is at or above {FIXED_VERSION}.",
        )
    elif vulnerable_version is None:
        status, severity, rationale = (
            Status.INFO,
            Severity.medium,
            "Version unknown; CVE-2026-27771 exposure posture cannot be assessed.",
        )
    elif registry_anon_open and not signin_required:
        status, severity, rationale = (
            Status.FAIL,
            Severity.critical,
            "Active exposure: vulnerable version plus anonymous /v2/ access and no sign-in enforcement signal.",
        )
    else:
        status, severity, rationale = (
            Status.WARN,
            Severity.critical,
            "Mitigated posture: vulnerable version remains, but anonymous /v2/ access is denied or sign-in is enforced.",
        )
    return [Finding(id="FG-CVE-27771", title="CVE-2026-27771 exposure posture",
                    severity=severity, status=status, evidence=evidence, rationale=rationale,
                    remediation=f"Update Gitea to >= {FIXED_VERSION}; keep REQUIRE_SIGNIN_VIEW=true until patched.",
                    references=["CVE-2026-27771", "https://blog.gitea.com/release-of-1.26.2/"], cwe="CWE-285")]


async def check_signin(client: ForgeClient, target: Target) -> list[Finding]:
    api_response = await client.get("/api/v1/repos/search?limit=1")
    anon_api = api_response.status_code if api_response is not None else None
    browse_response = await client.get("/explore/repos")
    anon_browse = browse_response.status_code if browse_response is not None else None
    required = anon_api in (401, 403) and anon_browse in (401, 403, 301, 302, 303)
    if required:
        return [Finding(id="FG-SIGNIN", title="Anonymous access requires sign-in", severity=Severity.info,
                        status=Status.PASS, evidence={"anon_api": anon_api, "anon_explore": anon_browse},
                        rationale="REQUIRE_SIGNIN_VIEW appears enforced; anonymous browsing/API access is denied.")]
    return [Finding(id="FG-SIGNIN", title="Anonymous browsing/API is open", severity=Severity.medium,
                    status=Status.WARN, evidence={"anon_api": anon_api, "anon_explore": anon_browse},
                    rationale="Anonymous users can read repository/API surface.",
                    remediation="Set REQUIRE_SIGNIN_VIEW=true if this is a private forge.")]


async def check_registry(client: ForgeClient, target: Target) -> list[Finding]:
    response = await client.get("/v2/")
    anon_v2 = response.status_code if response is not None else None
    if anon_v2 == 200:
        return [Finding(id="FG-REG", title="Container registry reachable anonymously", severity=Severity.high,
                        status=Status.WARN, evidence={"anon_v2_http": anon_v2},
                        rationale="OCI /v2/ root responds to anonymous clients.",
                        remediation="Require authentication for the registry; update past CVE-2026-27771.",
                        references=["CVE-2026-27771"])]
    return [Finding(id="FG-REG", title="Container registry not anonymously reachable", severity=Severity.info,
                    status=Status.PASS, evidence={"anon_v2_http": anon_v2},
                    rationale="Anonymous /v2/ access is denied.")]


async def check_anon(client: ForgeClient, target: Target) -> list[Finding]:
    paths = ["/api/v1/repos/search?limit=1", "/explore/repos", "/api/v1/users/search?limit=1"]
    open_surfaces = []
    for path in paths:
        response = await client.get(path)
        if response is not None and response.status_code == 200:
            open_surfaces.append(path)
    if open_surfaces:
        return [Finding(id="FG-ANON", title="Anonymously readable surfaces", severity=Severity.medium,
                        status=Status.WARN, evidence={"open": open_surfaces},
                        rationale="These endpoints return data without authentication.",
                        remediation="Enable REQUIRE_SIGNIN_VIEW or restrict visibility.")]
    return [Finding(id="FG-ANON", title="No anonymously readable surfaces detected", severity=Severity.info,
                    status=Status.PASS, evidence={"probed": paths},
                    rationale="Probed endpoints all require authentication.")]


async def run_all_checks(client: ForgeClient, known_version: str | None = None) -> tuple[list[Finding], Target]:
    target, anon_disclosed = await _detect(client, known_version)
    findings: list[Finding] = []
    findings += await check_version(client, target, anon_disclosed)
    findings += await check_cve_27771(client, target)
    findings += await check_signin(client, target)
    findings += await check_registry(client, target)
    findings += await check_anon(client, target)
    return findings, target
