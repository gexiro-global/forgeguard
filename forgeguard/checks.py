from __future__ import annotations

import re

from .client import ForgeClient
from .models import Finding, Severity, Status, Target
from .safety import SAFE_GET_PATHS

FIXED_VERSION = "1.26.2"
# Back-compat alias; the canonical read-only allowlist lives in forgeguard.safety.
SAFE_ANON_PATHS = SAFE_GET_PATHS


def _semver(version: str | None) -> tuple[int, int, int] | None:
    match = re.fullmatch(
        r"(\d+)\.(\d+)\.(\d+)(?:\+[0-9A-Za-z._-]+)?",
        (version or "").strip(),
    )
    if match is None:
        return None
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def _is_vulnerable(version: str | None) -> bool | None:
    """Return whether a Gitea version is below the first fixed release."""
    parsed, fixed = _semver(version), _semver(FIXED_VERSION)
    return None if parsed is None else parsed < fixed


def _looks_like_forgejo(version: str | None) -> bool:
    return "forgejo" in (version or "").lower()


async def _detect(
    client: ForgeClient, known_version: str | None
) -> tuple[Target, bool]:
    # v0.2.2 is intentionally Gitea-only. An explicit Forgejo marker fails safe.
    target = Target(url=client.base, forge="gitea", version=known_version)
    anon_disclosed = False
    response = await client.get("/api/v1/version", auth=client.has_token)
    if response is not None and response.status_code == 200:
        try:
            observed = response.json().get("version", target.version)
        except (AttributeError, TypeError, ValueError):
            observed = None
        if isinstance(observed, str):
            target.version = observed
        if not client.has_token:
            anon_disclosed = True
    if _looks_like_forgejo(target.version):
        target.forge = "forgejo"
    return target, anon_disclosed


async def check_version(
    client: ForgeClient, target: Target, anon_disclosed: bool
) -> list[Finding]:
    findings: list[Finding] = []
    affected = _is_vulnerable(target.version)
    if target.forge != "gitea":
        findings.append(
            Finding(
                id="FG-VER",
                title="Unsupported product version posture",
                severity=Severity.info,
                status=Status.INFO,
                evidence={"product": target.forge, "version": target.version},
                rationale=(
                    "ForgeGuard 0.2.2 applies Gitea version baselines only; "
                    "no Gitea patch conclusion was produced."
                ),
                remediation=(
                    "Use product-specific Forgejo guidance until dedicated Forgejo support is available."
                ),
            )
        )
    elif target.version is None:
        findings.append(
            Finding(
                id="FG-VER",
                title="Gitea version undetermined",
                severity=Severity.medium,
                status=Status.INFO,
                evidence={"version": None},
                rationale=(
                    "Version is not available from the safe API path and no local version was supplied."
                ),
                remediation=(
                    "Re-run with an authorized token or --known-version from trusted operator inventory."
                ),
            )
        )
    elif affected is None:
        findings.append(
            Finding(
                id="FG-VER",
                title="Gitea version could not be parsed",
                severity=Severity.medium,
                status=Status.INFO,
                evidence={"version": target.version},
                rationale="The observed version could not be compared with the Gitea fixed release.",
                remediation="Confirm the installed Gitea version from trusted operator inventory.",
            )
        )
    elif affected:
        findings.append(
            Finding(
                id="FG-VER",
                title="Gitea patch-currency gap",
                severity=Severity.high,
                status=Status.FAIL,
                evidence={"version": target.version, "first_fixed_in": FIXED_VERSION},
                rationale=(
                    f"Installed Gitea {target.version} is below the first release containing "
                    "the fix for CVE-2026-27771."
                ),
                remediation=(
                    f"Upgrade Gitea to >={FIXED_VERSION} or a newer currently supported security release."
                ),
                references=["CVE-2026-27771"],
            )
        )
    else:
        findings.append(
            Finding(
                id="FG-VER",
                title="Gitea version is at or above the first fixed release",
                severity=Severity.info,
                status=Status.PASS,
                evidence={"version": target.version, "first_fixed_in": FIXED_VERSION},
                rationale=f"Installed Gitea {target.version} is at or above {FIXED_VERSION}.",
            )
        )
    if anon_disclosed:
        findings.append(
            Finding(
                id="FG-VER-DISCLOSE",
                title="Version disclosed to anonymous users",
                severity=Severity.low,
                status=Status.WARN,
                evidence={"endpoint": "/api/v1/version"},
                rationale=(
                    "The exact version was returned to an anonymous request, increasing targeting context."
                ),
                remediation=(
                    "Review whether anonymous version disclosure is intended and restrict it if not."
                ),
            )
        )
    return findings


async def check_cve_27771(target: Target) -> list[Finding]:
    affected = _is_vulnerable(target.version)
    evidence = {
        "product": target.forge,
        "version": target.version,
        "affected_through": "1.26.1",
        "first_fixed_in": FIXED_VERSION,
    }
    if target.forge != "gitea":
        status, severity, rationale, remediation = (
            Status.INFO,
            Severity.info,
            "The Gitea advisory baseline was not applied because the product is unsupported.",
            "Use a product-specific advisory source for this target.",
        )
    elif affected is False:
        status, severity, rationale, remediation = (
            Status.PASS,
            Severity.info,
            (
                f"Installed Gitea {target.version} is at or above the first release containing "
                "the fix for CVE-2026-27771."
            ),
            "",
        )
    elif affected is None:
        status, severity, rationale, remediation = (
            Status.INFO,
            Severity.medium,
            "Version posture for CVE-2026-27771 cannot be determined.",
            (
                "Confirm the installed Gitea version from trusted operator inventory "
                "or an authorized version endpoint."
            ),
        )
    else:
        status, severity, rationale, remediation = (
            Status.FAIL,
            Severity.high,
            (
                "Installed Gitea version is within the affected range for CVE-2026-27771. "
                "This version check does not prove exploitability or data exposure."
            ),
            (
                f"Upgrade Gitea to >={FIXED_VERSION} or a newer currently supported security release."
            ),
        )
    return [
        Finding(
            id="FG-CVE-27771",
            title="CVE-2026-27771 version posture",
            severity=severity,
            status=status,
            evidence=evidence,
            rationale=rationale,
            remediation=remediation,
            references=[
                "CVE-2026-27771",
                "https://blog.gitea.com/release-of-1.26.2/",
            ],
            cwe="CWE-285",
        )
    ]


async def check_signin(client: ForgeClient, target: Target) -> list[Finding]:
    api_response = await client.get("/api/v1/repos/search?limit=1")
    anon_api = api_response.status_code if api_response is not None else None
    browse_response = await client.get("/explore/repos")
    anon_browse = browse_response.status_code if browse_response is not None else None
    controlled = anon_api in (401, 403) and anon_browse in (
        401,
        403,
        301,
        302,
        303,
        307,
        308,
    )
    evidence = {"anon_api": anon_api, "anon_explore": anon_browse}
    if controlled:
        return [
            Finding(
                id="FG-SIGNIN",
                title="Checked repository/API surfaces appear access-controlled",
                severity=Severity.info,
                status=Status.PASS,
                evidence=evidence,
                rationale=(
                    "Anonymous requests returned access-control or sign-in redirect responses on "
                    "the checked paths; no specific configuration key was read."
                ),
            )
        ]
    if anon_api == 200 or anon_browse == 200:
        return [
            Finding(
                id="FG-SIGNIN",
                title="Observed anonymous repository/API surface",
                severity=Severity.medium,
                status=Status.WARN,
                evidence=evidence,
                rationale=(
                    "At least one checked repository/API path returned HTTP 200 "
                    "to an anonymous request."
                ),
                remediation="Review whether anonymous access on the observed path is intended.",
            )
        ]
    return [
        Finding(
            id="FG-SIGNIN",
            title="Sign-in posture undetermined on checked paths",
            severity=Severity.medium,
            status=Status.INFO,
            evidence=evidence,
            rationale=(
                "The observed responses did not prove either anonymous readability or access control."
            ),
        )
    ]


async def check_registry(client: ForgeClient, target: Target) -> list[Finding]:
    response = await client.get("/v2/")
    anon_v2 = response.status_code if response is not None else None
    if anon_v2 == 200:
        return [
            Finding(
                id="FG-REG",
                title="OCI registry root responded to an anonymous request",
                severity=Severity.medium,
                status=Status.WARN,
                evidence={"anon_v2_http": anon_v2},
                rationale=(
                    "The OCI /v2/ root returned HTTP 200 anonymously; this does not prove access "
                    "to private packages, manifests, or blobs."
                ),
                remediation=(
                    "Review whether anonymous registry-root reachability is intended "
                    "and require authentication if not."
                ),
            )
        ]
    if anon_v2 is None:
        return [
            Finding(
                id="FG-REG",
                title="OCI registry root posture undetermined",
                severity=Severity.medium,
                status=Status.INFO,
                evidence={"anon_v2_http": None},
                rationale="No HTTP response was available for the anonymous /v2/ request.",
            )
        ]
    return [
        Finding(
            id="FG-REG",
            title="OCI registry root did not return HTTP 200 anonymously",
            severity=Severity.info,
            status=Status.PASS,
            evidence={"anon_v2_http": anon_v2},
            rationale=(
                f"The anonymous /v2/ request returned HTTP {anon_v2}; "
                "no package, manifest, or blob access was attempted."
            ),
        )
    ]


async def check_anon(client: ForgeClient, target: Target) -> list[Finding]:
    paths = [
        "/api/v1/repos/search?limit=1",
        "/explore/repos",
        "/api/v1/users/search?limit=1",
    ]
    statuses: dict[str, int | None] = {}
    open_surfaces = []
    for path in paths:
        response = await client.get(path)
        statuses[path] = response.status_code if response is not None else None
        if statuses[path] == 200:
            open_surfaces.append(path)
    if open_surfaces:
        return [
            Finding(
                id="FG-ANON",
                title="Observed anonymously readable checked endpoints",
                severity=Severity.medium,
                status=Status.WARN,
                evidence={"open": open_surfaces, "checked": statuses},
                rationale="The listed checked endpoints returned HTTP 200 to anonymous requests.",
                remediation="Review whether anonymous access on each observed path is intended.",
            )
        ]
    if any(status is None for status in statuses.values()):
        return [
            Finding(
                id="FG-ANON",
                title="Anonymous surface posture undetermined",
                severity=Severity.medium,
                status=Status.INFO,
                evidence={"checked": statuses},
                rationale="At least one checked endpoint did not return an HTTP response.",
            )
        ]
    return [
        Finding(
            id="FG-ANON",
            title="No anonymous HTTP 200 observed on checked endpoints",
            severity=Severity.info,
            status=Status.PASS,
            evidence={"checked": statuses},
            rationale=(
                "None of the three checked endpoints returned HTTP 200 to an anonymous request."
            ),
        )
    ]


async def run_all_checks(
    client: ForgeClient, known_version: str | None = None
) -> tuple[list[Finding], Target]:
    target, anon_disclosed = await _detect(client, known_version)
    findings: list[Finding] = []
    findings += await check_version(client, target, anon_disclosed)
    findings += await check_cve_27771(target)
    findings += await check_signin(client, target)
    findings += await check_registry(client, target)
    findings += await check_anon(client, target)
    return findings, target
