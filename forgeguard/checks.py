from __future__ import annotations

import re

from .client import ForgeClient
from .models import EvidenceState, Finding, Severity, Status, Target
from .safety import SAFE_GET_PATHS

FIXED_VERSION = "1.26.2"
# Back-compat alias; the canonical read-only allowlist lives in forgeguard.safety.
SAFE_ANON_PATHS = SAFE_GET_PATHS

_ACCESS_CONTROL_STATUSES = frozenset({401, 403})
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


def _semver(version: str | None) -> tuple[int, int, int] | None:
    match = re.fullmatch(
        r"(\d+)\.(\d+)\.(\d+)(?:\+[0-9A-Za-z._-]+)?",
        (version or "").strip(),
    )
    if match is None:
        return None
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def _is_vulnerable(version: str | None) -> bool | None:
    """Return whether a confirmed Gitea version is below the first fixed release."""
    parsed, fixed = _semver(version), _semver(FIXED_VERSION)
    return None if parsed is None else parsed < fixed


def _looks_like_forgejo(version: str | None) -> bool:
    return "forgejo" in (version or "").lower()


async def _detect(
    client: ForgeClient,
    known_version: str | None,
    product: str | None,
) -> tuple[Target, bool]:
    declared_product = (product or "").strip().lower()
    gitea_declared = declared_product == "gitea"
    target = Target(
        url=client.base,
        forge="gitea" if gitea_declared else "unknown",
        version=known_version,
        product_confirmed=gitea_declared,
        product_source="operator-declared" if gitea_declared else "unconfirmed",
    )
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
        target.product_confirmed = False
        target.product_source = (
            "version-marker-conflict" if gitea_declared else "version-marker"
        )
    return target, anon_disclosed


async def check_version(
    _client: ForgeClient, target: Target, anon_disclosed: bool
) -> list[Finding]:
    findings: list[Finding] = []
    evidence = {
        "product": target.forge,
        "product_confirmed": target.product_confirmed,
        "product_source": target.product_source,
        "version": target.version,
    }
    if target.forge == "forgejo":
        findings.append(
            Finding(
                id="FG-VER",
                title="Unsupported product version observation",
                severity=Severity.info,
                status=Status.INFO,
                evidence=evidence,
                rationale=(
                    "An explicit Forgejo version marker was observed. ForgeGuard 0.2.2 "
                    "does not apply Gitea advisory semantics to Forgejo."
                ),
                remediation="Use product-specific Forgejo guidance.",
                evidence_state=EvidenceState.INFORMATIONAL,
            )
        )
    elif not target.product_confirmed:
        findings.append(
            Finding(
                id="FG-VER",
                title="Product not confirmed for Gitea version evaluation",
                severity=Severity.info,
                status=Status.INFO,
                evidence=evidence,
                rationale=(
                    "A version value alone does not confirm Gitea. No Gitea-specific "
                    "version or advisory conclusion was produced."
                ),
                remediation=(
                    "Re-run with --product gitea only when trusted operator inventory "
                    "confirms that the authorized target is Gitea."
                ),
                evidence_state=EvidenceState.INFORMATIONAL,
            )
        )
    elif target.version is None:
        findings.append(
            Finding(
                id="FG-VER",
                title="Confirmed Gitea version unavailable",
                severity=Severity.info,
                status=Status.INFO,
                evidence=evidence,
                rationale=(
                    "The product was operator-confirmed as Gitea, but no version was "
                    "available from the safe API path or trusted inventory."
                ),
                remediation=(
                    "Re-run with an authorized token or --known-version from trusted "
                    "operator inventory."
                ),
                evidence_state=EvidenceState.INFORMATIONAL,
            )
        )
    elif _semver(target.version) is None:
        findings.append(
            Finding(
                id="FG-VER",
                title="Confirmed Gitea version could not be parsed",
                severity=Severity.info,
                status=Status.INFO,
                evidence=evidence,
                rationale=(
                    "The observed version could not be parsed for advisory comparison."
                ),
                remediation="Confirm the installed Gitea version from trusted inventory.",
                evidence_state=EvidenceState.INFORMATIONAL,
            )
        )
    else:
        findings.append(
            Finding(
                id="FG-VER",
                title="Confirmed Gitea version observed",
                severity=Severity.info,
                status=Status.PASS,
                evidence=evidence,
                rationale=(
                    f"Gitea {target.version} was observed for an operator-confirmed "
                    "Gitea target. CVE risk is scored separately by FG-CVE-27771."
                ),
                evidence_state=EvidenceState.INFORMATIONAL,
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
                    "The exact version was returned to an anonymous request, increasing "
                    "targeting context."
                ),
                remediation=(
                    "Review whether anonymous version disclosure is intended and restrict "
                    "it if not."
                ),
            )
        )
    return findings


async def check_cve_27771(target: Target) -> list[Finding]:
    affected = _is_vulnerable(target.version)
    evidence = {
        "product": target.forge,
        "product_confirmed": target.product_confirmed,
        "product_source": target.product_source,
        "version": target.version,
        "affected_through": "1.26.1",
        "first_fixed_in": FIXED_VERSION,
    }
    if target.forge == "forgejo":
        status, severity, rationale, remediation, evidence_state = (
            Status.INFO,
            Severity.info,
            (
                "The Gitea advisory baseline was not applied because an explicit Forgejo "
                "version marker conflicts with Gitea product confirmation."
            ),
            "Use a product-specific advisory source for this target.",
            EvidenceState.INDETERMINATE,
        )
    elif target.forge != "gitea" or not target.product_confirmed:
        status, severity, rationale, remediation, evidence_state = (
            Status.INFO,
            Severity.medium,
            (
                "CVE-2026-27771 posture cannot be determined because the target was not "
                "affirmatively confirmed as Gitea."
            ),
            (
                "Confirm the product from trusted operator inventory and re-run with "
                "--product gitea only for a Gitea target."
            ),
            EvidenceState.INDETERMINATE,
        )
    elif affected is False:
        status, severity, rationale, remediation, evidence_state = (
            Status.PASS,
            Severity.info,
            (
                f"Installed Gitea {target.version} is at or above the first release "
                "containing the fix for CVE-2026-27771."
            ),
            "",
            EvidenceState.ASSESSED,
        )
    elif affected is None:
        status, severity, rationale, remediation, evidence_state = (
            Status.INFO,
            Severity.medium,
            "Version posture for CVE-2026-27771 cannot be determined.",
            (
                "Confirm the installed Gitea version from trusted operator inventory "
                "or an authorized version endpoint."
            ),
            EvidenceState.INDETERMINATE,
        )
    else:
        status, severity, rationale, remediation, evidence_state = (
            Status.FAIL,
            Severity.high,
            (
                "Installed Gitea version is within the affected range for CVE-2026-27771. "
                "This version check does not prove exploitability or data exposure."
            ),
            (
                f"Upgrade Gitea to >={FIXED_VERSION} or a newer currently supported "
                "security release."
            ),
            EvidenceState.ASSESSED,
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
            cwe="CWE-862",
            evidence_state=evidence_state,
        )
    ]


async def check_signin(client: ForgeClient, target: Target) -> list[Finding]:
    api_response = await client.get("/api/v1/repos/search?limit=1")
    anon_api = api_response.status_code if api_response is not None else None
    browse_response = await client.get("/explore/repos")
    anon_browse = browse_response.status_code if browse_response is not None else None
    evidence = {"anon_api": anon_api, "anon_explore": anon_browse}
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
    if anon_api in _ACCESS_CONTROL_STATUSES and anon_browse in _ACCESS_CONTROL_STATUSES:
        return [
            Finding(
                id="FG-SIGNIN",
                title="Explicit access-control responses observed on checked paths",
                severity=Severity.info,
                status=Status.PASS,
                evidence=evidence,
                rationale=(
                    "Both checked paths returned HTTP 401 or 403 to anonymous requests; "
                    "no specific REQUIRE_SIGNIN_VIEW configuration value was inferred."
                ),
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
                "The observed responses did not prove either anonymous readability or "
                "explicit access control on all checked paths."
            ),
            evidence_state=EvidenceState.INDETERMINATE,
        )
    ]


async def check_registry(client: ForgeClient, target: Target) -> list[Finding]:
    response = await client.get("/v2/")
    anon_v2 = response.status_code if response is not None else None
    evidence = {"anon_v2_http": anon_v2}
    if anon_v2 == 200:
        return [
            Finding(
                id="FG-REG",
                title="OCI registry root responded to an anonymous request",
                severity=Severity.medium,
                status=Status.WARN,
                evidence=evidence,
                rationale=(
                    "The OCI /v2/ root returned HTTP 200 anonymously; this does not prove "
                    "access to private packages, manifests, or blobs."
                ),
                remediation=(
                    "Review whether anonymous registry-root reachability is intended "
                    "and require authentication if not."
                ),
            )
        ]
    if anon_v2 in _ACCESS_CONTROL_STATUSES:
        return [
            Finding(
                id="FG-REG",
                title="Explicit registry-root access-control response observed",
                severity=Severity.info,
                status=Status.PASS,
                evidence=evidence,
                rationale=(
                    f"The anonymous /v2/ request returned HTTP {anon_v2}, an explicit "
                    "authentication or access-denial response. No artifact access was attempted."
                ),
            )
        ]
    if anon_v2 is None:
        rationale = "No HTTP response was available for the anonymous /v2/ request."
    elif anon_v2 == 404:
        rationale = (
            "The anonymous /v2/ request returned HTTP 404; the registry root was not "
            "identified at this path, so access posture is undetermined."
        )
    elif anon_v2 in _REDIRECT_STATUSES:
        rationale = (
            f"The anonymous /v2/ request returned redirect HTTP {anon_v2}; redirects "
            "were not followed, so access posture is undetermined."
        )
    elif anon_v2 == 429:
        rationale = (
            "The anonymous /v2/ request was rate-limited with HTTP 429; access posture "
            "is undetermined."
        )
    elif 500 <= anon_v2 <= 599:
        rationale = (
            f"The anonymous /v2/ request returned server/backend error HTTP {anon_v2}; "
            "access posture is undetermined."
        )
    else:
        rationale = (
            f"The anonymous /v2/ request returned unclassified HTTP {anon_v2}; explicit "
            "access-control semantics were not proven."
        )
    return [
        Finding(
            id="FG-REG",
            title="OCI registry root posture undetermined",
            severity=Severity.medium,
            status=Status.INFO,
            evidence=evidence,
            rationale=rationale,
            evidence_state=EvidenceState.INDETERMINATE,
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
    if all(status in _ACCESS_CONTROL_STATUSES for status in statuses.values()):
        return [
            Finding(
                id="FG-ANON",
                title="Explicit access-control responses observed on anonymous checks",
                severity=Severity.info,
                status=Status.PASS,
                evidence={"checked": statuses},
                rationale=(
                    "Every checked endpoint returned HTTP 401 or 403 to the anonymous "
                    "request. No global sign-in configuration was inferred."
                ),
            )
        ]
    return [
        Finding(
            id="FG-ANON",
            title="Anonymous surface posture undetermined",
            severity=Severity.medium,
            status=Status.INFO,
            evidence={"checked": statuses},
            rationale=(
                "No checked endpoint returned HTTP 200, but one or more responses were "
                "not explicit HTTP 401/403 access-control evidence."
            ),
            evidence_state=EvidenceState.INDETERMINATE,
        )
    ]


async def run_all_checks(
    client: ForgeClient,
    known_version: str | None = None,
    product: str | None = None,
) -> tuple[list[Finding], Target]:
    target, anon_disclosed = await _detect(client, known_version, product)
    findings: list[Finding] = []
    findings += await check_version(client, target, anon_disclosed)
    findings += await check_cve_27771(target)
    findings += await check_signin(client, target)
    findings += await check_registry(client, target)
    findings += await check_anon(client, target)
    return findings, target
