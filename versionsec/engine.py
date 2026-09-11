from __future__ import annotations

from datetime import UTC, datetime

from .advisories.evaluator import catalog, evaluate
from .assessment import Assessment, EvidenceFinding, Identity
from .models import EvidenceState, Severity, Status, Target
from .policy import assess_score
from .providers.base import STANDARD_PATHS, release_version
from .providers.registry import get_provider
from .version import __version__


def identify(
    product: str | None, declared: str | None, observed: str | None
) -> Identity:
    def marker(raw):
        if raw and raw.endswith("+gitea-1.22.0"):
            parsed = release_version(raw)
            if parsed and parsed[0] in (15, 16):
                return "forgejo-compatibility"
        markers = [p for p in ("gitea", "forgejo") if p in (raw or "").lower()]
        return markers[0] if len(markers) == 1 else "conflicting" if markers else None

    declared_marker, observed_marker = marker(declared), marker(observed)
    markers = {
        m.replace("-compatibility", "") for m in (declared_marker, observed_marker) if m
    }
    conflict = bool(product and any(m != product for m in markers))
    provider = get_provider(product) if product else None
    parsed = provider.normalize_version(observed or declared) if provider else None
    normalized = ".".join(map(str, parsed)) if parsed else None
    declared_parsed = provider.normalize_version(declared) if provider else None
    observed_parsed = provider.normalize_version(observed) if provider else None
    version_conflict = bool(
        declared
        and observed
        and (
            declared_parsed is None
            or observed_parsed is None
            or declared_parsed != observed_parsed
        )
    )
    support = (
        "unknown"
        if not product or not normalized
        else (
            "qualified" if normalized in provider.qualified_versions else "unsupported"
        )
    )
    return Identity(
        declared_product=product,
        declared_version_marker=declared_marker,
        observed_product_marker=observed_marker,
        product_source="operator-declared" if product else "unconfirmed",
        declared_version=declared,
        observed_version=observed,
        normalized_version=normalized,
        product_conflict=conflict,
        version_conflict=version_conflict,
        support=support,
        provider_revision=provider.revision if provider else None,
    )


def finding(
    id_: str,
    title: str,
    observed: dict,
    expected: str,
    *,
    scope="http",
    source="anonymous-http",
    status=Status.INFO,
    state=EvidenceState.ASSESSED,
    reason="",
    group=None,
    applicability="applicable",
    references=(),
) -> EvidenceFinding:
    return EvidenceFinding(
        id=id_,
        title=title,
        severity=Severity.medium
        if status in (Status.WARN, Status.FAIL)
        else Severity.info,
        status=status,
        scope=scope,
        source=source,
        observed=observed,
        expected=expected,
        evidence=observed,
        evidence_state=state,
        applicability=applicability,
        reason=reason,
        rationale=reason,
        remediation=(
            "Review the named condition against operator policy; confirm configuration locally."
            if status in (Status.WARN, Status.FAIL)
            else ""
        ),
        references=sorted(references),
        penalty_group=group or id_,
    )


def result_for(
    identity,
    findings,
    *,
    target,
    profile,
    policy,
    metadata,
    skipped=(),
    count=0,
    scan_id="fg_local",
    run=None,
):
    findings = sorted(findings, key=lambda f: f.id)
    summary = {"pass": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        key = "pass" if f.status == Status.PASS else f.severity.value
        summary[key] += 1
    return Assessment(
        tool={
            "name": "VersionSec",
            "brand": "by Gexiro",
            "version": __version__,
            "schema": "forgeguard.assessment.v1",
            "positioning": "Bounded forge posture assessment.",
        },
        scan_id=scan_id,
        target=target,
        findings=findings,
        score=assess_score(findings),
        summary=summary,
        identity=identity,
        profile=profile,
        policy=policy,
        catalog=metadata,
        skipped_checks=sorted(skipped),
        request_count=count,
        limitations=[
            "Operator declarations are not independent product detection.",
            "A complete result covers selected checks only; no security certification.",
            "HTTP status does not prove data access or loaded configuration.",
            "Catalog coverage is finite; no runtime feeds or exploit tests.",
        ],
        run=run if run is not None else {"timestamp": datetime.now(UTC).isoformat()},
    )


async def assess(
    client,
    *,
    product=None,
    known_version=None,
    profile="standard",
    policy="unspecified",
    scan_id="fg_local",
):
    provider = get_provider(product) if product else None
    plan = (
        provider.request_plan(profile)
        if provider
        else (
            (STANDARD_PATHS[0],)
            if profile == "minimal"
            else (*STANDARD_PATHS, "/")
            if profile == "extended"
            else STANDARD_PATHS
        )
    )
    observed = None
    for path in plan:
        response = await client.get(
            path, auth=path == STANDARD_PATHS[0] and client.has_token
        )
        if (
            path == STANDARD_PATHS[0]
            and response is not None
            and response.status_code == 200
        ):
            try:
                payload = response.json()
                candidate = (
                    payload.get("version") if isinstance(payload, dict) else None
                )
                if isinstance(candidate, str) and candidate.strip():
                    observed = candidate.strip()
            except (ValueError, TypeError):
                pass
    identity = identify(product, known_version, observed)
    target = Target(
        url=client.base,
        forge=product or "unknown",
        version=identity.normalized_version,
        authorized=True,
        product_confirmed=bool(product) and not identity.product_conflict,
        product_source=identity.product_source,
    )
    eligible = (
        bool(product)
        and not identity.product_conflict
        and not identity.version_conflict
    )
    state = (
        EvidenceState.ASSESSED
        if eligible
        and identity.support == "qualified"
        and client.observations.get(STANDARD_PATHS[0], {}).get("complete")
        and not client.observations.get(STANDARD_PATHS[0], {}).get("error")
        and client.observations.get(STANDARD_PATHS[0], {}).get("status")
        in (200, 401, 403)
        else EvidenceState.INDETERMINATE
    )
    findings = [
        finding(
            "FG-VER",
            "Product and version provenance",
            identity.model_dump(),
            "Declared product and consistent qualified upstream version.",
            scope="version",
            source=identity.product_source,
            state=state,
            reason="Product is an operator declaration; version conflicts stop advisory inference.",
            applicability="applicable"
            if state == EvidenceState.ASSESSED
            else "undetermined",
        )
    ]
    records, meta = catalog(product or "unknown")
    findings.extend(evaluate(r, identity) for r in records)
    if observed and not client.has_token:
        findings.append(
            finding(
                "FG-VER-DISCLOSE",
                "Anonymous version disclosure",
                {"endpoint": STANDARD_PATHS[0], "disclosed": True},
                "Review intentional version disclosure.",
                reason="An explicit version value was returned anonymously; no independent penalty.",
                group="version-context",
            )
        )
    skipped = []
    if profile == "minimal":
        skipped = ["FG-SIGNIN", "FG-REG", "FG-ANON", "FG-HTTP"]
    else:
        controls = [
            ("FG-SIGNIN", "Repository browser HTTP response", ("/explore/repos",)),
            ("FG-REG", "OCI registry-root HTTP response", ("/v2/",)),
            ("FG-ANON", "Allowlisted API HTTP responses", STANDARD_PATHS[3:]),
        ]
        for id_, title, paths in controls:
            obs = {p: client.observations.get(p, {"error": "missing"}) for p in paths}
            statuses = [
                x.get("status") if x.get("complete") else None for x in obs.values()
            ]
            complete = all(s in (200, 401, 403) for s in statuses)
            open_ = any(s == 200 for s in statuses)
            # HTTP 200 is a status observation, never a private-data claim.
            status = (
                Status.WARN
                if open_ and policy == "private"
                else (Status.PASS if complete and not open_ else Status.INFO)
            )
            findings.append(
                finding(
                    id_,
                    title,
                    obs,
                    "Private intent: review anonymous HTTP 200; public/unspecified: informational.",
                    status=status,
                    state=EvidenceState.ASSESSED
                    if complete
                    else EvidenceState.INDETERMINATE,
                    reason="Only the named path statuses were observed. HTTP 200 may be a login page, proxy error or empty API; it does not prove data access. Unknown responses remain incomplete even alongside a warning.",
                    applicability="applicable" if complete else "undetermined",
                    group="anonymous-access"
                    if id_ in ("FG-SIGNIN", "FG-ANON")
                    else id_,
                    references=(provider.api_source,) if provider else (),
                )
            )
        # These observations reuse already fetched responses.
        headers = {p: client.observations.get(p, {"error": "missing"}) for p in plan}
        complete = all(
            x.get("complete") and x.get("status") in (200, 401, 403)
            for x in headers.values()
        )
        findings.append(
            finding(
                "FG-HTTP",
                "Transport and HTTP protection observations",
                headers,
                "Verified HTTPS; header summaries apply only to returned response types.",
                state=EvidenceState.ASSESSED
                if complete
                else EvidenceState.INDETERMINATE,
                applicability="applicable" if complete else "undetermined",
                reason="HTTPS means certificate verification on this request, not a TLS audit. X-Frame-Options only describes embedding protection for HTML; nosniff is a limited response observation. HSTS/CSP presence is informational and is not policy validation. Reverse proxies may supply headers. No penalty from presence alone.",
            )
        )
    if profile != "extended":
        skipped.append("FG-ROOT-HTTP")
    else:
        root = client.observations.get("/", {"error": "missing"})
        complete = root.get("complete") and root.get("status") in (200, 401, 403)
        findings.append(
            finding(
                "FG-ROOT-HTTP",
                "Root HTTP protection observation",
                root,
                "Review HTML frame protection and declared transport.",
                state=EvidenceState.ASSESSED
                if complete
                else EvidenceState.INDETERMINATE,
                applicability="applicable" if complete else "undetermined",
                reason="Root response only, without loading linked assets or interpreting CSP.",
            )
        )
    return result_for(
        identity,
        findings,
        target=target,
        profile=profile,
        policy=policy,
        metadata=meta,
        skipped=skipped,
        count=client.request_count,
        scan_id=scan_id,
    )
