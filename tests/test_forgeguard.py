from __future__ import annotations

import ast
import asyncio
import re
from importlib.metadata import version as distribution_version
from pathlib import Path

import pytest
from typer.testing import CliRunner

import forgeguard.cli as cli_module
from forgeguard import __version__
from forgeguard.checks import (
    FIXED_VERSION,
    SAFE_ANON_PATHS,
    _is_vulnerable,
    _semver,
    check_anon,
    check_cve_27771,
    check_registry,
    check_signin,
    check_version,
    run_all_checks,
)
from forgeguard.cli import app
from forgeguard.client import _UA, ForgeClient
from forgeguard.models import (
    EvidenceState,
    Finding,
    ScanResult,
    Score,
    Severity,
    Status,
    Target,
)
from forgeguard.report import render_markdown
from forgeguard.safety import SAFE_GET_PATHS
from forgeguard.scoring import (
    CORE_CHECK_IDS,
    WARN_FACTOR,
    grade_for,
    priority_key,
    score_findings,
)
from forgeguard.urls import InvalidTargetURL, normalize_target_url

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


class FakeResponse:
    def __init__(self, status_code: int, payload: object | None = None) -> None:
        self.status_code = status_code
        self._payload = {} if payload is None else payload

    def json(self) -> object:
        return self._payload


class BrokenJSONResponse(FakeResponse):
    def json(self) -> object:
        raise ValueError("synthetic malformed JSON")


class RecordingClient:
    def __init__(
        self, responses: dict[str, FakeResponse], has_token: bool = False
    ) -> None:
        self.base = "https://forge.example"
        self.has_token = has_token
        self.responses = responses
        self.requests: list[tuple[str, bool]] = []

    async def get(self, path: str, *, auth: bool = False) -> FakeResponse | None:
        self.requests.append((path, auth))
        return self.responses.get(path)


def run(coro):
    return asyncio.run(coro)


def by_id(findings: list[Finding], finding_id: str) -> Finding:
    return next(finding for finding in findings if finding.id == finding_id)


def complete_responses(
    *,
    version_status: int = 403,
    version: str | None = None,
    v2: int = 403,
    home: int = 403,
    api: int = 403,
    explore: int = 403,
    users: int = 403,
) -> dict[str, FakeResponse]:
    version_payload = {"version": version} if version is not None else {}
    return {
        "/api/v1/version": FakeResponse(version_status, version_payload),
        "/v2/": FakeResponse(v2),
        "/": FakeResponse(home),
        "/api/v1/repos/search?limit=1": FakeResponse(api),
        "/explore/repos": FakeResponse(explore),
        "/api/v1/users/search?limit=1": FakeResponse(users),
    }


def run_scored(
    responses: dict[str, FakeResponse],
    *,
    product: str | None = None,
    known_version: str | None = None,
    has_token: bool = False,
) -> tuple[list[Finding], Target, Score]:
    findings, target = run(
        run_all_checks(
            RecordingClient(responses, has_token=has_token),
            known_version=known_version,
            product=product,
        )
    )
    return findings, target, score_findings(findings)


def test_version_parsing_and_gitea_fixed_release_comparison() -> None:
    assert _semver("1.26.2") == (1, 26, 2)
    assert _semver("1.26.2+gitea") == (1, 26, 2)
    assert _semver("1.26.2-rc1") is None
    assert _semver("not-a-version") is None
    assert _is_vulnerable("1.26.1") is True
    assert _is_vulnerable(FIXED_VERSION) is False
    assert _is_vulnerable("1.27.0") is False
    assert _is_vulnerable(None) is None


@pytest.mark.parametrize("version", ["1.26.1", "1.26.2", "1.27.0", "2.0.0"])
def test_fg_ver_is_informational_observation_without_security_penalty(
    version: str,
) -> None:
    target = Target(
        url="https://forge.example",
        forge="gitea",
        version=version,
        product_confirmed=True,
        product_source="operator-declared",
    )
    finding = run(check_version(RecordingClient({}), target, False))[0]
    assert finding.id == "FG-VER"
    assert finding.status == Status.PASS
    assert finding.severity == Severity.info
    assert finding.evidence_state == EvidenceState.INFORMATIONAL
    assert "CVE risk is scored separately" in finding.rationale


@pytest.mark.parametrize("version", [None, "not-a-version", "1.26.2-rc1"])
def test_fg_ver_unknown_is_informational_not_a_penalty(version: str | None) -> None:
    target = Target(
        url="https://forge.example",
        forge="gitea",
        version=version,
        product_confirmed=True,
        product_source="operator-declared",
    )
    finding = run(check_version(RecordingClient({}), target, False))[0]
    assert finding.status == Status.INFO
    assert finding.severity == Severity.info
    assert finding.evidence_state == EvidenceState.INFORMATIONAL


def test_cve_gitea_1261_is_affected_fail_high_and_authoritative_cwe() -> None:
    finding = run(
        check_cve_27771(
            Target(
                url="https://forge.example",
                forge="gitea",
                version="1.26.1",
                product_confirmed=True,
                product_source="operator-declared",
            )
        )
    )[0]
    assert finding.status == Status.FAIL
    assert finding.severity == Severity.high
    assert finding.evidence_state == EvidenceState.ASSESSED
    assert finding.cwe == "CWE-862"
    assert "affected range" in finding.rationale
    assert "does not prove exploitability or data exposure" in finding.rationale


@pytest.mark.parametrize("version", ["1.26.2", "1.27.0", "2.0.0"])
def test_cve_confirmed_gitea_at_or_above_fixed_release_is_pass(version: str) -> None:
    finding = run(
        check_cve_27771(
            Target(
                url="https://forge.example",
                forge="gitea",
                version=version,
                product_confirmed=True,
                product_source="operator-declared",
            )
        )
    )[0]
    assert finding.status == Status.PASS
    assert finding.severity == Severity.info
    assert finding.evidence_state == EvidenceState.ASSESSED
    assert finding.remediation == ""


@pytest.mark.parametrize("version", [None, "1.26.2-rc1", "malformed"])
def test_cve_unknown_version_is_explicitly_indeterminate(version: str | None) -> None:
    finding = run(
        check_cve_27771(
            Target(
                url="https://forge.example",
                forge="gitea",
                version=version,
                product_confirmed=True,
                product_source="operator-declared",
            )
        )
    )[0]
    assert finding.status == Status.INFO
    assert finding.severity == Severity.medium
    assert finding.evidence_state == EvidenceState.INDETERMINATE


def test_forgejo_marker_conflicts_with_gitea_declaration_and_fails_safe() -> None:
    findings, target, score = run_scored(
        complete_responses(version_status=200, version="11.0.0+forgejo"),
        product="gitea",
    )
    assert target.forge == "forgejo"
    assert target.product_confirmed is False
    assert target.product_source == "version-marker-conflict"
    assert by_id(findings, "FG-CVE-27771").status == Status.INFO
    assert by_id(findings, "FG-CVE-27771").evidence_state == EvidenceState.INDETERMINATE
    assert score.assessed is False
    assert score.value is None
    assert score.grade == "N/A"


@pytest.mark.parametrize("version", ["9.9.9", "1.26.2"])
def test_generic_version_endpoint_does_not_confirm_gitea(version: str) -> None:
    findings, target, score = run_scored(
        complete_responses(version_status=200, version=version)
    )
    assert target.forge == "unknown"
    assert target.product_confirmed is False
    assert by_id(findings, "FG-VER").status == Status.INFO
    assert by_id(findings, "FG-CVE-27771").status == Status.INFO
    assert score.assessed is False
    assert score.value is None
    assert score.grade == "N/A"


def test_known_version_without_product_confirmation_is_ungraded() -> None:
    findings, target, score = run_scored(
        complete_responses(),
        known_version="1.26.2",
    )
    assert target.forge == "unknown"
    assert target.version == "1.26.2"
    assert by_id(findings, "FG-CVE-27771").evidence_state == EvidenceState.INDETERMINATE
    assert score.grade == "N/A"


@pytest.mark.parametrize("payload", [[], {"unexpected": "value"}, {"version": 1262}])
def test_malformed_version_response_keeps_product_unknown(payload: object) -> None:
    responses = complete_responses(version_status=200)
    responses["/api/v1/version"] = FakeResponse(200, payload)
    findings, target, score = run_scored(responses)
    assert target.forge == "unknown"
    assert target.product_confirmed is False
    assert by_id(findings, "FG-CVE-27771").evidence_state == EvidenceState.INDETERMINATE
    assert score.grade == "N/A"


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"unexpected": "value"},
        {"version": None},
        {"version": 1262},
        {"version": ""},
        {"version": "   "},
        [],
    ],
)
def test_empty_or_invalid_remote_version_does_not_claim_disclosure(
    payload: object,
) -> None:
    responses = complete_responses(version_status=200)
    responses["/api/v1/version"] = FakeResponse(200, payload)
    findings, target, score = run_scored(
        responses, product="gitea", known_version="1.26.2"
    )
    assert target.version == "1.26.2"
    assert all(finding.id != "FG-VER-DISCLOSE" for finding in findings)
    assert score.value == 100


def test_malformed_version_json_does_not_claim_disclosure() -> None:
    responses = complete_responses(version_status=200)
    responses["/api/v1/version"] = BrokenJSONResponse(200)
    findings, target, score = run_scored(
        responses, product="gitea", known_version="1.26.2"
    )
    assert target.version == "1.26.2"
    assert all(finding.id != "FG-VER-DISCLOSE" for finding in findings)
    assert score.value == 100


def test_nonempty_anonymous_remote_version_is_disclosure() -> None:
    findings, target, score = run_scored(
        complete_responses(version_status=200, version=" 1.26.2 "),
        product="gitea",
        known_version="1.26.1",
    )
    assert target.version == "1.26.2"
    assert by_id(findings, "FG-VER-DISCLOSE").status == Status.WARN
    assert score.value == 99


def test_explicit_product_confirmation_enables_gitea_cve_pass() -> None:
    findings, target, score = run_scored(
        complete_responses(version_status=200, version="1.26.2"),
        product="gitea",
        has_token=True,
    )
    assert target.forge == "gitea"
    assert target.product_confirmed is True
    assert target.product_source == "operator-declared"
    assert by_id(findings, "FG-CVE-27771").status == Status.PASS
    assert score.assessed is True
    assert score.value == 100
    assert score.grade == "A"


def test_registry_and_signin_responses_do_not_change_cve_verdict() -> None:
    cases = [
        complete_responses(v2=200, api=200, explore=200, users=200),
        complete_responses(v2=401, api=401, explore=401, users=401),
        complete_responses(v2=403, api=403, explore=403, users=403),
        complete_responses(v2=500, api=500, explore=500, users=500),
    ]
    cve_results = []
    for responses in cases:
        findings, _target, _score = run_scored(
            responses,
            known_version="1.26.1",
            product="gitea",
        )
        cve_results.append(by_id(findings, "FG-CVE-27771").model_dump())
    assert cve_results[0] == cve_results[1] == cve_results[2] == cve_results[3]
    assert cve_results[0]["status"] == Status.FAIL


def test_cve_check_performs_no_network_requests() -> None:
    finding = run(
        check_cve_27771(
            Target(
                url="https://forge.example",
                forge="gitea",
                version="1.26.1",
                product_confirmed=True,
                product_source="operator-declared",
            )
        )
    )[0]
    assert finding.status == Status.FAIL
    assert set(finding.evidence) == {
        "product",
        "product_confirmed",
        "product_source",
        "version",
        "affected_through",
        "first_fixed_in",
    }


def test_registry_200_is_limited_independent_observation() -> None:
    finding = run(
        check_registry(
            RecordingClient({"/v2/": FakeResponse(200)}),
            Target(url="https://forge.example"),
        )
    )[0]
    assert finding.status == Status.WARN
    assert finding.severity == Severity.medium
    assert finding.evidence_state == EvidenceState.ASSESSED
    assert "does not prove access" in finding.rationale
    assert "CVE-2026-27771" not in finding.model_dump_json()


@pytest.mark.parametrize("status_code", [401, 403])
def test_registry_explicit_access_control_is_narrow_pass(status_code: int) -> None:
    finding = run(
        check_registry(
            RecordingClient({"/v2/": FakeResponse(status_code)}),
            Target(url="https://forge.example"),
        )
    )[0]
    assert finding.status == Status.PASS
    assert finding.severity == Severity.info
    assert finding.evidence_state == EvidenceState.ASSESSED
    assert finding.evidence["anon_v2_http"] == status_code


@pytest.mark.parametrize(
    "status_code",
    [404, 301, 302, 303, 307, 308, 429, 500, 502, 503, 418],
)
def test_registry_ambiguous_or_error_status_is_indeterminate(status_code: int) -> None:
    finding = run(
        check_registry(
            RecordingClient({"/v2/": FakeResponse(status_code)}),
            Target(url="https://forge.example"),
        )
    )[0]
    assert finding.status == Status.INFO
    assert finding.severity == Severity.medium
    assert finding.evidence_state == EvidenceState.INDETERMINATE
    assert finding.evidence["anon_v2_http"] == status_code


def test_registry_no_response_is_indeterminate() -> None:
    finding = run(
        check_registry(RecordingClient({}), Target(url="https://forge.example"))
    )[0]
    assert finding.status == Status.INFO
    assert finding.evidence_state == EvidenceState.INDETERMINATE


@pytest.mark.parametrize("browse_status", [401, 403])
def test_signin_pass_requires_explicit_browsing_access_control(
    browse_status: int,
) -> None:
    finding = run(
        check_signin(
            RecordingClient({"/explore/repos": FakeResponse(browse_status)}),
            Target(url="https://forge.example"),
        )
    )[0]
    assert finding.status == Status.PASS
    assert finding.evidence_state == EvidenceState.ASSESSED
    assert "no specific REQUIRE_SIGNIN_VIEW" in finding.rationale


def test_signin_200_is_observed_warning() -> None:
    finding = run(
        check_signin(
            RecordingClient({"/explore/repos": FakeResponse(200)}),
            Target(url="https://forge.example"),
        )
    )[0]
    assert finding.status == Status.WARN
    assert finding.evidence_state == EvidenceState.ASSESSED


@pytest.mark.parametrize("status_code", [404, 302, 307, 429, 500, 502, 503])
def test_signin_ambiguous_or_error_status_is_indeterminate(status_code: int) -> None:
    finding = run(
        check_signin(
            RecordingClient({"/explore/repos": FakeResponse(status_code)}),
            Target(url="https://forge.example"),
        )
    )[0]
    assert finding.status == Status.INFO
    assert finding.evidence_state == EvidenceState.INDETERMINATE


def test_signin_no_response_is_indeterminate() -> None:
    finding = run(
        check_signin(RecordingClient({}), Target(url="https://forge.example"))
    )[0]
    assert finding.status == Status.INFO
    assert finding.evidence_state == EvidenceState.INDETERMINATE


def test_anonymous_200_warns_and_all_401_403_passes() -> None:
    paths = [
        "/api/v1/repos/search?limit=1",
        "/api/v1/users/search?limit=1",
    ]
    open_client = RecordingClient({path: FakeResponse(403) for path in paths})
    open_client.responses[paths[0]] = FakeResponse(200)
    open_finding = run(check_anon(open_client, Target(url=open_client.base)))[0]
    assert open_finding.status == Status.WARN
    assert open_finding.evidence_state == EvidenceState.ASSESSED

    controlled_client = RecordingClient(
        {
            paths[0]: FakeResponse(401),
            paths[1]: FakeResponse(403),
        }
    )
    controlled = run(check_anon(controlled_client, Target(url=controlled_client.base)))[
        0
    ]
    assert controlled.status == Status.PASS
    assert controlled.evidence_state == EvidenceState.ASSESSED


@pytest.mark.parametrize("status_code", [404, 302, 307, 429, 500, 502, 503])
def test_anonymous_ambiguous_or_error_status_is_indeterminate(status_code: int) -> None:
    paths = [
        "/api/v1/repos/search?limit=1",
        "/api/v1/users/search?limit=1",
    ]
    client = RecordingClient({path: FakeResponse(status_code) for path in paths})
    finding = run(check_anon(client, Target(url=client.base)))[0]
    assert finding.status == Status.INFO
    assert finding.evidence_state == EvidenceState.INDETERMINATE


def test_anonymous_missing_response_is_indeterminate() -> None:
    finding = run(check_anon(RecordingClient({}), Target(url="https://forge.example")))[
        0
    ]
    assert finding.status == Status.INFO
    assert finding.evidence_state == EvidenceState.INDETERMINATE


@pytest.mark.parametrize(
    (
        "api_status",
        "browse_status",
        "signin_status",
        "anon_status",
        "expected_value",
    ),
    [
        (200, 403, Status.PASS, Status.WARN, 97),
        (403, 200, Status.WARN, Status.PASS, 97),
        (200, 200, Status.WARN, Status.WARN, 94),
    ],
)
def test_signin_and_anonymous_api_have_disjoint_penalty_ownership(
    api_status: int,
    browse_status: int,
    signin_status: Status,
    anon_status: Status,
    expected_value: int,
) -> None:
    findings, _target, score = run_scored(
        complete_responses(api=api_status, explore=browse_status, users=403),
        product="gitea",
        known_version="1.26.2",
    )
    assert by_id(findings, "FG-SIGNIN").status == signin_status
    assert by_id(findings, "FG-ANON").status == anon_status
    assert score.value == expected_value


def test_single_api_warning_preserves_affected_boundary_grade() -> None:
    findings, _target, score = run_scored(
        complete_responses(api=200, explore=403, users=403),
        product="gitea",
        known_version="1.26.1",
    )
    assert by_id(findings, "FG-SIGNIN").status == Status.PASS
    assert by_id(findings, "FG-ANON").status == Status.WARN
    assert score.value == 77
    assert score.grade == "B"


def test_scoring_single_cve_penalty_closes_double_count() -> None:
    findings, _target, score = run_scored(
        complete_responses(),
        product="gitea",
        known_version="1.26.1",
    )
    assert by_id(findings, "FG-VER").status == Status.PASS
    assert by_id(findings, "FG-VER").severity == Severity.info
    assert by_id(findings, "FG-CVE-27771").status == Status.FAIL
    assert score.assessed is True
    assert score.value == 80
    assert score.grade == "B"
    assert score.sub == {"patch": 80, "registry": 100, "auth": 100}


def test_scoring_weights_warn_factor_and_grade_thresholds() -> None:
    findings = [
        Finding(
            id="FG-CVE-27771",
            title="cve",
            severity=Severity.high,
            status=Status.FAIL,
        ),
        Finding(
            id="FG-REG",
            title="registry",
            severity=Severity.medium,
            status=Status.WARN,
        ),
        Finding(
            id="FG-SIGNIN",
            title="signin",
            severity=Severity.info,
            status=Status.PASS,
        ),
        Finding(
            id="FG-ANON",
            title="anon",
            severity=Severity.info,
            status=Status.PASS,
        ),
    ]
    score = score_findings(findings)
    assert WARN_FACTOR == 0.35
    assert score.value == 77
    assert score.grade == "B"
    assert grade_for(90) == "A"
    assert grade_for(75) == "B"
    assert grade_for(60) == "C"
    assert grade_for(40) == "D"
    assert grade_for(39) == "F"


def test_all_core_evidence_missing_is_ungraded_not_a() -> None:
    score = score_findings([])
    assert score.assessed is False
    assert score.value is None
    assert score.grade == "N/A"
    assert score.incomplete_checks == list(CORE_CHECK_IDS)
    assert set(score.sub) == {"patch", "registry", "auth"}
    assert all(value is None for value in score.sub.values())


def test_unknown_version_is_ungraded_not_a() -> None:
    _findings, _target, score = run_scored(
        complete_responses(),
        product="gitea",
    )
    assert score.assessed is False
    assert score.value is None
    assert score.grade == "N/A"
    assert "FG-CVE-27771" in score.incomplete_checks


def test_registry_timeout_prevents_full_grade() -> None:
    responses = complete_responses()
    del responses["/v2/"]
    _findings, _target, score = run_scored(
        responses,
        product="gitea",
        known_version="1.26.2",
    )
    assert score.assessed is False
    assert score.grade == "N/A"
    assert "FG-REG" in score.incomplete_checks


def test_all_server_errors_are_ungraded_not_a() -> None:
    responses = complete_responses(
        version_status=500,
        v2=500,
        api=500,
        explore=500,
        users=500,
    )
    findings, _target, score = run_scored(responses, product="gitea")
    assert by_id(findings, "FG-REG").status == Status.INFO
    assert by_id(findings, "FG-ANON").status == Status.INFO
    assert score.assessed is False
    assert score.value is None
    assert score.grade == "N/A"


def test_fully_assessed_clean_confirmed_gitea_can_score_100_a() -> None:
    _findings, target, score = run_scored(
        complete_responses(),
        product="gitea",
        known_version="1.26.2",
    )
    assert target.product_confirmed is True
    assert score.assessed is True
    assert score.value == 100
    assert score.grade == "A"
    assert score.incomplete_checks == []


def test_status_adjusted_top_action_sorting() -> None:
    findings = [
        Finding(id="LOW", title="low", severity=Severity.low, status=Status.FAIL),
        Finding(
            id="MEDWARN",
            title="medium warn",
            severity=Severity.medium,
            status=Status.WARN,
        ),
        Finding(id="HIGH", title="high", severity=Severity.high, status=Status.FAIL),
    ]
    ordered = sorted(findings, key=priority_key, reverse=True)
    assert [finding.id for finding in ordered] == ["HIGH", "LOW", "MEDWARN"]


def test_markdown_report_uses_single_cve_action_and_score() -> None:
    findings, target, score = run_scored(
        complete_responses(),
        product="gitea",
        known_version="1.26.1",
    )
    target.authorized = True
    result = ScanResult(
        scan_id="test",
        target=target,
        score=score,
        findings=findings,
        summary={"high": 1, "pass": 4},
    )
    markdown = render_markdown(result)
    assert "**Score:** 80/100 (B)" in markdown
    assert markdown.count("P1 - Upgrade Gitea") == 1
    assert "does not prove exploitability" in markdown
    assert "active exposure" not in markdown.lower()
    assert "mitigated posture" not in markdown.lower()


def test_markdown_incomplete_assessment_is_explicitly_ungraded() -> None:
    findings, target, score = run_scored(complete_responses())
    target.authorized = True
    result = ScanResult(
        scan_id="incomplete",
        target=target,
        score=score,
        findings=findings,
    )
    markdown = render_markdown(result)
    assert "**Score:** N/A (assessment incomplete)" in markdown
    assert "Complete assessment evidence" in markdown
    assert "INFO / UNDETERMINED" in markdown
    assert "100/100" not in markdown


def test_markdown_neutralizes_untrusted_structure_html_and_backticks() -> None:
    malicious = "1.26.2\n\n# M3C_REMOTE_HEADING\n\n<script>m3c()</script>\n`break`"
    finding = Finding(
        id="FG-REMOTE\n# FAKE-ID",
        title="Remote <title>",
        severity=Severity.info,
        status=Status.INFO,
        evidence={"version": malicious},
        rationale=f"Observed {malicious}",
        remediation="Review `quoted` <input>.",
        references=["https://example.invalid/<ref>"],
    )
    result = ScanResult(
        scan_id="scan\n# FAKE-SCAN",
        target=Target(
            url="https://forge.example/\n# FAKE-URL",
            forge="gitea",
            version=malicious,
            authorized=True,
            product_confirmed=True,
            product_source="operator\n# FAKE-SOURCE",
        ),
        score=Score(value=100, grade="A"),
        findings=[finding],
        summary={"info": 1},
    )
    markdown = render_markdown(result)
    assert "\n# M3C_REMOTE_HEADING" not in markdown
    assert "<script>m3c()</script>" not in markdown
    assert r"\n\n# M3C\_REMOTE\_HEADING" in markdown
    assert "&lt;script&gt;m3c()&lt;/script&gt;" in markdown
    assert r"\`break\`" in markdown
    json_output = result.model_dump_json()
    assert r"\n\n# M3C_REMOTE_HEADING" in json_output
    assert "<script>m3c()</script>" in json_output


def test_json_round_trip_schema_and_completeness_truth() -> None:
    result = ScanResult(
        scan_id="roundtrip",
        target=Target(url="https://forge.example"),
        score=Score(
            value=None,
            grade="N/A",
            assessed=False,
            incomplete_checks=["FG-CVE-27771"],
        ),
    )
    restored = ScanResult.model_validate_json(result.model_dump_json())
    assert restored.tool["schema"] == "forgeguard.scan-result.v0.3"
    assert restored.tool["version"] == __version__
    assert restored.score.value is None
    assert restored.score.assessed is False


def test_distribution_import_runtime_json_and_user_agent_versions_match() -> None:
    installed = distribution_version("forgeguard")
    result = ScanResult(
        scan_id="version-truth",
        target=Target(url="https://forge.example"),
        score=Score(value=100, grade="A"),
    )
    assert installed == __version__ == result.tool["version"] == "0.5.0rc4"
    assert f"/{installed} " in _UA


def test_cli_requires_authorized_and_documents_product_confirmation() -> None:
    runner = CliRunner()
    denied = runner.invoke(app, ["scan", "--url", "https://forge.example"])
    assert denied.exit_code == 2
    assert "REFUSED" in _ANSI.sub("", denied.output)

    help_result = runner.invoke(
        app,
        ["scan", "--help"],
        env={"COLUMNS": "220", "NO_COLOR": "1", "TERM": "dumb"},
    )
    assert help_result.exit_code == 0
    help_text = " ".join(_ANSI.sub("", help_result.output).replace("│", " ").split())
    assert "--authorized" in help_text
    assert "--product" in help_text
    assert "unconfirmed, ungraded" in help_text
    assert "FORGEGUARD_TOKEN" in help_text


def test_cli_refuses_unsupported_product_declaration() -> None:
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--url",
            "https://forge.example",
            "--authorized",
            "--product",
            "gogs",
        ],
    )
    assert result.exit_code == 2
    assert "accepts only '--product gitea'" in _ANSI.sub("", result.output)


@pytest.mark.parametrize(
    "url",
    [
        "https://user:password@git.example.com",
        "https://git.example.com/?token=secret",
        "https://git.example.com/#secret",
        "ftp://git.example.com",
        "https:///missing-host",
    ],
)
def test_unsafe_target_urls_are_rejected(url: str) -> None:
    with pytest.raises(InvalidTargetURL):
        normalize_target_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "https://git.example.com/a/../b",
        "https://git.example.com/./gitea",
        "https://git.example.com/a/%2e%2e/b",
        "https://git.example.com/a/%252e%252e/b",
        "https://git.example.com/a/%25252e%25252e/b",
        "https://git.example.com/a/%252f%252e%252e%252fadmin",
        "https://git.example.com/a/%255c%252e%252e%255cadmin",
        r"https://git.example.com/a\..\b",
    ],
)
def test_target_url_rejects_dot_segments(url: str) -> None:
    with pytest.raises(InvalidTargetURL, match="dot segments"):
        normalize_target_url(url)


def test_target_url_preserves_legal_gitea_subpath() -> None:
    assert normalize_target_url("HTTPS://git.example.com/team/gitea/") == (
        "https://git.example.com/team/gitea"
    )


@pytest.mark.parametrize(
    ("url", "secret"),
    [
        ("https://user:password@git.example.com", "password"),
        ("https://git.example.com/?token=secret", "secret"),
        ("https://git.example.com/#fragment-secret", "fragment-secret"),
    ],
)
def test_cli_rejects_sensitive_url_without_echoing_it(url: str, secret: str) -> None:
    result = CliRunner().invoke(
        app,
        ["scan", "--url", url, "--authorized", "--product", "gitea"],
    )
    assert result.exit_code == 2
    assert "REFUSED" in _ANSI.sub("", result.output)
    assert secret not in result.output
    assert url not in result.output


def _synthetic_result() -> ScanResult:
    return ScanResult(
        scan_id="token-opsec",
        target=Target(
            url="https://forge.example",
            forge="gitea",
            version="1.26.2",
            authorized=True,
            product_confirmed=True,
            product_source="operator-declared",
        ),
        score=Score(value=100, grade="A"),
        findings=[],
        summary={"pass": 0},
    )


def test_command_line_token_is_absent_from_terminal_and_reports(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sentinel = "fg_test_token_not_real_7dA9"
    observed: dict[str, str | None] = {}

    async def fake_run(
        url: str,
        token: str | None,
        known_version: str | None,
        product: str | None,
        scan_id: str,
    ) -> ScanResult:
        observed["token"] = token
        observed["product"] = product
        return _synthetic_result()

    monkeypatch.setattr(cli_module, "_run", fake_run)
    output_path = tmp_path / "report.md"
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--url",
            "https://forge.example",
            "--authorized",
            "--product",
            "gitea",
            "--token",
            sentinel,
            "--format",
            "md,json",
            "--out",
            str(output_path),
        ],
    )
    assert result.exit_code == 0
    assert observed == {"token": sentinel, "product": "gitea"}
    assert "SECURITY WARNING" in _ANSI.sub("", result.output)
    assert sentinel not in result.output
    assert sentinel not in output_path.read_text()
    assert sentinel not in output_path.with_suffix(".json").read_text()


def test_dual_output_paths_are_distinct_or_refused_before_scan(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls = 0

    async def fake_run(
        url: str,
        token: str | None,
        known_version: str | None,
        product: str | None,
        scan_id: str,
    ) -> ScanResult:
        del url, token, known_version, product, scan_id
        nonlocal calls
        calls += 1
        return _synthetic_result()

    monkeypatch.setattr(cli_module, "_run", fake_run)
    for filename in ("report.md", "second-report", "archive.scan.md"):
        output_path = tmp_path / filename
        result = CliRunner().invoke(
            app,
            [
                "scan",
                "--url",
                "https://forge.example",
                "--authorized",
                "--product",
                "gitea",
                "--format",
                "md,json",
                "--out",
                str(output_path),
            ],
        )
        json_path = output_path.with_suffix(".json")
        assert result.exit_code == 0
        assert output_path.is_file()
        assert json_path.is_file()
        assert output_path != json_path

    collision = tmp_path / "collision.json"
    refused = CliRunner().invoke(
        app,
        [
            "scan",
            "--url",
            "https://forge.example",
            "--authorized",
            "--product",
            "gitea",
            "--format",
            "md,json",
            "--out",
            str(collision),
        ],
    )
    assert refused.exit_code == 2
    assert "resolve to the same file" in _ANSI.sub("", refused.output)
    assert calls == 3
    assert not collision.exists()


def test_environment_token_is_preferred_and_not_echoed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sentinel = "fg_env_token_not_real_4cB2"
    observed: dict[str, str | None] = {}

    async def fake_run(
        url: str,
        token: str | None,
        known_version: str | None,
        product: str | None,
        scan_id: str,
    ) -> ScanResult:
        observed["token"] = token
        observed["product"] = product
        return _synthetic_result()

    monkeypatch.setattr(cli_module, "_run", fake_run)
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--url",
            "https://forge.example",
            "--authorized",
            "--product",
            "gitea",
            "--format",
            "json",
        ],
        env={"FORGEGUARD_TOKEN": sentinel},
    )
    assert result.exit_code == 0
    assert observed == {"token": sentinel, "product": "gitea"}
    assert "SECURITY WARNING" not in _ANSI.sub("", result.output)
    assert sentinel not in result.output


def test_target_authorization_metadata_defaults_false() -> None:
    assert Target(url="https://forge.example").authorized is False
    assert _synthetic_result().target.authorized is True


def test_client_refuses_non_allowlisted_path() -> None:
    client = ForgeClient("https://forge.example")
    try:
        with pytest.raises(ValueError):
            run(client.get("/v2/private/manifests/latest"))
    finally:
        run(client.aclose())


def test_safe_get_paths_alias_matches_and_contains_no_artifact_path() -> None:
    assert set(SAFE_ANON_PATHS) == set(SAFE_GET_PATHS)
    assert all("blob" not in path and "manifest" not in path for path in SAFE_GET_PATHS)


def test_run_all_checks_is_single_target_and_safe_allowlist_only() -> None:
    client = RecordingClient(complete_responses())
    findings, target = run(
        run_all_checks(client, known_version="1.26.1", product="gitea")
    )
    assert target.url == "https://forge.example"
    assert target.product_confirmed is True
    assert {finding.id for finding in findings} >= {
        "FG-VER",
        "FG-CVE-27771",
        "FG-SIGNIN",
        "FG-REG",
        "FG-ANON",
    }
    requested_paths = [path for path, _auth in client.requests]
    assert set(requested_paths).issubset(set(SAFE_GET_PATHS))
    assert all(path.startswith("/") for path in requested_paths)
    assert len(requested_paths) == len(set(requested_paths))
    assert len({client.base}) == 1


def test_package_contains_no_state_changing_http_method_calls() -> None:
    package_root = Path(__file__).parents[1] / "forgeguard"
    forbidden: list[tuple[str, int, str]] = []
    for path in package_root.glob("*.py"):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr.lower() in {"post", "put", "patch", "delete"}
            ):
                forbidden.append((path.name, node.lineno, node.func.attr))
    assert forbidden == []


def test_registration_is_not_claimed_as_implemented() -> None:
    root = Path(__file__).parents[1]
    implemented_copy = [
        root / "README.md",
        root / "docs" / "USAGE.md",
        root / "forgeguard" / "cli.py",
        root / "pyproject.toml",
    ]
    for path in implemented_copy:
        lines = [
            line.lower()
            for line in path.read_text().splitlines()
            if "registration posture" in line.lower()
        ]
        assert all("not checked" in line or "not implemented" in line for line in lines)


def test_forgejo_is_not_claimed_in_implemented_product_copy() -> None:
    root = Path(__file__).parents[1]
    implemented_copy = [
        root / "README.md",
        root / "docs" / "USAGE.md",
        root / "forgeguard" / "__init__.py",
        root / "forgeguard" / "cli.py",
        root / "forgeguard" / "models.py",
        root / "pyproject.toml",
    ]
    for path in implemented_copy:
        assert "gitea/forgejo" not in path.read_text().lower()
        assert "gitea and forgejo" not in path.read_text().lower()


def test_authoritative_cwe_has_no_stale_value_in_public_text() -> None:
    root = Path(__file__).parents[1]
    text_paths = [
        root / "README.md",
        root / "CHANGELOG.md",
        *sorted((root / "docs").glob("*.md")),
        *sorted((root / "examples").glob("*")),
        *sorted((root / "forgeguard").glob("*.py")),
    ]
    for path in text_paths:
        text = path.read_text()
        assert "CWE-285" not in text


def test_ci_contains_required_semantic_integrity_gates() -> None:
    workflow = (
        Path(__file__).parents[1] / ".github" / "workflows" / "ci.yml"
    ).read_text()
    for command in [
        "ruff check .",
        "ruff format --check .",
        "pytest",
        "pip check",
        "python -m build",
        "twine check dist/*",
    ]:
        assert command in workflow
    assert 'python-version: ["3.11", "3.12"]' in workflow


def test_release_publish_is_fail_closed_on_full_quality_gate() -> None:
    # Qualification (test/build/attest) lives in ci.yml on the trusted push.
    ci = (Path(__file__).parents[1] / ".github" / "workflows" / "ci.yml").read_text()
    for command in [
        "ruff check .",
        "ruff format --check .",
        "python -m compileall forgeguard",
        "twine check dist/*",
        "python -m build",
        ".wheel-smoke/bin/python -m pip install dist/*.whl",
        ".wheel-smoke/bin/forgeguard scan --help",
    ]:
        assert command in ci, command
    assert 'python-version: ["3.11", "3.12"]' in ci

    # release.yml only promotes the already-qualified frozen set: no rebuild,
    # download the referenced run's artifacts, id-token scoped to the publish job.
    release = (
        Path(__file__).parents[1] / ".github" / "workflows" / "release.yml"
    ).read_text()
    assert "python -m build" not in release
    assert "gh run download" in release
    assert "needs: promote" in release
    assert release.index("promote:") < release.index("pypi-publish:")
    assert release.count("id-token: write") == 1


@pytest.mark.parametrize(
    "label",
    ["affected_pre_update", "patched_post_update"],
)
def test_synthetic_examples_match_current_schema_scoring_and_renderer(
    label: str,
) -> None:
    root = Path(__file__).parents[1] / "examples"
    result = ScanResult.model_validate_json(
        (root / f"scan_result_{label}.json").read_text()
    )
    expected_markdown = (root / f"scan_report_{label}.md").read_text()
    rescored = score_findings(result.findings)
    assert result.tool["version"] == "0.2.2"
    assert result.tool["schema"] == "forgeguard.scan-result.v0.3"
    assert result.target.url == "https://git.example.com"
    assert result.target.product_confirmed is True
    assert result.score == rescored
    assert render_markdown(result).rstrip("\n") == expected_markdown.rstrip("\n")
    assert "active exposure" not in expected_markdown.lower()
    assert "mitigated posture" not in expected_markdown.lower()

    if label == "affected_pre_update":
        assert result.score.value == 80
        assert result.score.grade == "B"
    else:
        assert result.score.value == 100
        assert result.score.grade == "A"
