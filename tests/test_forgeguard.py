from __future__ import annotations

import asyncio

import pytest
from typer.testing import CliRunner

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
from forgeguard.models import Finding, ScanResult, Score, Severity, Status, Target
from forgeguard.report import render_markdown
from forgeguard.safety import SAFE_GET_PATHS
from forgeguard.scoring import WARN_FACTOR, grade_for, priority_key, score_findings


class FakeResponse:
    def __init__(self, status_code: int, payload: dict | None = None) -> None:
        self.status_code = status_code
        self._payload = payload or {}

    def json(self) -> dict:
        return self._payload


class RecordingClient:
    def __init__(self, responses: dict[str, FakeResponse], has_token: bool = False) -> None:
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


def test_version_parsing_and_comparison() -> None:
    assert _semver("1.26.2") == (1, 26, 2)
    assert _semver("1.26.2+gitea") == (1, 26, 2)
    assert _semver("not-a-version") is None
    assert _is_vulnerable("1.25.3") is True
    assert _is_vulnerable(FIXED_VERSION) is False
    assert _is_vulnerable("1.27.0") is False
    assert _is_vulnerable(None) is None


def test_version_check_flags_below_fixed_release() -> None:
    target = Target(url="https://forge.example", version="1.25.3")
    finding = run(check_version(RecordingClient({}), target, False))[0]
    assert finding.id == "FG-VER"
    assert finding.status == Status.FAIL
    assert finding.severity == Severity.high
    assert finding.evidence["fixed_in"] == FIXED_VERSION


def test_version_check_passes_at_or_above_fixed_release() -> None:
    target = Target(url="https://forge.example", version="1.26.2")
    finding = run(check_version(RecordingClient({}), target, False))[0]
    assert finding.status == Status.PASS
    assert finding.title.startswith("Patched")


def test_cve_vulnerable_and_exposed_is_fail() -> None:
    client = RecordingClient({"/v2/": FakeResponse(200), "/": FakeResponse(200)})
    target = Target(url=client.base, version="1.25.3")
    finding = run(check_cve_27771(client, target))[0]
    assert finding.status == Status.FAIL
    assert finding.severity == Severity.critical
    assert finding.evidence["registry_anon_open"] is True
    assert "Active exposure" in finding.rationale
    assert "immediately" in finding.remediation


def test_cve_vulnerable_with_denied_v2_and_signin_is_warn() -> None:
    client = RecordingClient({"/v2/": FakeResponse(403), "/": FakeResponse(403)})
    target = Target(url=client.base, version="1.25.3")
    finding = run(check_cve_27771(client, target))[0]
    assert finding.status == Status.WARN
    assert finding.severity == Severity.critical
    assert finding.evidence["signin_required_inferred"] is True
    assert "Mitigated posture" in finding.rationale
    assert finding.remediation == "Update Gitea to >= 1.26.2; keep sign-in enforcement until patched."


def test_cve_patched_is_pass() -> None:
    client = RecordingClient({"/v2/": FakeResponse(200), "/": FakeResponse(200)})
    target = Target(url=client.base, version="1.26.2")
    finding = run(check_cve_27771(client, target))[0]
    assert finding.status == Status.PASS
    assert "Patched" in finding.rationale


def test_registry_unused_case_is_not_anonymous_reachable() -> None:
    client = RecordingClient({"/v2/": FakeResponse(404)})
    target = Target(url=client.base, version="1.25.3")
    finding = run(check_registry(client, target))[0]
    assert finding.status == Status.PASS
    assert finding.evidence["anon_v2_http"] == 404


def test_anonymous_access_posture_open_and_closed() -> None:
    open_client = RecordingClient({
        "/api/v1/repos/search?limit=1": FakeResponse(200),
        "/explore/repos": FakeResponse(403),
        "/api/v1/users/search?limit=1": FakeResponse(403),
    })
    open_finding = run(check_anon(open_client, Target(url=open_client.base)))[0]
    assert open_finding.status == Status.WARN
    assert open_finding.evidence["open"] == ["/api/v1/repos/search?limit=1"]

    closed_client = RecordingClient({
        "/api/v1/repos/search?limit=1": FakeResponse(403),
        "/explore/repos": FakeResponse(403),
        "/api/v1/users/search?limit=1": FakeResponse(403),
    })
    closed_finding = run(check_anon(closed_client, Target(url=closed_client.base)))[0]
    assert closed_finding.status == Status.PASS


def test_signin_posture() -> None:
    client = RecordingClient({
        "/api/v1/repos/search?limit=1": FakeResponse(403),
        "/explore/repos": FakeResponse(302),
    })
    finding = run(check_signin(client, Target(url=client.base)))[0]
    assert finding.status == Status.PASS


def test_scoring_weights_warn_factor_and_grade_thresholds() -> None:
    findings = [
        Finding(id="FG-VER", title="version", severity=Severity.high, status=Status.FAIL),
        Finding(id="FG-CVE-27771", title="cve", severity=Severity.critical, status=Status.WARN),
    ]
    score = score_findings(findings)
    assert WARN_FACTOR == 0.35
    assert score.value == 66
    assert score.grade == "C"
    assert grade_for(90) == "A"
    assert grade_for(75) == "B"
    assert grade_for(60) == "C"
    assert grade_for(40) == "D"
    assert grade_for(39) == "F"


def test_status_adjusted_top_action_sorting() -> None:
    findings = [
        Finding(id="LOW", title="low", severity=Severity.low, status=Status.FAIL),
        Finding(id="CRITWARN", title="critical warn", severity=Severity.critical, status=Status.WARN),
        Finding(id="HIGH", title="high", severity=Severity.high, status=Status.FAIL),
    ]
    ordered = sorted(findings, key=priority_key, reverse=True)
    assert [finding.id for finding in ordered] == ["HIGH", "CRITWARN", "LOW"]


def test_markdown_report_rendering_collapses_version_and_cve_action() -> None:
    findings = [
        Finding(id="FG-VER", title="Vulnerable version: patch-currency gap",
                severity=Severity.high, status=Status.FAIL,
                remediation="Update Gitea to >= 1.26.2."),
        Finding(id="FG-CVE-27771", title="CVE-2026-27771 exposure posture",
                severity=Severity.critical, status=Status.WARN,
                rationale="Mitigated posture: vulnerable version remains.",
                remediation="Update Gitea to >= 1.26.2; keep sign-in enforcement until patched."),
    ]
    result = ScanResult(scan_id="test", target=Target(url="https://forge.example", version="1.25.3"),
                        score=score_findings(findings), findings=findings,
                        summary={"critical": 1, "high": 1, "pass": 0})
    markdown = render_markdown(result)
    assert "ForgeGuard by Gexiro" in markdown
    assert "P1 - Update Gitea to >=1.26.2" in markdown
    assert "WARN / CRITICAL CVE - mitigated but unpatched" in markdown
    assert markdown.count("P1 - Update Gitea") == 1


def test_json_pydantic_serialization_round_trip() -> None:
    result = ScanResult(scan_id="roundtrip", target=Target(url="https://forge.example"),
                        score=Score(value=100, grade="A"))
    restored = ScanResult.model_validate_json(result.model_dump_json())
    assert restored.tool["name"] == "ForgeGuard"
    assert restored.tool["brand"] == "by Gexiro"
    assert restored.scan_id == "roundtrip"


def test_cli_default_requires_authorized_and_has_no_write_path() -> None:
    runner = CliRunner()
    denied = runner.invoke(app, ["scan", "--url", "https://forge.example"])
    assert denied.exit_code == 2
    assert "REFUSED" in denied.output

    help_result = runner.invoke(app, ["scan", "--help"])
    assert help_result.exit_code == 0
    assert "--authorized" in help_result.output
    assert "--emit-issue" not in help_result.output


def test_cve_check_performs_no_blob_or_manifest_requests() -> None:
    client = RecordingClient({"/v2/": FakeResponse(403), "/": FakeResponse(403)})
    run(check_cve_27771(client, Target(url=client.base, version="1.25.3")))
    requested_paths = [path for path, _auth in client.requests]
    assert requested_paths == ["/v2/", "/"]
    assert all("blob" not in path and "manifest" not in path for path in requested_paths)


def test_run_all_checks_is_single_target_and_safe_allowlist_only() -> None:
    client = RecordingClient({
        "/api/v1/version": FakeResponse(403),
        "/v2/": FakeResponse(403),
        "/": FakeResponse(403),
        "/api/v1/repos/search?limit=1": FakeResponse(403),
        "/explore/repos": FakeResponse(403),
        "/api/v1/users/search?limit=1": FakeResponse(403),
    })
    findings, target = run(run_all_checks(client, known_version="1.25.3"))
    assert target.url == "https://forge.example"
    assert {finding.id for finding in findings} >= {"FG-VER", "FG-CVE-27771", "FG-SIGNIN", "FG-REG", "FG-ANON"}
    requested_paths = [path for path, _auth in client.requests]
    assert set(requested_paths).issubset(set(SAFE_ANON_PATHS))
    assert all(path.startswith("/") for path in requested_paths)
    assert len({client.base}) == 1


def test_unauth_probes_are_limited_to_safe_allowlist() -> None:
    client = RecordingClient({
        "/api/v1/version": FakeResponse(200, {"version": "1.26.2"}),
        "/v2/": FakeResponse(403),
        "/": FakeResponse(403),
        "/api/v1/repos/search?limit=1": FakeResponse(403),
        "/explore/repos": FakeResponse(403),
        "/api/v1/users/search?limit=1": FakeResponse(403),
    })
    run(run_all_checks(client))
    unauth_paths = [path for path, auth in client.requests if not auth]
    assert set(unauth_paths).issubset(set(SAFE_ANON_PATHS))


# --- Pre-public hardening: runtime allowlist guard + state-dependent remediation ---


def test_client_refuses_non_allowlisted_path() -> None:
    from forgeguard.client import ForgeClient

    client = ForgeClient("https://forge.example")
    try:
        with pytest.raises(ValueError):
            run(client.get("/v2/private/manifests/latest"))
    finally:
        run(client.aclose())


def test_safe_get_paths_alias_matches() -> None:
    assert set(SAFE_ANON_PATHS) == set(SAFE_GET_PATHS)


def test_cve_patched_pass_has_empty_remediation() -> None:
    client = RecordingClient({"/v2/": FakeResponse(403), "/": FakeResponse(403)})
    finding = run(check_cve_27771(client, Target(url=client.base, version="1.26.2")))[0]
    assert finding.status == Status.PASS
    assert finding.remediation == ""


def test_patched_markdown_has_no_cve_action_line() -> None:
    findings = run(check_cve_27771(
        RecordingClient({"/v2/": FakeResponse(403), "/": FakeResponse(403)}),
        Target(url="https://forge.example", version="1.26.2")))
    result = ScanResult(scan_id="t", target=Target(url="https://forge.example", version="1.26.2"),
                        score=score_findings(findings), findings=findings, summary={})
    markdown = render_markdown(result)
    assert "CVE-2026-27771 exposure posture" in markdown
    assert "**Action:**" not in markdown
    assert "Update Gitea" not in markdown


def test_patched_json_cve_remediation_empty() -> None:
    findings = run(check_cve_27771(
        RecordingClient({"/v2/": FakeResponse(403), "/": FakeResponse(403)}),
        Target(url="https://forge.example", version="1.26.2")))
    cve = by_id(findings, "FG-CVE-27771")
    assert cve.remediation == ""
