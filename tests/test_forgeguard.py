from __future__ import annotations

import ast
import asyncio
import re
from importlib.metadata import version as distribution_version
from pathlib import Path

import forgeguard.cli as cli_module
import pytest
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
from forgeguard.models import Finding, ScanResult, Score, Severity, Status, Target
from forgeguard.report import render_markdown
from forgeguard.safety import SAFE_GET_PATHS
from forgeguard.scoring import WARN_FACTOR, grade_for, priority_key, score_findings
from forgeguard.urls import InvalidTargetURL, normalize_target_url
from typer.testing import CliRunner

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


class FakeResponse:
    def __init__(self, status_code: int, payload: dict | None = None) -> None:
        self.status_code = status_code
        self._payload = payload or {}

    def json(self) -> dict:
        return self._payload


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
    explore: int = 302,
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


def test_version_parsing_and_gitea_fixed_release_comparison() -> None:
    assert _semver("1.26.2") == (1, 26, 2)
    assert _semver("1.26.2+gitea") == (1, 26, 2)
    assert _semver("1.26.2-rc1") is None
    assert _semver("not-a-version") is None
    assert _is_vulnerable("1.26.1") is True
    assert _is_vulnerable(FIXED_VERSION) is False
    assert _is_vulnerable("1.27.0") is False
    assert _is_vulnerable(None) is None


def test_version_check_flags_gitea_1261() -> None:
    target = Target(url="https://forge.example", forge="gitea", version="1.26.1")
    finding = run(check_version(RecordingClient({}), target, False))[0]
    assert finding.id == "FG-VER"
    assert finding.status == Status.FAIL
    assert finding.severity == Severity.high
    assert finding.evidence["first_fixed_in"] == FIXED_VERSION


@pytest.mark.parametrize("version", ["1.26.2", "1.27.0", "2.0.0"])
def test_version_check_passes_gitea_at_or_above_first_fixed_release(
    version: str,
) -> None:
    target = Target(url="https://forge.example", forge="gitea", version=version)
    finding = run(check_version(RecordingClient({}), target, False))[0]
    assert finding.status == Status.PASS
    assert "first fixed release" in finding.title


@pytest.mark.parametrize("version", [None, "not-a-version", "1.26.2-rc1"])
def test_version_check_unknown_is_info(version: str | None) -> None:
    target = Target(url="https://forge.example", forge="gitea", version=version)
    finding = run(check_version(RecordingClient({}), target, False))[0]
    assert finding.status == Status.INFO
    assert finding.severity == Severity.medium


def test_cve_gitea_1261_is_affected_fail_high() -> None:
    finding = run(
        check_cve_27771(
            Target(url="https://forge.example", forge="gitea", version="1.26.1")
        )
    )[0]
    assert finding.status == Status.FAIL
    assert finding.severity == Severity.high
    assert finding.title == "CVE-2026-27771 version posture"
    assert "affected range" in finding.rationale
    assert "does not prove exploitability or data exposure" in finding.rationale
    assert finding.remediation == (
        "Upgrade Gitea to >=1.26.2 or a newer currently supported security release."
    )


@pytest.mark.parametrize("version", ["1.26.2", "1.27.0", "2.0.0"])
def test_cve_gitea_at_or_above_first_fixed_release_is_pass(version: str) -> None:
    finding = run(
        check_cve_27771(
            Target(url="https://forge.example", forge="gitea", version=version)
        )
    )[0]
    assert finding.status == Status.PASS
    assert finding.severity == Severity.info
    assert finding.remediation == ""
    assert "whole instance" not in finding.rationale.lower()


@pytest.mark.parametrize("version", [None, "1.26.2-rc1"])
def test_cve_unknown_version_is_info_medium(version: str | None) -> None:
    finding = run(
        check_cve_27771(
            Target(url="https://forge.example", forge="gitea", version=version)
        )
    )[0]
    assert finding.status == Status.INFO
    assert finding.severity == Severity.medium
    assert "cannot be determined" in finding.rationale


def test_forgejo_like_version_fails_safe_without_gitea_baseline() -> None:
    client = RecordingClient(
        complete_responses(version_status=200, version="11.0.0+forgejo")
    )
    findings, target = run(run_all_checks(client))
    assert target.forge == "forgejo"
    version_finding = by_id(findings, "FG-VER")
    cve_finding = by_id(findings, "FG-CVE-27771")
    assert version_finding.status == Status.INFO
    assert cve_finding.status == Status.INFO
    assert "Gitea 11.0.0" not in cve_finding.rationale
    assert "first release containing the fix" not in cve_finding.rationale


def test_registry_and_signin_responses_do_not_change_cve_verdict() -> None:
    cases = [
        complete_responses(v2=200, home=200, api=200, explore=200, users=200),
        complete_responses(v2=401, home=401, api=401, explore=302, users=401),
        complete_responses(v2=403, home=403, api=403, explore=403, users=403),
    ]
    cve_results = []
    for responses in cases:
        findings, _target = run(
            run_all_checks(RecordingClient(responses), known_version="1.26.1")
        )
        cve_results.append(by_id(findings, "FG-CVE-27771").model_dump())
    assert cve_results[0] == cve_results[1] == cve_results[2]
    assert cve_results[0]["status"] == Status.FAIL


def test_cve_check_performs_no_network_requests() -> None:
    target = Target(url="https://forge.example", forge="gitea", version="1.26.1")
    finding = run(check_cve_27771(target))[0]
    assert finding.status == Status.FAIL
    assert set(finding.evidence) == {
        "product",
        "version",
        "affected_through",
        "first_fixed_in",
    }


def test_registry_200_is_limited_independent_observation() -> None:
    finding = run(
        check_registry(
            RecordingClient({"/v2/": FakeResponse(200)}),
            Target(url="https://forge.example", forge="gitea"),
        )
    )[0]
    assert finding.status == Status.WARN
    assert finding.severity == Severity.medium
    assert finding.references == []
    assert "does not prove access" in finding.rationale
    assert "CVE-2026-27771" not in finding.model_dump_json()


@pytest.mark.parametrize("status_code", [401, 403, 404])
def test_registry_non_200_reports_exact_observation(status_code: int) -> None:
    finding = run(
        check_registry(
            RecordingClient({"/v2/": FakeResponse(status_code)}),
            Target(url="https://forge.example", forge="gitea"),
        )
    )[0]
    assert finding.status == Status.PASS
    assert finding.evidence["anon_v2_http"] == status_code
    assert f"HTTP {status_code}" in finding.rationale


def test_registry_no_response_is_info_not_pass() -> None:
    finding = run(
        check_registry(
            RecordingClient({}), Target(url="https://forge.example", forge="gitea")
        )
    )[0]
    assert finding.status == Status.INFO
    assert finding.severity == Severity.medium


def test_signin_posture_uses_observed_language() -> None:
    controlled = run(
        check_signin(
            RecordingClient(
                {
                    "/api/v1/repos/search?limit=1": FakeResponse(403),
                    "/explore/repos": FakeResponse(302),
                }
            ),
            Target(url="https://forge.example", forge="gitea"),
        )
    )[0]
    assert controlled.status == Status.PASS
    assert "appear access-controlled" in controlled.title
    assert "no specific configuration key was read" in controlled.rationale

    open_finding = run(
        check_signin(
            RecordingClient(
                {
                    "/api/v1/repos/search?limit=1": FakeResponse(200),
                    "/explore/repos": FakeResponse(403),
                }
            ),
            Target(url="https://forge.example", forge="gitea"),
        )
    )[0]
    assert open_finding.status == Status.WARN
    assert "Observed" in open_finding.title


def test_anonymous_access_posture_open_closed_and_unknown() -> None:
    paths = [
        "/api/v1/repos/search?limit=1",
        "/explore/repos",
        "/api/v1/users/search?limit=1",
    ]
    open_client = RecordingClient({path: FakeResponse(403) for path in paths})
    open_client.responses[paths[0]] = FakeResponse(200)
    open_finding = run(
        check_anon(open_client, Target(url=open_client.base, forge="gitea"))
    )[0]
    assert open_finding.status == Status.WARN
    assert open_finding.evidence["open"] == [paths[0]]

    closed_client = RecordingClient({path: FakeResponse(403) for path in paths})
    closed_finding = run(
        check_anon(closed_client, Target(url=closed_client.base, forge="gitea"))
    )[0]
    assert closed_finding.status == Status.PASS
    assert "checked endpoints" in closed_finding.title

    unknown_client = RecordingClient({paths[0]: FakeResponse(403)})
    unknown_finding = run(
        check_anon(unknown_client, Target(url=unknown_client.base, forge="gitea"))
    )[0]
    assert unknown_finding.status == Status.INFO


def test_scoring_weights_warn_factor_and_grade_thresholds() -> None:
    findings = [
        Finding(
            id="FG-VER", title="version", severity=Severity.high, status=Status.FAIL
        ),
        Finding(
            id="FG-REG", title="registry", severity=Severity.medium, status=Status.WARN
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


def test_markdown_report_uses_affected_version_not_exposure_language() -> None:
    findings = [
        run(
            check_version(
                RecordingClient({}),
                Target(url="https://forge.example", forge="gitea", version="1.26.1"),
                False,
            )
        )[0],
        run(
            check_cve_27771(
                Target(url="https://forge.example", forge="gitea", version="1.26.1")
            )
        )[0],
    ]
    result = ScanResult(
        scan_id="test",
        target=Target(url="https://forge.example", forge="gitea", version="1.26.1"),
        score=score_findings(findings),
        findings=findings,
        summary={"high": 2, "pass": 0},
    )
    markdown = render_markdown(result)
    assert "P1 - Upgrade Gitea to >=1.26.2" in markdown
    assert markdown.count("P1 - Upgrade Gitea") == 1
    assert "does not prove exploitability" in markdown
    assert "active exposure" not in markdown.lower()
    assert "mitigated posture" not in markdown.lower()


def test_json_pydantic_serialization_round_trip_and_runtime_version() -> None:
    result = ScanResult(
        scan_id="roundtrip",
        target=Target(url="https://forge.example", forge="gitea"),
        score=Score(value=100, grade="A"),
    )
    restored = ScanResult.model_validate_json(result.model_dump_json())
    assert restored.tool["name"] == "ForgeGuard"
    assert restored.tool["version"] == __version__
    assert restored.scan_id == "roundtrip"


def test_distribution_import_runtime_json_and_user_agent_versions_match() -> None:
    installed = distribution_version("forgeguard")
    result = ScanResult(
        scan_id="version-truth",
        target=Target(url="https://forge.example", forge="gitea"),
        score=Score(value=100, grade="A"),
    )
    assert installed == __version__ == result.tool["version"] == "0.2.2"
    assert f"/{installed} " in _UA


def test_cli_requires_authorized() -> None:
    runner = CliRunner()
    denied = runner.invoke(app, ["scan", "--url", "https://forge.example"])
    assert denied.exit_code == 2
    assert "REFUSED" in _ANSI.sub("", denied.output)

    help_result = runner.invoke(
        app,
        ["scan", "--help"],
        env={"COLUMNS": "200", "NO_COLOR": "1", "TERM": "dumb"},
    )
    assert help_result.exit_code == 0
    help_text = _ANSI.sub("", help_result.output)
    assert "--authorized" in help_text
    assert "FORGEGUARD_TOKEN" in help_text
    assert "--emit-issue" not in help_text


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


def test_target_url_preserves_legal_gitea_subpath() -> None:
    assert normalize_target_url("HTTPS://git.example.com/gitea/") == (
        "https://git.example.com/gitea"
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
    result = CliRunner().invoke(app, ["scan", "--url", url, "--authorized"])
    assert result.exit_code == 2
    assert "REFUSED" in _ANSI.sub("", result.output)
    assert secret not in result.output
    assert url not in result.output


def _synthetic_result() -> ScanResult:
    return ScanResult(
        scan_id="token-opsec",
        target=Target(url="https://forge.example", forge="gitea", version="1.26.2"),
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
        url: str, token: str | None, known_version: str | None, scan_id: str
    ) -> ScanResult:
        observed["token"] = token
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
            "--token",
            sentinel,
            "--format",
            "md,json",
            "--out",
            str(output_path),
        ],
    )
    assert result.exit_code == 0
    assert observed["token"] == sentinel
    assert "SECURITY WARNING" in _ANSI.sub("", result.output)
    assert sentinel not in result.output
    assert sentinel not in output_path.read_text()
    assert sentinel not in output_path.with_suffix(".json").read_text()


def test_environment_token_is_preferred_and_not_echoed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sentinel = "fg_env_token_not_real_4cB2"
    observed: dict[str, str | None] = {}

    async def fake_run(
        url: str, token: str | None, known_version: str | None, scan_id: str
    ) -> ScanResult:
        observed["token"] = token
        return _synthetic_result()

    monkeypatch.setattr(cli_module, "_run", fake_run)
    result = CliRunner().invoke(
        app,
        ["scan", "--url", "https://forge.example", "--authorized", "--format", "json"],
        env={"FORGEGUARD_TOKEN": sentinel},
    )
    assert result.exit_code == 0
    assert observed["token"] == sentinel
    assert "SECURITY WARNING" not in _ANSI.sub("", result.output)
    assert sentinel not in result.output


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
    findings, target = run(run_all_checks(client, known_version="1.26.1"))
    assert target.url == "https://forge.example"
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
    assert result.target.url == "https://git.example.com"
    assert result.score == rescored
    assert render_markdown(result).rstrip("\n") == expected_markdown.rstrip("\n")
    assert "active exposure" not in expected_markdown.lower()
    assert "mitigated posture" not in expected_markdown.lower()
