import json
import socket
from datetime import UTC, datetime, timedelta
from importlib.resources import files
from pathlib import Path

import httpx
import jsonschema
import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from forgeguard.assessment import Assessment
from forgeguard.cli import app
from forgeguard.exporters.sarif import to_sarif
from forgeguard.models import EvidenceState, Status
from forgeguard.runner_review import RunnerSnapshot, review

NOW = datetime(2026, 9, 11, 13, tzinfo=UTC)


def snapshot(product="forgejo"):
    name = (
        "forgejo-runner-snapshot.json"
        if product == "forgejo"
        else "gitea-runner-snapshot.json"
    )
    return RunnerSnapshot.model_validate_json(Path("examples", name).read_bytes())


def validate(result):
    data = result.model_dump(mode="json")
    for filename, obj in [
        ("assessment-v1.json", data),
        ("sarif-2.1.0.json", to_sarif(result)),
    ]:
        schema = json.loads(
            files("forgeguard").joinpath("schemas", filename).read_text()
        )
        jsonschema.validators.validator_for(schema)(schema).validate(obj)
    assert Assessment.model_validate(data) == result


@pytest.mark.parametrize("product", ["gitea", "forgejo"])
def test_offline_runner_schema_and_zero_network(monkeypatch, product):
    def denied(*a, **kw):
        raise AssertionError("Offline runner review attempted network")

    monkeypatch.setattr(socket, "getaddrinfo", denied)
    monkeypatch.setattr(httpx.AsyncClient, "send", denied)
    s = snapshot(product)
    schema = json.loads(
        files("forgeguard").joinpath("schemas", "runner-snapshot-v1.json").read_text()
    )
    jsonschema.Draft202012Validator(schema).validate(s.model_dump())
    result = review(s, now=NOW)
    assert result.request_count == 0
    assert result.score.assessed
    validate(result)


def test_safest_declared_posture_scores_100_a():
    result = review(snapshot("forgejo"), now=NOW)
    assert result.score.value == 100
    assert result.score.grade == "A"
    assert all(f.status in (Status.PASS, Status.INFO) for f in result.findings)


def test_host_execution_mixed_untrusted_is_single_fail_not_five():
    s = snapshot("gitea").model_copy(
        update={
            "workload_trust": "mixed-untrusted",
            "execution_engine": "host",
            "privileged": True,
            "docker_socket": "host-daemon-exposed-to-job",
            "valid_volumes": ["**"],
            "network": "host",
        }
    )
    result = review(s, now=NOW)
    by_id = {f.id: f for f in result.findings}
    assert by_id["FG-RUNNER-EXECUTION"].status == Status.FAIL
    for id_ in (
        "FG-RUNNER-PRIVILEGED",
        "FG-RUNNER-VOLUMES",
        "FG-RUNNER-DOCKER",
        "FG-RUNNER-NETWORK",
    ):
        assert by_id[id_].applicability == "not_applicable", id_
        assert by_id[id_].evidence_state == EvidenceState.INFORMATIONAL, id_
    # only one finding actually penalizes score for the single root cause
    penalized = [f for f in result.findings if f.status in (Status.WARN, Status.FAIL)]
    assert [f.id for f in penalized] == ["FG-RUNNER-EXECUTION"]


def test_docker_execution_privileged_volumes_docker_network_are_applicable():
    s = snapshot("gitea").model_copy(
        update={
            "workload_trust": "mixed-untrusted",
            "execution_engine": "docker",
            "privileged": True,
            "docker_socket": "host-daemon-exposed-to-job",
            "valid_volumes": ["**"],
            "network": "host",
        }
    )
    result = review(s, now=NOW)
    by_id = {f.id: f for f in result.findings}
    for id_ in (
        "FG-RUNNER-PRIVILEGED",
        "FG-RUNNER-VOLUMES",
        "FG-RUNNER-DOCKER",
        "FG-RUNNER-NETWORK",
    ):
        assert by_id[id_].applicability == "applicable", id_
        assert by_id[id_].status == Status.FAIL, id_


def test_trusted_only_downgrades_severity_from_fail_to_warn():
    s = snapshot("gitea").model_copy(
        update={"workload_trust": "trusted-only", "privileged": True}
    )
    result = review(s, now=NOW)
    by_id = {f.id: f for f in result.findings}
    assert by_id["FG-RUNNER-PRIVILEGED"].status == Status.WARN


def test_wrong_provider_runner_product_refused():
    with pytest.raises(ValidationError):
        RunnerSnapshot.model_validate(
            {**snapshot("gitea").model_dump(), "runner_product": "forgejo-runner"}
        )


def test_forbidden_secret_field_refused_without_echo(monkeypatch):
    raw = json.loads(Path("examples", "gitea-runner-snapshot.json").read_bytes())
    raw["token"] = "SECRET_SHOULD_NOT_LEAK_9f8e7d6c"
    path = Path("tests", "fixtures", "_runner_secret_tmp.json")
    path.write_text(json.dumps(raw))
    try:
        runner = CliRunner()
        result = runner.invoke(app, ["runner", "review", "--snapshot", str(path)])
        assert result.exit_code == 2
        assert "SECRET_SHOULD_NOT_LEAK_9f8e7d6c" not in result.output
        assert "REFUSED" in result.output
    finally:
        path.unlink()


def test_oversized_snapshot_refused():
    raw = json.loads(Path("examples", "gitea-runner-snapshot.json").read_bytes())
    raw["provenance"] = "x" * 300000
    path = Path("tests", "fixtures", "_runner_oversized_tmp.json")
    path.write_bytes(json.dumps(raw).encode())
    try:
        runner = CliRunner()
        result = runner.invoke(app, ["runner", "review", "--snapshot", str(path)])
        assert result.exit_code == 2
        assert "REFUSED" in result.output
    finally:
        path.unlink()


@pytest.mark.parametrize(
    "update",
    [
        {"snapshot_at": (NOW - timedelta(days=31)).isoformat()},
        {"snapshot_at": (NOW + timedelta(days=1)).isoformat()},
        {"server_version": "99.0.0"},
    ],
)
def test_stale_future_unsupported_server_version_is_undetermined(update):
    s = snapshot("forgejo").model_copy(update=update)
    result = review(s, now=NOW)
    assert not result.score.assessed


def test_timezone_naive_snapshot_timestamp_refused():
    raw = json.loads(Path("examples", "gitea-runner-snapshot.json").read_bytes())
    raw["snapshot_at"] = "2026-09-10T12:00:00"
    with pytest.raises(ValidationError):
        RunnerSnapshot.model_validate(raw)


def test_oversized_volume_entry_refused():
    raw = json.loads(Path("examples", "gitea-runner-snapshot.json").read_bytes())
    raw["valid_volumes"] = ["x" * 300]
    with pytest.raises(ValidationError):
        RunnerSnapshot.model_validate(raw)


def test_empty_volume_entry_refused():
    raw = json.loads(Path("examples", "gitea-runner-snapshot.json").read_bytes())
    raw["valid_volumes"] = [""]
    with pytest.raises(ValidationError):
        RunnerSnapshot.model_validate(raw)


def test_malformed_runner_version_is_indeterminate():
    s = snapshot("forgejo").model_copy(update={"runner_version": "not-a-version"})
    result = review(s, now=NOW)
    by_id = {f.id: f for f in result.findings}
    assert by_id["FG-RUNNER-VERSION"].applicability == "undetermined"
    assert not result.score.assessed


def test_ephemeral_persistent_is_info_not_fail():
    s = snapshot("forgejo").model_copy(update={"ephemeral": "persistent"})
    result = review(s, now=NOW)
    by_id = {f.id: f for f in result.findings}
    assert by_id["FG-RUNNER-EPHEMERAL"].status == Status.INFO


def test_plugin_not_applicable_when_unsupported_runner():
    s = snapshot("gitea").model_copy(update={"plugin_usage": "declared-experimental"})
    result = review(s, now=NOW)
    by_id = {f.id: f for f in result.findings}
    assert by_id["FG-RUNNER-PLUGIN"].applicability == "not_applicable"


def test_plugin_experimental_warns_on_forgejo_13_1():
    s = snapshot("forgejo").model_copy(update={"plugin_usage": "declared-experimental"})
    result = review(s, now=NOW)
    by_id = {f.id: f for f in result.findings}
    assert by_id["FG-RUNNER-PLUGIN"].applicability == "applicable"
    assert by_id["FG-RUNNER-PLUGIN"].status == Status.WARN


def test_plugin_unused_on_forgejo_13_1_is_not_applicable():
    s = snapshot("forgejo")
    result = review(s, now=NOW)
    by_id = {f.id: f for f in result.findings}
    assert by_id["FG-RUNNER-PLUGIN"].applicability == "not_applicable"


def test_broad_volume_patterns_detected():
    for pattern in ("**", "/**", "/", "/*"):
        s = snapshot("gitea").model_copy(update={"valid_volumes": [pattern]})
        result = review(s, now=NOW)
        by_id = {f.id: f for f in result.findings}
        assert by_id["FG-RUNNER-VOLUMES"].evidence["broad_patterns"] == [pattern], (
            pattern
        )


def test_narrow_volume_allowlist_passes():
    s = snapshot("gitea").model_copy(update={"valid_volumes": ["data", "/src/*.json"]})
    result = review(s, now=NOW)
    by_id = {f.id: f for f in result.findings}
    assert by_id["FG-RUNNER-VOLUMES"].status == Status.PASS


def test_provider_separation_gitea_vs_forgejo_distinct_sources():
    g = review(snapshot("gitea"), now=NOW)
    f = review(snapshot("forgejo"), now=NOW)
    g_refs = {r for finding in g.findings for r in finding.references}
    f_refs = {r for finding in f.findings for r in finding.references}
    assert g_refs != f_refs


def test_cli_runner_review_md_and_json_and_sarif(tmp_path):
    out = tmp_path / "runner_report"
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "runner",
            "review",
            "--snapshot",
            "examples/forgejo-runner-snapshot.json",
            "--format",
            "md,json,sarif",
            "--out",
            str(out),
        ],
    )
    assert result.exit_code == 0, result.output
    assert out.with_suffix("").exists() or out.exists()
    assert (tmp_path / "runner_report.json").exists()
    assert (tmp_path / "runner_report.sarif").exists()


def test_cli_runner_review_no_clobber_output(tmp_path):
    out = tmp_path / "exists.md"
    out.write_text("pre-existing")
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "runner",
            "review",
            "--snapshot",
            "examples/gitea-runner-snapshot.json",
            "--out",
            str(out),
        ],
    )
    assert result.exit_code == 2
    assert out.read_text() == "pre-existing"


def test_providers_command_lists_runner_metadata():
    runner = CliRunner()
    result = runner.invoke(app, ["providers"])
    data = json.loads(result.output)
    ids = {p["id"]: p for p in data}
    assert ids["gitea"]["runner_product"] == "gitea-runner"
    assert ids["forgejo"]["runner_product"] == "forgejo-runner"


def test_checks_command_lists_runner_checks():
    runner = CliRunner()
    result = runner.invoke(app, ["checks"])
    for id_ in (
        "FG-RUNNER-VERSION",
        "FG-RUNNER-EXECUTION",
        "FG-RUNNER-PRIVILEGED",
        "FG-RUNNER-VOLUMES",
        "FG-RUNNER-DOCKER",
        "FG-RUNNER-NETWORK",
        "FG-RUNNER-EPHEMERAL",
        "FG-RUNNER-PLUGIN",
    ):
        assert id_ in result.output
