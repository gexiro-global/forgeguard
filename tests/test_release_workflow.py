"""R01: the release workflow prepares candidates but never auto-publishes.

These tests parse the actual workflow YAML with GitHub Actions semantics (not a
word search) and unit-test the preflight gate logic. They prove exactly one
manual path can reach PyPI and that every other event/input is refused.
"""

import re
from pathlib import Path

import pytest
import yaml

from tools.release_preflight import evaluate

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
SHA_RE = re.compile(r"@[0-9a-f]{40}$")


def workflow():
    # 'on' is the YAML boolean True key; load raw text is fine here.
    return yaml.safe_load(WORKFLOW.read_text())


def triggers(wf):
    # PyYAML parses the bare key ``on`` as the boolean True.
    return wf.get("on", wf.get(True))


def test_manual_dispatch_publish_is_boolean_default_false():
    on = triggers(workflow())
    publish = on["workflow_dispatch"]["inputs"]["publish"]
    assert publish["type"] == "boolean"
    assert publish["default"] is False


def test_release_trigger_retained_for_verification_only():
    on = triggers(workflow())
    assert on["release"]["types"] == ["published"]


def test_top_level_permissions_are_read_only():
    assert workflow()["permissions"] == {"contents": "read"}


def test_publish_job_requires_manual_optin_and_approved_preflight():
    job = workflow()["jobs"]["pypi-publish"]
    condition = " ".join(job["if"].split())
    assert "github.event_name == 'workflow_dispatch'" in condition
    assert "inputs.publish == true" in condition
    assert "inputs.attestation_verified == true" in condition
    assert "needs.preflight.outputs.approved == 'true'" in condition
    assert job["needs"] == ["quality-gate", "preflight"]


def test_id_token_write_is_scoped_to_publish_job_only():
    jobs = workflow()["jobs"]
    assert jobs["pypi-publish"]["permissions"].get("id-token") == "write"
    for name, job in jobs.items():
        if name == "pypi-publish":
            continue
        assert job.get("permissions", {}).get("id-token") != "write", name
    assert "id-token" not in workflow().get("permissions", {})


def test_preflight_only_runs_on_workflow_dispatch():
    job = workflow()["jobs"]["preflight"]
    assert "github.event_name == 'workflow_dispatch'" in " ".join(job["if"].split())


def test_publisher_action_used_only_in_publish_job():
    jobs = workflow()["jobs"]
    for name, job in jobs.items():
        uses = [s.get("uses", "") for s in job.get("steps", [])]
        has_publisher = any("gh-action-pypi-publish" in u for u in uses)
        assert has_publisher == (name == "pypi-publish"), name


def test_all_actions_pinned_to_full_sha():
    for job in workflow()["jobs"].values():
        for step in job.get("steps", []):
            uses = step.get("uses")
            if uses:
                assert SHA_RE.search(uses), uses


def valid_inputs():
    sha = "a" * 40
    return {
        "event_name": "workflow_dispatch",
        "repository": "gexiro-global/forgeguard",
        "expected_repository": "gexiro-global/forgeguard",
        "publish": "true",
        "version": "0.5.0",
        "project_version": "0.5.0",
        "source_sha": sha,
        "git_head": sha,
        "run_id": "123456",
        "run_conclusion": "success",
        "attestation_verified": "true",
        "dist_files": ["forgeguard-0.5.0-py3-none-any.whl", "forgeguard-0.5.0.tar.gz"],
    }


def test_preflight_approves_the_single_valid_manual_path():
    assert evaluate(valid_inputs())["approved"] is True


@pytest.mark.parametrize(
    "mutation",
    [
        {"event_name": "release"},
        {"event_name": "push"},
        {"repository": "attacker/forgeguard"},
        {"expected_repository": "attacker/forgeguard"},
        {"publish": "false"},
        {"version": "0.4.0"},
        {"version": ""},
        {"source_sha": "b" * 40},  # != git_head
        {"source_sha": "short"},
        {"run_id": ""},
        {"run_id": "not-a-number"},
        {"run_conclusion": "failure"},
        {"run_conclusion": ""},
        {"attestation_verified": "false"},
        {"dist_files": []},
        {"dist_files": ["forgeguard-0.5.0-py3-none-any.whl"]},
        {"dist_files": ["forgeguard-0.5.0.tar.gz"]},
    ],
)
def test_preflight_refuses_every_broken_input(mutation):
    data = valid_inputs()
    data.update(mutation)
    result = evaluate(data)
    assert result["approved"] is False
    assert any(not c["ok"] for c in result["checks"])
