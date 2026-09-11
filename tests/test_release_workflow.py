"""R01: promotion validates a frozen qualified set and never auto-publishes.

Parses the actual workflow YAML with GitHub Actions semantics and unit-tests the
preflight gate. Proves: prepare-only succeeds without publishing (R01-A), the
gate requires a real attestation result rather than a boolean (R01-B), and the
exact artifacts are bound to the referenced run and manifest with no rebuild
(R01-C).
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
    return yaml.safe_load(WORKFLOW.read_text())


def triggers(wf):
    return wf.get("on", wf.get(True))


def test_manual_dispatch_publish_is_boolean_default_false():
    publish = triggers(workflow())["workflow_dispatch"]["inputs"]["publish"]
    assert publish["type"] == "boolean"
    assert publish["default"] is False


def test_dispatch_inputs_bind_run_and_manifest():
    inputs = triggers(workflow())["workflow_dispatch"]["inputs"]
    for key in (
        "version",
        "source_sha",
        "run_id",
        "run_attempt",
        "manifest_json",
        "manifest_sha256",
    ):
        assert key in inputs, key


def test_release_trigger_retained_for_verification_only():
    assert triggers(workflow())["release"]["types"] == ["published"]


def test_top_level_permissions_are_read_only():
    assert workflow()["permissions"] == {"contents": "read"}


def test_promotion_never_rebuilds():
    text = WORKFLOW.read_text()
    assert "python -m build" not in text
    assert "pyproject-build" not in text
    assert "gh run download" in text


def test_publish_job_requires_manual_optin_and_publish_allowed():
    job = workflow()["jobs"]["pypi-publish"]
    condition = " ".join(job["if"].split())
    assert "github.event_name == 'workflow_dispatch'" in condition
    assert "inputs.publish == true" in condition
    assert "needs.promote.outputs.publish_allowed == 'true'" in condition
    assert job["needs"] == "promote" or "promote" in job["needs"]


def test_id_token_write_scoped_to_publish_job_only():
    jobs = workflow()["jobs"]
    assert jobs["pypi-publish"]["permissions"].get("id-token") == "write"
    for name, job in jobs.items():
        if name == "pypi-publish":
            continue
        assert job.get("permissions", {}).get("id-token") != "write", name
    assert "id-token" not in workflow().get("permissions", {})


def test_promote_only_runs_on_workflow_dispatch():
    job = workflow()["jobs"]["promote"]
    assert "github.event_name == 'workflow_dispatch'" in " ".join(job["if"].split())


def test_publisher_action_used_only_in_publish_job():
    jobs = workflow()["jobs"]
    for name, job in jobs.items():
        uses = [s.get("uses", "") for s in job.get("steps", [])]
        assert any("gh-action-pypi-publish" in u for u in uses) == (
            name == "pypi-publish"
        ), name


def test_all_actions_pinned_to_full_sha():
    for job in workflow()["jobs"].values():
        for step in job.get("steps", []):
            if step.get("uses"):
                assert SHA_RE.search(step["uses"]), step["uses"]


SHA = "a" * 40
WHEEL = "w" * 64
SDIST = "s" * 64


def valid_inputs():
    return {
        "event_name": "workflow_dispatch",
        "repository": "gexiro-global/forgeguard",
        "expected_repository": "gexiro-global/forgeguard",
        "publish": "true",
        "version": "0.5.0",
        "project_version": "0.5.0",
        "source_sha": SHA,
        "manifest": {
            "version": "0.5.0",
            "source_sha": SHA,
            "source_ref": "refs/heads/x",
            "run_id": "123",
            "run_attempt": "1",
            "workflow": ".github/workflows/ci.yml",
            "event": "push",
            "wheel_sha256": WHEEL,
            "sdist_sha256": SDIST,
            "gates": {"test": "PASS", "build": "PASS"},
            "evidence_sha256": {"report": "e" * 64},
        },
        "observed_run": {
            "repository": "gexiro-global/forgeguard",
            "head_sha": SHA,
            "status": "completed",
            "conclusion": "success",
            "event": "push",
            "run_id": "123",
            "run_attempt": "1",
            "path": ".github/workflows/ci.yml",
        },
        "artifact_digests": {"wheel": WHEEL, "sdist": SDIST},
        "attestation_results": {
            "wheel": {
                "verified": True,
                "source_digest": SHA,
                "repository": "gexiro-global/forgeguard",
                "signer_workflow": "https://github.com/gexiro-global/forgeguard/.github/workflows/ci.yml@refs/heads/x",
                "subject_sha256": WHEEL,
            },
            "sdist": {
                "verified": True,
                "source_digest": SHA,
                "repository": "gexiro-global/forgeguard",
                "signer_workflow": "https://github.com/gexiro-global/forgeguard/.github/workflows/ci.yml@refs/heads/x",
                "subject_sha256": SDIST,
            },
        },
        "built_in_promotion": False,
    }


def test_valid_publishes_allowed():
    r = evaluate(valid_inputs())
    assert r["prepared"] is True and r["publish_allowed"] is True


def test_prepare_only_succeeds_without_publish():  # R01-A
    d = valid_inputs()
    d["publish"] = "false"
    r = evaluate(d)
    assert r["prepared"] is True
    assert r["publish_allowed"] is False


def test_release_event_cannot_publish_but_prepare_valid():
    d = valid_inputs()
    d["event_name"] = "release"
    assert evaluate(d)["publish_allowed"] is False


@pytest.mark.parametrize(
    "mut",
    [
        {
            "attestation_results": {
                "wheel": {"verified": False},
                "sdist": {"verified": False},
            }
        },
        {"repository": "attacker/forgeguard"},
        {"version": "0.4.0"},
        {"source_sha": "b" * 40},
        {"built_in_promotion": True},
    ],
)
def test_prepare_refuses_on_broken_data(mut):
    d = valid_inputs()
    d.update(mut)
    assert evaluate(d)["prepared"] is False


def test_prepare_refuses_on_digest_mismatch():  # R01-C
    d = valid_inputs()
    d["artifact_digests"] = {"wheel": "z" * 64, "sdist": SDIST}
    assert evaluate(d)["prepared"] is False


def test_prepare_refuses_on_attestation_source_mismatch():  # R01-B
    d = valid_inputs()
    d["attestation_results"]["wheel"]["source_digest"] = "c" * 40
    assert evaluate(d)["prepared"] is False


@pytest.mark.parametrize(
    "mut",
    [
        {"status": "in_progress", "conclusion": None},
        {"conclusion": "failure"},
        {"event": "pull_request"},
        {"head_sha": "d" * 40},
        {"run_id": "999"},
    ],
)
def test_prepare_refuses_on_bad_observed_run(mut):
    d = valid_inputs()
    d["observed_run"].update(mut)
    assert evaluate(d)["prepared"] is False


@pytest.mark.parametrize("drop", ["wheel_sha256", "run_id", "gates", "event"])
def test_prepare_refuses_on_incomplete_manifest(drop):
    d = valid_inputs()
    d["manifest"] = {k: v for k, v in d["manifest"].items() if k != drop}
    assert evaluate(d)["prepared"] is False


def test_prepare_refuses_on_open_manifest_gate():
    d = valid_inputs()
    d["manifest"]["gates"] = {"test": "PASS", "build": "FAIL"}
    assert evaluate(d)["prepared"] is False
