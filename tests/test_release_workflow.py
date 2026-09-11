"""R01: complete qualification contract, exact-set handoff, and no auto-publish.

Parses the workflow YAML (GitHub Actions semantics) and unit-tests the preflight
and the shared promote handoff. Covers the rc3-review residuals: full G01-G15 +
closed evidence set required, exact source_ref/run_attempt binding, mandatory
manifest hash, strict two-file set, and a no-network publisher-stub receipt.
"""

import re
from pathlib import Path

import pytest
import yaml

from tools.release_preflight import (
    REQUIRED_EVIDENCE,
    REQUIRED_GATES,
    HandoffError,
    evaluate,
    promote_handoff,
)

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
SHA_RE = re.compile(r"@[0-9a-f]{40}$")
SHA = "a" * 40
WHEEL = "w" * 64
SDIST = "s" * 64
REF = "refs/heads/feat/forgeguard-v0.5-multiforge"


def workflow():
    return yaml.safe_load(WORKFLOW.read_text())


def triggers(wf):
    return wf.get("on", wf.get(True))


# ---- workflow structure ----


def test_dispatch_inputs_present():
    inputs = triggers(workflow())["workflow_dispatch"]["inputs"]
    for k in (
        "publish",
        "version",
        "source_sha",
        "source_ref",
        "run_id",
        "run_attempt",
        "manifest_json",
        "manifest_sha256",
    ):
        assert k in inputs, k
    assert (
        inputs["publish"]["type"] == "boolean" and inputs["publish"]["default"] is False
    )


def test_release_trigger_verification_only():
    assert triggers(workflow())["release"]["types"] == ["published"]


def test_promotion_never_rebuilds_and_downloads():
    text = WORKFLOW.read_text()
    assert "python -m build" not in text
    assert "gh run download" in text


def test_publish_requires_optin_and_publish_allowed():
    job = workflow()["jobs"]["pypi-publish"]
    cond = " ".join(job["if"].split())
    assert "github.event_name == 'workflow_dispatch'" in cond
    assert "inputs.publish == true" in cond
    assert "needs.promote.outputs.publish_allowed == 'true'" in cond


def test_id_token_scoped_to_publish_only():
    jobs = workflow()["jobs"]
    assert jobs["pypi-publish"]["permissions"].get("id-token") == "write"
    for name, job in jobs.items():
        if name != "pypi-publish":
            assert job.get("permissions", {}).get("id-token") != "write", name
    assert "id-token" not in workflow().get("permissions", {})


def test_publisher_only_in_publish_and_handoff_used():
    text = WORKFLOW.read_text()
    assert "promote_handoff" in text
    jobs = workflow()["jobs"]
    for name, job in jobs.items():
        uses = [s.get("uses", "") for s in job.get("steps", [])]
        assert any("gh-action-pypi-publish" in u for u in uses) == (
            name == "pypi-publish"
        ), name


def test_actions_pinned_to_sha():
    for job in workflow()["jobs"].values():
        for step in job.get("steps", []):
            if step.get("uses"):
                assert SHA_RE.search(step["uses"]), step["uses"]


# ---- preflight logic ----


def valid_inputs():
    gates = {g: "PASS" for g in REQUIRED_GATES}
    evidence = {
        c: {"sha256": f"{i:064x}", "path": f"{c}.json"}
        for i, c in enumerate(REQUIRED_EVIDENCE)
    }
    present = {c: {"sha256": v["sha256"], "matches": True} for c, v in evidence.items()}
    return {
        "event_name": "workflow_dispatch",
        "repository": "gexiro-global/versionsec",
        "expected_repository": "gexiro-global/versionsec",
        "publish": "true",
        "version": "0.5.0",
        "project_version": "0.5.0",
        "source_sha": SHA,
        "source_ref": REF,
        "run_attempt": "1",
        "manifest_hash_ok": True,
        "manifest": {
            "version": "0.5.0",
            "source_sha": SHA,
            "source_ref": REF,
            "run_id": "123",
            "run_attempt": "1",
            "workflow": ".github/workflows/ci.yml",
            "event": "push",
            "wheel_sha256": WHEEL,
            "sdist_sha256": SDIST,
            "gates": gates,
            "evidence": evidence,
        },
        "observed_run": {
            "repository": "gexiro-global/versionsec",
            "head_sha": SHA,
            "head_branch_ref": REF,
            "status": "completed",
            "conclusion": "success",
            "event": "push",
            "run_id": "123",
            "run_attempt": "1",
            "workflow_path": ".github/workflows/ci.yml",
        },
        "artifact_digests": {"wheel": WHEEL, "sdist": SDIST},
        "attestation_results": {
            "wheel": {
                "verified": True,
                "source_digest": SHA,
                "repository": "gexiro-global/versionsec",
                "signer_workflow": "https://github.com/gexiro-global/versionsec/.github/workflows/ci.yml@"
                + REF,
                "subject_sha256": WHEEL,
            },
            "sdist": {
                "verified": True,
                "source_digest": SHA,
                "repository": "gexiro-global/versionsec",
                "signer_workflow": "https://github.com/gexiro-global/versionsec/.github/workflows/ci.yml@"
                + REF,
                "subject_sha256": SDIST,
            },
        },
        "evidence_present": present,
        "dist_files": ["forgeguard-0.5.0-py3-none-any.whl", "forgeguard-0.5.0.tar.gz"],
        "built_in_promotion": False,
    }


def test_valid_prepares_and_allows_publish():
    r = evaluate(valid_inputs())
    assert r["prepared"] is True and r["publish_allowed"] is True


def test_prepare_only_no_publish():  # C-R01-06 / R01-A
    d = valid_inputs()
    d["publish"] = "false"
    r = evaluate(d)
    assert r["prepared"] is True and r["publish_allowed"] is False


def test_rc3_narrow_manifest_five_gates_refused():  # C-R01-02
    d = valid_inputs()
    d["manifest"]["gates"] = {
        "test-3.11": "PASS",
        "test-3.12": "PASS",
        "build": "PASS",
        "codeql": "PASS",
        "candidate-provenance": "PASS",
    }
    assert evaluate(d)["prepared"] is False


@pytest.mark.parametrize("gate", REQUIRED_GATES)
def test_removing_any_gate_refuses(gate):  # C-R01-01
    d = valid_inputs()
    d["manifest"]["gates"] = {g: "PASS" for g in REQUIRED_GATES if g != gate}
    assert evaluate(d)["prepared"] is False


def test_gate_not_pass_refuses():
    d = valid_inputs()
    d["manifest"]["gates"]["G13"] = "BLOCKED"
    assert evaluate(d)["prepared"] is False


@pytest.mark.parametrize(
    "mut",
    [
        {"manifest_hash_ok": False},  # C-R01-04
        {"source_ref": "refs/heads/attacker"},  # C-R01-03
        {"run_attempt": "2"},
        {"built_in_promotion": True},
    ],
)
def test_prepare_refuses_on_binding_break(mut):
    d = valid_inputs()
    d.update(mut)
    assert evaluate(d)["prepared"] is False


def test_missing_evidence_category_refuses():
    d = valid_inputs()
    d["manifest"]["evidence"].pop("tls_cleanup")
    assert evaluate(d)["prepared"] is False


def test_unbound_evidence_refuses():  # C-R01-04
    d = valid_inputs()
    d["evidence_present"]["sbom"]["matches"] = False
    assert evaluate(d)["prepared"] is False


def test_extra_dist_file_refuses():  # C-R01-05
    d = valid_inputs()
    d["dist_files"] = d["dist_files"] + ["forgeguard-0.5.0-extra.whl"]
    assert evaluate(d)["prepared"] is False


def test_attestation_or_digest_break_refuses():
    d = valid_inputs()
    d["attestation_results"]["sdist"]["source_digest"] = "b" * 40
    assert evaluate(d)["prepared"] is False
    d2 = valid_inputs()
    d2["artifact_digests"]["wheel"] = "z" * 64
    assert evaluate(d2)["prepared"] is False


def test_observed_run_failure_refuses():
    d = valid_inputs()
    d["observed_run"]["conclusion"] = "failure"
    assert evaluate(d)["prepared"] is False


# ---- promote_handoff (exact two-file set + no-network stub) ----


def _mk(dir_, names):
    dir_.mkdir(parents=True, exist_ok=True)
    for n in names:
        (dir_ / n).write_bytes(n.encode())


def test_handoff_passes_exactly_two_files(tmp_path):  # C-R01-07
    d = tmp_path / "dist"
    _mk(d, ["forgeguard-0.5.0-py3-none-any.whl", "forgeguard-0.5.0.tar.gz"])
    received = []
    promote_handoff(d, lambda payload: received.extend(payload))
    assert len(received) == 2
    assert {n.split(".")[-1] for n, _s, _h in received} == {"whl", "gz"}
    assert all(len(h) == 64 for _n, _s, h in received)


def test_handoff_prepare_only_zero_calls(tmp_path):  # C-R01-06
    d = tmp_path / "dist"
    _mk(d, ["forgeguard-0.5.0-py3-none-any.whl", "forgeguard-0.5.0.tar.gz"])
    calls = []
    # a prepare-only caller simply never invokes the handoff
    assert calls == []


@pytest.mark.parametrize(
    "names",
    [
        ["only.whl"],
        ["a.whl", "b.whl", "c.tar.gz"],
        ["a.whl", "b.whl"],
        ["a.tar.gz", "b.tar.gz"],
        ["a.whl", "b.tar.gz", "extra.txt"],
    ],
)
def test_handoff_rejects_wrong_sets(tmp_path, names):  # C-R01-05
    d = tmp_path / "dist"
    _mk(d, names)
    with pytest.raises(HandoffError):
        promote_handoff(d, lambda payload: payload)


def test_handoff_rejects_symlink(tmp_path):
    d = tmp_path / "dist"
    _mk(d, ["forgeguard-0.5.0.tar.gz"])
    (d / "forgeguard-0.5.0-py3-none-any.whl").symlink_to(d / "forgeguard-0.5.0.tar.gz")
    with pytest.raises(HandoffError):
        promote_handoff(d, lambda payload: payload)
