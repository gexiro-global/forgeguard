"""Manual-publish preflight gate (R01). Validates inputs as DATA; never uploads.

The publish job is reachable only from a workflow_dispatch with publish=true and
an approved preflight. This helper refuses before any upload or id-token use
unless every check passes: workflow_dispatch event, exact repository identity,
publish opt-in, version==project version, a full source SHA that matches the
actually built commit, a referenced completed successful run, independently
verified attestations, and a non-empty built distribution set.

Inputs arrive through the environment and are never interpolated into a shell
command. ``evaluate`` is pure so it can be unit tested without GitHub Actions.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

EXPECTED_REPOSITORY = "gexiro-global/forgeguard"
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def evaluate(inputs: dict) -> dict:
    """Return {approved: bool, checks: [{name, ok, detail}]} from string inputs."""
    checks: list[dict] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"name": name, "ok": bool(ok), "detail": detail})

    event = inputs.get("event_name", "")
    check("event_is_workflow_dispatch", event == "workflow_dispatch", event)

    repo = inputs.get("repository", "")
    expected_repo = inputs.get("expected_repository", "")
    check(
        "repository_identity",
        repo == expected_repo == EXPECTED_REPOSITORY,
        f"{repo} vs {expected_repo}",
    )

    check("publish_opt_in", inputs.get("publish") == "true", str(inputs.get("publish")))

    version = inputs.get("version", "")
    project_version = inputs.get("project_version", "")
    check(
        "version_matches_project",
        bool(version) and version == project_version,
        f"input {version!r} vs project {project_version!r}",
    )

    source_sha = inputs.get("source_sha", "")
    git_head = inputs.get("git_head", "")
    check(
        "source_sha_is_full_and_built",
        bool(_SHA_RE.match(source_sha)) and source_sha == git_head,
        f"input {source_sha!r} vs built {git_head!r}",
    )

    run_id = inputs.get("run_id", "")
    check("run_id_present", bool(run_id) and run_id.isdigit(), run_id)
    check(
        "referenced_run_succeeded",
        inputs.get("run_conclusion") == "success",
        str(inputs.get("run_conclusion")),
    )

    check(
        "attestation_verified",
        inputs.get("attestation_verified") == "true",
        str(inputs.get("attestation_verified")),
    )

    dist_files = inputs.get("dist_files", []) or []
    wheels = [f for f in dist_files if f.endswith(".whl")]
    sdists = [f for f in dist_files if f.endswith(".tar.gz")]
    check(
        "distribution_set_present",
        len(wheels) == 1 and len(sdists) == 1,
        f"wheels={wheels} sdists={sdists}",
    )

    approved = all(c["ok"] for c in checks)
    return {"approved": approved, "checks": checks}


def _git_head() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def _project_version() -> str:
    try:
        data = tomllib.loads(Path("pyproject.toml").read_text())
        return data["project"]["version"]
    except (OSError, KeyError, tomllib.TOMLDecodeError):
        return ""


def _collect_inputs() -> dict:
    dist_dir = Path(os.environ.get("FG_DIST_DIR", "dist"))
    dist_files = sorted(p.name for p in dist_dir.glob("*")) if dist_dir.is_dir() else []
    return {
        "event_name": os.environ.get("FG_EVENT_NAME", ""),
        "repository": os.environ.get("FG_REPOSITORY", ""),
        "expected_repository": os.environ.get("FG_EXPECTED_REPOSITORY", ""),
        "publish": os.environ.get("FG_PUBLISH", ""),
        "version": os.environ.get("FG_INPUT_VERSION", ""),
        "project_version": _project_version(),
        "source_sha": os.environ.get("FG_SOURCE_SHA", ""),
        "git_head": _git_head(),
        "run_id": os.environ.get("FG_RUN_ID", ""),
        "run_conclusion": os.environ.get("FG_RUN_CONCLUSION", ""),
        "attestation_verified": os.environ.get("FG_ATTESTATION_VERIFIED", ""),
        "dist_files": dist_files,
    }


def _write_manifest(dist_dir: Path) -> None:
    if not dist_dir.is_dir():
        return
    lines = []
    for path in sorted(dist_dir.glob("*")):
        if path.is_file():
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            lines.append(f"{digest}  {path.name}")
    (dist_dir / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n" if lines else "")


def main() -> int:
    inputs = _collect_inputs()
    _write_manifest(Path(os.environ.get("FG_DIST_DIR", "dist")))
    result = evaluate(inputs)
    redacted = {k: v for k, v in inputs.items() if k != "dist_files"}
    redacted["dist_files"] = inputs["dist_files"]
    print(json.dumps({"inputs": redacted, **result}, indent=2))
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a", encoding="utf-8") as fh:
            fh.write(f"approved={'true' if result['approved'] else 'false'}\n")
    for c in result["checks"]:
        if not c["ok"]:
            print(f"::warning::preflight check failed: {c['name']} ({c['detail']})")
    if not result["approved"]:
        print("Preflight refused: manual publish contract not satisfied.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
