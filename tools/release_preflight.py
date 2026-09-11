"""Manual-publish preflight gate (R01-A/B/C). Validates inputs as DATA; never uploads.

Three separated concepts, never collapsed into one ``approved`` boolean:

* PREPARE (data validation): repository identity, version == project == manifest,
  a full source SHA, a qualification manifest whose schema and bindings match the
  referenced completed+successful trusted push run (run/attempt/ref/SHA/workflow/
  event), the exact wheel/sdist digests, and a real cryptographic attestation of
  those exact files. Any failure here refuses with a non-zero code even in
  prepare-only.
* PUBLISH GATE (owner intent): workflow_dispatch event + explicit ``publish=true``.
  With ``publish=false`` a correct prepare succeeds (exit 0, publish_allowed=false).
* PROMOTION uses the frozen, already-qualified artifact set (downloaded, not
  rebuilt); the caller re-checks the exact bytes before handing them to the
  publisher.

``attestation_verified`` is NOT a sufficient input: the actual verifier result is
required. ``evaluate`` is pure so it can be unit-tested without GitHub Actions.
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
EXPECTED_WORKFLOW = ".github/workflows/ci.yml"
EXPECTED_EVENT = "push"
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
MANIFEST_REQUIRED = [
    "version",
    "source_sha",
    "source_ref",
    "run_id",
    "run_attempt",
    "workflow",
    "event",
    "wheel_sha256",
    "sdist_sha256",
    "gates",
    "evidence_sha256",
]


def _add(checks, name, gate, ok, detail=""):
    checks.append({"name": name, "gate": gate, "ok": bool(ok), "detail": detail})


def evaluate(inputs: dict) -> dict:
    """Return {prepared, publish_allowed, checks:[{name,gate,ok,detail}]}.

    gate == 'data' failures block prepare (non-zero exit). gate == 'publish'
    failures only withhold publish_allowed (prepare-only can still succeed).
    """
    checks: list[dict] = []
    manifest = inputs.get("manifest") or {}
    observed = inputs.get("observed_run") or {}
    artifacts = inputs.get("artifact_digests") or {}
    att = inputs.get("attestation_results") or {}

    repo = inputs.get("repository", "")
    _add(
        checks,
        "repository_identity",
        "data",
        repo == inputs.get("expected_repository", "") == EXPECTED_REPOSITORY,
        f"{repo}",
    )

    # manifest schema
    missing = [k for k in MANIFEST_REQUIRED if k not in manifest]
    _add(checks, "manifest_schema_complete", "data", not missing, f"missing={missing}")
    gates = manifest.get("gates") or {}
    open_gates = [g for g, v in gates.items() if v not in ("PASS", True, "pass")]
    _add(
        checks,
        "manifest_no_open_gate",
        "data",
        bool(gates) and not open_gates,
        f"open={open_gates}",
    )

    version = inputs.get("version", "")
    project_version = inputs.get("project_version", "")
    _add(
        checks,
        "version_matches",
        "data",
        bool(version) and version == project_version == manifest.get("version"),
        f"input={version!r} project={project_version!r} manifest={manifest.get('version')!r}",
    )

    source_sha = inputs.get("source_sha", "")
    _add(checks, "source_sha_full", "data", bool(_SHA_RE.match(source_sha)), source_sha)
    _add(
        checks,
        "source_sha_matches_manifest",
        "data",
        source_sha == manifest.get("source_sha"),
        f"{source_sha} vs {manifest.get('source_sha')}",
    )

    # observed run must independently corroborate the manifest (from trusted API)
    _add(
        checks,
        "observed_run_repo",
        "data",
        observed.get("repository") == EXPECTED_REPOSITORY,
        str(observed.get("repository")),
    )
    _add(
        checks,
        "observed_run_head_sha",
        "data",
        observed.get("head_sha") == source_sha == manifest.get("source_sha"),
        str(observed.get("head_sha")),
    )
    _add(
        checks,
        "observed_run_completed_success",
        "data",
        observed.get("status") == "completed"
        and observed.get("conclusion") == "success",
        f"{observed.get('status')}/{observed.get('conclusion')}",
    )
    _add(
        checks,
        "observed_run_event_push",
        "data",
        observed.get("event") == EXPECTED_EVENT == manifest.get("event"),
        str(observed.get("event")),
    )
    _add(
        checks,
        "observed_run_id_attempt",
        "data",
        str(observed.get("run_id")) == str(manifest.get("run_id"))
        and str(observed.get("run_attempt")) == str(manifest.get("run_attempt")),
        f"{observed.get('run_id')}/{observed.get('run_attempt')}",
    )
    workflow = str(observed.get("workflow_path", observed.get("path", "")))
    _add(
        checks,
        "observed_run_workflow",
        "data",
        workflow.endswith(EXPECTED_WORKFLOW)
        and manifest.get("workflow", "").endswith("ci.yml"),
        workflow,
    )

    # exact artifact digests == manifest (downloaded, not rebuilt)
    _add(
        checks,
        "wheel_digest_matches_manifest",
        "data",
        bool(artifacts.get("wheel"))
        and artifacts.get("wheel") == manifest.get("wheel_sha256"),
        f"{artifacts.get('wheel')}",
    )
    _add(
        checks,
        "sdist_digest_matches_manifest",
        "data",
        bool(artifacts.get("sdist"))
        and artifacts.get("sdist") == manifest.get("sdist_sha256"),
        f"{artifacts.get('sdist')}",
    )
    _add(
        checks,
        "not_rebuilt_in_promotion",
        "data",
        inputs.get("built_in_promotion") is False,
        str(inputs.get("built_in_promotion")),
    )

    # real cryptographic attestation of the exact files (R01-B)
    for kind, digest_key in (("wheel", "wheel_sha256"), ("sdist", "sdist_sha256")):
        r = att.get(kind) or {}
        ok = (
            r.get("verified") is True
            and r.get("source_digest") == source_sha
            and r.get("repository") == EXPECTED_REPOSITORY
            and "/.github/workflows/ci.yml" in str(r.get("signer_workflow", ""))
            and r.get("subject_sha256") == manifest.get(digest_key)
        )
        _add(
            checks,
            f"attestation_verified_{kind}",
            "data",
            ok,
            f"verified={r.get('verified')} src={r.get('source_digest')} signer={r.get('signer_workflow')}",
        )

    # publish gate (owner intent) - not a prepare failure
    _add(
        checks,
        "event_is_workflow_dispatch",
        "publish",
        inputs.get("event_name") == "workflow_dispatch",
        str(inputs.get("event_name")),
    )
    _add(
        checks,
        "publish_opt_in",
        "publish",
        inputs.get("publish") == "true",
        str(inputs.get("publish")),
    )

    prepared = all(c["ok"] for c in checks if c["gate"] == "data")
    publish_allowed = prepared and all(
        c["ok"] for c in checks if c["gate"] == "publish"
    )
    return {"prepared": prepared, "publish_allowed": publish_allowed, "checks": checks}


# ---------- CLI wrappers (impure) ----------


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _project_version() -> str:
    try:
        return tomllib.loads(Path("pyproject.toml").read_text())["project"]["version"]
    except (OSError, KeyError, tomllib.TOMLDecodeError):
        return ""


def _gh_json(args: list[str]) -> dict | list | None:
    try:
        r = subprocess.run(
            ["gh", *args], capture_output=True, text=True, check=False, timeout=120
        )
        if r.returncode != 0:
            return None
        return json.loads(r.stdout or "null")
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return None


def _observed_run(repo: str, run_id: str) -> dict:
    data = _gh_json(["api", f"repos/{repo}/actions/runs/{run_id}"]) or {}
    return {
        "repository": (data.get("repository") or {}).get("full_name"),
        "head_sha": data.get("head_sha"),
        "status": data.get("status"),
        "conclusion": data.get("conclusion"),
        "event": data.get("event"),
        "run_id": data.get("id"),
        "run_attempt": data.get("run_attempt"),
        "path": data.get("path"),
    }


def _attest(path: Path, repo: str) -> dict:
    """Run the real verifier for one file; return parsed verified result."""
    try:
        r = subprocess.run(
            [
                "gh",
                "attestation",
                "verify",
                str(path),
                "--repo",
                repo,
                "--signer-workflow",
                f"{repo}/.github/workflows/ci.yml",
                "--format",
                "json",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=180,
        )
        verified = r.returncode == 0
        out = {}
        try:
            data = json.loads(r.stdout or "[]")
            att = data[0] if isinstance(data, list) and data else {}
            cert = ((att.get("verificationResult") or {}).get("signature") or {}).get(
                "certificate"
            ) or {}
            stmt = (att.get("verificationResult") or {}).get("statement") or {}
            file_sha = hashlib.sha256(path.read_bytes()).hexdigest()
            subjects = stmt.get("subject") or []
            # the attestation covers both wheel and sdist; pick the subject that
            # matches THIS file's own digest, not simply the first subject.
            match = next(
                (
                    s
                    for s in subjects
                    if (s.get("digest") or {}).get("sha256") == file_sha
                ),
                {},
            )
            out = {
                "source_digest": cert.get("sourceRepositoryDigest"),
                "repository": (cert.get("sourceRepositoryURI") or "").split(
                    "github.com/"
                )[-1],
                "signer_workflow": cert.get("buildSignerURI", ""),
                "subject_sha256": (match.get("digest") or {}).get("sha256"),
            }
        except (json.JSONDecodeError, IndexError, KeyError):
            verified = False
        return {"verified": verified, "exit_code": r.returncode, **out}
    except (OSError, subprocess.SubprocessError):
        return {"verified": False, "exit_code": 124}


def _collect_inputs() -> dict:
    repo = os.environ.get("FG_REPOSITORY", "")
    dist_dir = Path(os.environ.get("FG_DIST_DIR", "dist"))
    wheel = next(iter(sorted(dist_dir.glob("*.whl"))), None)
    sdist = next(iter(sorted(dist_dir.glob("*.tar.gz"))), None)
    manifest = {}
    mpath = os.environ.get("FG_MANIFEST_PATH", "")
    if mpath and Path(mpath).is_file():
        raw = Path(mpath).read_bytes()
        expected = os.environ.get("FG_MANIFEST_SHA256", "")
        if not expected or hashlib.sha256(raw).hexdigest() == expected:
            try:
                manifest = json.loads(raw)
            except json.JSONDecodeError:
                manifest = {}
    run_id = os.environ.get("FG_RUN_ID", "")
    return {
        "event_name": os.environ.get("FG_EVENT_NAME", ""),
        "repository": repo,
        "expected_repository": os.environ.get("FG_EXPECTED_REPOSITORY", ""),
        "publish": os.environ.get("FG_PUBLISH", ""),
        "version": os.environ.get("FG_INPUT_VERSION", ""),
        "project_version": _project_version(),
        "source_sha": os.environ.get("FG_SOURCE_SHA", ""),
        "manifest": manifest,
        "observed_run": _observed_run(repo, run_id) if run_id else {},
        "artifact_digests": {
            "wheel": _sha256(wheel) if wheel else None,
            "sdist": _sha256(sdist) if sdist else None,
        },
        "attestation_results": {
            "wheel": _attest(wheel, repo) if wheel else {"verified": False},
            "sdist": _attest(sdist, repo) if sdist else {"verified": False},
        },
        "built_in_promotion": os.environ.get("FG_BUILT_IN_PROMOTION", "false")
        == "true",
    }


def main() -> int:
    inputs = _collect_inputs()
    result = evaluate(inputs)
    printable = {k: v for k, v in inputs.items() if k != "manifest"}
    print(json.dumps({"inputs": printable, **result}, indent=2, default=str))
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a", encoding="utf-8") as fh:
            fh.write(f"prepared={'true' if result['prepared'] else 'false'}\n")
            fh.write(
                f"publish_allowed={'true' if result['publish_allowed'] else 'false'}\n"
            )
    for c in result["checks"]:
        if not c["ok"]:
            print(f"::warning::{c['gate']} check failed: {c['name']} ({c['detail']})")
    if not result["prepared"]:
        print("Preflight refused: preparation contract not satisfied.")
        return 1
    if result["publish_allowed"]:
        print("Prepared and publish authorised for this exact qualified set.")
    else:
        print("Prepared (prepare-only). Publish not authorised; no upload will occur.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
