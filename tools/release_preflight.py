"""Manual-publish preflight gate (R01). Validates inputs as DATA; never uploads.

Separated states, never collapsed: PREPARE (full data validation) vs the PUBLISH
gate (owner intent) vs PROMOTION of the frozen already-qualified set.

Prepare requires: repository identity; version == project == manifest; a full
source SHA and an EXACT allowed source ref; a qualification manifest whose schema
is complete, whose gates cover ALL of G01..G15 and are every one PASS, and whose
closed set of mandatory evidence categories are each present and hash-bound; the
referenced completed+successful trusted push run/attempt (compared to the API and
to the verified attestation); the exact wheel/sdist digests; a real cryptographic
attestation of those exact files; and no rebuild in promotion. The manifest hash
is mandatory. Any data failure refuses with a non-zero code even in prepare-only.

``evaluate`` is pure so it can be unit-tested without GitHub Actions.
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

EXPECTED_REPOSITORY = "gexiro-global/versionsec"
EXPECTED_WORKFLOW = ".github/workflows/ci.yml"
EXPECTED_EVENT = "push"
ALLOWED_SOURCE_REFS = {
    "refs/heads/feat/forgeguard-v0.5-multiforge",
    "refs/heads/feat/forgeguard-v0.6-control-plane-hardening",
    "refs/heads/feat/versionsec-0.7-rebrand",
    "refs/heads/fix/versionsec-0.7.1-release-contract",
    "refs/heads/release/versionsec-0.7.2-metadata-docs",
}
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
REQUIRED_GATES = [f"G{i:02d}" for i in range(1, 16)]
REQUIRED_EVIDENCE = [
    "tests_py311",
    "tests_py312",
    "r01_contract",
    "r05_contract",
    "http_matrix",
    "readback",
    "tls",
    "tls_cleanup",
    "install_wheel",
    "install_sdist",
    "sbom",
    "inventory_audit",
    "attestation",
    "secret_license",
    "source_state",
    "review",
]
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
    "evidence",
]


def _add(checks, name, gate, ok, detail=""):
    checks.append({"name": name, "gate": gate, "ok": bool(ok), "detail": detail})


def evaluate(inputs: dict) -> dict:
    """Return {prepared, publish_allowed, checks:[{name,gate,ok,detail}]}."""
    checks: list[dict] = []
    manifest = inputs.get("manifest") or {}
    observed = inputs.get("observed_run") or {}
    artifacts = inputs.get("artifact_digests") or {}
    att = inputs.get("attestation_results") or {}
    evidence_present = inputs.get("evidence_present") or {}

    repo = inputs.get("repository", "")
    _add(
        checks,
        "repository_identity",
        "data",
        repo == inputs.get("expected_repository", "") == EXPECTED_REPOSITORY,
        repo,
    )

    _add(
        checks,
        "manifest_hash_verified",
        "data",
        inputs.get("manifest_hash_ok") is True,
        str(inputs.get("manifest_hash_ok")),
    )

    missing = [k for k in MANIFEST_REQUIRED if k not in manifest]
    _add(checks, "manifest_schema_complete", "data", not missing, f"missing={missing}")

    gates = manifest.get("gates") or {}
    gate_missing = [g for g in REQUIRED_GATES if g not in gates]
    gate_bad = [g for g in REQUIRED_GATES if gates.get(g) not in ("PASS",)]
    _add(
        checks,
        "manifest_all_gates_present",
        "data",
        not gate_missing,
        f"missing={gate_missing}",
    )
    _add(
        checks, "manifest_all_gates_pass", "data", not gate_bad, f"not_pass={gate_bad}"
    )

    ev = manifest.get("evidence") or {}
    ev_missing = [c for c in REQUIRED_EVIDENCE if c not in ev]
    _add(
        checks,
        "manifest_evidence_categories_complete",
        "data",
        not ev_missing,
        f"missing={ev_missing}",
    )
    bad_ev = []
    for cat, entry in ev.items():
        digest = (entry or {}).get("sha256") if isinstance(entry, dict) else None
        present = evidence_present.get(cat) or {}
        if not (
            digest
            and _DIGEST_RE.match(digest)
            and present.get("sha256") == digest
            and present.get("matches") is True
        ):
            bad_ev.append(cat)
    _add(
        checks,
        "manifest_evidence_files_present_and_bound",
        "data",
        bool(ev) and not bad_ev,
        f"unbound={bad_ev}",
    )

    version = inputs.get("version", "")
    pv = inputs.get("project_version", "")
    _add(
        checks,
        "version_matches",
        "data",
        bool(version) and version == pv == manifest.get("version"),
        f"input={version!r} project={pv!r} manifest={manifest.get('version')!r}",
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

    src_ref = inputs.get("source_ref", "")
    _add(checks, "source_ref_allowed", "data", src_ref in ALLOWED_SOURCE_REFS, src_ref)
    _add(
        checks,
        "source_ref_matches",
        "data",
        bool(src_ref)
        and src_ref == manifest.get("source_ref") == observed.get("head_branch_ref"),
        f"input={src_ref!r} manifest={manifest.get('source_ref')!r} observed={observed.get('head_branch_ref')!r}",
    )

    run_attempt = str(inputs.get("run_attempt", ""))
    _add(
        checks,
        "run_attempt_bound",
        "data",
        bool(run_attempt)
        and run_attempt
        == str(manifest.get("run_attempt"))
        == str(observed.get("run_attempt")),
        f"input={run_attempt} manifest={manifest.get('run_attempt')} observed={observed.get('run_attempt')}",
    )

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
        "observed_run_id",
        "data",
        str(observed.get("run_id")) == str(manifest.get("run_id")),
        f"{observed.get('run_id')}",
    )
    workflow = str(observed.get("workflow_path", observed.get("path", "")))
    _add(
        checks,
        "observed_run_workflow",
        "data",
        workflow == EXPECTED_WORKFLOW == manifest.get("workflow"),
        workflow,
    )

    _add(
        checks,
        "wheel_digest_matches_manifest",
        "data",
        artifacts.get("wheel") == manifest.get("wheel_sha256")
        and bool(artifacts.get("wheel")),
        str(artifacts.get("wheel")),
    )
    _add(
        checks,
        "sdist_digest_matches_manifest",
        "data",
        artifacts.get("sdist") == manifest.get("sdist_sha256")
        and bool(artifacts.get("sdist")),
        str(artifacts.get("sdist")),
    )

    dist_files = inputs.get("dist_files") or []
    wheels = [f for f in dist_files if f.endswith(".whl")]
    sdists = [f for f in dist_files if f.endswith(".tar.gz")]
    _add(
        checks,
        "exact_two_file_set",
        "data",
        len(dist_files) == 2 and len(wheels) == 1 and len(sdists) == 1,
        f"{sorted(dist_files)}",
    )
    _add(
        checks,
        "not_rebuilt_in_promotion",
        "data",
        inputs.get("built_in_promotion") is False,
        str(inputs.get("built_in_promotion")),
    )

    for kind, dk in (("wheel", "wheel_sha256"), ("sdist", "sdist_sha256")):
        r = att.get(kind) or {}
        ok = (
            r.get("verified") is True
            and r.get("source_digest") == source_sha
            and r.get("repository") == EXPECTED_REPOSITORY
            and "/.github/workflows/ci.yml" in str(r.get("signer_workflow", ""))
            and r.get("subject_sha256") == manifest.get(dk)
        )
        _add(
            checks,
            f"attestation_verified_{kind}",
            "data",
            ok,
            f"verified={r.get('verified')} src={r.get('source_digest')}",
        )

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


class HandoffError(AssertionError):
    """Raised when the exact two-file promotion set is invalid."""


def promote_handoff(dist_dir, stub):
    """Validate the exact wheel+sdist set and hand exactly those files to ``stub``.

    ``stub`` is a callable receiving a list of (name, size, sha256); it must not
    reach the network. Returns the stub's receipt. Rejects missing/extra/duplicate
    artifacts, symlinks, and paths escaping the staging directory. Counts files.
    """
    dist_dir = Path(dist_dir).resolve()
    entries = [p for p in sorted(dist_dir.iterdir())]
    files = [p for p in entries if p.is_file() and not p.is_symlink()]
    if any(p.is_symlink() for p in entries):
        raise HandoffError("symlink in staging dir")
    if len(files) != 2:
        raise HandoffError(f"expected exactly 2 files, got {[p.name for p in entries]}")
    wheels = [p for p in files if p.name.endswith(".whl")]
    sdists = [p for p in files if p.name.endswith(".tar.gz")]
    if len(wheels) != 1 or len(sdists) != 1:
        raise HandoffError(
            f"need exactly one wheel and one sdist: {[p.name for p in files]}"
        )
    payload = []
    for p in (wheels[0], sdists[0]):
        rp = p.resolve()
        if not rp.is_relative_to(dist_dir):
            raise HandoffError(f"path escapes staging: {p.name}")
        payload.append(
            (p.name, p.stat().st_size, hashlib.sha256(p.read_bytes()).hexdigest())
        )
    return stub(payload)


# ---------- CLI wrappers (impure) ----------


def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _project_version():
    try:
        return tomllib.loads(Path("pyproject.toml").read_text())["project"]["version"]
    except (OSError, KeyError, tomllib.TOMLDecodeError):
        return ""


def _observed_run(repo, run_id):
    try:
        r = subprocess.run(
            ["gh", "api", f"repos/{repo}/actions/runs/{run_id}"],
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
        data = json.loads(r.stdout or "null") or {}
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        data = {}
    head_branch = data.get("head_branch")
    return {
        "repository": (data.get("repository") or {}).get("full_name"),
        "head_sha": data.get("head_sha"),
        "head_branch_ref": f"refs/heads/{head_branch}" if head_branch else None,
        "status": data.get("status"),
        "conclusion": data.get("conclusion"),
        "event": data.get("event"),
        "run_id": data.get("id"),
        "run_attempt": data.get("run_attempt"),
        "path": data.get("path"),
    }


def _attest(path, repo):
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
            a = data[0] if isinstance(data, list) and data else {}
            cert = ((a.get("verificationResult") or {}).get("signature") or {}).get(
                "certificate"
            ) or {}
            stmt = (a.get("verificationResult") or {}).get("statement") or {}
            file_sha = _sha256(path)
            match = next(
                (
                    s
                    for s in (stmt.get("subject") or [])
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


def _collect_inputs():
    repo = os.environ.get("FG_REPOSITORY", "")
    dist_dir = Path(os.environ.get("FG_DIST_DIR", "dist"))
    wheel = next(iter(sorted(dist_dir.glob("*.whl"))), None)
    sdist = next(iter(sorted(dist_dir.glob("*.tar.gz"))), None)
    manifest, manifest_hash_ok = {}, False
    mpath = os.environ.get("FG_MANIFEST_PATH", "")
    expected = os.environ.get("FG_MANIFEST_SHA256", "")
    if mpath and Path(mpath).is_file():
        raw = Path(mpath).read_bytes()
        manifest_hash_ok = (
            bool(expected) and hashlib.sha256(raw).hexdigest() == expected
        )
        if manifest_hash_ok:
            try:
                manifest = json.loads(raw)
            except json.JSONDecodeError:
                manifest = {}
    # bind evidence files declared by the manifest, from the evidence dir
    ev_dir = Path(os.environ.get("FG_EVIDENCE_DIR", ""))
    evidence_present = {}
    for cat, entry in (manifest.get("evidence") or {}).items():
        rel = (entry or {}).get("path") if isinstance(entry, dict) else None
        p = (ev_dir / rel) if (ev_dir and rel) else None
        if p and p.is_file():
            actual = _sha256(p)
            evidence_present[cat] = {
                "sha256": actual,
                "matches": actual == (entry or {}).get("sha256"),
            }
        else:
            evidence_present[cat] = {"sha256": None, "matches": False}
    run_id = os.environ.get("FG_RUN_ID", "")
    return {
        "event_name": os.environ.get("FG_EVENT_NAME", ""),
        "repository": repo,
        "expected_repository": os.environ.get("FG_EXPECTED_REPOSITORY", ""),
        "publish": os.environ.get("FG_PUBLISH", ""),
        "version": os.environ.get("FG_INPUT_VERSION", ""),
        "project_version": _project_version(),
        "source_sha": os.environ.get("FG_SOURCE_SHA", ""),
        "source_ref": os.environ.get("FG_SOURCE_REF", ""),
        "run_attempt": os.environ.get("FG_RUN_ATTEMPT", ""),
        "manifest": manifest,
        "manifest_hash_ok": manifest_hash_ok,
        "observed_run": _observed_run(repo, run_id) if run_id else {},
        "artifact_digests": {
            "wheel": _sha256(wheel) if wheel else None,
            "sdist": _sha256(sdist) if sdist else None,
        },
        "attestation_results": {
            "wheel": _attest(wheel, repo) if wheel else {"verified": False},
            "sdist": _attest(sdist, repo) if sdist else {"verified": False},
        },
        "evidence_present": evidence_present,
        "dist_files": sorted(p.name for p in dist_dir.glob("*"))
        if dist_dir.is_dir()
        else [],
        "built_in_promotion": os.environ.get("FG_BUILT_IN_PROMOTION", "false")
        == "true",
    }


def main():
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
    print(
        "Prepared and publish authorised."
        if result["publish_allowed"]
        else "Prepared (prepare-only). Publish not authorised; no upload."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
