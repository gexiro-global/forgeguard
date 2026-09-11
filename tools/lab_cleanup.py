"""Verified cleanup of run-owned Docker resources (importable, no Docker at import).

Each resource is removed, then an inspect confirms absence. A removal failure or a
resource that is still present blocks PASS; an unreachable daemon is reported
distinctly from "resource is gone". ``run`` is injected so the logic is unit
testable without Docker.
"""

from __future__ import annotations


def _daemon_unreachable(stderr: str) -> bool:
    e = (stderr or "").lower()
    return (
        "cannot connect to the docker daemon" in e
        or "is the docker daemon running" in e
    )


def _remove_and_verify(kind: str, name: str, run) -> dict:
    if kind == "container":
        remove = ["docker", "rm", "-f", name]
        inspect = ["docker", "container", "inspect", name]
    else:
        remove = ["docker", "network", "rm", name]
        inspect = ["docker", "network", "inspect", name]
    rc_rm, err_rm = run(remove)
    rc_insp, err_insp = run(inspect)
    daemon = _daemon_unreachable(err_rm) or _daemon_unreachable(err_insp)
    absent = (rc_insp != 0) and not daemon  # inspect fails => resource not found
    ok = rc_rm == 0 and absent
    if ok:
        status = "removed_and_absent"
    elif daemon:
        status = "daemon_unreachable"
    elif rc_insp == 0:
        status = "still_present"
    else:
        status = "remove_failed"
    return {
        "kind": kind,
        "name": name,
        "remove_exit": rc_rm,
        "inspect_exit": rc_insp,
        "absent": absent,
        "daemon_unreachable": daemon,
        "ok": ok,
        "status": status,
    }


def cleanup_resources(created: list[tuple[str, str]], run) -> dict:
    """Remove created resources in reverse and verify absence.

    created: list of (kind, name), kind in {'container','network'}. run(args) ->
    (returncode, stderr). Returns {status, resources, failures}.
    """
    results = [_remove_and_verify(kind, name, run) for kind, name in reversed(created)]
    failures = [r for r in results if not r["ok"]]
    return {
        "status": "PASS" if not failures else "FAIL",
        "resources": results,
        "failures": failures,
    }
