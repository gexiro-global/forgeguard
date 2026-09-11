"""C-TLS: verified cleanup blocks PASS on failed removal, lingering resource, or
unreachable daemon; a real removal+absence is required.
"""

from tools.lab_cleanup import cleanup_resources

CREATED = [("network", "fgtls-net"), ("container", "fgtls-server")]


def fake_run(script):
    """script maps ('rm'|'inspect', name) -> (rc, stderr)."""

    def run(args):
        name = args[-1]
        op = "rm" if ("rm" in args) else "inspect"
        return script.get((op, name), (0, ""))

    return run


def test_clean_removal_passes():
    # rm ok (0); inspect fails (1 = not found)
    script = {("inspect", n): (1, "Error: No such object") for _, n in CREATED}
    rep = cleanup_resources(CREATED, fake_run(script))
    assert rep["status"] == "PASS"
    assert all(r["absent"] and r["ok"] for r in rep["resources"])


def test_still_present_fails():
    # container inspect returns 0 => still present
    script = {
        ("inspect", "fgtls-server"): (0, ""),
        ("inspect", "fgtls-net"): (1, "no such"),
    }
    rep = cleanup_resources(CREATED, fake_run(script))
    assert rep["status"] == "FAIL"
    assert any(r["status"] == "still_present" for r in rep["failures"])


def test_remove_failed_fails():
    script = {
        ("rm", "fgtls-server"): (1, "permission denied"),
        ("inspect", "fgtls-server"): (1, "no such"),
        ("inspect", "fgtls-net"): (1, "no such"),
    }
    rep = cleanup_resources(CREATED, fake_run(script))
    assert rep["status"] == "FAIL"
    assert any(r["status"] == "remove_failed" for r in rep["failures"])


def test_daemon_unreachable_distinguished_and_fails():
    msg = "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?"
    script = {("rm", n): (1, msg) for _, n in CREATED}
    script.update({("inspect", n): (1, msg) for _, n in CREATED})
    rep = cleanup_resources(CREATED, fake_run(script))
    assert rep["status"] == "FAIL"
    assert all(r["daemon_unreachable"] and not r["absent"] for r in rep["resources"])
    assert all(r["status"] == "daemon_unreachable" for r in rep["resources"])


def test_partial_one_absent_one_present_fails():
    script = {
        ("inspect", "fgtls-net"): (0, ""),  # network still present
        ("inspect", "fgtls-server"): (1, "no such"),
    }
    rep = cleanup_resources(CREATED, fake_run(script))
    assert rep["status"] == "FAIL"
    assert len(rep["failures"]) == 1
