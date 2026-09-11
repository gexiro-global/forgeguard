"""E-FINAL: inventory/audit reconciliation is a set comparison, not a count."""

from tools.audit_reconcile import normalize, reconcile


def test_full_coverage_ok():
    inv = {"httpx": "0.28.1", "pydantic": "2.13.5", "typer": "0.27.2"}
    r = reconcile(inv, dict(inv))
    assert r["ok"] and not r["missing"] and not r["version_mismatches"]


def test_detects_removed_record():
    inv = {"httpx": "0.28.1", "setuptools": "84.0.0", "wheel": "0.48.0"}
    audited = {"httpx": "0.28.1"}  # tooling silently dropped
    r = reconcile(inv, audited)
    assert r["missing"] == ["setuptools", "wheel"]
    assert not r["ok"]


def test_detects_version_swap_at_same_count():
    inv = {"packaging": "26.3", "httpx": "0.28.1"}
    audited = {"packaging": "25.0", "httpx": "0.28.1"}  # same count, wrong version
    r = reconcile(inv, audited)
    assert len(inv) == len(audited)
    assert r["version_mismatches"] == [
        {"package": "packaging", "inventory": "26.3", "audited": "25.0"}
    ]
    assert not r["ok"]


def test_detects_unexpected_extra():
    r = reconcile({"httpx": "0.28.1"}, {"httpx": "0.28.1", "evil": "1.0"})
    assert r["unexpected"] == ["evil"]
    assert not r["ok"]


def test_name_normalisation():
    assert normalize("PyYAML") == "pyyaml"
    assert normalize("typing_extensions") == "typing-extensions"
    r = reconcile({"PyYAML": "6.0.3"}, {"pyyaml": "6.0.3"})
    assert r["ok"]
