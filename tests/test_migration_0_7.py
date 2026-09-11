"""ForgeGuard -> VersionSec 0.7.0 migration contract.

Every assertion here protects an existing user: canonical VersionSec surfaces must
work, and the retained ForgeGuard compatibility surfaces must keep working and must
resolve to the same implementation rather than a drifting copy.
"""

import json
import subprocess
import sys
from importlib.metadata import distribution
from importlib.metadata import version as distribution_version
from pathlib import Path

import pytest
from typer.testing import CliRunner

import forgeguard
import versionsec
from versionsec.cli import app

RUNNER = CliRunner()
ROOT = Path(__file__).parents[1]


def test_canonical_import_and_version():
    assert versionsec.__version__ == "0.7.0"
    assert distribution_version("versionsec") == "0.7.0"


def test_legacy_import_resolves_to_canonical_implementation():
    assert forgeguard.__version__ == versionsec.__version__
    # not a copy: the shim must hand back the very same module objects
    assert forgeguard.cli is versionsec.cli
    assert forgeguard.engine is versionsec.engine
    assert forgeguard.runner_review is versionsec.runner_review


def test_legacy_submodule_import_statement_works():
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import forgeguard.cli, versionsec.cli; "
                "assert forgeguard.cli is versionsec.cli; print('ok')"
            ),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "ok" in result.stdout


def test_legacy_import_is_quiet():
    """A migration warning on stdout/stderr would break existing automation."""
    result = subprocess.run(
        [sys.executable, "-c", "import forgeguard"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert result.stdout == ""
    assert result.stderr == ""


@pytest.mark.parametrize(
    "argv",
    [
        ["--help"],
        ["providers"],
        ["checks"],
        ["runner", "review", "--help"],
        ["config", "review", "--help"],
        ["scan", "--help"],
    ],
)
def test_canonical_cli_surfaces(argv):
    result = RUNNER.invoke(app, argv)
    assert result.exit_code == 0, result.output


def test_both_console_scripts_are_declared():
    entry_points = {
        ep.name: ep.value
        for ep in distribution("versionsec").entry_points
        if ep.group == "console_scripts"
    }
    assert entry_points["versionsec"] == "versionsec.cli:main"
    assert entry_points["forgeguard"] == "versionsec.cli:main", (
        "legacy CLI alias must stay available and point at the canonical implementation"
    )


def test_canonical_env_var_wins_over_legacy_alias(monkeypatch, tmp_path):
    """Deterministic precedence: VERSIONSEC_TOKEN beats FORGEGUARD_TOKEN."""
    from versionsec import cli as cli_module

    seen = {}

    def fake_run(url, token, known_version, product, scan_id, **kwargs):
        seen["token"] = token
        raise SystemExit(0)

    monkeypatch.setattr(cli_module.asyncio, "run", lambda coro: coro)
    monkeypatch.setattr(cli_module, "_run", fake_run)
    monkeypatch.setenv("VERSIONSEC_TOKEN", "canonical-token")
    monkeypatch.setenv("FORGEGUARD_TOKEN", "legacy-token")
    RUNNER.invoke(
        app,
        [
            "scan",
            "--url",
            "https://git.example.com",
            "--authorized",
            "--product",
            "gitea",
        ],
    )
    assert seen.get("token") == "canonical-token"


def test_legacy_env_var_still_accepted(monkeypatch):
    from versionsec import cli as cli_module

    seen = {}

    def fake_run(url, token, known_version, product, scan_id, **kwargs):
        seen["token"] = token
        raise SystemExit(0)

    monkeypatch.setattr(cli_module.asyncio, "run", lambda coro: coro)
    monkeypatch.setattr(cli_module, "_run", fake_run)
    monkeypatch.delenv("VERSIONSEC_TOKEN", raising=False)
    monkeypatch.setenv("FORGEGUARD_TOKEN", "legacy-token")
    RUNNER.invoke(
        app,
        [
            "scan",
            "--url",
            "https://git.example.com",
            "--authorized",
            "--product",
            "gitea",
        ],
    )
    assert seen.get("token") == "legacy-token"


def test_help_documents_canonical_env_var():
    result = RUNNER.invoke(app, ["scan", "--help"])
    assert "VERSIONSEC_TOKEN" in result.output


def test_runner_review_still_works_after_rebrand(tmp_path):
    out = tmp_path / "runner_report"
    result = RUNNER.invoke(
        app,
        [
            "runner",
            "review",
            "--snapshot",
            str(ROOT / "examples" / "forgejo-runner-snapshot.json"),
            "--format",
            "md,json,sarif",
            "--out",
            str(out),
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads((tmp_path / "runner_report.json").read_text())
    assert payload["score"]["value"] == 100
    assert payload["tool"]["name"] == "VersionSec"
    ids = sorted(f["id"] for f in payload["findings"])
    assert ids == [
        "FG-RUNNER-DOCKER",
        "FG-RUNNER-EPHEMERAL",
        "FG-RUNNER-EXECUTION",
        "FG-RUNNER-NETWORK",
        "FG-RUNNER-PLUGIN",
        "FG-RUNNER-PRIVILEGED",
        "FG-RUNNER-VERSION",
        "FG-RUNNER-VOLUMES",
    ], "stable FG-RUNNER-* identifiers must survive the rebrand"


def test_stable_schema_identifiers_are_not_rebranded(tmp_path):
    """Machine-readable schema IDs stay on the forgeguard.* namespace on purpose."""
    out = tmp_path / "r"
    RUNNER.invoke(
        app,
        [
            "runner",
            "review",
            "--snapshot",
            str(ROOT / "examples" / "gitea-runner-snapshot.json"),
            "--format",
            "json",
            "--out",
            str(out),
        ],
    )
    payload = json.loads((tmp_path / "r.json").read_text())
    assert payload["schema_id"] == "forgeguard.assessment.v1"
    assert payload["tool"]["schema"] == "forgeguard.assessment.v1"
    for name in (
        "assessment-v1.json",
        "config-snapshot-v1.json",
        "runner-snapshot-v1.json",
    ):
        assert (ROOT / "versionsec" / "schemas" / name).is_file()


def test_sarif_driver_is_rebranded_but_rule_ids_are_stable(tmp_path):
    out = tmp_path / "r"
    RUNNER.invoke(
        app,
        [
            "runner",
            "review",
            "--snapshot",
            str(ROOT / "examples" / "gitea-runner-snapshot.json"),
            "--format",
            "sarif",
            "--out",
            str(out),
        ],
    )
    sarif = json.loads((tmp_path / "r.sarif").read_text())
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "VersionSec"
    assert "versionsec" in driver["informationUri"]
    assert all(r["id"].startswith("FG-") for r in driver["rules"])


def test_markdown_report_uses_new_brand(tmp_path):
    out = tmp_path / "r.md"
    RUNNER.invoke(
        app,
        [
            "runner",
            "review",
            "--snapshot",
            str(ROOT / "examples" / "gitea-runner-snapshot.json"),
            "--out",
            str(out),
        ],
    )
    text = out.read_text()
    assert "VersionSec" in text
    assert "ForgeGuard" not in text


def test_user_agent_is_rebranded():
    from versionsec.client import _UA

    assert _UA.startswith("VersionSec-by-Gexiro/0.7.0")


def test_no_unintended_active_forgeguard_branding_in_package():
    """Active-brand scan over the shipped package.

    Allowed survivors are only: the frozen machine-readable schema identifiers, and
    the compatibility shim itself (which must name the old brand to explain itself).
    """
    offenders = []
    for path in sorted((ROOT / "versionsec").rglob("*.py")):
        for number, line in enumerate(path.read_text().splitlines(), start=1):
            if "forgeguard" not in line.lower():
                continue
            if "forgeguard.assessment.v1" in line:
                continue
            if "forgeguard.scan-result.v0.3" in line:
                continue
            if "forgeguard.config-snapshot.v1" in line:
                continue
            if "forgeguard.runner-snapshot.v1" in line:
                continue
            if "FORGEGUARD_TOKEN" in line:
                # COMPATIBILITY: documented legacy env alias, retained on purpose.
                continue
            offenders.append(f"{path.relative_to(ROOT)}:{number}: {line.strip()}")
    assert offenders == [], offenders
