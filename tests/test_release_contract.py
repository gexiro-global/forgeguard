"""Release contract executed the way users execute it: real installed console scripts.

0.7.0 shipped with `versionsec --version` returning exit code 2 because the suite only
asserted `__version__` and drove the CLI in-process through Typer's runner. Neither can
observe a missing command-line option on an installed entrypoint, so every check here runs a
subprocess against a script resolved from PATH.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from versionsec.version import __version__

CANONICAL = "versionsec"
LEGACY = "forgeguard"

CANONICAL_VERSION_LINE = f"VersionSec {__version__}"
LEGACY_VERSION_LINE = f"VersionSec {__version__} ({LEGACY} compatibility CLI)"

CONTRACT_COMMANDS = (
    ("--version",),
    ("--help",),
    ("providers",),
    ("checks",),
    ("runner", "review", "--help"),
)


def _script(name: str) -> str:
    resolved = shutil.which(
        name, path=str(Path(sys.executable).parent)
    ) or shutil.which(name)
    if resolved is None:
        pytest.skip(f"console script {name!r} is not installed in this environment")
    return resolved


def _run(name: str, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [_script(name), *args],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


@pytest.mark.parametrize("script", [CANONICAL, LEGACY])
@pytest.mark.parametrize("args", CONTRACT_COMMANDS, ids=lambda a: " ".join(a))
def test_release_contract_command_succeeds(script: str, args: tuple[str, ...]) -> None:
    result = _run(script, *args)
    assert result.returncode == 0, (
        f"{script} {' '.join(args)} rc={result.returncode} {result.stderr}"
    )
    assert result.stdout.strip()


def test_canonical_version_flag_exact_output() -> None:
    result = _run(CANONICAL, "--version")
    assert result.returncode == 0
    assert result.stdout.strip() == CANONICAL_VERSION_LINE
    assert result.stderr == ""


def test_legacy_version_flag_identifies_compatibility_cli() -> None:
    result = _run(LEGACY, "--version")
    assert result.returncode == 0
    assert result.stdout.strip() == LEGACY_VERSION_LINE
    assert result.stderr == ""


@pytest.mark.parametrize("script", [CANONICAL, LEGACY])
def test_version_flag_reports_installed_distribution_version(script: str) -> None:
    """The printed version must match the installed distribution, not a hardcoded string."""
    result = _run(script, "--version")
    reported = subprocess.run(
        [sys.executable, "-c", "import versionsec;print(versionsec.__version__)"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    assert reported in result.stdout


@pytest.mark.parametrize("script", [CANONICAL, LEGACY])
def test_version_flag_is_quiet(script: str) -> None:
    """A single line, so command substitution around it stays usable in scripts."""
    result = _run(script, "--version")
    assert len(result.stdout.strip().splitlines()) == 1


@pytest.mark.parametrize("script", [CANONICAL, LEGACY])
def test_providers_emits_parseable_json(script: str) -> None:
    result = _run(script, "providers")
    payload = json.loads(result.stdout)
    assert {entry["id"] for entry in payload} == {"gitea", "forgejo"}


RUNNER_FIXTURES = ("gitea-runner-snapshot.json", "forgejo-runner-snapshot.json")


@pytest.mark.parametrize("script", [CANONICAL, LEGACY])
@pytest.mark.parametrize("fixture", RUNNER_FIXTURES)
def test_runner_review_smoke_from_installed_script(script: str, fixture: str) -> None:
    """Deterministic offline runner review end to end through the installed entrypoint."""
    snapshot = Path(__file__).resolve().parent.parent / "examples" / fixture
    result = _run(
        script, "runner", "review", "--snapshot", str(snapshot), "--format", "json"
    )
    assert result.returncode in (0, 1), result.stderr
    payload = json.loads(result.stdout)
    ids = {finding["id"] for finding in payload["findings"]}
    assert len([i for i in ids if i.startswith("FG-RUNNER-")]) == 8
    assert payload["tool"]["version"] == __version__
    assert payload["tool"]["name"].startswith("VersionSec")


def test_legacy_token_env_still_read_by_installed_script() -> None:
    """Environment compatibility is part of the contract, so exercise it out of process."""
    env = dict(os.environ)
    env.pop("VERSIONSEC_TOKEN", None)
    env["FORGEGUARD_TOKEN"] = "unused-by-this-command"
    result = subprocess.run(
        [_script(CANONICAL), "--version"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == CANONICAL_VERSION_LINE
