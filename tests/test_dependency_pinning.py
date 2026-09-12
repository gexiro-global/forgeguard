"""Every externally installed dependency is version-pinned and hash-pinned.

Structural only: no network, no installation. These tests fail if a lock file
drifts from its input, if a hash disappears, if the runtime layer is resolved
inconsistently between locks, or if a workflow gains a ``pip install`` that
could fetch an unverified artifact from an index.
"""

import re
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
REQ = ROOT / "requirements"
WORKFLOWS = ROOT / ".github" / "workflows"
LAYERS = ("runtime", "dev", "build", "fuzz")

_PIN = re.compile(r"^([A-Za-z0-9._-]+)==([^ \\\n]+)", re.MULTILINE)
_HASH = "--hash=sha256:"


def _pins(path: Path) -> dict[str, str]:
    return {
        m.group(1).lower().replace("_", "-"): m.group(2).strip()
        for m in _PIN.finditer(path.read_text(encoding="utf-8"))
    }


@pytest.mark.parametrize("layer", LAYERS)
def test_lock_exists_for_every_input(layer):
    assert (REQ / f"{layer}.in").is_file()
    assert (REQ / f"{layer}.txt").is_file()


@pytest.mark.parametrize("layer", LAYERS)
def test_every_locked_requirement_carries_a_hash(layer):
    text = (REQ / f"{layer}.txt").read_text(encoding="utf-8")
    blocks = re.split(r"\n(?=[A-Za-z0-9])", text)
    unhashed = [b.splitlines()[0] for b in blocks if _PIN.match(b) and _HASH not in b]
    assert not unhashed, f"{layer}.txt requirements without a hash: {unhashed}"


@pytest.mark.parametrize("layer", LAYERS)
def test_lock_satisfies_every_declared_input_pin(layer):
    declared = _pins(REQ / f"{layer}.in")
    locked = _pins(REQ / f"{layer}.txt")
    drifted = {
        name: (want, locked.get(name))
        for name, want in declared.items()
        if locked.get(name) != want
    }
    assert not drifted, f"{layer}.in pins not reflected in {layer}.txt: {drifted}"


@pytest.mark.parametrize("layer", ("dev", "fuzz"))
def test_runtime_layer_is_resolved_identically_everywhere(layer):
    runtime = _pins(REQ / "runtime.txt")
    other = _pins(REQ / f"{layer}.txt")
    conflicting = {
        name: (version, other[name])
        for name, version in runtime.items()
        if name in other and other[name] != version
    }
    assert not conflicting, f"runtime vs {layer} version conflict: {conflicting}"


def test_dev_extra_in_pyproject_matches_the_dev_input():
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    extra = data["project"]["optional-dependencies"]["dev"]
    declared = {
        name.lower().replace("_", "-"): version
        for name, version in (item.split("==", 1) for item in extra)
    }
    locked = _pins(REQ / "dev.in")
    mismatched = {
        name: (version, locked.get(name))
        for name, version in declared.items()
        if locked.get(name) != version
    }
    assert not mismatched, f"pyproject dev extra drifted from dev.in: {mismatched}"


def _install_sites():
    """Every file that can run pip during CI or a fuzzing build."""
    yield from sorted(WORKFLOWS.glob("*.yml"))
    build = ROOT / ".clusterfuzzlite" / "build.sh"
    if build.is_file():
        yield build


def test_no_automation_installs_an_unverified_package():
    offenders = []
    for path in _install_sites():
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.strip()
            # Prose about pip is not an install; only inspect real commands.
            if stripped.startswith("#"):
                continue
            if "pip install" not in stripped and "pip3 install" not in stripped:
                continue
            if "--require-hashes" in stripped or "--no-deps" in stripped:
                continue
            offenders.append(f"{path.name}:{number}: {stripped}")
    assert not offenders, (
        "pip install without --require-hashes (index fetch) or --no-deps "
        f"(local artifact): {offenders}"
    )
