"""The README is also the PyPI long description.

PyPI renders it on its own domain, so a relative link like ``[x](MIGRATION.md)``
resolves to ``https://pypi.org/project/versionsec/MIGRATION.md`` and 404s. GitHub
hides the problem because relative links work there. This locks the README to
absolute canonical URLs so the defect cannot come back silently.

No network access: the check is purely structural.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
CANONICAL_BLOB = "https://github.com/gexiro-global/versionsec/blob/main/"

# [label](target), ignoring image embeds, which are badges and already absolute.
_LINK = re.compile(r"(?<!\!)\[[^\]]*\]\(([^)]+)\)")
_PORTABLE_SCHEMES = ("https://", "http://", "mailto:", "#")


def _readme_targets() -> list[str]:
    return _LINK.findall(README.read_text(encoding="utf-8"))


def test_long_description_is_the_readme() -> None:
    """If this ever stops being true the rest of the module guards the wrong file."""
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert config["project"]["readme"] == "README.md"


def test_no_relative_links_in_long_description() -> None:
    relative = [t for t in _readme_targets() if not t.startswith(_PORTABLE_SCHEMES)]
    assert relative == [], (
        "These README links are relative and 404 on pypi.org, which renders the "
        f"same text as the long description: {relative}. Use {CANONICAL_BLOB}<path>."
    )


def test_repository_documents_use_the_canonical_blob_url() -> None:
    """An absolute link to the wrong host is portable but still wrong."""
    repo_docs = [
        t
        for t in _readme_targets()
        if t.startswith("https://github.com/gexiro-global/versionsec/")
        and t.endswith((".md", "/LICENSE"))
    ]
    assert repo_docs, "expected the README to link at least one repository document"
    bad = [t for t in repo_docs if not t.startswith(CANONICAL_BLOB)]
    assert bad == [], f"repository documents must be linked via {CANONICAL_BLOB}: {bad}"


@pytest.mark.parametrize("name", ["MIGRATION.md", "LICENSE", "AUTHORIZED_USE.md"])
def test_key_documents_stay_linked(name: str) -> None:
    """Guard the specific documents a new user is sent to from PyPI."""
    assert f"{CANONICAL_BLOB}{name}" in README.read_text(encoding="utf-8")


def test_every_linked_repository_document_exists() -> None:
    """An absolute link is no good if it points at a file that was renamed away."""
    missing = []
    for target in _readme_targets():
        if not target.startswith(CANONICAL_BLOB):
            continue
        relative = target[len(CANONICAL_BLOB) :].split("#", 1)[0]
        if not (ROOT / relative).exists():
            missing.append(relative)
    assert missing == [], (
        f"README links to repository paths that do not exist: {missing}"
    )
