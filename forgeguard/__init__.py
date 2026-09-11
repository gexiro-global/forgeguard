"""Compatibility shim: ForgeGuard was renamed to VersionSec in 0.7.0.

``import forgeguard`` and ``import forgeguard.cli`` keep working and resolve to the
canonical ``versionsec`` implementation. There is no second implementation here: every
name is an alias of the canonical module object, so the two import paths cannot drift.

Canonical from 0.7.0 onward::

    python -m pip install versionsec
    import versionsec

The legacy path stays quiet on purpose - it emits no warning to stdout or stderr, so
existing automation does not break. See MIGRATION.md.
"""

from __future__ import annotations

import importlib
import sys

import versionsec as _versionsec

__version__ = _versionsec.__version__
__all__ = list(getattr(_versionsec, "__all__", []))

_SUBMODULES = (
    "advisories",
    "advisories.evaluator",
    "advisories.models",
    "assessment",
    "checks",
    "cli",
    "client",
    "config_review",
    "engine",
    "exporters",
    "exporters.json",
    "exporters.markdown",
    "exporters.sarif",
    "models",
    "output",
    "policy",
    "providers",
    "providers.base",
    "providers.forgejo",
    "providers.gitea",
    "providers.registry",
    "report",
    "runner_review",
    "safety",
    "scoring",
    "urls",
    "version",
)

# Register each canonical submodule under the legacy name as well, so that the
# statement form ``import forgeguard.cli`` resolves without a second implementation.
for _name in _SUBMODULES:
    try:
        _module = importlib.import_module(f"versionsec.{_name}")
    except ModuleNotFoundError:  # pragma: no cover - defensive
        continue
    sys.modules[f"{__name__}.{_name}"] = _module
    if "." not in _name:
        globals()[_name] = _module
del _name, _module


def __getattr__(name: str):
    """Any remaining attribute resolves against the canonical package."""
    try:
        return getattr(_versionsec, name)
    except AttributeError as exc:
        raise AttributeError(name) from exc


def __dir__():
    return sorted(set(dir(_versionsec)) | {n for n in _SUBMODULES if "." not in n})
