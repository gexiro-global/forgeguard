from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version


def package_version() -> str:
    """Return installed distribution version without duplicating it in runtime code."""
    try:
        return version("forgeguard")
    except PackageNotFoundError:
        return "0+unknown"


__version__ = package_version()
