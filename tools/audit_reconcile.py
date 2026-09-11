"""E-FINAL: reconcile a dependency inventory against a dependency-audit input/output.

Audit completeness is a SET comparison, not a record count. Equal counts do not
prove coverage: a removed record plus an added one keeps the count. This helper
normalises names (PEP 503) and compares exact versions, reporting what is
missing from the audit, unexpectedly extra, or version-mismatched.
"""

from __future__ import annotations

import re


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def reconcile(inventory: dict[str, str], audited: dict[str, str]) -> dict:
    """inventory/audited map distribution name -> exact version.

    Returns {missing, unexpected, version_mismatches, ok}. ``missing`` = in
    inventory but not audited; ``unexpected`` = audited but not in inventory;
    ``version_mismatches`` = same package, different version.
    """
    inv = {normalize(n): v for n, v in inventory.items()}
    aud = {normalize(n): v for n, v in audited.items()}
    missing = sorted(n for n in inv if n not in aud)
    unexpected = sorted(n for n in aud if n not in inv)
    version_mismatches = [
        {"package": n, "inventory": inv[n], "audited": aud[n]}
        for n in sorted(inv)
        if n in aud and inv[n] != aud[n]
    ]
    return {
        "missing": missing,
        "unexpected": unexpected,
        "version_mismatches": version_mismatches,
        "ok": not (missing or unexpected or version_mismatches),
    }
