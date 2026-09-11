"""Docker-free qualification contract for the integration lab (R02).

The lab helper previously stored the CLI return code but never asserted it
before marking a variant PASS. These pure functions declare the expected exit
code and native HTTP status contract *before* a variant runs, so a correct
report paired with a wrong exit code fails, an empty or partial matrix fails,
and the oracle is not derived from the same assessor's own output.

CLI exit contract (versionsec.cli._finish): 0 clean, 2 usage/refusal,
3 execution/write error, 4 not assessed (incomplete), 5 warn/fail at full
assessment. Exit 4 takes precedence over 5.
"""

from __future__ import annotations

# The four exact tested releases (product, version). 1.26.4 is a historical
# regression fixture with a known confirmed finding, never a recommendation.
EXPECTED_RELEASES: list[tuple[str, str]] = [
    ("gitea", "1.26.4"),
    ("gitea", "1.27.3"),
    ("forgejo", "16.0.4"),
    ("forgejo", "15.0.8"),
]

# Public releases that carry a confirmed catalog finding at full assessment.
CONFIRMED_PUBLIC_FINDING_VERSIONS = {"1.26.4"}

NATIVE_STATUS_FINDING_IDS = ("FG-SIGNIN", "FG-REG", "FG-ANON")


class QualifyError(AssertionError):
    """Raised when an observed variant breaches the pre-declared contract."""


def expected_exit(private: bool, version: str) -> int:
    if private:
        return 4  # native 303 redirect leaves the assessment incomplete
    if version in CONFIRMED_PUBLIC_FINDING_VERSIONS:
        return 5  # confirmed directory finding at a full assessment
    return 0


def expected_native_statuses(private: bool) -> dict[str, int]:
    return {
        "/explore/repos": 303 if private else 200,
        "/v2/": 401,
        "/api/v1/repos/search?limit=1": 403 if private else 200,
        "/api/v1/users/search?limit=1": 403 if private else 200,
    }


def variant_name(product: str, version: str, private: bool, registration: bool) -> str:
    return f"{product}-{version}-{'private' if private else 'public'}-reg{int(registration)}"


def expected_variants() -> list[str]:
    out: list[str] = []
    for product, version in EXPECTED_RELEASES:
        for private in (False, True):
            for registration in (False, True):
                out.append(variant_name(product, version, private, registration))
    return out


def flatten_native(native_statuses: dict) -> dict[str, int]:
    return {
        path: obs["status"]
        for fid, paths in native_statuses.items()
        if fid in NATIVE_STATUS_FINDING_IDS
        for path, obs in paths.items()
    }


def qualify(
    *,
    product: str,
    version: str,
    private: bool,
    registration: bool,
    report: dict | None,
    exit_code: int,
    native_statuses: dict,
) -> dict:
    """Return a details dict on success; raise QualifyError on any breach.

    ``report`` is the parsed JSON from ``versionsec scan`` or ``None`` when the
    output was not valid JSON. ``native_statuses`` maps finding id -> {path: {"status": int}}.
    """
    if report is None:
        raise QualifyError("scan output was not valid JSON")
    exp_exit = expected_exit(private, version)
    if exit_code != exp_exit:
        raise QualifyError(f"exit {exit_code} != expected {exp_exit}")
    normalized = report.get("identity", {}).get("normalized_version")
    if normalized != version:
        raise QualifyError(f"normalized_version {normalized!r} != {version!r}")
    if report.get("request_count") != 6:
        raise QualifyError(f"request_count {report.get('request_count')!r} != 6")
    assessed = report.get("score", {}).get("assessed")
    if assessed is not (not private):
        raise QualifyError(f"assessed {assessed!r} != {not private!r}")
    findings = report.get("findings", [])
    if product == "forgejo" and any(
        str(f.get("id", "")).startswith("FG-CVE") for f in findings
    ):
        raise QualifyError("forgejo report must not carry gitea FG-CVE findings")
    known_advisory = product == "gitea" and version in CONFIRMED_PUBLIC_FINDING_VERSIONS
    # R02-B: the known Gitea 1.26.4 advisory is a confirmed fail in ALL four
    # variants (public and private); private stays incomplete with exit 4.
    if known_advisory and not any(
        f.get("id") == "FG-CVE-78433" and f.get("status") == "fail" for f in findings
    ):
        raise QualifyError(
            f"expected FG-CVE-78433=fail on gitea {version} "
            f"({'private' if private else 'public'})"
        )
    # R02-A: a public variant carries no unexpected warn/fail finding, checked
    # independently of the CLI exit code. The only frozen exception is the known
    # Gitea 1.26.4 advisory above.
    if not private:
        unexpected = [
            f.get("id")
            for f in findings
            if f.get("status") in ("warn", "fail")
            and not (known_advisory and f.get("id") == "FG-CVE-78433")
        ]
        if unexpected:
            raise QualifyError(
                f"unexpected warn/fail in clean public variant: {unexpected}"
            )
    exp_native = expected_native_statuses(private)
    actual_native = flatten_native(native_statuses)
    if actual_native != exp_native:
        raise QualifyError(f"native status {actual_native} != expected {exp_native}")
    return {
        "expected_exit": exp_exit,
        "actual_exit": exit_code,
        "expected_statuses": exp_native,
        "actual_statuses": actual_native,
    }


def evaluate_matrix(matrix: list[dict], cleanup_failures: list) -> list[str]:
    """Whole-run gate: exactly the expected unique variants, all PASS, clean cleanup."""
    variants = [row.get("variant") for row in matrix]
    problems: list[str] = []
    if sorted(v for v in variants if v) != sorted(expected_variants()):
        problems.append("variant set does not match the exact expected matrix")
    if len(variants) != len(set(variants)):
        problems.append("duplicate variants present")
    if not matrix:
        problems.append("empty matrix cannot pass")
    if any(row.get("status") != "PASS" for row in matrix):
        problems.append("a non-PASS variant is present")
    if cleanup_failures:
        problems.append("cleanup failures present")
    return problems
