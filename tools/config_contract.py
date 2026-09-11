"""R05: importable config-review qualification contract (no Docker side effects).

The lab and the tests share this. It checks the real config-review output against
an independent oracle for the frozen 16-variant matrix: exact finding statuses,
completeness/assessed, request_count, and the exit code of EVERY export format
(not one overwritten value). A declared non-default sign-in/registration value
that was not actually observed must fail rather than silently become a default.
"""

from __future__ import annotations

from forgeguard.providers.registry import get_provider

CONFIG_FINDINGS = (
    "FG-CONFIG-REGISTRATION",
    "FG-CONFIG-SIGNIN",
    "FG-CONFIG-PRIVACY",
    "FG-CONFIG-MFA",
)


class ConfigQualifyError(AssertionError):
    """Raised when a config-review result breaches the frozen oracle."""


def expected_statuses(policy: str, registration: bool) -> dict:
    """Frozen oracle for the lab matrix. Derived from policy/fixtures, not output."""
    if policy == "public":
        return dict.fromkeys(CONFIG_FINDINGS, "info")
    # private intent
    return {
        "FG-CONFIG-SIGNIN": "pass",
        "FG-CONFIG-PRIVACY": "warn",
        "FG-CONFIG-MFA": "warn",
        # registration off (DISABLE_REGISTRATION true) -> pass; on -> warn
        "FG-CONFIG-REGISTRATION": "pass" if not registration else "warn",
    }


def expected_exit(policy: str) -> int:
    # public: all INFO -> assessed, no warn/fail -> 0; private: warns present -> 5
    return 0 if policy == "public" else 5


def non_default_keys(product: str, declared: dict) -> list[str]:
    """Keys whose declared value differs from the provider default."""
    defaults = {s.key: s.default for s in get_provider(product).settings}
    out = []
    for key, value in declared.items():
        if key in defaults and value != defaults[key] and value != "missing":
            out.append(key)
    return out


def qualify_config(
    *,
    product: str,
    policy: str,
    registration: bool,
    declared: dict,
    observed: dict,
    review_json: dict,
    exits_by_format: dict,
) -> dict:
    """Return details on success; raise ConfigQualifyError on any breach.

    ``observed`` maps key -> value or 'missing'. ``review_json`` is the parsed JSON
    config-review report. ``exits_by_format`` maps 'json'/'md'/'sarif' -> exit int.
    """
    # 1. a declared non-default signin/registration value must be actually observed
    for key in non_default_keys(product, declared):
        if observed.get(key) == "missing":
            raise ConfigQualifyError(
                f"non-default {key} declared but not observed (would silently default)"
            )

    # 2. exactly the four findings, no duplicates
    findings = review_json.get("findings", [])
    ids = [f.get("id") for f in findings]
    config_ids = [i for i in ids if i in CONFIG_FINDINGS]
    if sorted(config_ids) != sorted(CONFIG_FINDINGS):
        raise ConfigQualifyError(f"config findings mismatch: {sorted(config_ids)}")
    if len(config_ids) != len(set(config_ids)):
        raise ConfigQualifyError("duplicate config finding id")

    # 3. statuses match the oracle exactly
    status_by_id = {
        f["id"]: f.get("status") for f in findings if f.get("id") in CONFIG_FINDINGS
    }
    want = expected_statuses(policy, registration)
    if status_by_id != want:
        raise ConfigQualifyError(f"status mismatch: got {status_by_id} want {want}")

    # 4. every config finding is complete/assessed (offline snapshot fully supplied)
    for f in findings:
        if (
            f.get("id") in CONFIG_FINDINGS
            and f.get("evidence_state") not in ("assessed", None)
            and f.get("applicability") != "applicable"
        ):
            raise ConfigQualifyError(f"{f['id']} not complete/applicable")

    # 5. overall assessed + request_count == 0
    score = review_json.get("score", {})
    if score.get("assessed") is not True:
        raise ConfigQualifyError(f"assessed != True ({score.get('assessed')})")
    if review_json.get("request_count") not in (0, None):
        raise ConfigQualifyError(
            f"request_count != 0 ({review_json.get('request_count')})"
        )

    # 6. exit code of EVERY format equals the expected exit
    exp_exit = expected_exit(policy)
    for fmt in ("json", "md", "sarif"):
        if exits_by_format.get(fmt) != exp_exit:
            raise ConfigQualifyError(
                f"exit[{fmt}]={exits_by_format.get(fmt)} != {exp_exit}"
            )

    return {"statuses": status_by_id, "expected_exit": exp_exit, "assessed": True}
