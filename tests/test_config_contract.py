"""R05: the config qualifier enforces statuses/completeness/assessed/exits, not
just the presence of four finding ids. Reproduces the rc3 reviewer's four
negative cases plus duplicate/missing findings.
"""

import pytest

from tools.config_contract import (
    CONFIG_FINDINGS,
    ConfigQualifyError,
    expected_exit,
    expected_statuses,
    qualify_config,
)

GITEA_DECLARED_PRIVATE_REGOFF = {
    "service.DISABLE_REGISTRATION": True,
    "service.REGISTER_EMAIL_CONFIRM": False,
    "service.REGISTER_MANUAL_CONFIRM": False,
    "service.REQUIRE_SIGNIN_VIEW": True,
    "repository.FORCE_PRIVATE": False,
    "repository.DEFAULT_PRIVATE": "last",
    "security.TWO_FACTOR_AUTH": "",
}


def review(
    policy,
    registration,
    *,
    statuses=None,
    assessed=True,
    request_count=0,
    drop=None,
    dup=None,
):
    st = dict(expected_statuses(policy, registration))
    if statuses:
        st.update(statuses)
    findings = []
    for fid in CONFIG_FINDINGS:
        if drop and fid == drop:
            continue
        findings.append(
            {
                "id": fid,
                "status": st[fid],
                "evidence_state": "assessed",
                "applicability": "applicable",
            }
        )
    if dup:
        findings.append(
            {
                "id": dup,
                "status": st[dup],
                "evidence_state": "assessed",
                "applicability": "applicable",
            }
        )
    return {
        "findings": findings,
        "score": {"assessed": assessed},
        "request_count": request_count,
    }


def good_exits(policy):
    e = expected_exit(policy)
    return {"json": e, "md": e, "sarif": e}


def test_public_positive():
    d = qualify_config(
        product="gitea",
        policy="public",
        registration=True,
        declared={
            k: (False if k == "service.DISABLE_REGISTRATION" else v)
            for k, v in GITEA_DECLARED_PRIVATE_REGOFF.items()
        },
        observed={
            "service.REQUIRE_SIGNIN_VIEW": False,
            "service.DISABLE_REGISTRATION": False,
        },
        review_json=review("public", True),
        exits_by_format=good_exits("public"),
    )
    assert d["expected_exit"] == 0


def test_private_regoff_positive():
    obs = {"service.REQUIRE_SIGNIN_VIEW": True, "service.DISABLE_REGISTRATION": True}
    d = qualify_config(
        product="gitea",
        policy="private",
        registration=False,
        declared=GITEA_DECLARED_PRIVATE_REGOFF,
        observed=obs,
        review_json=review("private", False),
        exits_by_format=good_exits("private"),
    )
    assert d["statuses"]["FG-CONFIG-REGISTRATION"] == "pass"
    assert d["expected_exit"] == 5


def test_reviewer_changed_registration_status_refused():
    obs = {"service.REQUIRE_SIGNIN_VIEW": True, "service.DISABLE_REGISTRATION": True}
    with pytest.raises(ConfigQualifyError):
        qualify_config(
            product="gitea",
            policy="private",
            registration=False,
            declared=GITEA_DECLARED_PRIVATE_REGOFF,
            observed=obs,
            review_json=review(
                "private", False, statuses={"FG-CONFIG-REGISTRATION": "warn"}
            ),
            exits_by_format=good_exits("private"),
        )


def test_reviewer_assessed_false_refused():
    obs = {"service.REQUIRE_SIGNIN_VIEW": True, "service.DISABLE_REGISTRATION": True}
    with pytest.raises(ConfigQualifyError):
        qualify_config(
            product="gitea",
            policy="private",
            registration=False,
            declared=GITEA_DECLARED_PRIVATE_REGOFF,
            observed=obs,
            review_json=review("private", False, assessed=False),
            exits_by_format=good_exits("private"),
        )


def test_reviewer_wrong_exit_any_format_refused():
    obs = {"service.REQUIRE_SIGNIN_VIEW": True, "service.DISABLE_REGISTRATION": True}
    exits = good_exits("private")
    exits["sarif"] = 0
    with pytest.raises(ConfigQualifyError):
        qualify_config(
            product="gitea",
            policy="private",
            registration=False,
            declared=GITEA_DECLARED_PRIVATE_REGOFF,
            observed=obs,
            review_json=review("private", False),
            exits_by_format=exits,
        )


def test_reviewer_missing_nondefault_signin_refused():
    # REQUIRE_SIGNIN_VIEW=True is non-default for private; if not observed it must fail
    obs = {
        "service.DISABLE_REGISTRATION": True,
        "service.REQUIRE_SIGNIN_VIEW": "missing",
    }
    with pytest.raises(ConfigQualifyError):
        qualify_config(
            product="gitea",
            policy="private",
            registration=False,
            declared=GITEA_DECLARED_PRIVATE_REGOFF,
            observed=obs,
            review_json=review("private", False),
            exits_by_format=good_exits("private"),
        )


def test_request_count_nonzero_refused():
    obs = {"service.REQUIRE_SIGNIN_VIEW": True, "service.DISABLE_REGISTRATION": True}
    with pytest.raises(ConfigQualifyError):
        qualify_config(
            product="gitea",
            policy="private",
            registration=False,
            declared=GITEA_DECLARED_PRIVATE_REGOFF,
            observed=obs,
            review_json=review("private", False, request_count=3),
            exits_by_format=good_exits("private"),
        )


def test_missing_finding_refused():
    obs = {"service.REQUIRE_SIGNIN_VIEW": True, "service.DISABLE_REGISTRATION": True}
    with pytest.raises(ConfigQualifyError):
        qualify_config(
            product="gitea",
            policy="private",
            registration=False,
            declared=GITEA_DECLARED_PRIVATE_REGOFF,
            observed=obs,
            review_json=review("private", False, drop="FG-CONFIG-MFA"),
            exits_by_format=good_exits("private"),
        )


def test_duplicate_finding_refused():
    obs = {"service.REQUIRE_SIGNIN_VIEW": True, "service.DISABLE_REGISTRATION": True}
    with pytest.raises(ConfigQualifyError):
        qualify_config(
            product="gitea",
            policy="private",
            registration=False,
            declared=GITEA_DECLARED_PRIVATE_REGOFF,
            observed=obs,
            review_json=review("private", False, dup="FG-CONFIG-SIGNIN"),
            exits_by_format=good_exits("private"),
        )
