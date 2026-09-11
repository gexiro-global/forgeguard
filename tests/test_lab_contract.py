"""R02: unit tests for the integration lab's qualification contract.

These exercise the pure helper with controlled subprocess-shaped inputs. They
never launch Docker or touch production. A correct report paired with a wrong
exit code must fail, invalid/missing JSON must fail, and an empty or partial
matrix must fail.
"""

import pytest

from tools.lab_contract import (
    QualifyError,
    evaluate_matrix,
    expected_exit,
    expected_native_statuses,
    expected_variants,
    qualify,
)


def native(private):
    return {
        "FG-ANON": {
            p: {"status": v} for p, v in expected_native_statuses(private).items()
        }
    }


def report(version, private, findings=None, request_count=6, normalized=None):
    return {
        "identity": {
            "normalized_version": version if normalized is None else normalized
        },
        "request_count": request_count,
        "score": {"assessed": not private},
        "findings": [] if findings is None else findings,
    }


CONFIRMED = [{"id": "FG-CVE-78433", "status": "fail"}]


def test_public_clean_qualifies():
    d = qualify(
        product="gitea",
        version="1.27.3",
        private=False,
        registration=False,
        report=report("1.27.3", False),
        exit_code=0,
        native_statuses=native(False),
    )
    assert d["expected_exit"] == 0 and d["actual_exit"] == 0


def test_private_incomplete_qualifies():
    d = qualify(
        product="gitea",
        version="1.27.3",
        private=True,
        registration=True,
        report=report("1.27.3", True),
        exit_code=4,
        native_statuses=native(True),
    )
    assert d["expected_exit"] == 4


def test_confirmed_public_qualifies():
    d = qualify(
        product="gitea",
        version="1.26.4",
        private=False,
        registration=False,
        report=report("1.26.4", False, CONFIRMED),
        exit_code=5,
        native_statuses=native(False),
    )
    assert d["expected_exit"] == 5


def test_correct_report_but_wrong_exit_fails():
    with pytest.raises(QualifyError):
        qualify(
            product="gitea",
            version="1.27.3",
            private=False,
            registration=False,
            report=report("1.27.3", False),
            exit_code=5,
            native_statuses=native(False),
        )


def test_incomplete_with_zero_exit_fails():
    with pytest.raises(QualifyError):
        qualify(
            product="gitea",
            version="1.27.3",
            private=True,
            registration=False,
            report=report("1.27.3", True),
            exit_code=0,
            native_statuses=native(True),
        )


def test_missing_json_fails():
    with pytest.raises(QualifyError):
        qualify(
            product="gitea",
            version="1.27.3",
            private=False,
            registration=False,
            report=None,
            exit_code=0,
            native_statuses=native(False),
        )


def test_wrong_request_count_fails():
    with pytest.raises(QualifyError):
        qualify(
            product="gitea",
            version="1.27.3",
            private=False,
            registration=False,
            report=report("1.27.3", False, request_count=5),
            exit_code=0,
            native_statuses=native(False),
        )


def test_version_mismatch_fails():
    with pytest.raises(QualifyError):
        qualify(
            product="gitea",
            version="1.27.3",
            private=False,
            registration=False,
            report=report("1.27.3", False, normalized="1.27.2"),
            exit_code=0,
            native_statuses=native(False),
        )


def test_forgejo_with_cve_finding_fails():
    with pytest.raises(QualifyError):
        qualify(
            product="forgejo",
            version="16.0.4",
            private=False,
            registration=False,
            report=report("16.0.4", False, [{"id": "FG-CVE-78433", "status": "fail"}]),
            exit_code=5,
            native_statuses=native(False),
        )


def test_missing_confirmed_finding_fails():
    with pytest.raises(QualifyError):
        qualify(
            product="gitea",
            version="1.26.4",
            private=False,
            registration=False,
            report=report("1.26.4", False, [{"id": "FG-OTHER", "status": "warn"}]),
            exit_code=5,
            native_statuses=native(False),
        )


def test_r02a_unexpected_warn_in_public_with_exit0_fails():
    # A WARN finding paired with exit 0 (inconsistent CLI) must be rejected
    # independently of the exit code.
    with pytest.raises(QualifyError):
        qualify(
            product="gitea",
            version="1.27.3",
            private=False,
            registration=False,
            report=report("1.27.3", False, [{"id": "FG-SOMETHING", "status": "warn"}]),
            exit_code=0,
            native_statuses=native(False),
        )


def test_r02a_public_1264_rejects_extra_warn_beyond_known_advisory():
    with pytest.raises(QualifyError):
        qualify(
            product="gitea",
            version="1.26.4",
            private=False,
            registration=False,
            report=report(
                "1.26.4",
                False,
                [*CONFIRMED, {"id": "FG-EXTRA", "status": "warn"}],
            ),
            exit_code=5,
            native_statuses=native(False),
        )


def test_r02b_private_1264_requires_known_advisory():
    # Private 1.26.4 stays incomplete (exit 4) but must still carry the finding.
    with pytest.raises(QualifyError):
        qualify(
            product="gitea",
            version="1.26.4",
            private=True,
            registration=False,
            report=report("1.26.4", True, []),
            exit_code=4,
            native_statuses=native(True),
        )


def test_r02b_private_1264_with_advisory_and_exit4_qualifies():
    d = qualify(
        product="gitea",
        version="1.26.4",
        private=True,
        registration=False,
        report=report("1.26.4", True, CONFIRMED),
        exit_code=4,
        native_statuses=native(True),
    )
    assert d["expected_exit"] == 4


def test_native_status_mismatch_fails():
    bad = {
        "FG-ANON": {"/explore/repos": {"status": 200}}
    }  # incomplete/private-mismatched
    with pytest.raises(QualifyError):
        qualify(
            product="gitea",
            version="1.27.3",
            private=True,
            registration=False,
            report=report("1.27.3", True),
            exit_code=4,
            native_statuses=bad,
        )


def test_exit_precedence_incomplete_over_finding():
    # Private 1.26.4 is incomplete (4), not a confirmed-finding exit (5).
    assert expected_exit(True, "1.26.4") == 4
    assert expected_exit(False, "1.26.4") == 5


def full_pass_matrix():
    return [{"variant": v, "status": "PASS"} for v in expected_variants()]


def test_matrix_full_pass_has_no_problems():
    assert evaluate_matrix(full_pass_matrix(), []) == []
    assert len(full_pass_matrix()) == 16


def test_matrix_missing_variant_fails():
    m = full_pass_matrix()[:-1]
    assert evaluate_matrix(m, [])


def test_matrix_empty_fails():
    assert evaluate_matrix([], [])


def test_matrix_duplicate_variant_fails():
    m = full_pass_matrix()
    m[1] = dict(m[0])
    assert evaluate_matrix(m, [])


def test_matrix_non_pass_fails():
    m = full_pass_matrix()
    m[0]["status"] = "FAIL"
    assert evaluate_matrix(m, [])


def test_matrix_cleanup_failure_fails():
    assert evaluate_matrix(full_pass_matrix(), [{"resource": "x"}])
