import itertools
import json
import socket
from datetime import datetime
from pathlib import Path

import pytest

from tools.golden_cases import CLOCK, cases, execute
from versionsec.assessment import Assessment
from versionsec.engine import finding
from versionsec.exporters.json import render_json
from versionsec.exporters.markdown import render_markdown
from versionsec.exporters.sarif import to_sarif
from versionsec.models import EvidenceState, Severity, Status
from versionsec.policy import assess_score

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def offline_only(monkeypatch):
    def deny(*args, **kwargs):
        raise AssertionError("Unexpected network")

    monkeypatch.setattr(socket, "getaddrinfo", deny)
    monkeypatch.setattr(socket.socket, "connect", deny)

    class FrozenDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return CLOCK

    monkeypatch.setattr("forgeguard.engine.datetime", FrozenDatetime)


@pytest.mark.parametrize("name", list(cases()))
def test_real_engine_matches_frozen_full_golden(name, offline_only):
    result = execute(name)
    expected = Assessment.model_validate_json(
        (ROOT / "examples" / ("golden-" + name + ".json")).read_bytes()
    )
    assert result.scan_id and isinstance(result.scan_id, str)
    timestamp = result.run.get("timestamp", result.run.get("reviewed_at"))
    assert datetime.fromisoformat(timestamp) == CLOCK
    assert result.normalized() == expected.normalized()
    assert json.loads(render_json(result)) == expected.model_dump(mode="json")
    assert (
        render_markdown(result)
        == (ROOT / "examples" / ("golden-" + name + ".md")).read_text()
    )
    assert to_sarif(result) == json.loads(
        (ROOT / "examples" / ("golden-" + name + ".sarif")).read_text()
    )
    from test_multiforge import validate

    validate(result)


def test_golden_detects_material_changes(offline_only):
    result = execute("complete")
    expected = result.normalized()
    for field, value in [
        ("request_count", 999),
        ("policy", "public"),
        ("identity", result.identity.model_copy(update={"product_conflict": True})),
    ]:
        assert result.model_copy(update={field: value}).normalized() != expected


def test_normalized_preserves_snapshot_provenance(offline_only):
    result = execute("offline")
    changed = result.model_copy(
        update={
            "run": {
                **result.run,
                "provenance": "different supplied origin",
                "snapshot_at": "2026-09-09T18:00:00+00:00",
            }
        }
    )
    assert changed.normalized() != result.normalized()
    later = result.model_copy(
        update={"run": {**result.run, "reviewed_at": "2026-09-11T18:00:00+00:00"}}
    )
    assert later.normalized() == result.normalized()


def item(id_, status, severity, group):
    value = finding(id_, id_, {}, "", status=Status(status), group=group)
    return value.model_copy(update={"severity": Severity(severity)})


SCORES = [
    ([("fail", "high", "one"), ("fail", "medium", "one")], 80),
    ([("fail", "high", "one"), ("fail", "medium", "two")], 70),
    ([("warn", "medium", "one"), ("warn", "medium", "one")], 97),
    ([("warn", "medium", "one"), ("warn", "medium", "two")], 94),
    ([("fail", "medium", "one"), ("warn", "high", "one")], 90),
    ([("pass", "high", "one"), ("info", "critical", "two")], 100),
    (
        [
            ("fail", "critical", "one"),
            ("fail", "critical", "two"),
            ("fail", "critical", "three"),
        ],
        0,
    ),
]


@pytest.mark.parametrize("spec,expected", SCORES)
def test_assess_score_numeric_oracle_and_permutations(spec, expected):
    findings = [item("FG-TEST-" + str(i), *row) for i, row in enumerate(spec)]
    for order in itertools.permutations(findings):
        score = assess_score(list(order))
        assert score.value == expected
        assert score.assessed and score.incomplete_checks == []
        assert len(order) == len(findings)
        assert (
            assess_score([*order, item("FG-INFO", "info", "info", "other")]).value
            == expected
        )


@pytest.mark.parametrize("group", ["version-advisories", "anonymous-access"])
def test_named_penalty_groups_preserve_findings(group):
    findings = [
        item("FG-ONE", "fail", "high", group),
        item("FG-TWO", "fail", "medium", group),
    ]
    assert assess_score(findings).value == 80
    assert [f.id for f in findings] == ["FG-ONE", "FG-TWO"]


@pytest.mark.parametrize("status", ["warn", "fail"])
def test_score_incomplete_dominates_confirmed(status):
    findings = [
        item("FG-KNOWN", status, "high", "one"),
        finding(
            "FG-UNKNOWN",
            "",
            {},
            "",
            state=EvidenceState.INDETERMINATE,
            applicability="undetermined",
        ),
    ]
    for order in itertools.permutations(findings):
        s = assess_score(list(order))
        assert (s.value, s.grade, s.assessed, s.incomplete_checks) == (
            None,
            "N/A",
            False,
            ["FG-UNKNOWN"],
        )
        assert findings[1].applicability == "undetermined"
    s = assess_score([])
    assert (s.value, s.grade, s.assessed, s.incomplete_checks) == (
        None,
        "N/A",
        False,
        ["FG-COVERAGE"],
    )
