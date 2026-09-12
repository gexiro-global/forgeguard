"""Property-based tests for snapshot review and report serialisation.

These run in the normal suite: offline, no network, no Docker, bounded example
counts so CI stays predictable. They assert invariants that must hold for every
valid snapshot, not the specific values of one fixture. The Atheris harnesses in
``fuzz/`` attack the same entry points from the other direction, with raw bytes.
"""

import json
from datetime import UTC, datetime, timedelta

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from versionsec.config_review import Snapshot
from versionsec.config_review import review as config_review
from versionsec.exporters.json import render_json
from versionsec.exporters.markdown import render_markdown
from versionsec.exporters.sarif import to_sarif
from versionsec.models import EvidenceState, Status
from versionsec.providers.registry import get_provider
from versionsec.runner_review import RunnerSnapshot
from versionsec.runner_review import review as runner_review

PROFILE = settings(
    max_examples=150,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)

ALIASES = st.from_regex(r"\A[a-zA-Z0-9_-]{1,64}\Z")
PROVENANCE = st.text(min_size=1, max_size=256).filter(lambda s: s.strip() != "")
PRODUCTS = st.sampled_from(["gitea", "forgejo"])


@st.composite
def moments(draw):
    """Timestamps spanning fresh, stale and future, so neither branch is starved."""
    offset = draw(st.integers(min_value=-40 * 86400, max_value=5 * 86400))
    return (datetime.now(UTC) - timedelta(seconds=offset)).isoformat()


@st.composite
def config_snapshots(draw):
    product = draw(PRODUCTS)
    provider = get_provider(product)
    keys = [s.key for s in provider.settings]
    chosen = draw(st.lists(st.sampled_from(keys), unique=True, max_size=len(keys)))
    split = draw(st.integers(min_value=0, max_value=len(chosen)))
    explicit, defaults = chosen[:split], chosen[split:]
    allowed = {s.key: s.values for s in provider.settings}
    settings_map = {key: draw(st.sampled_from(list(allowed[key]))) for key in explicit}
    return Snapshot(
        schema_id="forgeguard.config-snapshot.v1",
        product=product,
        version=draw(st.sampled_from(["1.26.4", "1.25.0", "9.9.9", "not-a-version"])),
        instance_alias=draw(ALIASES),
        snapshot_at=draw(moments()),
        provenance=draw(PROVENANCE),
        settings=settings_map,
        declared_defaults=defaults,
    )


@st.composite
def runner_snapshots(draw):
    product = draw(PRODUCTS)
    return RunnerSnapshot(
        schema_id="forgeguard.runner-snapshot.v1",
        product=product,
        server_version=draw(st.sampled_from(["1.26.4", "1.25.0", "9.9.9"])),
        runner_product=f"{product}-runner",
        runner_version=draw(
            st.sampled_from(["3.0.0", "13.1.0", "0.1.0", "not-a-version"])
        ),
        instance_alias=draw(ALIASES),
        runner_alias=draw(ALIASES),
        snapshot_at=draw(moments()),
        provenance=draw(PROVENANCE),
        runner_scope=draw(st.sampled_from(["dedicated", "shared"])),
        workload_trust=draw(st.sampled_from(["trusted-only", "mixed-untrusted"])),
        ephemeral=draw(st.sampled_from(["ephemeral", "once", "persistent"])),
        execution_engine=draw(st.sampled_from(["docker", "lxc", "host", "plugin"])),
        privileged=draw(st.booleans()),
        docker_socket=draw(
            st.sampled_from(
                [
                    "not-exposed",
                    "host-daemon-exposed-to-job",
                    "dedicated-dind",
                    "rootless-dind",
                    "unknown",
                ]
            )
        ),
        valid_volumes=draw(
            st.lists(
                st.one_of(
                    st.sampled_from(["**", "/", "..", "/srv/build"]),
                    st.text(min_size=1, max_size=64),
                ),
                max_size=8,
            )
        ),
        network=draw(st.sampled_from(["isolated", "host", "custom"])),
        plugin_usage=draw(
            st.sampled_from(["unused", "declared-experimental", "unknown"])
        ),
    )


@PROFILE
@given(snapshot=config_snapshots(), policy=st.sampled_from(["unspecified", "private"]))
def test_config_review_always_produces_a_serialisable_result(snapshot, policy):
    result = config_review(snapshot, policy=policy)
    rendered = render_json(result)
    assert rendered.isascii()
    assert json.loads(rendered)
    json.dumps(to_sarif(result))
    assert isinstance(render_markdown(result), str)


@PROFILE
@given(snapshot=config_snapshots())
def test_config_review_never_scores_an_unspecified_policy(snapshot):
    """Without a declared policy there is nothing to judge against, so INFO only."""
    result = config_review(snapshot, policy="unspecified")
    assert all(f.status is Status.INFO for f in result.findings)


@PROFILE
@given(snapshot=config_snapshots(), policy=st.sampled_from(["unspecified", "private"]))
def test_indeterminate_findings_are_never_presented_as_assessed(snapshot, policy):
    """A finding may only carry a pass/warn verdict when it was actually assessed."""
    for f in config_review(snapshot, policy=policy).findings:
        if f.evidence_state is not EvidenceState.ASSESSED:
            assert f.status is Status.INFO


@PROFILE
@given(snapshot=config_snapshots(), policy=st.sampled_from(["unspecified", "private"]))
def test_config_review_never_confirms_the_product(snapshot, policy):
    """An operator-supplied snapshot cannot confirm what a server is running."""
    result = config_review(snapshot, policy=policy)
    assert result.target.product_confirmed is False
    assert result.target.scope == "operator-snapshot"
    assert result.target.product_source == "operator-declared"


@PROFILE
@given(snapshot=config_snapshots())
def test_config_review_is_deterministic(snapshot):
    moment = datetime.now(UTC)
    first = config_review(snapshot, policy="private", now=moment)
    second = config_review(snapshot, policy="private", now=moment)
    assert render_json(first) == render_json(second)


@PROFILE
@given(snapshot=runner_snapshots())
def test_runner_review_always_produces_a_serialisable_result(snapshot):
    result = runner_review(snapshot)
    rendered = render_json(result)
    assert rendered.isascii()
    assert json.loads(rendered)
    json.dumps(to_sarif(result))
    assert isinstance(render_markdown(result), str)


@PROFILE
@given(snapshot=runner_snapshots())
def test_runner_review_emits_every_check_exactly_once(snapshot):
    ids = [f.id for f in runner_review(snapshot).findings]
    assert len(ids) == len(set(ids))
    assert all(i.startswith("FG-RUNNER-") for i in ids)


@PROFILE
@given(snapshot=runner_snapshots())
def test_host_execution_never_yields_a_container_verdict(snapshot):
    """With no container there is nothing to judge about privilege, volumes,
    socket exposure or network, so those checks must stay informational."""
    if snapshot.execution_engine != "host":
        return
    container_checks = {
        "FG-RUNNER-PRIVILEGED",
        "FG-RUNNER-VOLUMES",
        "FG-RUNNER-DOCKER",
        "FG-RUNNER-NETWORK",
    }
    for f in runner_review(snapshot).findings:
        if f.id in container_checks:
            assert f.status is Status.INFO


@PROFILE
@given(snapshot=runner_snapshots())
def test_stale_runner_snapshot_is_never_assessed(snapshot):
    """A snapshot older than the freshness window cannot support a verdict."""
    far_future = datetime.now(UTC) + timedelta(days=400)
    for f in runner_review(snapshot, now=far_future).findings:
        assert f.evidence_state is not EvidenceState.ASSESSED
        assert f.status is Status.INFO
