import asyncio
import json
import socket
from datetime import UTC, datetime, timedelta
from importlib.resources import files
from pathlib import Path

import httpx
import jsonschema
import pytest
from typer.testing import CliRunner

from forgeguard.advisories.evaluator import catalog, evaluate
from forgeguard.advisories.models import Advisory
from forgeguard.assessment import Assessment
from forgeguard.cli import app
from forgeguard.client import ForgeClient
from forgeguard.config_review import Snapshot, review
from forgeguard.engine import assess, identify
from forgeguard.exporters.sarif import to_sarif
from forgeguard.models import EvidenceState, Status
from forgeguard.output import prepare_outputs, write_atomic
from forgeguard.providers.base import release_version
from forgeguard.providers.registry import PROVIDERS

NOW = datetime(2026, 9, 10, 18, tzinfo=UTC)
PRODUCTS = [("gitea", "1.27.3"), ("forgejo", "16.0.4"), ("forgejo", "15.0.8")]


def run(coro):
    return asyncio.run(coro)


def validate(result):
    data = result.model_dump(mode="json")
    for filename, obj in [
        ("assessment-v1.json", data),
        ("sarif-2.1.0.json", to_sarif(result)),
    ]:
        schema = json.loads(
            files("forgeguard").joinpath("schemas", filename).read_text()
        )
        jsonschema.validators.validator_for(schema)(schema).validate(obj)
    assert Assessment.model_validate(data) == result


async def with_transport(
    product, version, statuses=None, profile="standard", policy="public"
):
    statuses = statuses or {}
    client = ForgeClient("https://synthetic.invalid/team")

    def handler(request):
        path = request.url.raw_path.decode().removeprefix("/team")
        code = statuses.get(path, 200 if path == "/api/v1/version" else 403)
        if code is None:
            raise httpx.ReadTimeout("synthetic")
        if path == "/api/v1/version":
            return httpx.Response(code, json={"version": version})
        return httpx.Response(
            code,
            text="SYNTHETIC_PRIVATE_NAME_DO_NOT_RETAIN",
            headers={"content-type": "text/html", "set-cookie": "secret=synthetic"},
        )

    await client._anon.aclose()
    await client._auth.aclose()
    client._anon = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client._auth = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    try:
        return await assess(client, product=product, profile=profile, policy=policy)
    finally:
        await client.aclose()


@pytest.mark.parametrize("product,version", PRODUCTS)
@pytest.mark.parametrize(
    "status", [None, 301, 302, 303, 307, 308, 404, 429, 500, 502, 503, 418]
)
def test_provider_error_matrix_never_passes(product, version, status):
    result = run(with_transport(product, version, {"/v2/": status}))
    assert not result.score.assessed
    assert result.score.value is None
    f = next(x for x in result.findings if x.id == "FG-REG")
    assert f.evidence_state == EvidenceState.INDETERMINATE
    assert f.status != Status.PASS
    validate(result)


@pytest.mark.parametrize("product,version", PRODUCTS)
@pytest.mark.parametrize("policy", ["public", "private", "unspecified"])
def test_public_policy_and_partial_warning_preserve_completeness(
    product, version, policy
):
    statuses = {
        "/explore/repos": 200,
        "/v2/": 200,
        "/api/v1/repos/search?limit=1": 200,
        "/api/v1/users/search?limit=1": 503,
    }
    result = run(with_transport(product, version, statuses, policy=policy))
    assert not result.score.assessed
    api = next(x for x in result.findings if x.id == "FG-ANON")
    assert api.evidence_state == EvidenceState.INDETERMINATE
    assert api.status == (Status.WARN if policy == "private" else Status.INFO)
    assert "SYNTHETIC_PRIVATE_NAME" not in result.model_dump_json()
    assert "secret=synthetic" not in result.model_dump_json()
    validate(result)


@pytest.mark.parametrize("product,version", PRODUCTS)
@pytest.mark.parametrize(
    "profile,count", [("minimal", 1), ("standard", 5), ("extended", 6)]
)
def test_profile_request_count_determinism_and_schema(product, version, profile, count):
    first = run(with_transport(product, version, profile=profile))
    second = run(with_transport(product, version, profile=profile))
    assert first.request_count == count
    assert first.score.assessed
    assert first.normalized() == second.normalized()
    assert first.identity.product_source == "operator-declared"
    validate(first)


@pytest.mark.parametrize("product,marker", [("gitea", "forgejo"), ("forgejo", "gitea")])
def test_conflicting_product_blocks_every_advisory(product, marker):
    identity = identify(product, None, "1.27.3+" + marker)
    assert identity.product_conflict
    for r in catalog(product)[0]:
        assert evaluate(r, identity).evidence_state == EvidenceState.INDETERMINATE


def test_conflicting_inventory_is_retained_and_not_silently_resolved():
    i = identify("gitea", "1.26.1", "1.27.3")
    assert i.declared_version == "1.26.1"
    assert i.observed_version == "1.27.3"
    assert i.version_conflict
    assert all(evaluate(r, i).status == Status.INFO for r in catalog("gitea")[0])


@pytest.mark.parametrize(
    "version",
    ["", "v1.27.3", "1.27.3-rc1", "1.27.3-vendor", "01.27.3", "1.27.3+foo..bar"],
)
def test_ambiguous_versions_stay_unknown(version):
    assert release_version(version) is None


@pytest.mark.parametrize(
    "version,expected",
    [
        ("1.26.1", "affected"),
        ("1.26.2", "fixed"),
        ("1.27.3", "fixed"),
        ("1.27.4", "undetermined"),
        ("2.0.0", "undetermined"),
    ],
)
def test_gitea_catalog_boundaries(version, expected):
    f = evaluate(catalog("gitea")[0][0], identify("gitea", version, None))
    assert f.observed["outcome"] == expected


@pytest.mark.parametrize(
    "version,expected",
    [
        ("15.0.7", "undetermined"),
        ("15.0.8", "fixed"),
        ("15.0.9", "undetermined"),
        ("16.0.3", "undetermined"),
        ("16.0.4", "fixed"),
        ("17.0.0", "undetermined"),
    ],
)
def test_forgejo_disjoint_exact_fix_evidence(version, expected):
    f = evaluate(catalog("forgejo")[0][0], identify("forgejo", version, None))
    assert f.observed["outcome"] == expected


def snapshot(product="gitea"):
    return Snapshot.model_validate_json(
        Path("examples", product + "-snapshot.json").read_bytes()
    )


@pytest.mark.parametrize("product", ["gitea", "forgejo"])
def test_offline_config_schema_and_zero_network(monkeypatch, product):
    def denied(*a, **kw):
        raise AssertionError("Offline review attempted network")

    monkeypatch.setattr(socket, "getaddrinfo", denied)
    monkeypatch.setattr(httpx.AsyncClient, "send", denied)
    s = snapshot(product)
    schema = json.loads(
        files("forgeguard").joinpath("schemas", "config-snapshot-v1.json").read_text()
    )
    jsonschema.Draft202012Validator(schema).validate(s.model_dump())
    result = review(s, now=NOW, policy="public")
    assert result.request_count == 0
    assert result.score.assessed
    assert all(f.status == Status.INFO for f in result.findings)
    assert result.target.authorized is False
    validate(result)


@pytest.mark.parametrize("product", ["gitea", "forgejo"])
def test_missing_stale_future_unsupported_and_cross_product_config(product):
    original = snapshot(product)
    for s in [
        original.model_copy(update={"settings": {}}),
        original.model_copy(
            update={"snapshot_at": (NOW - timedelta(days=31)).isoformat()}
        ),
        original.model_copy(
            update={"snapshot_at": (NOW + timedelta(days=1)).isoformat()}
        ),
        original.model_copy(update={"version": "99.0.0"}),
    ]:
        result = review(s, now=NOW, policy="private")
        assert not result.score.assessed
        assert all(f.status != Status.PASS for f in result.findings)
    assert not review(
        original, now=NOW, product="forgejo" if product == "gitea" else "gitea"
    ).score.assessed


@pytest.mark.parametrize("product", ["gitea", "forgejo"])
@pytest.mark.parametrize(
    "change", ["secret", "wrong-type", "foreign-mfa", "default-conflict"]
)
def test_closed_snapshot_refuses_unsupported_input(product, change):
    data = snapshot(product).model_dump()
    if change == "secret":
        data["settings"]["mailer.PASSWD"] = "SECRET_SENTINEL"
    elif change == "wrong-type":
        data["settings"]["service.DISABLE_REGISTRATION"] = 1
    elif change == "foreign-mfa":
        foreign = PROVIDERS["forgejo" if product == "gitea" else "gitea"].settings[-1]
        data["settings"][foreign.key] = foreign.default
    else:
        data["declared_defaults"] = ["service.DISABLE_REGISTRATION"]
    with pytest.raises(ValueError):
        Snapshot.model_validate(data)


@pytest.mark.parametrize("product", ["gitea", "forgejo"])
def test_defaults_explicit_and_conflicting_confirmation(product):
    s = snapshot(product)
    keys = list(s.settings)
    declared = s.model_copy(update={"settings": {}, "declared_defaults": keys})
    assert review(declared, now=NOW).score.assessed
    values = dict(s.settings)
    values["service.REGISTER_EMAIL_CONFIRM"] = True
    values["service.REGISTER_MANUAL_CONFIRM"] = True
    result = review(s.model_copy(update={"settings": values}), now=NOW)
    assert "FG-CONFIG-REGISTRATION" in result.score.incomplete_checks


def test_transport_token_and_cookie_separation_and_budget():
    calls = []

    async def exercise():
        client = ForgeClient(
            "https://synthetic.invalid", token="synthetic-token", request_budget=2
        )

        def handler(request):
            calls.append((request.method, request.url.path, dict(request.headers)))
            return httpx.Response(
                200,
                json={"version": "1.27.3"},
                headers={"set-cookie": "session=should-not-persist"},
            )

        await client._auth.aclose()
        await client._anon.aclose()
        client._auth = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        client._anon = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        try:
            await client.get("/api/v1/version", auth=True)
            await client.get("/v2/")
            assert await client.get("/") is None
            with pytest.raises(ValueError):
                await client.get("/v2/", auth=True)
        finally:
            await client.aclose()

    run(exercise())
    assert len(calls) == 2
    assert calls[0][2]["authorization"] == "token synthetic-token"
    assert "authorization" not in calls[1][2]
    assert all("cookie" not in c[2] and c[0] == "GET" for c in calls)


def test_http_never_sends_token_and_no_redirects():
    async def exercise():
        client = ForgeClient("http://127.0.0.1", token="synthetic-token")
        assert not client.has_token
        calls = []

        def handler(request):
            calls.append(request)
            assert "authorization" not in request.headers
            return httpx.Response(
                302, headers={"location": "https://elsewhere.invalid/"}
            )

        await client._anon.aclose()
        client._anon = httpx.AsyncClient(
            transport=httpx.MockTransport(handler), follow_redirects=False
        )
        try:
            response = await client.get("/api/v1/version", auth=True)
            assert response.status_code == 302
            assert len(calls) == 1
        finally:
            await client.aclose()

    run(exercise())


@pytest.mark.parametrize(
    "kwargs",
    [
        {"verify": False},
        {"timeout": 11},
        {"total_timeout": 61},
        {"request_budget": 13},
        {"body_limit": 262145},
    ],
)
def test_transport_bounds_refused(kwargs):
    with pytest.raises(ValueError):
        ForgeClient("https://synthetic.invalid", **kwargs)


@pytest.mark.parametrize("compressed", [False, True])
def test_body_limit_after_decompression(compressed):
    import gzip

    async def exercise():
        client = ForgeClient("https://synthetic.invalid")
        content = b"x" * 262145
        headers = {}
        if compressed:
            content = gzip.compress(content)
            headers["content-encoding"] = "gzip"
        await client._anon.aclose()
        client._anon = httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(200, content=content, headers=headers)
            )
        )
        try:
            assert await client.get("/") is None
            assert client.observations["/"]["error"] == "body_limit"
        finally:
            await client.aclose()

    run(exercise())


def test_total_deadline_and_timeout_fail_closed():
    async def exercise():
        client = ForgeClient("https://synthetic.invalid", timeout=0.01)

        async def handler(request):
            await asyncio.sleep(0.02)
            return httpx.Response(200)

        await client._anon.aclose()
        client._anon = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        try:
            assert await client.get("/") is None
            client._deadline = 0
            assert await client.get("/") is None
            assert client.request_count == 1
        finally:
            await client.aclose()

    run(exercise())


@pytest.mark.parametrize("product", ["gitea", "forgejo"])
def test_dry_run_zero_network_and_format_validation(monkeypatch, product):
    def denied(*a, **kw):
        raise AssertionError("Network attempted")

    monkeypatch.setattr(socket, "getaddrinfo", denied)
    monkeypatch.setattr(ForgeClient, "__init__", denied)
    args = [
        "scan",
        "--url",
        "https://synthetic.invalid",
        "--authorized",
        "--product",
        product,
    ]
    result = CliRunner().invoke(app, [*args, "--dry-run", "--profile", "extended"])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["request_budget"] == 6
    for fmt in ["bad", "", "json,json", "md,json"]:
        assert CliRunner().invoke(app, [*args, "--format", fmt]).exit_code == 2


def test_output_no_clobber_input_symlink_and_atomic_write(tmp_path):
    p = tmp_path / "input.json"
    p.write_text("original")
    with pytest.raises(ValueError):
        prepare_outputs("json", p, p)
    symlink = tmp_path / "symlink.json"
    symlink.symlink_to(p)
    with pytest.raises(ValueError):
        prepare_outputs("json", symlink)
    with pytest.raises(FileExistsError):
        write_atomic(p, "replacement")
    assert p.read_text() == "original"
    q = tmp_path / "new.json"
    write_atomic(q, "{}")
    assert q.read_text() == "{}"
    assert not list(tmp_path.glob(".forgeguard-*"))


def test_sarif_incomplete_without_fake_vulnerabilities():
    result = run(with_transport("gitea", "1.27.3", {"/v2/": 503}))
    sarif = to_sarif(result)
    assert sarif["runs"][0]["results"] == []
    assert sarif["runs"][0]["properties"]["assessmentComplete"] is False
    validate(result)


def test_catalog_rejects_overlapping_ranges():
    data = catalog("gitea")[0][0].model_dump()
    data["fixed"] = data["affected"]
    with pytest.raises(ValueError):
        Advisory.model_validate(data)


@pytest.mark.parametrize("profile", ["minimal", "standard"])
@pytest.mark.parametrize(
    "mode", ["timeout", "invalid_json", "invalid_version", "truncated"]
)
def test_inventory_never_hides_failed_version_read(profile, mode):
    async def exercise():
        client = ForgeClient("https://synthetic.invalid")

        def handler(request):
            if request.url.path == "/api/v1/version":
                if mode == "timeout":
                    raise httpx.ReadTimeout("synthetic")
                if mode == "invalid_version":
                    return httpx.Response(200, json={"version": 123})
                return httpx.Response(
                    200, content=b"{" if mode == "invalid_json" else b"x" * 262145
                )
            return httpx.Response(403)

        await client._anon.aclose()
        client._anon = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        try:
            result = await assess(
                client, product="gitea", known_version="1.27.3", profile=profile
            )
            assert not result.score.assessed
            assert "FG-VER" in result.score.incomplete_checks
        finally:
            await client.aclose()

    run(exercise())


@pytest.mark.parametrize(
    "product,version", [("gitea", "1.27.3+forgejo"), ("forgejo", "16.0.4+gitea")]
)
def test_inventory_product_marker_and_config_conflict(product, version):
    identity = identify(product, version, None)
    assert identity.product_conflict
    assert all(evaluate(r, identity).status == Status.INFO for r in catalog(product)[0])
    result = review(snapshot(product).model_copy(update={"version": version}), now=NOW)
    assert not result.score.assessed
    assert all(f.status != Status.PASS for f in result.findings)


def test_vendor_metadata_never_implies_upstream_fixed():
    i = identify("gitea", "1.27.3+vendor.backport", None)
    assert i.normalized_version is None
    assert all(evaluate(r, i).status == Status.INFO for r in catalog("gitea")[0])


def test_cli_config_formats_and_exit_contract(tmp_path):
    s = snapshot()
    s = s.model_copy(update={"snapshot_at": datetime.now(UTC).isoformat()})
    path = tmp_path / "snapshot.json"
    path.write_text(s.model_dump_json())
    for fmt in ["json", "md", "sarif"]:
        result = CliRunner().invoke(
            app, ["config", "review", "--snapshot", str(path), "--format", fmt]
        )
        assert result.exit_code == 0
        if fmt != "md":
            json.loads(result.stdout)
        else:
            assert "supplied snapshot" in result.stdout
    violation = CliRunner().invoke(
        app,
        [
            "config",
            "review",
            "--snapshot",
            str(path),
            "--policy",
            "private",
            "--format",
            "json",
        ],
    )
    assert violation.exit_code == 5
    assert json.loads(violation.stdout)["score"]["assessed"]
    unknown = CliRunner().invoke(
        app, ["config", "review", "--snapshot", str(path), "--product", "forgejo"]
    )
    assert unknown.exit_code == 4
    path.write_text('{"secret": "DO_NOT_ECHO_SENTINEL"}')
    refused = CliRunner().invoke(app, ["config", "review", "--snapshot", str(path)])
    assert refused.exit_code == 2
    assert "DO_NOT_ECHO_SENTINEL" not in refused.output
    for args in [["providers"], ["checks"], ["config", "--help"]]:
        assert CliRunner().invoke(app, args).exit_code == 0


def test_cli_live_transport_is_locally_mocked(monkeypatch):
    def factory(*args, **kwargs):
        client = ForgeClient(*args, **kwargs)

        async def replace():
            await client._anon.aclose()
            await client._auth.aclose()

        run(replace())
        transport = httpx.MockTransport(
            lambda request: (
                httpx.Response(200, json={"version": "1.27.3"})
                if request.url.path.endswith("/version")
                else httpx.Response(403)
            )
        )
        client._anon = httpx.AsyncClient(transport=transport)
        client._auth = httpx.AsyncClient(transport=transport)
        return client

    from forgeguard import cli

    monkeypatch.setattr(cli, "ForgeClient", factory)
    # Construct the mock clients outside the CLI's running loop.
    client = factory("https://synthetic.invalid")
    monkeypatch.setattr(cli, "ForgeClient", lambda *a, **kw: client)
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--url",
            "https://synthetic.invalid",
            "--authorized",
            "--product",
            "gitea",
            "--profile",
            "extended",
            "--policy",
            "private",
            "--format",
            "sarif",
        ],
    )
    assert result.exit_code == 0
    assert json.loads(result.stdout)["version"] == "2.1.0"


@pytest.mark.parametrize(
    "name", ["complete", "confirmed", "mixed", "unsupported", "public", "offline"]
)
def test_golden_contracts(name):
    result = Assessment.model_validate_json(
        Path("examples", "golden-" + name + ".json").read_text()
    )
    validate(result)
    assert to_sarif(result) == json.loads(
        Path("examples", "golden-" + name + ".sarif").read_text()
    )
    from forgeguard.exporters.markdown import render_markdown

    assert (
        render_markdown(result)
        == Path("examples", "golden-" + name + ".md").read_text()
    )
    if name in ("mixed", "unsupported"):
        assert not result.score.assessed
    if name == "public":
        assert all(f.status not in (Status.WARN, Status.FAIL) for f in result.findings)


def test_official_sarif_schema_hash_and_notice():
    import hashlib

    schema = files("forgeguard").joinpath("schemas", "sarif-2.1.0.json")
    assert (
        hashlib.sha256(schema.read_bytes()).hexdigest()
        == "c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e"
    )
    assert (
        "All Rights Reserved"
        in files("forgeguard").joinpath("schemas", "OASIS_NOTICE.md").read_text()
    )


@pytest.mark.parametrize("version", ["15.0.8", "16.0.4"])
def test_forgejo_native_compatibility_version(version):
    identity = identify("forgejo", version, version + "+gitea-1.22.0")
    assert identity.normalized_version == version
    assert not identity.product_conflict
    assert not identity.version_conflict
    assert identity.observed_product_marker == "forgejo-compatibility"
    assert all(
        evaluate(r, identity).status == Status.PASS for r in catalog("forgejo")[0]
    )
    conflicting = identify("gitea", None, version + "+gitea-1.22.0")
    assert conflicting.product_conflict
    unknown = identify(None, None, version + "+gitea-1.22.0")
    assert unknown.product_source == "unconfirmed"
    assert unknown.normalized_version is None
