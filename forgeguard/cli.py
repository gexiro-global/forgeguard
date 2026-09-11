from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError

from .client import ForgeClient
from .config_review import Snapshot, review
from .engine import assess
from .models import Status
from .output import prepare_outputs, render_outputs
from .providers.registry import PROVIDERS
from .urls import normalize_target_url

app = typer.Typer(
    add_completion=False,
    help="ForgeGuard by Gexiro. Bounded posture for one authorized forge.",
)
config_app = typer.Typer(
    help="Offline review of explicitly supplied anonymized snapshots."
)
app.add_typer(config_app, name="config")


async def _run(
    url,
    token,
    known_version,
    product,
    scan_id,
    *,
    profile="standard",
    policy="unspecified",
    ca_bundle=None,
):
    budget = {"minimal": 1, "standard": 5, "extended": 6}[profile]
    client = ForgeClient(
        url,
        token=token,
        request_budget=budget,
        verify=str(ca_bundle) if ca_bundle else True,
    )
    try:
        return await assess(
            client,
            product=product,
            known_version=known_version,
            profile=profile,
            policy=policy,
            scan_id=scan_id,
        )
    finally:
        await client.aclose()


def _refuse(message):
    typer.echo("REFUSED: " + message, err=True)
    raise typer.Exit(2)


def _finish(result, paths):
    try:
        rendered = render_outputs(result, paths)
    except (OSError, ValueError):
        typer.echo("EXECUTION ERROR: could not safely write report output", err=True)
        raise typer.Exit(3)
    if rendered is not None:
        typer.echo(rendered, nl=False)
    if not result.score.assessed:
        raise typer.Exit(4)
    if any(f.status in (Status.FAIL, Status.WARN) for f in result.findings):
        raise typer.Exit(5)


@app.command()
def scan(
    ctx: typer.Context,
    url: Annotated[str, typer.Option("--url", help="One authorized HTTP(S) base URL")],
    authorized: Annotated[bool, typer.Option("--authorized/--no-authorized")] = False,
    product: Annotated[
        str | None,
        typer.Option(
            "--product",
            help="Operator-declared gitea or forgejo; omission is unconfirmed, ungraded",
        ),
    ] = None,
    token: Annotated[
        str | None,
        typer.Option(
            "--token",
            envvar="FORGEGUARD_TOKEN",
            help="Prefer FORGEGUARD_TOKEN; legacy argument may enter shell history",
        ),
    ] = None,
    known_version: Annotated[
        str | None,
        typer.Option(
            "--known-version",
            help="Trusted inventory version; does not identify product",
        ),
    ] = None,
    scan_id: Annotated[str, typer.Option("--scan-id")] = "fg_local",
    out: Annotated[Path | None, typer.Option("--out")] = None,
    fmt: Annotated[
        str, typer.Option("--format", help="Comma list: md,json,sarif")
    ] = "md",
    profile: Annotated[str, typer.Option("--profile")] = "standard",
    policy: Annotated[
        str, typer.Option("--policy", help="public, private or unspecified")
    ] = "unspecified",
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Show plan without DNS or HTTP")
    ] = False,
    ca_bundle: Annotated[
        Path | None, typer.Option("--ca-bundle", help="Explicit trusted CA bundle")
    ] = None,
):
    """Assess one instance with bounded GET-only requests."""
    if not authorized:
        _refuse("pass --authorized to affirm authorization")
    product = product.strip().lower() if product is not None else None
    if product is not None and product not in PROVIDERS:
        _refuse("accepts only '--product gitea' or '--product forgejo'")
    if profile not in ("minimal", "standard", "extended") or policy not in (
        "private",
        "public",
        "unspecified",
    ):
        _refuse("Unknown profile or policy")
    try:
        url = normalize_target_url(url)
        paths = prepare_outputs(fmt, out)
        if ca_bundle and (not ca_bundle.is_file() or ca_bundle.is_symlink()):
            raise ValueError("CA bundle must be a regular file")
        if known_version and len(known_version) > 128:
            raise ValueError("Inventory version is too long")
    except ValueError as exc:
        _refuse(str(exc))
    plan = PROVIDERS[product or "gitea"].request_plan(profile)
    if dry_run:
        typer.echo(
            json.dumps(
                {
                    "product": product or "unknown",
                    "profile": profile,
                    "policy": policy,
                    "paths": list(plan),
                    "method": "GET",
                    "request_budget": len(plan),
                    "request_timeout_seconds": 10,
                    "total_timeout_seconds": 60,
                    "body_limit_bytes": 262144,
                    "authenticated_paths": ["/api/v1/version"]
                    if token and url.startswith("https:")
                    else [],
                },
                sort_keys=True,
            )
        )
        return
    source = ctx.get_parameter_source("token")
    if token and source is not None and source.name == "COMMANDLINE":
        typer.echo(
            "SECURITY WARNING: prefer FORGEGUARD_TOKEN; --token may enter shell history",
            err=True,
        )
    try:
        # Preserve the existing five positional arguments for integrations.
        extra = {}
        if profile != "standard":
            extra["profile"] = profile
        if policy != "unspecified":
            extra["policy"] = policy
        if ca_bundle:
            extra["ca_bundle"] = ca_bundle
        result = asyncio.run(_run(url, token, known_version, product, scan_id, **extra))
    except (OSError, ValueError):
        typer.echo("EXECUTION ERROR: assessment could not be completed", err=True)
        raise typer.Exit(3)
    _finish(result, paths)


@config_app.command("review")
def config_review(
    snapshot: Annotated[Path, typer.Option("--snapshot")],
    policy: Annotated[str, typer.Option("--policy")] = "unspecified",
    product: Annotated[
        str | None, typer.Option("--product", help="Optional expected snapshot product")
    ] = None,
    out: Annotated[Path | None, typer.Option("--out")] = None,
    fmt: Annotated[str, typer.Option("--format")] = "md",
):
    """Zero-network configuration review; no app.ini discovery or runtime claims."""
    if policy not in ("public", "private", "unspecified") or product not in (
        None,
        "gitea",
        "forgejo",
    ):
        _refuse("Unknown policy or product")
    try:
        paths = prepare_outputs(fmt, out, snapshot)
        if snapshot.is_symlink() or not snapshot.is_file():
            raise ValueError("Snapshot must be a regular file")
        with snapshot.open("rb") as stream:
            raw = stream.read(262145)
        if len(raw) > 262144:
            raise ValueError("Snapshot exceeds size limit")
        parsed = Snapshot.model_validate_json(raw)
        result = review(parsed, policy=policy, product=product)
    except (ValueError, ValidationError, OSError):
        # Validation errors can contain rejected secret-bearing input.
        _refuse("Invalid snapshot or output path; check the closed snapshot schema")
    _finish(result, paths)


@app.command("providers")
def list_providers():
    """Show provider capabilities and exact configuration qualification targets."""
    typer.echo(
        json.dumps(
            [
                {
                    "id": p.id,
                    "revision": p.revision,
                    "qualification_targets": list(p.qualified_versions),
                    "config_keys": [s.key for s in p.settings],
                    "api_source": p.api_source,
                    "config_source": p.config_source,
                    "integration_status": "See release candidate evidence; target list is not a test result.",
                }
                for p in PROVIDERS.values()
            ],
            indent=2,
        )
    )


@app.command("checks")
def list_checks():
    """List implemented checks and their evidence scopes."""
    from .advisories.evaluator import catalog

    checks = {
        "FG-VER": "Operator product and version provenance",
        "FG-VER-DISCLOSE": "Observed anonymous version",
        "FG-SIGNIN": "Repository-browser HTTP status only",
        "FG-REG": "OCI root HTTP status only",
        "FG-ANON": "Two allowlisted API statuses only",
        "FG-HTTP": "Bounded transport/header observations",
        "FG-ROOT-HTTP": "Extended root HTTP observation",
    }
    for p in PROVIDERS:
        for r in catalog(p)[0]:
            checks[r.id] = p + ": " + r.title
    for suffix in ("REGISTRATION", "SIGNIN", "PRIVACY", "MFA"):
        checks["FG-CONFIG-" + suffix] = "Offline declared " + suffix.lower()
    for id_, text in sorted(checks.items()):
        typer.echo(f"{id_:28} {text}")


def main():
    app()


if __name__ == "__main__":
    app()
