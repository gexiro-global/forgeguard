from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated

import typer

from .checks import run_all_checks
from .client import ForgeClient
from .models import ScanResult, Status
from .report import render_markdown
from .scoring import score_findings
from .urls import InvalidTargetURL

POSITIONING = (
    "Read-only security posture and supply-chain visibility for self-hosted Gitea."
)

app = typer.Typer(
    add_completion=False,
    help=f"ForgeGuard by Gexiro. {POSITIONING} One own/authorized instance only.",
)


def _summarize(findings) -> dict[str, int]:
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "pass": 0}
    for finding in findings:
        if finding.status == Status.PASS:
            summary["pass"] += 1
        else:
            summary[finding.severity.value] = summary.get(finding.severity.value, 0) + 1
    return summary


async def _run(
    url: str, token: str | None, known_version: str | None, scan_id: str
) -> ScanResult:
    client = ForgeClient(url, token=token)
    try:
        findings, target = await run_all_checks(client, known_version=known_version)
    finally:
        await client.aclose()
    target.url = client.base
    target.authorized = True
    return ScanResult(
        scan_id=scan_id,
        target=target,
        score=score_findings(findings),
        findings=findings,
        summary=_summarize(findings),
    )


@app.command()
def scan(
    ctx: typer.Context,
    url: Annotated[
        str, typer.Option("--url", help="Base URL of your authorized Gitea instance")
    ],
    authorized: Annotated[
        bool,
        typer.Option(
            "--authorized/--no-authorized",
            help="Affirm you own or are authorized to assess this target",
        ),
    ] = False,
    token: Annotated[
        str | None,
        typer.Option(
            "--token",
            envvar="FORGEGUARD_TOKEN",
            show_envvar=True,
            help=(
                "Optional version-read token. Prefer FORGEGUARD_TOKEN; command-line values "
                "may be visible in shell history/process listings."
            ),
        ),
    ] = None,
    known_version: Annotated[
        str | None,
        typer.Option(
            "--known-version",
            help="Gitea version from trusted local inventory if the API is auth-walled",
        ),
    ] = None,
    scan_id: Annotated[
        str, typer.Option("--scan-id", help="Identifier to embed in output")
    ] = "fg_local",
    out: Annotated[
        Path | None,
        typer.Option("--out", help="Write the Markdown report to this path"),
    ] = None,
    fmt: Annotated[str, typer.Option("--format", help="Comma list: md,json")] = "md",
) -> None:
    """Run a read-only posture scan against one authorized Gitea instance."""
    if not authorized:
        typer.secho(
            "REFUSED: pass --authorized to affirm you own or are authorized to assess this target. "
            "ForgeGuard is scoped to your own authorized instances.",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(2)
    token_source = ctx.get_parameter_source("token")
    if token and token_source is not None and token_source.name == "COMMANDLINE":
        typer.secho(
            "SECURITY WARNING: prefer FORGEGUARD_TOKEN; --token values may be visible "
            "in shell history or process listings.",
            fg=typer.colors.YELLOW,
            err=True,
        )
    try:
        result = asyncio.run(_run(url, token, known_version, scan_id))
    except InvalidTargetURL as exc:
        typer.secho(f"REFUSED: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from exc
    formats = [item.strip() for item in fmt.split(",")]
    if "json" in formats:
        json_output = result.model_dump_json(indent=2)
        if out:
            Path(str(out)).with_suffix(".json").write_text(json_output)
        else:
            typer.echo(json_output)
    if "md" in formats:
        markdown_output = render_markdown(result)
        if out:
            Path(out).write_text(markdown_output)
            typer.secho(f"report -> {out}", fg=typer.colors.GREEN)
        else:
            typer.echo(markdown_output)


@app.command("checks")
def list_checks() -> None:
    """List the v0.2 read-only check catalog."""
    typer.echo("ForgeGuard by Gexiro - v0.2 checks")
    for check_id, description in [
        ("FG-VER", "Gitea patch currency against the first fixed release"),
        ("FG-CVE-27771", "Gitea CVE-2026-27771 affected/fixed version posture"),
        ("FG-SIGNIN", "Observed access-control responses on checked paths"),
        ("FG-REG", "Anonymous OCI registry-root reachability"),
        ("FG-ANON", "Observed anonymous HTTP 200 responses on checked paths"),
    ]:
        typer.echo(f"{check_id:14} {description}")


def main() -> None:
    app()


if __name__ == "__main__":
    app()
