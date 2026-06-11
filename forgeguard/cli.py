from __future__ import annotations

import asyncio
from pathlib import Path

import typer

from .checks import run_all_checks
from .client import ForgeClient
from .models import ScanResult, Status
from .report import render_markdown
from .scoring import score_findings

POSITIONING = "Read-only security posture and supply-chain visibility for self-hosted Gitea/Forgejo."

app = typer.Typer(
    add_completion=False,
    help=f"ForgeGuard by Gexiro. {POSITIONING} Own/authorized instances only.",
)


def _summarize(findings) -> dict[str, int]:
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "pass": 0}
    for finding in findings:
        if finding.status == Status.PASS:
            summary["pass"] += 1
        else:
            summary[finding.severity.value] = summary.get(finding.severity.value, 0) + 1
    return summary


async def _run(url: str, token: str | None, known_version: str | None, scan_id: str) -> ScanResult:
    client = ForgeClient(url, token=token)
    try:
        findings, target = await run_all_checks(client, known_version=known_version)
    finally:
        await client.aclose()
    target.url = url
    target.authorized = True
    return ScanResult(scan_id=scan_id, target=target, score=score_findings(findings),
                      findings=findings, summary=_summarize(findings))


@app.command()
def scan(
    url: str = typer.Option(..., "--url", help="Base URL of your Gitea/Forgejo instance"),
    authorized: bool = typer.Option(False, "--authorized/--no-authorized",
                                    help="Affirm you own or are authorized to assess this target"),
    token: str | None = typer.Option(None, "--token", help="Optional API token for authenticated version read"),
    known_version: str | None = typer.Option(None, "--known-version",
                                             help="Version from local inventory if the API is auth-walled"),
    scan_id: str = typer.Option("fg_local", "--scan-id", help="Identifier to embed in the output artifact"),
    out: Path | None = typer.Option(None, "--out", help="Write the markdown report to this path"),
    fmt: str = typer.Option("md", "--format", help="Comma list: md,json"),
) -> None:
    """Run a read-only posture scan against one authorized instance."""
    if not authorized:
        typer.secho(
            "REFUSED: pass --authorized to affirm you own or are authorized to assess this target. "
            "ForgeGuard is scoped to your own authorized instances.",
            fg=typer.colors.RED,
        )
        raise typer.Exit(2)
    result = asyncio.run(_run(url, token, known_version, scan_id))
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
        ("FG-VER", "Patch currency vs CVE-2026-27771 fixed release"),
        ("FG-CVE-27771", "Container registry CVE-2026-27771 exposure posture"),
        ("FG-SIGNIN", "REQUIRE_SIGNIN_VIEW enforcement"),
        ("FG-REG", "Registry anonymous reachability"),
        ("FG-ANON", "Anonymously readable surfaces"),
    ]:
        typer.echo(f"{check_id:14} {description}")


def main() -> None:
    app()


if __name__ == "__main__":
    app()
