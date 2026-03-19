import logging
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from argus.config import DEFAULT_OUTPUT_DIR, VERSION
from argus.core.engine import run_scan
from argus.output.csv_writer import write_assets_csv
from argus.output.html_writer import write_html_report
from argus.output.json_writer import write_json_report
from argus.utils.logger import set_log_level

app = typer.Typer(
    help=(
        "Argus — attack surface intelligence engine\n\n"
        "Common usage:\n"
        "  argus scan example.com --tech --output reports\n"
        "  argus scan example.com --verbose\n"
        "  argus scan example.com --debug\n\n"
        "Run 'argus scan --help' to see all scan options."
    ),
    no_args_is_help=True,
)
console = Console()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(
        False,
        "--version",
        "-v",
        help="Show Argus version and exit",
    ),
) -> None:
    """Argus CLI."""
    if version:
        console.print(f"[bold cyan]Argus[/bold cyan] v{VERSION}")
        raise typer.Exit()

    if ctx.invoked_subcommand is None:
        console.print(ctx.get_help())


def severity_label(severity: str) -> str:
    styles = {
        "high": "[bold red]HIGH[/bold red]",
        "medium": "[bold yellow]MEDIUM[/bold yellow]",
        "info": "[bold blue]INFO[/bold blue]",
        "low": "[bold green]LOW[/bold green]",
    }
    return styles.get(severity.lower(), severity.upper())


@app.command()
def scan(
    target: str = typer.Argument(
        ...,
        help="Target domain or URL (for example: example.com or https://example.com)",
    ),
    passive: bool = typer.Option(
        True,
        "--passive/--no-passive",
        help="Enable passive discovery",
    ),
    tech: bool = typer.Option(
        True,
        "--tech/--no-tech",
        help="Enable technology fingerprinting",
    ),
    output: Path = typer.Option(
        Path(DEFAULT_OUTPUT_DIR),
        "--output",
        "-o",
        help="Directory to save reports",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        help="Show informational logs",
    ),
    debug: bool = typer.Option(
        False,
        "--debug",
        help="Show debug logs",
    ),
) -> None:
    """Run an Argus scan against a target."""
    if debug:
        set_log_level(logging.DEBUG)
    elif verbose:
        set_log_level(logging.INFO)
    else:
        set_log_level(logging.WARNING)

    console.print(f"[bold cyan]Argus[/bold cyan] scanning [bold]{target}[/bold]")

    try:
        result = run_scan(target=target, enable_tech=tech)
    except ValueError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(code=1)
    except Exception as exc:
        console.print(f"[bold red]Unexpected error:[/bold red] {exc}")
        raise typer.Exit(code=1)

    json_path = write_json_report(result, output)
    csv_path = write_assets_csv(result, output)
    html_path = write_html_report(result, output)

    assets_table = Table(title="Discovered Assets")
    assets_table.add_column("Host", style="cyan", no_wrap=True)
    assets_table.add_column("IPs")
    assets_table.add_column("Status", justify="center")
    assets_table.add_column("Title")
    assets_table.add_column("Technologies")
    assets_table.add_column("Services")
    assets_table.add_column("Signals")

    for asset in result.assets:
        title = asset.web.title if asset.web and asset.web.title else "-"
        techs = ", ".join(asset.web.technologies) if asset.web and asset.web.technologies else "-"

        services = (
            ", ".join(
                f"{svc.service_name or 'unknown'}:{svc.port}"
                for svc in asset.services[:4]
            )
            if asset.services
            else "-"
        )
        if asset.services and len(asset.services) > 4:
            services += f" (+{len(asset.services) - 4})"

        signals = ", ".join(asset.risk_signals[:4]) if asset.risk_signals else "-"
        if asset.risk_signals and len(asset.risk_signals) > 4:
            signals += f" (+{len(asset.risk_signals) - 4})"

        ips = ", ".join(asset.ip_addresses) if asset.ip_addresses else "-"
        status = str(asset.web.status_code) if asset.web and asset.web.status_code else "-"

        assets_table.add_row(
            asset.host,
            ips,
            status,
            title,
            techs,
            services,
            signals,
        )

    console.print(assets_table)

    findings_table = Table(title="Findings")
    findings_table.add_column("Severity", no_wrap=True)
    findings_table.add_column("Asset", style="cyan")
    findings_table.add_column("Title")
    findings_table.add_column("Impact")

    if result.findings:
        for finding in result.findings:
            impact = finding.impact or "-"
            findings_table.add_row(
                severity_label(finding.severity),
                finding.asset,
                finding.title,
                impact,
            )
        console.print(findings_table)
    else:
        console.print(Panel("No findings generated for this scan.", title="Findings", expand=False))

    high_count = sum(1 for f in result.findings if f.severity.lower() == "high")
    medium_count = sum(1 for f in result.findings if f.severity.lower() == "medium")
    info_count = sum(1 for f in result.findings if f.severity.lower() == "info")
    low_count = sum(1 for f in result.findings if f.severity.lower() == "low")

    summary_text = (
        f"Candidate hosts: {result.summary.candidate_hosts}\n"
        f"Resolved hosts: {result.summary.resolved_hosts}\n"
        f"Live web assets: {result.summary.live_web_assets}\n"
        f"Exposed services: {result.summary.exposed_services}\n"
        f"Assets with signals: {result.summary.assets_with_signals}\n"
        f"Total findings: {len(result.findings)}\n"
        f"High: {high_count} | Medium: {medium_count} | Info: {info_count} | Low: {low_count}"
    )

    console.print(Panel(summary_text, title="Scan Summary", expand=False))
    console.print(f"[green]JSON report written to:[/green] {json_path}")
    console.print(f"[green]CSV export written to:[/green] {csv_path}")
    console.print(f"[green]HTML report written to:[/green] {html_path}")


if __name__ == "__main__":
    app()

      
