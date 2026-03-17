import typer
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from argus.core.engine import run_scan
from argus.output.json_writer import write_json_report
from argus.output.csv_writer import write_assets_csv
from argus.output.html_writer import write_html_report

app = typer.Typer(
    help="Argus - attack surface intelligence CLI",
    no_args_is_help=True,
)
console = Console()


@app.callback()
def main() -> None:
    """Argus root command group."""
    pass


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target domain"),
    passive: bool = typer.Option(True, "--passive/--no-passive", help="Enable passive recon"),
    tech: bool = typer.Option(True, "--tech/--no-tech", help="Enable technology fingerprinting"),
    output: Path = typer.Option(Path("reports"), "--output", "-o", help="Output directory"),
) -> None:
    """Run a basic Argus scan."""
    console.print(f"[bold cyan]Argus[/bold cyan] scanning [bold]{target}[/bold]")

    try:
        result = run_scan(target=target, enable_tech=tech)
    except ValueError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(code=1)

    json_path = write_json_report(result, output)
    csv_path = write_assets_csv(result, output)
    html_path = write_html_report(result, output)

    table = Table(title="Discovered Assets")
    table.add_column("Host")
    table.add_column("IPs")
    table.add_column("Title")
    table.add_column("Technologies")
    table.add_column("Signals")

    for asset in result.assets:
        title = asset.web.title if asset.web and asset.web.title else "-"
        techs = ", ".join(asset.web.technologies) if asset.web and asset.web.technologies else "-"
        signals = ", ".join(asset.risk_signals) if asset.risk_signals else "-"
        ips = ", ".join(asset.ip_addresses) if asset.ip_addresses else "-"
        table.add_row(asset.host, ips, title, techs, signals)

    console.print(table)

    summary_text = (
        f"Candidate hosts: {result.summary.candidate_hosts}\n"
        f"Resolved hosts: {result.summary.resolved_hosts}\n"
        f"Live web assets: {result.summary.live_web_assets}\n"
        f"Assets with signals: {result.summary.assets_with_signals}\n"
        f"Findings: {len(result.findings)}"
    )

    console.print(Panel(summary_text, title="Scan Summary", expand=False))
    console.print(f"[green]JSON report written to:[/green] {json_path}")
    console.print(f"[green]CSV export written to:[/green] {csv_path}")
    console.print(f"[green]HTML report written to:[/green] {html_path}")


if __name__ == "__main__":
    app()