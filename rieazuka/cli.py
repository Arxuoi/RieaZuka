from __future__ import annotations

import asyncio
from collections import Counter
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from .core import ScopeError
from .engine import AVAILABLE_MODULES, scan as run_scan
from .reporting import write_html, write_json

app = typer.Typer(help="RieaZuka — authorized, low-impact web security auditing agent.", no_args_is_help=True)
console = Console()


@app.command("version")
def version() -> None:
    """Show version."""
    console.print(f"RieaZuka {__version__}")


@app.command("modules")
def modules_command() -> None:
    """List built-in audit modules."""
    for name in AVAILABLE_MODULES:
        console.print(name)


@app.command("scan")
def scan_command(
    target: Annotated[str, typer.Argument(help="HTTP(S) URL to audit")],
    scope: Annotated[str, typer.Option("--scope", help="Exact hostname authorized for this scan")],
    ack_authorized: Annotated[bool, typer.Option("--ack-authorized", help="Confirm authorization for non-local targets")] = False,
    modules: Annotated[str, typer.Option("--modules", help="Comma-separated module names")] = ",".join(AVAILABLE_MODULES),
    json_output: Annotated[str | None, typer.Option("--json", help="Write JSON report")] = None,
    html_output: Annotated[str | None, typer.Option("--html", help="Write HTML report")] = None,
    timeout: Annotated[float, typer.Option("--timeout", min=1.0, max=30.0)] = 8.0,
) -> None:
    """Run a bounded security audit against an explicitly scoped target."""
    selected = [item.strip() for item in modules.split(",") if item.strip()]
    try:
        result = asyncio.run(run_scan(target, scope, ack_authorized, selected, timeout))
    except (ScopeError, ValueError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from exc

    table = Table(title=f"RieaZuka audit — {result.target}")
    table.add_column("Severity")
    table.add_column("Module")
    table.add_column("Finding")
    for finding in result.findings:
        table.add_row(finding.severity.value.upper(), finding.module, finding.title)
    console.print(table)
    counts = Counter(f.severity.value for f in result.findings)
    console.print(f"high={counts['high']} medium={counts['medium']} low={counts['low']} info={counts['info']} errors={len(result.errors)}")
    for error in result.errors:
        console.print(f"[yellow]Warning:[/yellow] {error}")
    if json_output:
        write_json(result, json_output)
        console.print(f"JSON report: {json_output}")
    if html_output:
        write_html(result, html_output)
        console.print(f"HTML report: {html_output}")


if __name__ == "__main__":
    app()
