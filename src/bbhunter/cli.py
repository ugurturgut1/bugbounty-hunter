from __future__ import annotations

import typer
from rich.console import Console
from rich.table import Table

from bbhunter.discovery import ALL_CONNECTORS
from bbhunter.state import get_program, list_programs, upsert_program

app = typer.Typer(help="Personal bug-bounty discovery/recon/reporting pipeline")
console = Console()


@app.command()
def sync(limit: int | None = typer.Option(None, help="Max programs per platform (for testing)")):
    """Fetch programs + scope + policy from every configured platform connector."""
    total = 0
    for connector_cls in ALL_CONNECTORS:
        connector = connector_cls()
        if not connector.is_configured():
            console.print(f"[yellow]skip[/yellow] {connector.platform_name}: not configured")
            continue
        console.print(f"[cyan]syncing[/cyan] {connector.platform_name}...")
        try:
            programs = connector.fetch_programs(limit=limit)
        except NotImplementedError as e:
            console.print(f"[yellow]skip[/yellow] {connector.platform_name}: {e}")
            continue
        for program in programs:
            upsert_program(program)
            total += 1
        console.print(f"  {len(programs)} program(s) synced")
    console.print(f"[green]done[/green] -- {total} program(s) in state db")


@app.command(name="list")
def list_cmd():
    """List cached programs with their rules-engine confidence."""
    programs = list_programs()
    table = Table()
    table.add_column("Platform")
    table.add_column("Handle")
    table.add_column("Bounties?")
    table.add_column("In-scope assets")
    table.add_column("Rules confidence")
    table.add_column("Active testing allowed?")
    for p in programs:
        table.add_row(
            p.platform.value,
            p.handle,
            "yes" if p.offers_bounties else "no",
            str(len(p.in_scope)),
            p.rules.confidence,
            "yes" if p.rules.confidence == "high" and p.rules.automated_scanners_allowed else "no",
        )
    console.print(table)


@app.command()
def show(key: str):
    """Show full detail for one program, e.g. `hackerone:shopify`."""
    program = get_program(key)
    if not program:
        console.print(f"[red]not found[/red]: {key}")
        raise typer.Exit(1)
    console.print(program.model_dump_json(indent=2))


if __name__ == "__main__":
    app()
