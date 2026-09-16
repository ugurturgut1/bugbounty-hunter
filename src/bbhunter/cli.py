from __future__ import annotations

import typer
from rich.console import Console
from rich.table import Table

from bbhunter.discovery import ALL_CONNECTORS
from bbhunter.models import AssetType
from bbhunter.recon import run_passive_recon
from bbhunter.state import (
    get_program,
    get_recon_result,
    list_findings,
    list_programs,
    upsert_finding,
    upsert_program,
    upsert_recon_result,
)

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


@app.command()
def recon(key: str):
    """Run passive recon (subdomain enum, fingerprinting, CVE keyword
    matching) against one program's in-scope URL/wildcard assets, e.g.
    `bbhunter recon intigriti:coca-cola`. Sends live but low-impact,
    rate-limited requests to the program's own listed assets -- see
    recon/passive.py for exactly what and why."""
    program = get_program(key)
    if not program:
        console.print(f"[red]not found[/red]: {key}")
        raise typer.Exit(1)

    recon_asset_count = sum(1 for a in program.in_scope if a.asset_type in (AssetType.URL, AssetType.WILDCARD))
    if recon_asset_count == 0:
        console.print(f"[yellow]nothing to do[/yellow]: no in-scope URL/wildcard assets for {key}")
        raise typer.Exit(0)

    console.print(f"[cyan]running passive recon[/cyan] on {key} ({recon_asset_count} seed asset(s))...")
    result, findings = run_passive_recon(program)
    upsert_recon_result(result)
    for finding in findings:
        upsert_finding(finding)

    total_hosts = len(result.fingerprints)
    console.print(f"[green]done[/green] -- {total_hosts} host(s) fingerprinted, {len(findings)} CVE-keyword candidate(s)")
    if findings:
        console.print("[yellow]note[/yellow]: these are coarse keyword matches, not confirmed vulnerabilities -- "
                       "review with `bbhunter findings` before doing anything else with them")


@app.command()
def findings(status: str | None = typer.Option(None, help="Filter by status, e.g. candidate")):
    """List findings (candidate vulnerabilities awaiting your review)."""
    rows = list_findings(status=status)
    table = Table()
    table.add_column("ID")
    table.add_column("Program")
    table.add_column("Title")
    table.add_column("Status")
    for f in rows:
        table.add_row(f.id, f.program_key, f.title, f.status.value)
    console.print(table)


if __name__ == "__main__":
    app()
