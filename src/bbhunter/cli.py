from __future__ import annotations

from datetime import datetime

import typer
from rich.console import Console
from rich.table import Table

from bbhunter.discovery import ALL_CONNECTORS
from bbhunter.models import AssetType, TestType
from bbhunter.recon import run_passive_recon
from bbhunter.testing import run_active_checks
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
    table.add_column("Human-reviewed?")
    table.add_column("Active testing allowed?")
    for p in programs:
        table.add_row(
            p.platform.value,
            p.handle,
            "yes" if p.offers_bounties else "no",
            str(len(p.in_scope)),
            p.rules.confidence,
            "yes" if p.rules.human_reviewed else "no",
            "yes" if p.rules.permits(TestType.ACTIVE_LOW_IMPACT) else "no",
        )
    console.print(table)


@app.command(name="review-rules")
def review_rules_cmd(key: str):
    """Print everything needed to make a human decision about active
    testing on a program: the raw policy text and the heuristic's read
    of it. Doesn't change any state -- pair with `approve-active`."""
    program = get_program(key)
    if not program:
        console.print(f"[red]not found[/red]: {key}")
        raise typer.Exit(1)

    r = program.rules
    console.print(f"[bold]{program.name}[/bold] ({key})")
    console.print(f"Policy URL: {program.policy_url or program.url}")
    console.print()
    console.print("[bold]Raw policy text:[/bold]")
    console.print(program.raw_policy_text or "[dim](none captured)[/dim]")
    console.print()
    console.print("[bold]Heuristic read:[/bold]")
    console.print(f"  confidence: {r.confidence}")
    console.print(f"  automated_scanners_allowed: {r.automated_scanners_allowed}")
    console.print(f"  safe_harbor: {r.safe_harbor}")
    console.print(f"  requires_authorization_request: {r.requires_authorization_request}")
    console.print(f"  explicitly_disallowed_techniques: {r.explicitly_disallowed_techniques}")
    console.print(f"  required_user_agent: {r.required_user_agent}")
    console.print(f"  required_request_header: {r.required_request_header}")
    console.print(f"  raw_notes: {r.raw_notes}")
    console.print()
    if r.human_reviewed:
        console.print(f"[green]Already human-reviewed[/green] at {r.reviewed_at}: {r.review_notes}")
    else:
        console.print("[yellow]Not yet human-reviewed.[/yellow] Use `bbhunter approve-active` to record a decision.")


@app.command(name="approve-active")
def approve_active_cmd(
    key: str,
    test_types: list[str] = typer.Option(..., "--test-type", help="TestType(s) to allow, e.g. active_low_impact"),
    note: str = typer.Option(..., "--note", help="Why -- cite the specific policy language that justifies this"),
):
    """Record an explicit human decision that a program's policy allows
    active testing. This is the only way RulesOfEngagement.confidence
    ever becomes "high" -- the heuristic in rules_engine.py cannot do
    this on its own. Run `review-rules` first."""
    program = get_program(key)
    if not program:
        console.print(f"[red]not found[/red]: {key}")
        raise typer.Exit(1)

    try:
        parsed_types = {TestType(t) for t in test_types}
    except ValueError as e:
        console.print(f"[red]invalid test type[/red]: {e}. Valid: {[t.value for t in TestType]}")
        raise typer.Exit(1)

    program.rules.human_reviewed = True
    program.rules.confidence = "high"
    program.rules.reviewed_at = datetime.utcnow()
    program.rules.review_notes = note
    program.rules.allowed_test_types = program.rules.allowed_test_types | parsed_types
    upsert_program(program)
    console.print(f"[green]recorded[/green]: {key} now permits {sorted(t.value for t in parsed_types)}")


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


@app.command(name="test-active")
def test_active_cmd(key: str):
    """Run Phase 3 active checks (exposed-file/misconfig scan, read-only)
    against a program -- refuses unless `approve-active` has already
    recorded a human decision permitting it."""
    program = get_program(key)
    if not program:
        console.print(f"[red]not found[/red]: {key}")
        raise typer.Exit(1)

    if not program.rules.permits(TestType.ACTIVE_LOW_IMPACT):
        console.print(
            f"[red]blocked[/red]: {key} does not permit active testing. "
            "Run `bbhunter review-rules` then `bbhunter approve-active` if the policy actually allows it."
        )
        raise typer.Exit(1)

    console.print(f"[cyan]running active checks[/cyan] on {key}...")
    new_findings = run_active_checks(program)
    for finding in new_findings:
        upsert_finding(finding)
    console.print(f"[green]done[/green] -- {len(new_findings)} candidate(s) found")
    if new_findings:
        console.print("[yellow]note[/yellow]: verify each manually before drafting a PoC -- "
                       "see `bbhunter findings`")


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
