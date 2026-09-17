from __future__ import annotations

from datetime import datetime

import typer
from rich.console import Console
from rich.table import Table

from bbhunter.discovery import ALL_CONNECTORS
from bbhunter.models import AssetType, FindingStatus, TestType
from bbhunter.prioritize import prioritize
from bbhunter.recon import run_passive_recon
from bbhunter.recon.passive import _tool_path
from bbhunter.reporting import (
    ManualSubmissionRequired,
    draft_poc,
    draft_report,
    mark_submitted_manually,
    submit_report,
)
from bbhunter.testing import run_active_checks
from bbhunter.state import (
    get_finding,
    get_program,
    get_recon_result,
    list_findings,
    list_programs,
    list_reconned_program_keys,
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


@app.command(name="prioritize")
def prioritize_cmd(
    top: int = typer.Option(15, "--top", help="How many programs to show"),
    show_reconned: bool = typer.Option(
        False, "--show-reconned", help="Include programs already reconned once (default: hide them)"
    ),
    search: str = typer.Option(
        None, "--search", help="Case-insensitive substring filter on program key/name, e.g. --search bank"
    ),
    sort_by: str = typer.Option(
        "score", "--sort", help="score (default, effort-vs-payoff) | time (fastest first) | seeds (largest scope first)"
    ),
):
    """Browse synced programs with an estimated recon time for each, e.g.
    to decide which of several newly-uncovered large scopes is actually
    worth the time before running `bbhunter recon`. Default sort is a
    rough recon-effort-vs-payoff score -- see prioritize.py for exactly
    what it is (and isn't); it's a heuristic to shortlist candidates for
    a human to sanity-check, not a real EV model. `--sort time`/`--sort
    seeds` drop the scoring entirely if you'd rather just browse by
    those numbers directly."""
    programs = list_programs()
    reconned = list_reconned_program_keys()
    ranked = prioritize(programs, reconned)
    if not show_reconned:
        ranked = [r for r in ranked if not r.already_reconned]
    if search:
        needle = search.lower()
        ranked = [r for r in ranked if needle in r.program_key.lower() or needle in r.name.lower()]

    if sort_by == "time":
        ranked.sort(key=lambda r: r.est_recon_minutes)
    elif sort_by == "seeds":
        ranked.sort(key=lambda r: r.eligible_seeds, reverse=True)
    elif sort_by != "score":
        console.print(f"[red]invalid --sort[/red]: {sort_by!r}. Valid: score | time | seeds")
        raise typer.Exit(1)

    table = Table(width=200)
    table.add_column("Program", no_wrap=True)
    table.add_column("Score", justify="right")
    table.add_column("Est. recon time", justify="right")
    table.add_column("Seeds", justify="right")
    table.add_column("Bounty?")
    table.add_column("Reconned?")
    table.add_column("Why")
    for r in ranked[:top]:
        table.add_row(
            f"{r.program_key} ({r.name})",
            f"{r.score:.2f}",
            f"{r.est_recon_minutes:.0f}m",
            str(r.eligible_seeds),
            "yes" if r.offers_bounties else "no",
            "yes" if r.already_reconned else "no",
            "; ".join(r.reasons),
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
def recon(
    key: str,
    max_subdomains_per_seed: int = typer.Option(
        25, "--max-subdomains-per-seed",
        help="Cap on crt.sh-discovered subdomains fingerprinted per seed host. 0 = only fingerprint the "
             "seed hosts themselves, skipping subdomain expansion -- much faster, less thorough. Never "
             "affects per-request pacing against the target, only how much breadth gets covered.",
    ),
):
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
    console.print("[dim]Ctrl-C (or `kill -INT`/`pkill -INT -f` on this process) stops cleanly and saves "
                   "whatever's been gathered so far -- nothing is lost.[/dim]")
    result, findings = run_passive_recon(program, max_subdomains_per_seed=max_subdomains_per_seed)
    upsert_recon_result(result)
    for finding in findings:
        upsert_finding(finding)

    total_hosts = len(result.fingerprints)
    if result.complete:
        console.print(f"[green]done[/green] -- {total_hosts} host(s) fingerprinted, {len(findings)} CVE-keyword candidate(s)")
    else:
        console.print(
            f"[yellow]stopped early[/yellow] -- covered {result.seeds_processed}/{result.seeds_total} seed asset(s) "
            f"before being interrupted, {total_hosts} host(s) fingerprinted, {len(findings)} CVE-keyword candidate(s) "
            f"so far. Re-run `bbhunter recon {key}` to pick up where a fresh full pass would start (it doesn't "
            "resume mid-scope, it restarts, but nothing gathered this run is lost)."
        )
    if findings:
        console.print("[yellow]note[/yellow]: these are coarse keyword matches, not confirmed vulnerabilities -- "
                       "review with `bbhunter findings` before doing anything else with them")
    if result.crtsh_failures:
        console.print(
            f"[yellow]warning[/yellow]: crt.sh query failed for {len(result.crtsh_failures)} seed host(s) "
            f"({', '.join(result.crtsh_failures)}) -- subdomain results for those are incomplete, not confirmed-empty"
        )
    if result.wayback_failures:
        console.print(
            f"[yellow]warning[/yellow]: archive.org CDX query failed for {len(result.wayback_failures)} seed host(s) "
            f"({', '.join(result.wayback_failures)}) -- subdomain/param-URL results for those are incomplete"
        )
    if result.subfinder_failures and not _tool_path("subfinder"):
        console.print(
            "[yellow]note[/yellow]: `subfinder` isn't installed -- subdomain coverage is crt.sh + archive.org only. "
            "See README.md Setup for `go install ...subfinder@latest`."
        )
    elif result.subfinder_failures:
        console.print(
            f"[yellow]warning[/yellow]: subfinder run failed for {len(result.subfinder_failures)} seed host(s) "
            f"({', '.join(result.subfinder_failures)})"
        )
    if result.param_urls:
        total_param_urls = sum(len(v) for v in result.param_urls.values())
        console.print(
            f"[dim]{total_param_urls} historic URL(s) with query strings found via Wayback -- input set for "
            f"`bbhunter test-active --injection` (still gated the same as every other active check).[/dim]"
        )


@app.command(name="test-active")
def test_active_cmd(
    key: str,
    injection: bool = typer.Option(
        False, "--injection",
        help="Also run single-request, signature-based reflected-XSS and SQL-error probes against "
             "Wayback-discovered param URLs. Same permits(ACTIVE_LOW_IMPACT) gate as everything else "
             "here -- this flag only decides whether to include that check class, it grants no new access.",
    ),
    nuclei: bool = typer.Option(
        False, "--nuclei",
        help="Also run the `nuclei` binary with a curated misconfig/exposure/tech/cve template set "
             "(dos/intrusive/fuzz/bruteforce/hijack tags excluded), rate-limited to 1 req/s. Requires "
             "`nuclei` installed (see README) and is skipped silently otherwise. Same gate as --injection.",
    ),
):
    """Run Phase 3 active checks (exposed-file/misconfig scan, read-only)
    against a program -- refuses unless `approve-active` has already
    recorded a human decision permitting it. Also tests subdomains a
    prior `bbhunter recon` run discovered under any WILDCARD-scoped
    seed asset, not just the exact seed hostnames."""
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

    recon_result = get_recon_result(key)
    if injection and (not recon_result or not recon_result.param_urls):
        console.print(
            "[yellow]note[/yellow]: --injection requested but no Wayback param URLs are on file for this "
            "program -- run `bbhunter recon` first. Continuing with the exposed-file/misconfig checks only."
        )
    if nuclei and not _tool_path("nuclei"):
        console.print(
            "[yellow]note[/yellow]: --nuclei requested but the `nuclei` binary isn't installed -- skipping "
            "that check class. See README.md Setup for `go install ...nuclei/v3/cmd/nuclei@latest`."
        )
    extras = ", ".join(name for name, flag in (("injection", injection), ("nuclei", nuclei)) if flag)
    console.print(f"[cyan]running active checks[/cyan] on {key}{f' (incl. {extras})' if extras else ''}...")
    new_findings = run_active_checks(program, recon_result, injection=injection, nuclei=nuclei)
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


@app.command(name="show-finding")
def show_finding_cmd(finding_id: str):
    """Show full detail for one finding, including PoC/report file paths."""
    finding = get_finding(finding_id)
    if not finding:
        console.print(f"[red]not found[/red]: {finding_id}")
        raise typer.Exit(1)
    console.print(finding.model_dump_json(indent=2))


@app.command(name="draft-poc")
def draft_poc_cmd(finding_id: str):
    """Phase 4 step 1: scaffold a PoC markdown file for a candidate
    finding. Writes TODOs for reproduction steps and impact -- you must
    fill those in and verify the finding yourself before approving it."""
    finding = get_finding(finding_id)
    if not finding:
        console.print(f"[red]not found[/red]: {finding_id}")
        raise typer.Exit(1)
    program = get_program(finding.program_key)
    if not program:
        console.print(f"[red]program not found[/red]: {finding.program_key}")
        raise typer.Exit(1)

    try:
        finding = draft_poc(finding, program)
    except RuntimeError as e:
        console.print(f"[red]blocked[/red]: {e}")
        raise typer.Exit(1)
    upsert_finding(finding)
    console.print(f"[green]drafted[/green]: {finding.poc_path}")
    console.print("[yellow]note[/yellow]: fill in Reproduction steps and Impact yourself, "
                   "then `bbhunter approve-poc` once you've personally verified it")


@app.command(name="approve-poc")
def approve_poc_cmd(finding_id: str, note: str = typer.Option(..., "--note", help="What you verified")):
    """Record that you personally reproduced and verified this finding."""
    finding = get_finding(finding_id)
    if not finding:
        console.print(f"[red]not found[/red]: {finding_id}")
        raise typer.Exit(1)
    if finding.status != FindingStatus.POC_DRAFTED:
        console.print(f"[red]blocked[/red]: status is {finding.status.value}, not poc_drafted")
        raise typer.Exit(1)
    finding.status = FindingStatus.POC_APPROVED
    finding.notes = f"{finding.notes} | PoC approved: {note}" if finding.notes else f"PoC approved: {note}"
    upsert_finding(finding)
    console.print(f"[green]approved[/green]: {finding_id}")


@app.command(name="reject-poc")
def reject_poc_cmd(finding_id: str, note: str = typer.Option(..., "--note", help="Why this isn't real")):
    """Record that this candidate didn't hold up under manual verification."""
    finding = get_finding(finding_id)
    if not finding:
        console.print(f"[red]not found[/red]: {finding_id}")
        raise typer.Exit(1)
    if finding.status != FindingStatus.POC_DRAFTED:
        console.print(f"[red]blocked[/red]: status is {finding.status.value}, not poc_drafted")
        raise typer.Exit(1)
    finding.status = FindingStatus.POC_REJECTED
    finding.notes = f"{finding.notes} | PoC rejected: {note}" if finding.notes else f"PoC rejected: {note}"
    upsert_finding(finding)
    console.print(f"[green]recorded[/green]: {finding_id} marked poc_rejected")


@app.command(name="draft-report")
def draft_report_cmd(
    finding_id: str,
    severity: str = typer.Option(..., "--severity", help="none|low|medium|high|critical"),
):
    """Phase 4 step 2: draft a disclosure report from an approved PoC.
    Runs after `approve-poc`, or again after `reject-report` to redraft --
    pulls reproduction steps and impact straight from the approved PoC
    file."""
    finding = get_finding(finding_id)
    if not finding:
        console.print(f"[red]not found[/red]: {finding_id}")
        raise typer.Exit(1)
    program = get_program(finding.program_key)
    if not program:
        console.print(f"[red]program not found[/red]: {finding.program_key}")
        raise typer.Exit(1)

    try:
        finding = draft_report(finding, program, severity=severity)
    except (RuntimeError, ValueError) as e:
        console.print(f"[red]blocked[/red]: {e}")
        raise typer.Exit(1)
    upsert_finding(finding)
    console.print(f"[green]drafted[/green]: {finding.report_path}")
    console.print("[yellow]note[/yellow]: fill in Suggested remediation, then review the whole report "
                   "before `bbhunter approve-report`")


@app.command(name="approve-report")
def approve_report_cmd(finding_id: str, note: str = typer.Option(..., "--note", help="Confirmation note")):
    """Record that you reviewed the drafted report and it's ready to submit."""
    finding = get_finding(finding_id)
    if not finding:
        console.print(f"[red]not found[/red]: {finding_id}")
        raise typer.Exit(1)
    if finding.status != FindingStatus.REPORT_DRAFTED:
        console.print(f"[red]blocked[/red]: status is {finding.status.value}, not report_drafted")
        raise typer.Exit(1)
    finding.status = FindingStatus.REPORT_APPROVED
    finding.notes = f"{finding.notes} | Report approved: {note}" if finding.notes else f"Report approved: {note}"
    upsert_finding(finding)
    console.print(f"[green]approved[/green]: {finding_id} -- ready for `bbhunter submit`")


@app.command(name="reject-report")
def reject_report_cmd(finding_id: str, note: str = typer.Option(..., "--note", help="What needs to change")):
    """Send a drafted report back -- record why it's not ready to submit."""
    finding = get_finding(finding_id)
    if not finding:
        console.print(f"[red]not found[/red]: {finding_id}")
        raise typer.Exit(1)
    if finding.status != FindingStatus.REPORT_DRAFTED:
        console.print(f"[red]blocked[/red]: status is {finding.status.value}, not report_drafted")
        raise typer.Exit(1)
    finding.status = FindingStatus.REPORT_REJECTED
    finding.notes = f"{finding.notes} | Report rejected: {note}" if finding.notes else f"Report rejected: {note}"
    upsert_finding(finding)
    console.print(f"[green]recorded[/green]: {finding_id} marked report_rejected")


@app.command()
def submit(
    finding_id: str,
    manual: bool = typer.Option(False, "--manual", help="Skip the API call; record a manual submission instead"),
    note: str = typer.Option(None, "--note", help="Required with --manual: how/where you submitted it"),
):
    """Phase 4 step 3, the last gate: submit an approved report. Refuses
    unless status is report_approved. Automated only for HackerOne
    (POST /hackers/reports) -- every other platform requires pasting the
    drafted report into that platform's own UI, then `--manual`."""
    finding = get_finding(finding_id)
    if not finding:
        console.print(f"[red]not found[/red]: {finding_id}")
        raise typer.Exit(1)
    program = get_program(finding.program_key)
    if not program:
        console.print(f"[red]program not found[/red]: {finding.program_key}")
        raise typer.Exit(1)

    if manual:
        if not note:
            console.print("[red]blocked[/red]: --manual requires --note describing how/where you submitted it")
            raise typer.Exit(1)
        try:
            finding = mark_submitted_manually(finding, note=note)
        except RuntimeError as e:
            console.print(f"[red]blocked[/red]: {e}")
            raise typer.Exit(1)
        upsert_finding(finding)
        console.print(f"[green]recorded[/green]: {finding_id} marked submitted")
        return

    try:
        finding = submit_report(finding, program)
    except ManualSubmissionRequired as e:
        console.print(f"[yellow]manual submission required[/yellow]: {e}")
        raise typer.Exit(1)
    except RuntimeError as e:
        console.print(f"[red]blocked[/red]: {e}")
        raise typer.Exit(1)
    upsert_finding(finding)
    console.print(f"[green]submitted[/green]: {finding_id}")


if __name__ == "__main__":
    app()
