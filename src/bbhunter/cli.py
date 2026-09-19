from __future__ import annotations

import os
import uuid
from datetime import datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from bbhunter.discovery import ALL_CONNECTORS
from bbhunter.models import AIEndpointConfig, AssetType, FindingStatus, TestRun, TestType
from bbhunter.prioritize import prioritize
from bbhunter.recon import run_passive_recon
from bbhunter.recon.passive import _tool_path
from bbhunter.reporting import (
    ManualSubmissionRequired,
    draft_poc,
    draft_report,
    mark_submitted_manually,
    poc_has_unfilled_todos,
    submit_report,
)
from bbhunter.testing import run_active_checks
from bbhunter.testing.active import _select_hosts
from bbhunter.testing.aggressive_discovery import (
    FFUF_RATE_PER_SECOND,
    MAX_DISCOVERY_HOSTS_PER_PROGRAM,
    resolve_wordlist,
    run_aggressive_discovery,
    wordlist_line_count,
)
from bbhunter.testing.ai_safety import run_ai_safety_probes
from bbhunter.testing.credential_testing import MAX_CREDENTIALS_PER_RUN, run_credential_test
from bbhunter.testing.exploit_framework import run_exploit_framework_check
from bbhunter.testing.idor import run_bfla_check, run_idor_check
from bbhunter.testing.mass_assignment import run_mass_assignment_check
from bbhunter.testing.sqli_exploit import SQLMAP_DUMP_ROW_LIMIT, run_sqli_exploitation
from bbhunter.state import (
    get_ai_endpoint,
    get_finding,
    get_program,
    get_recon_result,
    list_findings,
    list_programs,
    list_reconned_program_keys,
    list_test_runs,
    record_test_run,
    upsert_ai_endpoint,
    upsert_finding,
    upsert_program,
    upsert_recon_result,
)


def _log_test_run(key: str, test_type: TestType, findings_created: int, detail: str) -> None:
    record_test_run(TestRun(
        id=str(uuid.uuid4()),
        program_key=key,
        test_type=test_type,
        findings_created=findings_created,
        detail=detail,
    ))

app = typer.Typer(help="Personal bug-bounty discovery/recon/reporting pipeline")
console = Console()


def _parse_headers(raw: list[str]) -> dict[str, str]:
    """Parses repeatable '--header "Key: Value"' CLI options into a
    dict, exiting with a clear error on anything malformed rather than
    silently dropping it."""
    headers: dict[str, str] = {}
    for h in raw:
        if ":" not in h:
            console.print(f"[red]invalid header[/red]: {h!r} (expected 'Key: Value')")
            raise typer.Exit(1)
        key, _, value = h.partition(":")
        headers[key.strip()] = value.strip()
    return headers


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


_RISK_WARNINGS: dict[TestType, str] = {
    TestType.AGGRESSIVE_DISCOVERY: (
        "Content-discovery/parameter fuzzing sends a HIGH VOLUME of requests (hundreds-thousands) -- "
        "unlike every other check in this project (single-request/low-volume). Confirm the policy's "
        "rate-limit and testing-hours notes are compatible with that volume, and that 'automated "
        "scanners' language in the policy actually covers high-volume fuzzing, not just occasional "
        "low-rate requests. Wordlist choice controls this directly: `test-discovery --wordlist` can use "
        "a cloned SecLists list (github.com/danielmiessler/SecLists, see README Setup) ranging from a "
        "few thousand entries ('common') to hundreds of thousands ('large') -- request count (and "
        "therefore run time and how much this looks like a scanning attack to the target) scales "
        "linearly with wordlist size. `test-discovery` prints the resolved wordlist's actual entry "
        "count and total request estimate before it starts -- read that number, and default to "
        "'common'/the small built-in list rather than 'large' unless the program's policy is explicit "
        "about welcoming exhaustive automated scanning."
    ),
    TestType.SQLI_EXPLOITATION: (
        "sqlmap can extract REAL DATA from the target's database once run past confirmation mode. "
        "Pulling more than the minimum needed to prove impact (e.g. current DB name, banner) may "
        "itself violate a program's data-handling policy even when SQLi itself is in scope. Confirm "
        "the policy explicitly permits extraction (not just detection), and that you will handle any "
        "extracted data per the program's disclosure requirements -- delete it after reporting, never "
        "keep or share it beyond what the report needs."
    ),
    TestType.CREDENTIAL_TESTING: (
        "Login/credential testing is one of the MOST COMMONLY EXPLICITLY PROHIBITED techniques across "
        "bug bounty programs, even ones that otherwise welcome automated scanning -- it risks locking "
        "out real user accounts (a denial of service to actual users, not just the target company). "
        "This project only ever tests a small, explicit credential list you supply yourself -- never an "
        "open-ended wordlist brute force. Confirm the policy explicitly names credential/login testing "
        "as permitted (not just 'active testing' in general), and that every credential you're about to "
        "test is either your own test account or one the program has explicitly provided."
    ),
    TestType.EXPLOITATION_FRAMEWORK: (
        "This tier aims to ACTUALLY confirm command execution (a real, minimal command like `id`/"
        "`whoami`), not just a benign detection signature -- carrying real legal/operational risk even "
        "under an authorized program, since a real exploit chain means real access to potentially "
        "sensitive systems. Confirm the policy explicitly permits proof-of-concept exploitation to this "
        "depth. Keep any interaction to the absolute minimum needed to prove impact, and stop "
        "immediately and report if you gain more access than expected -- never escalate, pivot, or "
        "leave anything persistent on the target."
    ),
}


@app.command(name="approve-active")
def approve_active_cmd(
    key: str,
    test_types: list[str] = typer.Option(..., "--test-type", help="TestType(s) to allow, e.g. active_low_impact"),
    note: str = typer.Option(..., "--note", help="Why -- cite the specific policy language that justifies this"),
    i_understand_the_risk: bool = typer.Option(
        False, "--i-understand-the-risk",
        help="Required in addition to --note for any of the higher-risk tiers (aggressive_discovery, "
             "sqli_exploitation, credential_testing, exploitation_framework) -- run once without it first "
             "to see the specific risk warning for what you're about to approve.",
    ),
    required_user_agent: str | None = typer.Option(
        None, "--required-user-agent",
        help="Set/correct the policy's required User-Agent string if the rules-engine heuristic missed "
             "it in review-rules's raw policy text -- e.g. a program that wants "
             "'toolresearcher_<your-h1-username>'. Read the actual policy text yourself first; this is "
             "never guessed or invented.",
    ),
    required_header: str | None = typer.Option(
        None, "--required-header",
        help="Set/correct a required 'Key: Value' request header the same way, if the policy names one.",
    ),
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

    risky = parsed_types & set(_RISK_WARNINGS)
    if risky and not i_understand_the_risk:
        console.print(f"[red]stopping before recording approval for: {sorted(t.value for t in risky)}[/red]")
        for t in sorted(risky, key=lambda t: t.value):
            console.print(f"\n[bold red]RISK[/bold red] ({t.value}):")
            console.print(f"  {_RISK_WARNINGS[t]}")
        console.print(
            "\n[yellow]Re-run this exact command with --i-understand-the-risk once you've confirmed the "
            "policy text actually covers this specific technique, not just 'automated testing' in "
            "general.[/yellow]"
        )
        raise typer.Exit(1)

    if required_header is not None and ":" not in required_header:
        console.print(f"[red]invalid --required-header[/red]: {required_header!r} (expected 'Key: Value')")
        raise typer.Exit(1)

    program.rules.human_reviewed = True
    program.rules.confidence = "high"
    program.rules.reviewed_at = datetime.utcnow()
    program.rules.review_notes = note
    program.rules.allowed_test_types = program.rules.allowed_test_types | parsed_types
    if required_user_agent is not None:
        program.rules.required_user_agent = required_user_agent
    if required_header is not None:
        program.rules.required_request_header = required_header
    upsert_program(program)
    console.print(f"[green]recorded[/green]: {key} now permits {sorted(t.value for t in parsed_types)}")
    if required_user_agent is not None:
        console.print(f"[dim]required User-Agent set to '{required_user_agent}' for all future requests to this program[/dim]")
    if required_header is not None:
        console.print(f"[dim]required header set to '{required_header}' for all future requests to this program[/dim]")


@app.command()
def show(key: str):
    """Show full detail for one program, e.g. `hackerone:shopify`."""
    program = get_program(key)
    if not program:
        console.print(f"[red]not found[/red]: {key}")
        raise typer.Exit(1)
    console.print(program.model_dump_json(indent=2))


@app.command()
def report(key: str):
    """Full per-program audit trail: scope/approval status, everything
    passive recon found (hosts, subdomains, param URLs), every check
    that has actually been run against this program (from `test_runs`,
    which records a run whether or not it produced a Finding -- a clean
    result otherwise leaves no trace), and every Finding on file. Meant
    to answer "what have we looked at here and what came of it" without
    re-deriving it from scattered command output."""
    program = get_program(key)
    if not program:
        console.print(f"[red]not found[/red]: {key}")
        raise typer.Exit(1)

    r = program.rules
    console.print(f"[bold]{program.name}[/bold] ({key}) -- {program.platform.value}")
    console.print(f"  bounties: {'yes' if program.offers_bounties else 'no'}  |  safe harbor: {r.safe_harbor}  |  "
                   f"in-scope assets: {len(program.in_scope)}  |  last synced: {program.last_synced}")
    console.print(f"  active testing: {'[green]permitted[/green]' if r.human_reviewed and r.confidence == 'high' else '[yellow]not approved[/yellow]'}"
                   f" (confidence={r.confidence}, allowed_test_types={sorted(t.value for t in r.allowed_test_types) if r.human_reviewed else '[]'})")
    if r.requires_authorization_request:
        console.print("  [red]requires prior written authorization[/red] -- confirm this has actually been granted before any active check")

    recon_result = get_recon_result(key)
    console.print()
    console.print("[bold]Recon[/bold]")
    if not recon_result:
        console.print("  [dim]none yet -- run `bbhunter recon` " + key + "`[/dim]")
    else:
        console.print(f"  last run: {recon_result.last_run}  |  seeds: {recon_result.seeds_processed}/{recon_result.seeds_total}"
                       f"{' (incomplete)' if not recon_result.complete else ''}")
        total_subdomains = sum(len(v) for v in recon_result.subdomains.values())
        total_param_urls = sum(len(v) for v in recon_result.param_urls.values())
        console.print(f"  {len(recon_result.fingerprints)} host(s) fingerprinted, {total_subdomains} subdomain(s) discovered, "
                       f"{total_param_urls} param URL(s) from Wayback")
        if recon_result.fingerprints:
            table = Table(title="Fingerprinted hosts")
            table.add_column("Host")
            table.add_column("Status")
            table.add_column("Server")
            table.add_column("Tech")
            for host, fp in sorted(recon_result.fingerprints.items()):
                table.add_row(
                    host,
                    str(fp.get("status_code", "")),
                    str(fp.get("server", "") or ""),
                    ", ".join(fp.get("tech", []) or []) if isinstance(fp.get("tech"), list) else str(fp.get("tech", "") or ""),
                )
            console.print(table)
        failures = []
        if recon_result.crtsh_failures:
            failures.append(f"crt.sh failed for {len(recon_result.crtsh_failures)} seed(s)")
        if recon_result.certspotter_failures:
            failures.append(f"certspotter failed for {len(recon_result.certspotter_failures)} seed(s)")
        if recon_result.subfinder_failures:
            failures.append(f"subfinder failed for {len(recon_result.subfinder_failures)} seed(s)")
        if recon_result.assetfinder_failures:
            failures.append(f"assetfinder failed for {len(recon_result.assetfinder_failures)} seed(s)")
        if recon_result.wayback_failures:
            failures.append(f"Wayback failed for {len(recon_result.wayback_failures)} seed(s)")
        if failures:
            console.print(f"  [yellow]incomplete coverage[/yellow]: {'; '.join(failures)}")

    runs = list_test_runs(key)
    console.print()
    console.print("[bold]Test run history[/bold]")
    if not runs:
        console.print("  [dim]no active checks have been run against this program yet[/dim]")
    else:
        table = Table()
        table.add_column("When")
        table.add_column("Check")
        table.add_column("Detail")
        table.add_column("Findings", justify="right")
        for run in runs:
            table.add_row(
                str(run.ran_at),
                run.test_type.value,
                run.detail,
                str(run.findings_created),
            )
        console.print(table)

    program_findings = [f for f in list_findings() if f.program_key == key]
    console.print()
    console.print(f"[bold]Findings[/bold] ({len(program_findings)})")
    if not program_findings:
        console.print("  [dim]none on file[/dim]")
    else:
        table = Table()
        table.add_column("ID")
        table.add_column("Test type")
        table.add_column("Asset")
        table.add_column("Title")
        table.add_column("Status")
        table.add_column("Severity")
        for f in program_findings:
            table.add_row(f.id, f.test_type.value, f.asset, f.title, f.status.value, f.severity or "")
        console.print(table)


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
    result, findings = run_passive_recon(
        program,
        max_subdomains_per_seed=max_subdomains_per_seed,
        on_progress=lambda msg: console.print(f"[dim]{msg}[/dim]"),
    )
    upsert_recon_result(result)
    for finding in findings:
        upsert_finding(finding)
    _log_test_run(
        key, TestType.PASSIVE_RECON, len(findings),
        f"{result.seeds_processed}/{result.seeds_total} seed(s), {len(result.fingerprints)} host(s) fingerprinted"
        f"{'' if result.complete else ' (interrupted)'}",
    )

    total_hosts = len(result.fingerprints)
    cve_count = sum(1 for f in findings if f.test_type == TestType.VERSION_CVE_MATCH)
    other_count = len(findings) - cve_count
    findings_summary = (
        f"{len(findings)} candidate finding(s) ({cve_count} CVE-keyword match(es), {other_count} other -- "
        "TLS/DNS/JS/disclosure/etc.)"
        if findings
        else "0 candidate findings"
    )
    if result.complete:
        console.print(f"[green]done[/green] -- {total_hosts} host(s) fingerprinted, {findings_summary}")
    else:
        console.print(
            f"[yellow]stopped early[/yellow] -- covered {result.seeds_processed}/{result.seeds_total} seed asset(s) "
            f"before being interrupted, {total_hosts} host(s) fingerprinted, {findings_summary} "
            f"so far. Re-run `bbhunter recon {key}` to pick up where a fresh full pass would start (it doesn't "
            "resume mid-scope, it restarts, but nothing gathered this run is lost)."
        )
    if findings:
        console.print("[yellow]note[/yellow]: every one of these is a coarse automated signal, not a confirmed "
                       "vulnerability -- review with `bbhunter findings` before doing anything else with them")
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
    if result.certspotter_failures:
        console.print(
            f"[dim]note[/dim]: certspotter query failed/rate-limited for {len(result.certspotter_failures)} seed "
            f"host(s) ({', '.join(result.certspotter_failures)}) -- expected on programs with many seeds, its "
            "unauthenticated tier is capped at 10 requests/hour; crt.sh remains the primary CT-log source"
        )
    if result.subfinder_failures and not _tool_path("subfinder"):
        console.print(
            "[yellow]note[/yellow]: `subfinder` isn't installed -- subdomain coverage is crt.sh + Certspotter + "
            "archive.org only. See README.md Setup for `go install ...subfinder@latest`."
        )
    elif result.subfinder_failures:
        console.print(
            f"[yellow]warning[/yellow]: subfinder run failed for {len(result.subfinder_failures)} seed host(s) "
            f"({', '.join(result.subfinder_failures)})"
        )
    if result.assetfinder_failures and not _tool_path("assetfinder"):
        console.print(
            "[dim]note[/dim]: `assetfinder` isn't installed -- optional, see README.md Setup for "
            "`go install github.com/tomnomnom/assetfinder@latest`."
        )
    elif result.assetfinder_failures:
        console.print(
            f"[yellow]warning[/yellow]: assetfinder run failed for {len(result.assetfinder_failures)} seed host(s) "
            f"({', '.join(result.assetfinder_failures)})"
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
        help="Also run single-request, signature-based reflected-XSS, SQL-error, NoSQL-error, and "
             "command-injection (benign echo-canary only) probes against Wayback-discovered param URLs. "
             "Same permits(ACTIVE_LOW_IMPACT) gate as everything else here -- this flag only decides "
             "whether to include that check class, it grants no new access.",
    ),
    nuclei: bool = typer.Option(
        False, "--nuclei",
        help="Also run the `nuclei` binary with a curated template set: misconfig/exposure/tech/cve/ssl/"
             "cache plus cors/ssrf/jwt/graphql/takeover/ssti/xxe/host-header/prototype-pollution/redirect "
             "(rce/sqli/dos/intrusive/fuzz/bruteforce/hijack/default-login/auth-bypass tags excluded), "
             "rate-limited to 1 req/s. Requires `nuclei` installed (see README) and is skipped silently "
             "otherwise. Same gate as --injection.",
    ),
    cloud_buckets: bool = typer.Option(
        False, "--cloud-buckets",
        help="Also check a small set of S3/GCS/Azure bucket-name variations derived from this program's "
             "own in-scope domains for a publicly-listable cloud storage bucket. Every request goes to "
             "the cloud PROVIDER's infrastructure, not the target's own hosts. Findings land at 'info' "
             "severity with an explicit ownership-verification caveat -- a same-named bucket can "
             "legitimately belong to an unrelated third party. Same gate as --injection/--nuclei.",
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
    extras = ", ".join(
        name for name, flag in (("injection", injection), ("nuclei", nuclei), ("cloud-buckets", cloud_buckets)) if flag
    )
    console.print(f"[cyan]running active checks[/cyan] on {key}{f' (incl. {extras})' if extras else ''}...")
    new_findings = run_active_checks(program, recon_result, injection=injection, nuclei=nuclei, cloud_buckets=cloud_buckets)
    for finding in new_findings:
        upsert_finding(finding)
    _log_test_run(
        key, TestType.ACTIVE_LOW_IMPACT, len(new_findings),
        f"exposed-file/misconfig scan{f', incl. {extras}' if extras else ''}",
    )
    console.print(f"[green]done[/green] -- {len(new_findings)} candidate(s) found")
    if new_findings:
        console.print("[yellow]note[/yellow]: verify each manually before drafting a PoC -- "
                       "see `bbhunter findings`")


@app.command(name="ai-endpoint-set")
def ai_endpoint_set_cmd(
    key: str,
    url: str = typer.Option(..., "--url", help="The AI/LLM product endpoint URL, e.g. a chat-completions API"),
    request_template_file: Path = typer.Option(
        ..., "--request-template-file",
        help="Path to a JSON file for the request body, containing a {{PROMPT}} placeholder somewhere "
             "in a string value, e.g. {\"model\": \"...\", \"messages\": [{\"role\": \"user\", "
             "\"content\": \"{{PROMPT}}\"}]}",
    ),
    response_path: str = typer.Option(
        ..., "--response-path",
        help="Dot-separated path into the JSON response for the model's text reply, e.g. "
             "choices.0.message.content (numeric segments index into arrays)",
    ),
    method: str = typer.Option("POST", "--method"),
    header: list[str] = typer.Option(
        [], "--header", help="Extra static 'Key: Value' header, repeatable. Not for secrets -- use --auth-env-var."
    ),
    auth_header: str | None = typer.Option(None, "--auth-header", help="Header name for the auth token, e.g. Authorization"),
    auth_env_var: str | None = typer.Option(
        None, "--auth-env-var", help="Env var holding the raw API key/token -- read at request time only, never stored"
    ),
    auth_template: str = typer.Option("Bearer {token}", "--auth-template", help="How to format the token into the header value"),
    conversation_template_file: Path | None = typer.Option(
        None, "--conversation-template-file",
        help="Optional: path to a JSON file for multi-turn probes (`test-ai --multiturn`), containing "
             "a {{MESSAGES}} placeholder, e.g. {\"messages\": \"{{MESSAGES}}\"} for an API that takes "
             "the whole history as an array. Skip this if you only want the single-turn probes.",
    ),
    note: str | None = typer.Option(None, "--note", help="Why this endpoint is in scope, e.g. citing the program's policy"),
):
    """Configure how to send a prompt to a program's in-scope AI/LLM
    product endpoint and read back its text response, for later use by
    `bbhunter test-ai`. Never stores a real credential -- only the name
    of the env var to read one from at request time."""
    program = get_program(key)
    if not program:
        console.print(f"[red]not found[/red]: {key}")
        raise typer.Exit(1)

    if not request_template_file.exists():
        console.print(f"[red]not found[/red]: {request_template_file}")
        raise typer.Exit(1)
    request_template = request_template_file.read_text()
    if "{{PROMPT}}" not in request_template:
        console.print("[red]invalid template[/red]: request template must contain a {{PROMPT}} placeholder")
        raise typer.Exit(1)

    conversation_template: str | None = None
    if conversation_template_file is not None:
        if not conversation_template_file.exists():
            console.print(f"[red]not found[/red]: {conversation_template_file}")
            raise typer.Exit(1)
        conversation_template = conversation_template_file.read_text()
        if "{{MESSAGES}}" not in conversation_template:
            console.print("[red]invalid template[/red]: conversation template must contain a {{MESSAGES}} placeholder")
            raise typer.Exit(1)

    headers = _parse_headers(header)

    config = AIEndpointConfig(
        program_key=key,
        url=url,
        method=method,
        headers=headers,
        auth_header=auth_header,
        auth_env_var=auth_env_var,
        auth_template=auth_template,
        request_template=request_template,
        response_text_path=response_path,
        conversation_template=conversation_template,
        notes=note,
    )
    upsert_ai_endpoint(config)
    console.print(f"[green]saved[/green]: AI endpoint config for {key} -> {url}")
    if auth_env_var and not os.environ.get(auth_env_var):
        console.print(
            f"[yellow]note[/yellow]: ${auth_env_var} isn't set in this environment -- `test-ai` will send "
            "requests without an auth header until it is"
        )


@app.command(name="ai-endpoint-show")
def ai_endpoint_show_cmd(key: str):
    """Show the AI endpoint config saved for a program, if any. Never
    prints a real credential -- only the configured env var name."""
    config = get_ai_endpoint(key)
    if not config:
        console.print(f"[yellow]none configured[/yellow] for {key} -- use `bbhunter ai-endpoint-set` first")
        raise typer.Exit(1)
    console.print(config.model_dump_json(indent=2))


@app.command(name="test-ai")
def test_ai_cmd(
    key: str,
    multiturn: bool = typer.Option(
        False, "--multiturn",
        help="Also run scripted 3-turn jailbreak chains (roleplay/persona framing, gradual "
             "system-prompt probing) -- up to 6 more requests. Requires --conversation-template-file "
             "to have been set via ai-endpoint-set; skipped with a note otherwise. Same gate as the "
             "base probes, not a separate tier.",
    ),
):
    """Run the opt-in AI/LLM safety probes (prompt injection, system-
    prompt leakage, sensitive-info disclosure, excessive agency,
    improper output handling, indirect prompt injection, misinformation
    -- see testing/ai_safety.py) against a program's configured AI
    endpoint. Refuses unless `approve-active --test-type ai_safety_probe`
    has already recorded a human decision permitting it -- same gate as
    every other active check, no passive-floor exception for this one.

    Unlike the web checks, each probe here is a real call to the
    program's AI model, which may cost real money per request if it's a
    paid model API -- this runs exactly 7 requests total (13 with
    --multiturn), but that's worth knowing before running it repeatedly."""
    program = get_program(key)
    if not program:
        console.print(f"[red]not found[/red]: {key}")
        raise typer.Exit(1)

    config = get_ai_endpoint(key)
    if not config:
        console.print(f"[red]not configured[/red]: run `bbhunter ai-endpoint-set {key}` first")
        raise typer.Exit(1)

    if not program.rules.permits(TestType.AI_SAFETY_PROBE):
        console.print(
            f"[red]blocked[/red]: {key} does not permit AI safety probes. Run `bbhunter review-rules` then "
            "`bbhunter approve-active --test-type ai_safety_probe --note \"...\"` if the policy actually "
            "covers testing this AI product endpoint."
        )
        raise typer.Exit(1)

    if multiturn and not config.conversation_template:
        console.print(
            "[yellow]note[/yellow]: --multiturn requested but no conversation template is configured -- "
            "run `bbhunter ai-endpoint-set --conversation-template-file ...` first. Continuing with the "
            "single-turn probes only."
        )

    request_count = "7 requests" if not (multiturn and config.conversation_template) else "up to 13 requests"
    console.print(f"[cyan]running AI safety probes[/cyan] against {config.url} for {key} ({request_count})...")
    new_findings = run_ai_safety_probes(program, config, multiturn=multiturn)
    for finding in new_findings:
        upsert_finding(finding)
    _log_test_run(key, TestType.AI_SAFETY_PROBE, len(new_findings), f"against {config.url} ({request_count}{', +multiturn' if multiturn else ''})")
    console.print(f"[green]done[/green] -- {len(new_findings)} candidate(s) found")
    if new_findings:
        console.print("[yellow]note[/yellow]: these are heuristic signals -- read the actual model responses "
                       "yourself before treating any as confirmed, see `bbhunter findings`")


@app.command(name="test-idor")
def test_idor_cmd(
    key: str,
    url: str = typer.Option(..., "--url", help="A resource URL known to belong to the 'owner' identity, e.g. https://target/api/orders/12345"),
    owner_header: list[str] = typer.Option(
        ..., "--owner-header", help="'Key: Value' auth header for the identity that owns the resource, repeatable"
    ),
    other_header: list[str] = typer.Option(
        ..., "--other-header", help="'Key: Value' auth header for a second, unrelated identity, repeatable"
    ),
    owner_note: str | None = typer.Option(
        None, "--owner-note", help="How you know this resource belongs to the owner identity, e.g. \"order 12345, created by test account A\""
    ),
):
    """Check one resource URL for IDOR by fetching it once as its
    confirmed owner and once as a second, unrelated identity -- exactly
    two requests. Refuses unless `approve-active` has already recorded a
    human decision permitting active testing (same gate as
    `test-active`). Both identities' credentials must be real sessions
    you (or the user directing this) actually control -- never invented,
    guessed, or brute-forced."""
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

    owner_headers = _parse_headers(owner_header)
    other_headers = _parse_headers(other_header)

    console.print(f"[cyan]checking IDOR[/cyan] on {url} for {key} (2 requests)...")
    new_findings = run_idor_check(program, url, owner_headers, other_headers, owner_note=owner_note)
    for finding in new_findings:
        upsert_finding(finding)
    _log_test_run(key, TestType.ACTIVE_LOW_IMPACT, len(new_findings), f"IDOR check on {url}")
    if new_findings:
        console.print("[red]candidate found[/red] -- see `bbhunter findings`, verify manually before drafting a PoC")
    else:
        console.print("[green]no candidate[/green] -- either properly denied, or the baseline request as the "
                       "owner identity itself didn't succeed (check --owner-header/the URL)")


@app.command(name="test-bfla")
def test_bfla_cmd(
    key: str,
    url: str = typer.Option(..., "--url", help="An administrative/privileged function or endpoint URL, e.g. https://target/admin/users"),
    authorized_header: list[str] = typer.Option(
        ..., "--authorized-header", help="'Key: Value' auth header for an identity authorized to use this function, repeatable"
    ),
    other_header: list[str] = typer.Option(
        ..., "--other-header", help="'Key: Value' auth header for a lower-privileged/unrelated identity, repeatable"
    ),
    authorized_note: str | None = typer.Option(
        None, "--authorized-note", help="How you know this identity is authorized for this function, e.g. \"test account A has the admin role\""
    ),
):
    """Check one administrative/privileged function or endpoint for
    Broken Function Level Authorization (OWASP API5:2023) by fetching it
    once as an authorized identity and once as a lower-privileged one --
    exactly two requests, same mechanism as `test-idor` pointed at a
    function instead of a data object. Refuses unless `approve-active`
    has already recorded a human decision permitting active testing.
    Both identities' credentials must be real sessions you (or the user
    directing this) actually control -- never invented, guessed, or
    brute-forced."""
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

    authorized_headers = _parse_headers(authorized_header)
    other_headers = _parse_headers(other_header)

    console.print(f"[cyan]checking BFLA[/cyan] on {url} for {key} (2 requests)...")
    new_findings = run_bfla_check(program, url, authorized_headers, other_headers, authorized_note=authorized_note)
    for finding in new_findings:
        upsert_finding(finding)
    _log_test_run(key, TestType.ACTIVE_LOW_IMPACT, len(new_findings), f"BFLA check on {url}")
    if new_findings:
        console.print("[red]candidate found[/red] -- see `bbhunter findings`, verify manually before drafting a PoC")
    else:
        console.print("[green]no candidate[/green] -- either properly denied, or the baseline request as the "
                       "authorized identity itself didn't succeed (check --authorized-header/the URL)")


def _coerce_field_value(raw: str):
    """Best-effort type coercion for a CLI-supplied field value, so
    `--field isAdmin=true` produces a real JSON boolean rather than the
    literal string "true"."""
    if raw.lower() in ("true", "false"):
        return raw.lower() == "true"
    try:
        return int(raw)
    except ValueError:
        pass
    try:
        return float(raw)
    except ValueError:
        pass
    return raw


@app.command(name="test-mass-assignment")
def test_mass_assignment_cmd(
    key: str,
    url: str = typer.Option(..., "--url", help="A resource URL you own/control and are fine mutating, e.g. https://target/api/profile/42"),
    owner_header: list[str] = typer.Option(
        ..., "--owner-header", help="'Key: Value' auth header for the identity that owns this resource, repeatable"
    ),
    field: str = typer.Option(..., "--field", help="One 'name=value' pair to attempt to inject, e.g. isAdmin=true"),
    confirm_disposable: bool = typer.Option(
        False, "--confirm-disposable",
        help="Required. Confirms this exact resource is one you own/control and accept the risk of an "
             "imperfect revert on -- this check sends a real write.",
    ),
    owner_note: str | None = typer.Option(None, "--owner-note", help="How you know you own/control this resource"),
):
    """THE ONE CHECK IN THIS PROJECT THAT SENDS A REAL WRITE. Sends one
    PATCH adding a privileged field to a resource you confirm you own,
    checks whether it stuck, and attempts a best-effort revert (not
    guaranteed -- read the finding's evidence for the actual outcome).
    Requires its own separate `approve-active --test-type
    mass_assignment_probe` decision, distinct from every other active
    check on this program. Never run this against a resource you don't
    personally control."""
    if not confirm_disposable:
        console.print(
            "[red]refusing[/red]: --confirm-disposable is required. This check sends a real, state-changing "
            "PATCH request to the exact URL given, then attempts a best-effort (not guaranteed) revert. "
            "Only pass this flag if you own/control this specific resource and accept that risk."
        )
        raise typer.Exit(1)

    if "=" not in field:
        console.print(f"[red]invalid --field[/red]: {field!r} (expected 'name=value')")
        raise typer.Exit(1)
    field_name, _, raw_value = field.partition("=")
    field_value = _coerce_field_value(raw_value)

    program = get_program(key)
    if not program:
        console.print(f"[red]not found[/red]: {key}")
        raise typer.Exit(1)

    if not program.rules.permits(TestType.MASS_ASSIGNMENT_PROBE):
        console.print(
            f"[red]blocked[/red]: {key} does not permit mass assignment testing. Run `bbhunter review-rules` "
            "then `bbhunter approve-active --test-type mass_assignment_probe --note \"...\"` if the policy "
            "actually allows write-capable testing -- this is separate from active_low_impact approval."
        )
        raise typer.Exit(1)

    owner_headers = _parse_headers(owner_header)

    console.print(
        f"[yellow]warning[/yellow]: sending a real PATCH to {url} with field '{field_name}' = {field_value!r}, "
        "then attempting a best-effort revert (up to 4 requests total)..."
    )
    new_findings = run_mass_assignment_check(program, url, owner_headers, field_name, field_value, owner_note=owner_note)
    for finding in new_findings:
        upsert_finding(finding)
    _log_test_run(key, TestType.MASS_ASSIGNMENT_PROBE, len(new_findings), f"mass-assignment probe on {url} (field: {field_name})")
    if new_findings:
        console.print(
            "[red]candidate found[/red] -- see `bbhunter findings`, read the evidence for the revert outcome "
            "before doing anything else with this resource"
        )
    else:
        console.print("[green]no candidate[/green] -- the field was rejected, didn't stick, or the baseline "
                       "request itself didn't succeed (check --owner-header/the URL)")


@app.command(name="test-discovery")
def test_discovery_cmd(
    key: str,
    wordlist: str | None = typer.Option(
        None, "--wordlist",
        help="'small'/'common'/'medium'/'large' (SecLists shorthand, see README Setup for the clone "
             "command), a SecLists-relative path, or an absolute path to your own wordlist. Defaults to "
             "SecLists' common.txt if SecLists is cloned, else a small built-in list. Bigger wordlist = "
             "more requests -- see the risk warning printed by `approve-active` for this tier.",
    ),
):
    """High-volume content discovery (`ffuf`) + hidden-parameter fuzzing
    (`arjun`) -- hundreds to low-thousands of requests, unlike every
    other check in this project. Requires its own
    `approve-active --test-type aggressive_discovery --i-understand-the-risk`
    decision, separate from every other active-testing tier."""
    program = get_program(key)
    if not program:
        console.print(f"[red]not found[/red]: {key}")
        raise typer.Exit(1)

    if not program.rules.permits(TestType.AGGRESSIVE_DISCOVERY):
        console.print(
            f"[red]blocked[/red]: {key} does not permit aggressive discovery. Run `bbhunter review-rules` "
            "then `bbhunter approve-active --test-type aggressive_discovery --i-understand-the-risk "
            "--note \"...\"` if the policy actually allows high-volume automated fuzzing -- this is "
            "separate from active_low_impact approval."
        )
        raise typer.Exit(1)

    recon_result = get_recon_result(key)
    hosts = _select_hosts(program, recon_result)[:MAX_DISCOVERY_HOSTS_PER_PROGRAM]
    resolved_path, _ = resolve_wordlist(wordlist)
    word_count = wordlist_line_count(resolved_path)
    console.print(
        f"[yellow]warning[/yellow]: wordlist {resolved_path} ({word_count} entries) against "
        f"{len(hosts)} host(s) -- up to {word_count * len(hosts)} ffuf request(s) at "
        f"{FFUF_RATE_PER_SECOND}/s, plus one arjun run per host..."
    )
    new_findings = run_aggressive_discovery(program, recon_result, wordlist=wordlist)
    for finding in new_findings:
        upsert_finding(finding)
    _log_test_run(
        key, TestType.AGGRESSIVE_DISCOVERY, len(new_findings),
        f"ffuf content discovery (wordlist: {resolved_path}, {word_count} entries) + arjun param fuzzing",
    )
    if new_findings:
        console.print(f"[red]{len(new_findings)} candidate(s) found[/red] -- see `bbhunter findings`")
    else:
        console.print("[green]no candidates[/green] (or ffuf/arjun aren't installed -- see README.md Setup)")


@app.command(name="test-sqli")
def test_sqli_cmd(
    key: str,
    url: str = typer.Option(..., "--url", help="A parameter-bearing URL to run sqlmap against, e.g. https://target/search?q=1"),
    dump: bool = typer.Option(
        False, "--dump",
        help=f"Also extract up to {SQLMAP_DUMP_ROW_LIMIT} row(s) of real data (sqlmap --dump, capped). "
             "Without this flag, sqlmap only confirms the injection + pulls the DB banner/current-db name -- "
             "no application data is extracted.",
    ),
):
    """sqlmap-driven confirmation (and, with --dump, bounded extraction)
    of a SQL injection -- past `test-active --injection`'s own single-
    quote signature probe. Requires its own
    `approve-active --test-type sqli_exploitation --i-understand-the-risk`
    decision."""
    program = get_program(key)
    if not program:
        console.print(f"[red]not found[/red]: {key}")
        raise typer.Exit(1)

    if not program.rules.permits(TestType.SQLI_EXPLOITATION):
        console.print(
            f"[red]blocked[/red]: {key} does not permit SQLi exploitation. Run `bbhunter review-rules` then "
            "`bbhunter approve-active --test-type sqli_exploitation --i-understand-the-risk --note \"...\"` "
            "if the policy actually allows this -- separate from active_low_impact approval."
        )
        raise typer.Exit(1)

    console.print(f"[yellow]warning[/yellow]: running sqlmap against {url}{' with --dump' if dump else ''}...")
    new_findings = run_sqli_exploitation(program, url, dump=dump)
    for finding in new_findings:
        upsert_finding(finding)
    _log_test_run(key, TestType.SQLI_EXPLOITATION, len(new_findings), f"sqlmap against {url}" + (" (--dump)" if dump else ""))
    if new_findings:
        console.print("[red]confirmed[/red] -- see `bbhunter findings`, read the evidence before doing anything else")
    else:
        console.print("[green]nothing confirmed[/green] (or sqlmap isn't installed -- see README.md Setup)")


@app.command(name="test-credentials")
def test_credentials_cmd(
    key: str,
    login_url: str = typer.Option(..., "--login-url", help="The login endpoint to POST credentials to"),
    username_field: str = typer.Option(..., "--username-field", help="Form field name for the username, e.g. 'email'"),
    password_field: str = typer.Option(..., "--password-field", help="Form field name for the password"),
    credential: list[str] = typer.Option(
        ..., "--credential",
        help="One 'username:password' pair to test, repeatable, capped at "
             f"{MAX_CREDENTIALS_PER_RUN}. Must be your own test account(s) or ones the program explicitly "
             "provided -- never invented/guessed.",
    ),
    success_signature: str | None = typer.Option(
        None, "--success-signature", help="A string that only appears on a successful-login response, e.g. 'dashboard'"
    ),
    failure_signature: str | None = typer.Option(
        None, "--failure-signature", help="A string that only appears on a failed-login response, e.g. 'invalid password'"
    ),
):
    """Tests a small, explicit credential list against a login endpoint
    -- never an open-ended wordlist brute force. Requires its own
    `approve-active --test-type credential_testing --i-understand-the-risk`
    decision. Stops immediately on any lockout/rate-limit signal."""
    program = get_program(key)
    if not program:
        console.print(f"[red]not found[/red]: {key}")
        raise typer.Exit(1)

    if not program.rules.permits(TestType.CREDENTIAL_TESTING):
        console.print(
            f"[red]blocked[/red]: {key} does not permit credential testing. Run `bbhunter review-rules` then "
            "`bbhunter approve-active --test-type credential_testing --i-understand-the-risk --note \"...\"` "
            "if the policy explicitly names credential/login testing as permitted."
        )
        raise typer.Exit(1)

    try:
        pairs = []
        for c in credential:
            if ":" not in c:
                raise typer.BadParameter(f"expected 'username:password', got {c!r}")
            username, _, password = c.partition(":")
            pairs.append((username, password))
    except typer.BadParameter as e:
        console.print(f"[red]invalid --credential[/red]: {e}")
        raise typer.Exit(1)

    console.print(f"[yellow]warning[/yellow]: testing {len(pairs)} credential pair(s) against {login_url}...")
    try:
        new_findings = run_credential_test(
            program, login_url, username_field, password_field, pairs,
            success_signature=success_signature, failure_signature=failure_signature,
        )
    except ValueError as e:
        console.print(f"[red]refused[/red]: {e}")
        raise typer.Exit(1)
    for finding in new_findings:
        upsert_finding(finding)
    _log_test_run(key, TestType.CREDENTIAL_TESTING, len(new_findings), f"credential test on {login_url} ({len(pairs)} pair(s))")
    if new_findings:
        console.print("[red]result(s) found[/red] -- see `bbhunter findings`, verify manually before drafting a PoC")
    else:
        console.print("[green]no hits[/green] -- none of the tested credentials looked successful")


@app.command(name="test-exploit")
def test_exploit_cmd(
    key: str,
    url: str = typer.Option(..., "--url", help="A parameter-bearing URL to run commix against, e.g. https://target/ping?host=1"),
):
    """commix-driven command-execution confirmation -- a single benign
    `echo <marker>` via `--os-cmd`, never an interactive/persistent
    shell. Requires its own
    `approve-active --test-type exploitation_framework --i-understand-the-risk`
    decision."""
    program = get_program(key)
    if not program:
        console.print(f"[red]not found[/red]: {key}")
        raise typer.Exit(1)

    if not program.rules.permits(TestType.EXPLOITATION_FRAMEWORK):
        console.print(
            f"[red]blocked[/red]: {key} does not permit exploitation-framework testing. Run "
            "`bbhunter review-rules` then `bbhunter approve-active --test-type exploitation_framework "
            "--i-understand-the-risk --note \"...\"` if the policy actually allows proof-of-concept "
            "exploitation to this depth."
        )
        raise typer.Exit(1)

    console.print(f"[yellow]warning[/yellow]: running commix against {url} (single benign echo command only)...")
    new_findings = run_exploit_framework_check(program, url)
    for finding in new_findings:
        upsert_finding(finding)
    _log_test_run(key, TestType.EXPLOITATION_FRAMEWORK, len(new_findings), f"commix against {url}")
    if new_findings:
        console.print(
            "[red]command execution confirmed[/red] -- see `bbhunter findings`. Stop here, do not "
            "escalate -- report what was confirmed."
        )
    else:
        console.print("[green]nothing confirmed[/green] (or commix isn't installed -- see README.md Setup)")


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
    """Record that you personally reproduced and verified this finding.
    Refuses -- in code, not just by convention -- if the PoC file's
    Reproduction steps or Impact section still has an unfilled TODO:
    this is the actual anti-hallucination gate, not `draft-report`'s
    later re-check of the same thing, since a finding could otherwise
    sit at `POC_APPROVED` with nothing real ever written down."""
    finding = get_finding(finding_id)
    if not finding:
        console.print(f"[red]not found[/red]: {finding_id}")
        raise typer.Exit(1)
    if finding.status != FindingStatus.POC_DRAFTED:
        console.print(f"[red]blocked[/red]: status is {finding.status.value}, not poc_drafted")
        raise typer.Exit(1)
    if not finding.poc_path or not Path(finding.poc_path).exists():
        console.print(f"[red]blocked[/red]: no PoC file on record at {finding.poc_path!r}")
        raise typer.Exit(1)
    if poc_has_unfilled_todos(finding.poc_path):
        console.print(
            f"[red]refusing[/red]: {finding.poc_path} still has an unfilled TODO in Reproduction "
            "steps or Impact. Write the actual reproduction steps and impact -- based on real, "
            "personal verification, not speculation -- before approving this."
        )
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
