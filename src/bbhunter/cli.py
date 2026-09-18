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
    submit_report,
)
from bbhunter.testing import run_active_checks
from bbhunter.testing.ai_safety import run_ai_safety_probes
from bbhunter.testing.idor import run_bfla_check, run_idor_check
from bbhunter.testing.mass_assignment import run_mass_assignment_check
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
        if recon_result.subfinder_failures:
            failures.append(f"subfinder failed for {len(recon_result.subfinder_failures)} seed(s)")
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
    result, findings = run_passive_recon(program, max_subdomains_per_seed=max_subdomains_per_seed)
    upsert_recon_result(result)
    for finding in findings:
        upsert_finding(finding)
    _log_test_run(
        key, TestType.PASSIVE_RECON, len(findings),
        f"{result.seeds_processed}/{result.seeds_total} seed(s), {len(result.fingerprints)} host(s) fingerprinted"
        f"{'' if result.complete else ' (interrupted)'}",
    )

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
        help="Also run the `nuclei` binary with a curated template set: misconfig/exposure/tech/cve plus "
             "cors/ssrf/jwt/graphql/takeover/ssti/xxe/host-header/prototype-pollution/redirect (rce/sqli/"
             "dos/intrusive/fuzz/bruteforce/hijack/default-login/auth-bypass tags excluded), rate-limited "
             "to 1 req/s. Requires `nuclei` installed (see README) and is skipped silently otherwise. Same "
             "gate as --injection.",
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
