"""Phase 3: active testing.

The original checks here are read-only misconfig/exposed-file probes --
no injection payloads, no state-changing requests. A second, opt-in
class added later (`injection=True`) still only ever sends single-request,
signature-based detection probes (an HTML-special-char canary for
reflected XSS, a single quote for a SQL-error signature) against
Wayback-discovered URLs that already carry query parameters -- never a
boolean/time-based blind technique, never more than one marker per
request, never any follow-through past detection. This is the
"safe XSS/SQLi probes" class TestType.ACTIVE_LOW_IMPACT's own docstring
in models.py already scopes for -- it is not a new permission level.

Everything in this module only runs when
RulesOfEngagement.permits(TestType.ACTIVE_LOW_IMPACT) is True, which
requires an explicit recorded human decision (see cli.py `review-rules`
/ `approve-active`) -- never something this module, any heuristic, or
automation driving this CLI can unlock on its own.

The exposed-file checks are gated behind a soft-404 baseline: many sites
return HTTP 200 with a generic page for ANY path, and naively flagging
"status == 200" on those would be pure noise. We fetch one random
nonexistent path first and only flag a candidate if its response is
both 200, meaningfully different in size from that baseline, AND its
body matches a signature specific to the file we're checking for. The
injection checks use the same per-URL baseline idea: a SQL-error
signature only counts if it's present in the mutated response and
absent from the unmutated one.

If a ReconResult is passed in, subdomains recon already discovered under
a WILDCARD-scoped seed asset are tested too, since a wildcard entry
covers them by definition -- a plain URL-type seed asset only ever
tests that exact host, since a sibling subdomain found by recon is not
automatically in scope just because it resolves under the same domain.
Injection probes are scoped identically: only URLs whose host is
already in that same selected-hosts set are ever tested, even though
`ReconResult.param_urls` itself is keyed by seed host, not by the
individual URLs' own hosts.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import subprocess
import time
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from bbhunter.models import AssetType, Finding, FindingStatus, Program, ReconResult, RulesOfEngagement, TestType
from bbhunter.recon.passive import _extract_host, _request_headers, _tool_path

# Curated for TestType.ACTIVE_LOW_IMPACT: detection-only template classes.
# Explicitly excludes anything nuclei itself tags as higher-impact --
# denial-of-service-adjacent, fuzzing, credential brute-forcing, session
# hijacking -- regardless of what -tags would otherwise pull in.
NUCLEI_TAGS = "misconfig,exposure,tech,cve"
NUCLEI_EXCLUDE_TAGS = "dos,intrusive,fuzz,bruteforce,hijack"
NUCLEI_RATE_LIMIT_PER_SECOND = 1  # matches this module's own REQUEST_DELAY_SECONDS pacing philosophy, not nuclei's much higher default
NUCLEI_RUN_TIMEOUT_SECONDS = 900  # whole-run cap across every host handed to a single nuclei invocation

REQUEST_DELAY_SECONDS = 1.5
MAX_HOSTS_PER_PROGRAM = 40
MAX_SUBDOMAINS_PER_WILDCARD_SEED = 5  # keeps one large wildcard seed from eating the whole per-program budget
MAX_INJECTION_URLS_PER_PROGRAM = 30  # each URL costs 3 requests (baseline + xss + sqli probe) at REQUEST_DELAY_SECONDS pacing

_SQL_ERROR_SIGNATURES = [
    "sql syntax",
    "mysql_fetch",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlstate",
    "ora-01756",
    "ora-00933",
    "pg_query(): query failed",
    "postgresql query failed",
    "microsoft odbc",
    "sqlite3.operationalerror",
    "syntax error in sql statement",
    "npgsql.postgresexception",
    "system.data.sqlclient.sqlexception",
]

# path -> (title, signature substrings that must appear in the body for a real hit, severity)
_CHECKS: dict[str, tuple[str, tuple[str, ...], str]] = {
    "/.git/config": ("Exposed .git/config", ("[core]", "repositoryformatversion"), "medium"),
    "/.git/HEAD": ("Exposed .git/HEAD", ("ref:",), "medium"),
    "/.env": ("Exposed .env file", ("=",), "high"),
    "/.env.local": ("Exposed .env.local file", ("=",), "high"),
    "/.aws/credentials": ("Exposed AWS credentials file", ("aws_access_key_id", "[default]"), "critical"),
    "/wp-config.php.bak": ("Exposed WordPress config backup", ("db_name", "<?php"), "high"),
    "/config.php.bak": ("Exposed PHP config backup", ("<?php",), "high"),
    "/.svn/entries": ("Exposed .svn/entries", ("svn",), "medium"),
    "/docker-compose.yml": ("Exposed docker-compose.yml", ("version:", "services:"), "medium"),
    "/backup.sql": ("Exposed SQL backup", ("insert into", "create table"), "high"),
    "/actuator/env": ("Exposed Spring Boot actuator env", ("propertysources", "systemproperties"), "high"),
    "/server-status": ("Exposed Apache mod_status", ("apache server status",), "low"),
    "/phpinfo.php": ("Exposed phpinfo()", ("phpinfo()", "php version"), "medium"),
}

_SECURITY_HEADERS = [
    "content-security-policy",
    "x-frame-options",
    "strict-transport-security",
    "x-content-type-options",
]


def _baseline(client: httpx.Client, host: str) -> tuple[int, int] | None:
    probe_path = f"/bbhunter-baseline-{secrets.token_hex(8)}"
    try:
        resp = client.get(f"https://{host}{probe_path}", timeout=15, follow_redirects=True)
        return resp.status_code, len(resp.content)
    except httpx.HTTPError:
        return None


def _check_host(client: httpx.Client, host: str) -> list[dict]:
    hits: list[dict] = []
    baseline = _baseline(client, host)
    time.sleep(REQUEST_DELAY_SECONDS)

    for path, (title, signatures, severity) in _CHECKS.items():
        try:
            resp = client.get(f"https://{host}{path}", timeout=15, follow_redirects=True)
        except httpx.HTTPError:
            time.sleep(REQUEST_DELAY_SECONDS)
            continue
        time.sleep(REQUEST_DELAY_SECONDS)

        if resp.status_code != 200:
            continue
        if baseline and baseline[0] == 200 and abs(len(resp.content) - baseline[1]) < 32:
            continue  # looks like the same soft-404 page as the baseline probe
        body_lower = resp.text.lower()
        if not any(sig.lower() in body_lower for sig in signatures):
            continue

        hits.append(
            {
                "path": path,
                "title": title,
                "severity": severity,
                "status_code": resp.status_code,
                "url": str(resp.url),
            }
        )

    try:
        resp = client.get(f"https://{host}/", timeout=15, follow_redirects=True)
        present = {k.lower() for k in resp.headers}
        missing = [h for h in _SECURITY_HEADERS if h not in present]
        if missing:
            hits.append(
                {
                    "path": "/",
                    "title": f"Missing security headers: {', '.join(missing)}",
                    "severity": "info",
                    "status_code": resp.status_code,
                    "url": str(resp.url),
                }
            )
    except httpx.HTTPError:
        pass
    time.sleep(REQUEST_DELAY_SECONDS)

    return hits


def _replace_param(parts, params: list[tuple[str, str]], index: int, new_value: str) -> str:
    mutated = list(params)
    mutated[index] = (mutated[index][0], new_value)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(mutated), parts.fragment))


def _check_injection_signals(client: httpx.Client, url: str) -> list[dict]:
    """One baseline request plus, per query parameter, one reflected-XSS
    probe and one SQL-error-signature probe -- three requests total per
    parameter-bearing path, never more. Returns a list of hit dicts;
    empty if nothing fired or the URL couldn't be parsed/fetched."""
    hits: list[dict] = []
    parts = urlsplit(url)
    params = parse_qsl(parts.query, keep_blank_values=True)
    if not params:
        return hits

    try:
        baseline = client.get(url, timeout=15, follow_redirects=True)
    except httpx.HTTPError:
        return hits
    time.sleep(REQUEST_DELAY_SECONDS)
    baseline_body = baseline.text.lower()

    for i, (name, value) in enumerate(params):
        xss_canary = f"bbh{secrets.token_hex(4)}<>\"'"
        xss_url = _replace_param(parts, params, i, value + xss_canary)
        try:
            resp = client.get(xss_url, timeout=15, follow_redirects=True)
        except httpx.HTTPError:
            resp = None
        time.sleep(REQUEST_DELAY_SECONDS)
        if resp is not None and xss_canary in resp.text:
            hits.append(
                {
                    "kind": "reflected-xss-candidate",
                    "param": name,
                    "url": str(resp.url),
                    "severity": "medium",
                    "evidence": (
                        f"GET {resp.url} -> parameter '{name}' reflected the canary "
                        f"'{xss_canary}' unescaped (raw '<', '>', '\"', \"'\" all came back verbatim). "
                        "Signature-only detection -- verify it actually breaks out of the surrounding "
                        "markup/attribute context before treating this as exploitable."
                    ),
                }
            )

        sqli_url = _replace_param(parts, params, i, value + "'")
        try:
            resp = client.get(sqli_url, timeout=15, follow_redirects=True)
        except httpx.HTTPError:
            resp = None
        time.sleep(REQUEST_DELAY_SECONDS)
        if resp is not None:
            body_lower = resp.text.lower()
            sig = next((s for s in _SQL_ERROR_SIGNATURES if s in body_lower and s not in baseline_body), None)
            if sig:
                hits.append(
                    {
                        "kind": "sql-error-signature",
                        "param": name,
                        "url": str(resp.url),
                        "severity": "high",
                        "evidence": (
                            f"GET {resp.url} -> appending a single quote to parameter '{name}' produced "
                            f"database-error signature '{sig}' in the response body, absent from the "
                            "unmutated baseline request. Single-quote probe only -- no extraction attempted; "
                            "verify manually and check whether the program's policy permits going further."
                        ),
                    }
                )

    return hits


def run_nuclei_scan(
    hosts: list[str], rules: RulesOfEngagement, *, timeout: float = NUCLEI_RUN_TIMEOUT_SECONDS
) -> list[dict] | None:
    """Runs the `nuclei` binary once against every host, restricted to
    NUCLEI_TAGS/NUCLEI_EXCLUDE_TAGS and rate-limited to
    NUCLEI_RATE_LIMIT_PER_SECOND with a single connection (`-bulk-size 1
    -c 1`) -- deliberately far below nuclei's own defaults, matching how
    conservative every other check in this module already is. Honors
    the program's required User-Agent/header the same way every other
    live request here does. Returns None if the binary isn't installed
    or the run itself errors/times out -- callers must treat that as
    "skip this source", never as "zero findings". An empty list is a
    genuine "ran, found nothing"."""
    binary = _tool_path("nuclei")
    if not binary or not hosts:
        return None

    headers = _request_headers(rules)
    header_args = []
    for key, value in headers.items():
        header_args += ["-H", f"{key}: {value}"]

    targets = "\n".join(f"https://{h}" for h in hosts)
    try:
        proc = subprocess.run(
            [
                binary,
                "-jsonl",
                "-silent",
                "-tags", NUCLEI_TAGS,
                "-etags", NUCLEI_EXCLUDE_TAGS,
                "-rate-limit", str(NUCLEI_RATE_LIMIT_PER_SECOND),
                "-bulk-size", "1",
                "-c", "1",
                "-timeout", "15",
            ]
            + header_args,
            input=targets,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (subprocess.SubprocessError, OSError):
        return None

    results: list[dict] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            results.append(json.loads(line))
        except ValueError:
            continue
    return results


def _select_hosts(program: Program, recon_result: ReconResult | None) -> list[str]:
    """Exact hosts from in-scope URL/WILDCARD assets, plus -- only for
    WILDCARD-type assets -- a capped slice of subdomains a prior recon
    run discovered under that seed. A plain URL entry only ever
    contributes its exact host: a sibling subdomain recon happened to
    find is not in scope just because it resolves under the same parent
    domain. The per-seed subdomain cap keeps one large wildcard from
    consuming the whole per-program host budget and starving every other
    seed asset of coverage."""
    hosts: list[str] = []
    for asset in program.in_scope:
        if asset.asset_type not in (AssetType.URL, AssetType.WILDCARD):
            continue
        host = _extract_host(asset.identifier)
        if not host:
            continue
        if host not in hosts:
            hosts.append(host)
        if asset.asset_type == AssetType.WILDCARD and recon_result:
            subdomains = recon_result.subdomains.get(host, [])[:MAX_SUBDOMAINS_PER_WILDCARD_SEED]
            for subdomain in subdomains:
                if subdomain not in hosts:
                    hosts.append(subdomain)
    return hosts[:MAX_HOSTS_PER_PROGRAM]


def run_active_checks(
    program: Program,
    recon_result: ReconResult | None = None,
    *,
    injection: bool = False,
    nuclei: bool = False,
) -> list[Finding]:
    """`injection=True` additionally runs the reflected-XSS/SQL-error-
    signature checks (see module docstring) against Wayback-discovered
    param URLs from `recon_result`. `nuclei=True` additionally runs the
    curated nuclei template set (see `run_nuclei_scan`) against the same
    selected hosts, skipped silently if the binary isn't installed. Both
    are gated by the exact same `permits(ACTIVE_LOW_IMPACT)` check as
    everything else here -- neither is a separate or higher permission
    tier, just a separate opt-in since each is a qualitatively different
    request shape worth a deliberate choice to include."""
    if not program.rules.permits(TestType.ACTIVE_LOW_IMPACT):
        raise RuntimeError(
            f"{program.key}: active testing blocked by rules.permits() -- run `bbhunter review-rules` "
            "and `bbhunter approve-active` first if this program's policy actually allows it"
        )

    headers = _request_headers(program.rules)
    hosts = _select_hosts(program, recon_result)
    host_set = set(hosts)

    findings: list[Finding] = []
    with httpx.Client(headers=headers) as client:
        for host in hosts:
            for hit in _check_host(client, host):
                findings.append(
                    Finding(
                        id=f"{program.key}:{host}:{hit['path']}",
                        program_key=program.key,
                        asset=host,
                        title=hit["title"],
                        vuln_class="exposure" if hit["severity"] != "info" else "hardening",
                        test_type=TestType.ACTIVE_LOW_IMPACT,
                        evidence=f"GET {hit['url']} -> HTTP {hit['status_code']}. Path: {hit['path']}.",
                        status=FindingStatus.CANDIDATE,
                        notes=f"severity guess: {hit['severity']} -- verify manually before drafting a PoC",
                    )
                )

        if injection and recon_result and recon_result.param_urls:
            injection_urls: list[str] = []
            for urls in recon_result.param_urls.values():
                for url in urls:
                    url_host = _extract_host(url)
                    if url_host in host_set and url not in injection_urls:
                        injection_urls.append(url)

            for url in injection_urls[:MAX_INJECTION_URLS_PER_PROGRAM]:
                for hit in _check_injection_signals(client, url):
                    digest = hashlib.sha256(f"{url}:{hit['param']}:{hit['kind']}".encode()).hexdigest()[:12]
                    findings.append(
                        Finding(
                            id=f"{program.key}:{digest}",
                            program_key=program.key,
                            asset=_extract_host(url) or url,
                            title=f"{hit['kind']} on parameter '{hit['param']}'",
                            vuln_class=hit["kind"],
                            test_type=TestType.ACTIVE_LOW_IMPACT,
                            evidence=hit["evidence"],
                            status=FindingStatus.CANDIDATE,
                            notes=f"severity guess: {hit['severity']} -- verify manually before drafting a PoC",
                        )
                    )

    if nuclei:
        nuclei_results = run_nuclei_scan(hosts, program.rules) or []
        for result in nuclei_results:
            info = result.get("info") or {}
            template_id = result.get("template-id", "unknown-template")
            matched_at = result.get("matched-at") or result.get("host") or ""
            digest = hashlib.sha256(f"{matched_at}:{template_id}".encode()).hexdigest()[:12]
            findings.append(
                Finding(
                    id=f"{program.key}:nuclei:{digest}",
                    program_key=program.key,
                    asset=_extract_host(matched_at) or matched_at,
                    title=f"nuclei: {info.get('name') or template_id}",
                    vuln_class=f"nuclei-{template_id}",
                    test_type=TestType.ACTIVE_LOW_IMPACT,
                    evidence=(
                        f"nuclei template '{template_id}' matched at {matched_at}. "
                        f"{(info.get('description') or '')[:400]}"
                    ),
                    status=FindingStatus.CANDIDATE,
                    notes=f"nuclei severity: {info.get('severity', 'unknown')} -- verify manually before drafting a PoC",
                )
            )

    return findings
