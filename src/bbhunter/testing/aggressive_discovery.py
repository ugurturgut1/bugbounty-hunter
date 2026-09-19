"""TestType.AGGRESSIVE_DISCOVERY -- high-volume content-discovery (`ffuf`)
and hidden-parameter fuzzing (`arjun`). Unlike every other check in this
project (single-request/low-volume, see testing/active.py's own module
docstring), these two genuinely send hundreds to low-thousands of
requests to the target. That is exactly why this is its own TestType,
gated by its own `approve-active --test-type aggressive_discovery
--i-understand-the-risk` decision (see cli.py's `_RISK_WARNINGS`) rather
than folded into `ACTIVE_LOW_IMPACT` -- a program's policy permitting
"safe single-request probes" does not automatically also permit a
high-volume fuzzing run, and this module never assumes it does.

Both tools are optional external binaries, same `_tool_path`/graceful-
skip contract as subfinder/httpx/nuclei/assetfinder/dnsx elsewhere in
this project: `None` back from the runner means "binary not installed
or the run failed," never "found nothing."

Rate is capped well below both tools' own defaults
(`FFUF_RATE_PER_SECOND`/`FFUF_THREADS`) -- this still isn't "safe" in
the way a single canary request is, which is the entire reason it needs
its own approval tier, but it isn't run at the tools' full, aggressive
defaults either.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path

from bbhunter.models import Finding, FindingStatus, Program, ReconResult, RulesOfEngagement, TestType
from bbhunter.recon.passive import _request_headers, _tool_path
from bbhunter.testing.active import _select_hosts

MAX_DISCOVERY_HOSTS_PER_PROGRAM = 10  # narrower than MAX_HOSTS_PER_PROGRAM -- each host here costs
                                       # hundreds-thousands of requests, not one

FFUF_TIMEOUT_SECONDS = 300
FFUF_RATE_PER_SECOND = 5  # requests/sec -- conservative, well below ffuf's own (unlimited) default
FFUF_THREADS = 5
FFUF_REQUEST_TIMEOUT_SECONDS = 10
FFUF_MATCH_CODES = "200,204,301,302,307,401,403"
MAX_FFUF_RESULTS = 100

ARJUN_TIMEOUT_SECONDS = 180
ARJUN_THREADS = 5

# A small, curated set of common paths -- not meant to be exhaustive (this is not SecLists).
# Set BBHUNTER_FFUF_WORDLIST to an absolute path to use a bigger/custom wordlist instead;
# falls back to this built-in list if unset or unreadable.
_DEFAULT_WORDLIST = [
    ".env", ".env.local", ".env.production", ".git/config", ".git/HEAD", ".svn/entries",
    ".DS_Store", ".htaccess", ".htpasswd", "web.config", "docker-compose.yml", "Dockerfile",
    "backup.sql", "backup.zip", "backup.tar.gz", "dump.sql", "database.sql",
    "admin", "admin/", "administrator", "admin.php", "admin/login", "login", "login.php",
    "wp-admin", "wp-login.php", "wp-config.php.bak", "phpinfo.php", "info.php", "test.php",
    "api", "api/", "api/v1", "api/v2", "api/docs", "swagger.json", "swagger-ui.html",
    "openapi.json", "graphql", "graphiql", "actuator", "actuator/health", "actuator/env",
    "metrics", "debug", "status", "health", "healthz", "server-status", "server-info",
    "console", "console/", "shell", "cgi-bin/", "config.php", "config.json", "config.yml",
    "settings.py", "web.xml", "crossdomain.xml", "sitemap.xml", "robots.txt",
    "phpmyadmin/", "adminer.php", "elmah.axd", "trace.axd", "_profiler", "telescope",
    "vendor/", "node_modules/", "composer.json", "package.json", "package-lock.json",
    ".well-known/security.txt", "storage/logs/laravel.log", "app.log", "error.log",
    "uploads/", "files/", "static/", "assets/", "tmp/", "temp/", "cache/",
    "v1/users", "v1/admin", "v2/users", "internal", "internal-api", "private",
]


def _wordlist_path() -> tuple[str, bool]:
    """Returns (path, is_temp_file) -- caller unlinks the file only when
    `is_temp_file` is True. `BBHUNTER_FFUF_WORDLIST` lets a user point at
    a bigger/custom list they already have; falls back to the small
    built-in one above if unset or unreadable."""
    custom = os.environ.get("BBHUNTER_FFUF_WORDLIST")
    if custom and os.path.isfile(custom):
        return custom, False
    fd, path = tempfile.mkstemp(suffix=".txt", prefix="bbhunter-wordlist-")
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(_DEFAULT_WORDLIST))
    return path, True


def run_ffuf_discovery(
    host: str, rules: RulesOfEngagement, *, timeout: float = FFUF_TIMEOUT_SECONDS
) -> list[dict] | None:
    """One `ffuf` run against `https://{host}/FUZZ`, matching only the
    status codes in `FFUF_MATCH_CODES`. Returns a list of hit dicts (kind/
    severity/evidence, same shape everything else in this project uses),
    or `None` if the binary is missing or the run failed -- callers must
    fall back accordingly, never treat `None` as "found nothing"."""
    binary = _tool_path("ffuf")
    if not binary:
        return None

    wordlist, wordlist_is_temp = _wordlist_path()
    out_fd, out_path = tempfile.mkstemp(suffix=".json", prefix="bbhunter-ffuf-")
    os.close(out_fd)

    headers = _request_headers(rules)
    header_args: list[str] = []
    for key, value in headers.items():
        header_args += ["-H", f"{key}: {value}"]

    try:
        subprocess.run(
            [
                binary, "-u", f"https://{host}/FUZZ", "-w", wordlist,
                "-mc", FFUF_MATCH_CODES, "-rate", str(FFUF_RATE_PER_SECOND),
                "-t", str(FFUF_THREADS), "-timeout", str(FFUF_REQUEST_TIMEOUT_SECONDS),
                "-o", out_path, "-of", "json", "-s",
            ] + header_args,
            capture_output=True,
            timeout=timeout,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    finally:
        if wordlist_is_temp:
            Path(wordlist).unlink(missing_ok=True)

    try:
        with open(out_path) as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    finally:
        Path(out_path).unlink(missing_ok=True)

    hits: list[dict] = []
    for result in (data.get("results") or [])[:MAX_FFUF_RESULTS]:
        url = result.get("url")
        status = result.get("status")
        length = result.get("length")
        hits.append(
            {
                "kind": "content-discovery-hit",
                "url": url,
                "severity": "info",
                "evidence": (
                    f"ffuf content discovery found {url} -> HTTP {status} ({length} bytes). Not "
                    "reachable via passive recon's own crawling/Wayback data -- worth a manual look at "
                    "what it exposes before deciding whether it's a real finding."
                ),
            }
        )
    return hits


def run_arjun_discovery(url: str, *, timeout: float = ARJUN_TIMEOUT_SECONDS) -> list[str] | None:
    """One `arjun` run against `url`, discovering hidden GET parameter
    names via its own wordlist-based brute force. Returns the sorted
    list of discovered parameter names (feed these into
    `testing/active.py`'s `_check_injection_signals` manually against
    `url?paramname=x` for further signature-based detection -- this
    module only discovers parameter names, it never itself sends an
    injection payload), or `None` if the binary is missing or the run
    failed."""
    binary = _tool_path("arjun")
    if not binary:
        return None

    out_fd, out_path = tempfile.mkstemp(suffix=".json", prefix="bbhunter-arjun-")
    os.close(out_fd)
    try:
        subprocess.run(
            [binary, "-u", url, "-oJ", out_path, "-t", str(ARJUN_THREADS)],
            capture_output=True,
            timeout=timeout,
        )
    except (subprocess.SubprocessError, OSError):
        return None

    try:
        with open(out_path) as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    finally:
        Path(out_path).unlink(missing_ok=True)

    params: set[str] = set()
    for entry in data.values() if isinstance(data, dict) else []:
        if isinstance(entry, dict):
            params.update(entry.get("params") or [])
    return sorted(params)


def run_aggressive_discovery(program: Program, recon_result: ReconResult | None = None) -> list[Finding]:
    """`bbhunter test-discovery` entry point. Requires
    `permits(TestType.AGGRESSIVE_DISCOVERY)` -- the same
    `approve-active --test-type aggressive_discovery --i-understand-the-risk`
    decision described in cli.py's `_RISK_WARNINGS`, never anything a
    heuristic can grant itself. Runs `run_ffuf_discovery` against a
    capped host list (`MAX_DISCOVERY_HOSTS_PER_PROGRAM`, narrower than
    the low-impact checks' own host cap since each host here costs far
    more requests), then `run_arjun_discovery` against the same hosts'
    root URL. Silently skips whichever tool isn't installed -- see each
    function's own docstring."""
    if not program.rules.permits(TestType.AGGRESSIVE_DISCOVERY):
        raise RuntimeError(
            f"{program.key}: aggressive discovery blocked by rules.permits() -- run `bbhunter review-rules` "
            "and `bbhunter approve-active --test-type aggressive_discovery --i-understand-the-risk` first"
        )

    hosts = _select_hosts(program, recon_result)[:MAX_DISCOVERY_HOSTS_PER_PROGRAM]
    findings: list[Finding] = []

    for host in hosts:
        for hit in run_ffuf_discovery(host, program.rules) or []:
            digest = hashlib.sha256(f"{host}:{hit['url']}".encode()).hexdigest()[:12]
            findings.append(
                Finding(
                    id=f"{program.key}:{digest}",
                    program_key=program.key,
                    asset=host,
                    title=f"Content discovery hit: {hit['url']}",
                    vuln_class=hit["kind"],
                    test_type=TestType.AGGRESSIVE_DISCOVERY,
                    evidence=hit["evidence"],
                    status=FindingStatus.CANDIDATE,
                    notes=f"severity guess: {hit['severity']} -- verify manually before drafting a PoC",
                )
            )

        params = run_arjun_discovery(f"https://{host}/") or []
        if params:
            digest = hashlib.sha256(f"{host}:arjun:{','.join(params)}".encode()).hexdigest()[:12]
            findings.append(
                Finding(
                    id=f"{program.key}:{digest}",
                    program_key=program.key,
                    asset=host,
                    title=f"Hidden parameter(s) discovered: {', '.join(params[:10])}",
                    vuln_class="hidden-parameter-discovery",
                    test_type=TestType.AGGRESSIVE_DISCOVERY,
                    evidence=(
                        f"arjun discovered {len(params)} hidden GET parameter(s) on https://{host}/: "
                        f"{', '.join(params)}. Not an injection finding by itself -- worth manually "
                        "re-testing each one (e.g. `bbhunter test-active --injection` after adding it to "
                        "a Wayback-style param URL) for the signature-based checks elsewhere in this "
                        "project."
                    ),
                    status=FindingStatus.CANDIDATE,
                    notes="severity guess: info -- verify manually before drafting a PoC",
                )
            )

    return findings
