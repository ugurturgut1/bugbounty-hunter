"""Phase 3: active testing.

The original checks here are read-only misconfig/exposed-file probes --
no injection payloads, no state-changing requests. A second, opt-in
class added later (`injection=True`) still only ever sends single-request,
signature-based detection probes (an HTML-special-char canary for
reflected XSS, a single quote for a SQL-error signature, a JS-string-
breakout probe for a NoSQL/driver-error signature, a CRLF sequence
followed by a canary header name for CRLF/header-injection, and a benign
`echo <marker>` shell-canary for command injection) against Wayback-
discovered URLs that already carry query parameters, plus one
CVE-2014-6271 (Shellshock) `User-Agent` probe per selected host -- also
a benign `echo <marker>` canary, drawn from
docs/EXTERNAL_RESOURCES.md's mapping of EdOverflow's bugbounty-
cheatsheet per-class notes onto this project. Never a boolean/time-based
blind technique, never more than one marker per request per class,
never any follow-through past detection (every echo-based probe only
ever runs a no-op `echo`, nothing that reads, writes, or changes
anything). This is the "safe XSS/SQLi probes" class
TestType.ACTIVE_LOW_IMPACT's own docstring in models.py already scopes
for -- it is not a new permission level.

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

Exposed-file checks are also tech-stack-aware (`_detected_stacks`,
`_STACK_CHECKS`): a WordPress-specific check only runs against a host
recon's fingerprint data actually flagged as WordPress, rather than every
check running against every host regardless of what it's running. A host
with no fingerprint on file (e.g. `test-active` run without a prior
`recon`) still gets the stack-agnostic `_GENERIC_CHECKS` -- narrowing
never drops below that floor, it only adds more when there's a real
signal to add them on.
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
from bbhunter.testing.cloud_storage import check_cloud_buckets_for_name

# Curated for TestType.ACTIVE_LOW_IMPACT: detection-only template classes,
# chosen 2026-09-17 to close real gaps against OWASP Top 10 2021 (A10 SSRF)
# and the vuln classes that actually drive bug bounty payouts in practice
# (CORS misconfig, JWT weaknesses, GraphQL introspection, subdomain
# takeover, SSTI, XXE, host-header injection, prototype pollution,
# open-redirect -- all covered by nuclei's own vetted template set rather
# than reinventing detection logic for each). Every one of these
# categories' nuclei templates is single-request/signature-based, same as
# everything else in this module -- SSRF templates use an out-of-band
# interactsh callback to detect the request left the target, not a
# destructive payload.
#
# Explicitly excludes anything nuclei itself tags as higher-impact --
# denial-of-service-adjacent, fuzzing, credential brute-forcing/default
# logins, auth-bypass, session hijacking, remote code execution (many RCE
# templates actually execute a command like `id` to confirm, which is
# exploitation, not detection), and blind/time-based SQLi (this module's
# own SQLi coverage stays to the error-signature-only check in
# `_check_injection_signals`, deliberately never blind/time-based) --
# regardless of what -tags would otherwise pull in. IDOR, business-logic,
# and race-condition classes aren't included: they're inherently
# app-specific and not meaningfully templatable, so nuclei has near-zero
# real coverage for them anyway.
# `ssl`/`cache` added 2026-09-18, live-verified against the real nuclei-templates
# repo (v3.11.1): `-tags <old set>,ssl,cache -etags <same excludes>` matches 5,775
# templates vs. 5,727 without them (+48 net, after exclusions) -- a modest, real
# addition, not a noise bomb. `ssl` (61 templates) is a dedicated `ssl/` directory:
# expired/self-signed/revoked certs, deprecated TLS versions, insecure cipher
# suites, mismatched-hostname certs -- complements (doesn't duplicate) Phase 1's
# openssl-based TLS checks in recon/passive.py, which don't check cipher suites,
# TLS version, or revocation at all. `cache` (40 templates, mostly redundant with
# `cve` for WordPress-plugin CVEs already caught either way) pulls in the real
# net-new templates: generic cache-poisoning/cache-poisoning-xss and Next.js
# cache-poisoning detection -- a live, common bug-bounty-payout class. The single
# actual `cache-poisoning` tag (1 template) is too narrow on its own since the
# generic detection templates are tagged just `cache`. `NUCLEI_EXCLUDE_TAGS`
# still wins on overlap (confirmed: `cache-poisoning-fuzz.yaml` is tagged both
# `cache` and `fuzz` and stays excluded).
NUCLEI_TAGS = "misconfig,exposure,tech,cve,cors,ssrf,jwt,graphql,takeover,ssti,xxe,host-header,prototype-pollution,redirect,ssl,cache"
NUCLEI_EXCLUDE_TAGS = "dos,intrusive,fuzz,bruteforce,hijack,rce,sqli,default-login,authentication-bypass"
NUCLEI_RATE_LIMIT_PER_SECOND = 1  # matches this module's own REQUEST_DELAY_SECONDS pacing philosophy, not nuclei's much higher default
NUCLEI_RUN_TIMEOUT_SECONDS = 900  # whole-run cap across every host handed to a single nuclei invocation

REQUEST_DELAY_SECONDS = 1.5
MAX_HOSTS_PER_PROGRAM = 40
MAX_SUBDOMAINS_PER_WILDCARD_SEED = 5  # keeps one large wildcard seed from eating the whole per-program budget
MAX_INJECTION_URLS_PER_PROGRAM = 30  # each URL costs 6 requests (baseline + xss + sqli + nosqli + cmdi + crlf probe) at
                                      # REQUEST_DELAY_SECONDS pacing; separately, one Shellshock probe runs per selected host

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

# NoSQL drivers/ODMs surface a JS-eval or query-parse error rather than a SQL
# dialect error -- these come from MongoDB's $where JS evaluator, the driver
# itself, or Mongoose's schema validation, triggered by the same "break out of
# the value's string context" probe idea as the SQLi single-quote check above.
_NOSQL_ERROR_SIGNATURES = [
    "mongoerror",
    "mongoserverexception",
    "mongoserverselectionerror",
    "bsonerror",
    "syntaxerror: unexpected token",
    "unterminated string in json",
    "e11000 duplicate key",
]

# path -> (title, signature substrings that must appear in the body for a real hit, severity)
# Stack-agnostic: worth checking on every host regardless of detected tech,
# since none of these are specific to one framework/server.
_GENERIC_CHECKS: dict[str, tuple[str, tuple[str, ...], str]] = {
    "/.git/config": ("Exposed .git/config", ("[core]", "repositoryformatversion"), "medium"),
    "/.git/HEAD": ("Exposed .git/HEAD", ("ref:",), "medium"),
    "/.env": ("Exposed .env file", ("=",), "high"),
    "/.env.local": ("Exposed .env.local file", ("=",), "high"),
    "/.aws/credentials": ("Exposed AWS credentials file", ("aws_access_key_id", "[default]"), "critical"),
    "/.svn/entries": ("Exposed .svn/entries", ("svn",), "medium"),
    "/docker-compose.yml": ("Exposed docker-compose.yml", ("version:", "services:"), "medium"),
    "/backup.sql": ("Exposed SQL backup", ("insert into", "create table"), "high"),
    # The following aren't gated by a detected tech stack the way _STACK_CHECKS entries are:
    # each is its own small standalone app/endpoint commonly deployed alongside (rather than
    # as part of) whatever framework the main site runs, so recon's fingerprint of the main
    # site's tech doesn't predict whether one of these also exists at a well-known path.
    "/metrics": ("Exposed Prometheus-format metrics endpoint", ("# help", "# type"), "medium"),
    "/phpmyadmin/": ("Publicly accessible phpMyAdmin instance", ("phpmyadmin",), "info"),
    "/adminer.php": ("Publicly accessible Adminer instance", ("adminer",), "info"),
    "/v2/_catalog": ("Exposed Docker Registry catalog (unauthenticated)", ('"repositories"',), "high"),
}

# tech-detect keyword (matched case-insensitively as a substring against
# ReconResult.fingerprints[host]["tech"]/"server"/"powered_by") -> extra
# checks worth running only when that stack was actually detected. Keeps
# `test-active` from firing e.g. a WordPress config-backup probe at every
# single host regardless of what it's actually running -- narrower host
# selection means more of the program's own rate-limit budget goes to
# checks that could plausibly hit, not ones that can't by construction.
# Falls back to _GENERIC_CHECKS-only when no fingerprint data is on file
# for a host (e.g. --nuclei/--injection run without a prior `recon`).
_STACK_CHECKS: dict[str, dict[str, tuple[str, tuple[str, ...], str]]] = {
    "wordpress": {
        "/wp-config.php.bak": ("Exposed WordPress config backup", ("db_name", "<?php"), "high"),
        "/wp-json/wp/v2/users": ("WordPress user enumeration via REST API", ('"slug"', '"name"'), "low"),
    },
    "php": {
        "/config.php.bak": ("Exposed PHP config backup", ("<?php",), "high"),
        "/phpinfo.php": ("Exposed phpinfo()", ("phpinfo()", "php version"), "medium"),
    },
    "spring": {
        "/actuator/env": ("Exposed Spring Boot actuator env", ("propertysources", "systemproperties"), "high"),
        "/actuator/heapdump": ("Exposed Spring Boot heap dump", ("java",), "critical"),
        "/actuator/mappings": ("Exposed Spring Boot actuator mappings", ("dispatcherservlet",), "medium"),
    },
    "apache": {
        "/server-status": ("Exposed Apache mod_status", ("apache server status",), "low"),
    },
    "laravel": {
        "/storage/logs/laravel.log": ("Exposed Laravel log file", ("local.error", "stack trace"), "medium"),
        "/telescope/requests": ("Exposed Laravel Telescope debug panel", ("telescope", "requests"), "high"),
        "/_ignition/health-check": ("Exposed Laravel Ignition debug endpoint", ("ignition", "health"), "high"),
    },
    "express": {
        "/package.json": ("Exposed package.json", ('"dependencies"', '"name"'), "low"),
    },
    "node.js": {
        "/package.json": ("Exposed package.json", ('"dependencies"', '"name"'), "low"),
    },
    "ruby on rails": {
        "/config/database.yml": ("Exposed Rails database.yml", ("adapter:", "database:"), "high"),
    },
    "asp.net": {
        "/web.config": ("Exposed web.config", ("<configuration>", "connectionstrings"), "high"),
    },
    "django": {
        "/admin/login/": ("Exposed Django admin login page", ("csrfmiddlewaretoken", "django administration"), "info"),
    },
    "flask": {
        "/console": ("Possible exposed Werkzeug debugger console (RCE-adjacent if reachable)", ("werkzeug debugger", "traceback"), "critical"),
    },
    "werkzeug": {
        "/console": ("Possible exposed Werkzeug debugger console (RCE-adjacent if reachable)", ("werkzeug debugger", "traceback"), "critical"),
    },
    "jenkins": {
        "/api/json": ("Exposed Jenkins API (unauthenticated)", ('"jobs"', "hudson.model"), "high"),
    },
    "elasticsearch": {
        "/_cluster/health": ("Exposed Elasticsearch cluster health API", ('"cluster_name"', '"status"'), "high"),
        "/_cat/indices?v": ("Exposed Elasticsearch indices listing (unauthenticated)", ("health", "index"), "critical"),
    },
    "kibana": {
        "/api/status": ("Exposed Kibana status API", ('"kibana"', '"status"'), "low"),
    },
    "grafana": {
        "/api/health": ("Exposed Grafana health API", ('"database"', '"version"'), "info"),
        "/api/datasources": ("Exposed Grafana datasources API (auth misconfig)", ('"id"', '"type"'), "high"),
    },
    "prometheus": {
        "/api/v1/status/config": ("Exposed Prometheus config API", ("global", "scrape_configs"), "high"),
    },
    "consul": {
        "/v1/agent/self": ("Exposed Consul agent API (unauthenticated)", ('"config"', '"member"'), "high"),
    },
    "vault": {
        "/v1/sys/health": ("Exposed Vault health endpoint", ("initialized", "sealed"), "info"),
    },
    "rabbitmq": {
        "/api/overview": ("Exposed RabbitMQ management API (unauthenticated)", ("rabbitmq_version", "management_version"), "high"),
    },
    "traefik": {
        "/api/rawdata": ("Exposed Traefik dashboard API", ('"routers"', '"services"'), "medium"),
        "/api/version": ("Exposed Traefik version API", ('"version"',), "low"),
    },
    "nextcloud": {
        "/status.php": ("Exposed Nextcloud status.php", ('"installed"', '"version"'), "info"),
    },
    "magento": {
        "/app/etc/env.php": ("Exposed Magento env.php (DB credentials)", ("'db'", "'password'"), "critical"),
    },
    "drupal": {
        "/CHANGELOG.txt": ("Exposed Drupal CHANGELOG.txt (version disclosure)", ("drupal",), "low"),
    },
    "joomla": {
        "/administrator/manifests/files/joomla.xml": ("Exposed Joomla version manifest", ("<version>",), "low"),
    },
    "strapi": {
        "/admin/init": ("Exposed Strapi admin init API", ("strapiversion", "currentenvironment"), "info"),
    },
    "solr": {
        "/solr/admin/info/system": ("Exposed Apache Solr system info", ("solr_home", "lucene"), "high"),
    },
    "jira": {
        "/rest/api/2/serverInfo": ("Exposed Jira server info API", ("servertitle", "version"), "info"),
    },
    "confluence": {
        "/rest/api/space": ("Exposed Confluence space API (unauthenticated)", ('"results"', '"space"'), "medium"),
    },
}


def _detected_stacks(tech: list[str], server: str | None, powered_by: str | None) -> set[str]:
    """Which `_STACK_CHECKS` keys apply, based on tech-detect output plus
    the plain Server/X-Powered-By headers (covers hosts fingerprinted via
    `fingerprint_host` alone, without the optional `httpx` binary's
    tech-detect). Substring match, case-insensitive, deliberately
    permissive -- a false-positive stack match just means a few extra
    cheap, narrow, soft-404-gated requests; a false negative silently
    skips a check that could have found something, which is worse."""
    haystack = " ".join([*tech, server or "", powered_by or ""]).lower()
    return {stack for stack in _STACK_CHECKS if stack in haystack}

_SECURITY_HEADERS = [
    "content-security-policy",
    "x-frame-options",
    "strict-transport-security",
    "x-content-type-options",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
]

# A present-but-weak CSP is a different (and more common) finding than a
# missing one -- these directive values defeat most of what CSP is meant
# to stop. Checked against the whole header value, case-insensitively.
_WEAK_CSP_SIGNATURES = (
    "unsafe-inline",
    "unsafe-eval",
    "script-src *",
    "default-src *",
)

# Header names that suggest a program actually surfaces rate-limit state
# to clients. Absence is a genuinely weak signal (plenty of real rate
# limiters never expose it via headers), so this is always reported at
# "info" severity with an explicit caveat -- OWASP API4:2023 Unrestricted
# Resource Consumption, but this is nowhere near a confirmation of it.
_RATE_LIMIT_HEADERS = {"x-ratelimit-limit", "ratelimit-limit", "retry-after"}

# OWASP API9:2023 Improper Inventory Management: shadow/deprecated API
# versions and exposed API documentation. Only paths with a strong,
# specific content signature are included (an OpenAPI/Swagger document
# has a very recognizable shape) -- no bare "/api/v1"-style guesses with
# a weak signature, which would just flag every JSON response ever.
_API_INVENTORY_CHECKS: dict[str, tuple[str, tuple[str, ...], str]] = {
    "/swagger.json": ("Exposed Swagger/OpenAPI spec", ('"swagger"', '"openapi"', '"paths"'), "info"),
    "/openapi.json": ("Exposed OpenAPI spec", ('"openapi"', '"paths"'), "info"),
    "/.well-known/openapi.json": ("Exposed OpenAPI spec (well-known)", ('"openapi"', '"paths"'), "info"),
    "/api-docs": ("Exposed API docs endpoint", ('"swagger"', '"openapi"', '"paths"'), "info"),
    "/v1/swagger.json": (
        "Exposed v1 API spec -- verify whether v1 is still meant to be reachable, or is a shadow/deprecated version",
        ('"swagger"', '"openapi"'),
        "low",
    ),
    "/v2/swagger.json": (
        "Exposed v2 API spec -- verify this matches the currently documented/intended version",
        ('"swagger"', '"openapi"'),
        "low",
    ),
}

# OWASP API3:2023 Broken Object Property Level Authorization (the
# excessive-data-exposure half; the write-capable mass-assignment half
# lives in testing/mass_assignment.py, gated separately). Signature-only,
# key-name match -- never inspects values, so this can't itself leak a
# real secret into a Finding's evidence.
_SENSITIVE_FIELD_NAMES = (
    "password",
    "passwd",
    "password_hash",
    "passwordhash",
    "hashed_password",
    "secret",
    "api_key",
    "apikey",
    "access_token",
    "accesstoken",
    "refresh_token",
    "refreshtoken",
    "private_key",
    "privatekey",
    "client_secret",
    "clientsecret",
    "ssn",
    "social_security_number",
    "credit_card",
    "creditcard",
    "card_number",
    "cvv",
    "cvv2",
    "is_admin",
    "isadmin",
    "internal_notes",
    "internal_only",
)


def _scan_json_for_sensitive_fields(data, *, _depth: int = 0) -> list[str]:
    """Recursively walks a parsed JSON value looking for dict keys that
    match `_SENSITIVE_FIELD_NAMES` -- signature-only on the KEY name,
    never inspects or returns the value itself. Depth-capped at 6 and
    breadth-capped at 20 items per list, both far beyond any normal API
    response shape, to keep this from pathologically walking a huge or
    deeply-nested payload."""
    if _depth > 6:
        return []
    found: list[str] = []
    if isinstance(data, dict):
        for key, value in data.items():
            if any(name in str(key).lower() for name in _SENSITIVE_FIELD_NAMES):
                found.append(str(key))
            found.extend(_scan_json_for_sensitive_fields(value, _depth=_depth + 1))
    elif isinstance(data, list):
        for item in data[:20]:
            found.extend(_scan_json_for_sensitive_fields(item, _depth=_depth + 1))
    return found


def _baseline(client: httpx.Client, host: str) -> tuple[int, int] | None:
    probe_path = f"/bbhunter-baseline-{secrets.token_hex(8)}"
    try:
        resp = client.get(f"https://{host}{probe_path}", timeout=15, follow_redirects=True)
        return resp.status_code, len(resp.content)
    except httpx.HTTPError:
        return None


def _landed_off_host(resp: httpx.Response, host: str) -> bool:
    """True if `resp` ended up on a host other than `host` after following
    redirects -- almost always an SSO/auth-gateway interstitial (Cloudflare
    Access, Okta, Azure AD, ...). Its HTTP 200 is the *login page*, not the
    requested resource, so treating it as an exposed file or reading its
    headers is a false positive. Observed live 2026-10-03:
    alertmanager.gener8ads.com sits behind Cloudflare Access, so every probed
    path 200'd as the login portal on gener8.cloudflareaccess.com -- including
    /.env.local, which the scanner then flagged 'high'."""
    landed = urlsplit(str(resp.url)).hostname
    return bool(landed) and landed != host


_CORS_PROBE_ORIGIN = "https://bbhunter-cors-probe.example"


def _check_cors(client: httpx.Client, host: str) -> dict | None:
    """One GET to the root carrying a throwaway cross-origin `Origin`
    header, to detect a reflecting CORS policy. A server that echoes an
    arbitrary attacker origin back in `access-control-allow-origin` AND
    sets `access-control-allow-credentials: true` lets any site read
    authenticated responses cross-origin -- a real, commonly-bountied
    misconfiguration. Read-only, single request; reflecting `*` without
    credentials is browser-safe and deliberately NOT flagged."""
    try:
        resp = client.get(
            f"https://{host}/",
            headers={"Origin": _CORS_PROBE_ORIGIN},
            timeout=15,
            follow_redirects=True,
        )
    except httpx.HTTPError:
        return None
    if _landed_off_host(resp, host):
        return None
    acao = resp.headers.get("access-control-allow-origin", "")
    acac = resp.headers.get("access-control-allow-credentials", "").lower() == "true"
    reflects = acao == _CORS_PROBE_ORIGIN or acao == "null"
    if reflects and acac:
        return {
            "path": "/",
            "title": "CORS misconfiguration: reflects arbitrary Origin with credentials",
            "severity": "high",
            "status_code": resp.status_code,
            "url": str(resp.url),
            "detail": (
                f"Access-Control-Allow-Origin reflected the probe value {acao!r} and "
                "Access-Control-Allow-Credentials: true -- any origin can read authenticated "
                "responses. Verify against a real authenticated endpoint before drafting a PoC."
            ),
        }
    return None


def _check_host(client: httpx.Client, host: str, fingerprint: dict | None = None) -> list[dict]:
    hits: list[dict] = []
    baseline = _baseline(client, host)
    time.sleep(REQUEST_DELAY_SECONDS)

    fingerprint = fingerprint or {}
    stacks = _detected_stacks(fingerprint.get("tech") or [], fingerprint.get("server"), fingerprint.get("powered_by"))
    checks = dict(_GENERIC_CHECKS)
    checks.update(_API_INVENTORY_CHECKS)
    for stack in stacks:
        checks.update(_STACK_CHECKS[stack])

    for path, (title, signatures, severity) in checks.items():
        try:
            resp = client.get(f"https://{host}{path}", timeout=15, follow_redirects=True)
        except httpx.HTTPError:
            time.sleep(REQUEST_DELAY_SECONDS)
            continue
        time.sleep(REQUEST_DELAY_SECONDS)

        if resp.status_code != 200:
            continue
        if _landed_off_host(resp, host):
            continue  # redirected to an auth gateway/other host -- not this host's own file
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
        if _landed_off_host(resp, host):
            # root redirected to an auth gateway -- these headers describe the
            # gateway's login page, not the target, so every check below would
            # be a false positive. We simply can't assess the target here.
            return hits
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

        csp = resp.headers.get("content-security-policy")
        if csp:
            csp_lower = csp.lower()
            weak_directives = [sig for sig in _WEAK_CSP_SIGNATURES if sig in csp_lower]
            if weak_directives:
                hits.append(
                    {
                        "path": "/",
                        "title": f"Weak Content-Security-Policy directive(s): {', '.join(weak_directives)}",
                        "severity": "low",
                        "status_code": resp.status_code,
                        "url": str(resp.url),
                    }
                )

        if not (present & _RATE_LIMIT_HEADERS):
            hits.append(
                {
                    "path": "/",
                    "title": "No rate-limit headers observed on the root response",
                    "severity": "info",
                    "status_code": resp.status_code,
                    "url": str(resp.url),
                }
            )

        if "json" in resp.headers.get("content-type", "").lower():
            try:
                data = resp.json()
            except ValueError:
                data = None
            if data is not None:
                sensitive_fields = sorted(set(_scan_json_for_sensitive_fields(data)))
                if sensitive_fields:
                    hits.append(
                        {
                            "path": "/",
                            "title": (
                                "Possible excessive data exposure: sensitive-looking field name(s) in "
                                f"JSON response: {', '.join(sensitive_fields[:10])}"
                            ),
                            "severity": "medium",
                            "status_code": resp.status_code,
                            "url": str(resp.url),
                        }
                    )
    except httpx.HTTPError:
        pass

    time.sleep(REQUEST_DELAY_SECONDS)
    cors_hit = _check_cors(client, host)
    if cors_hit:
        hits.append(cors_hit)
    time.sleep(REQUEST_DELAY_SECONDS)

    return hits


def _replace_param(parts, params: list[tuple[str, str]], index: int, new_value: str) -> str:
    mutated = list(params)
    mutated[index] = (mutated[index][0], new_value)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(mutated), parts.fragment))


def _check_injection_signals(client: httpx.Client, url: str) -> list[dict]:
    """One baseline request plus, per query parameter, one reflected-XSS
    probe, one SQL-error-signature probe, one NoSQL-error-signature
    probe, one command-injection canary probe, and one CRLF/header-
    injection canary probe -- six requests total per parameter-bearing
    path, never more. Returns a list of hit dicts; empty if nothing
    fired or the URL couldn't be parsed/fetched."""
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

        nosqli_url = _replace_param(parts, params, i, value + "'||'1'=='1")
        try:
            resp = client.get(nosqli_url, timeout=15, follow_redirects=True)
        except httpx.HTTPError:
            resp = None
        time.sleep(REQUEST_DELAY_SECONDS)
        if resp is not None:
            body_lower = resp.text.lower()
            sig = next((s for s in _NOSQL_ERROR_SIGNATURES if s in body_lower and s not in baseline_body), None)
            if sig:
                hits.append(
                    {
                        "kind": "nosql-error-signature",
                        "param": name,
                        "url": str(resp.url),
                        "severity": "high",
                        "evidence": (
                            f"GET {resp.url} -> appending a JS-string-breakout probe to parameter '{name}' "
                            f"produced NoSQL/driver-error signature '{sig}' in the response body, absent "
                            "from the unmutated baseline request. Signature-only probe, no extraction "
                            "attempted; verify manually and check whether the program's policy permits "
                            "going further."
                        ),
                    }
                )

        cmdi_marker = f"BBHCMD{secrets.token_hex(4)}"
        cmdi_url = _replace_param(parts, params, i, f"{value}; echo {cmdi_marker} #")
        try:
            resp = client.get(cmdi_url, timeout=15, follow_redirects=True)
        except httpx.HTTPError:
            resp = None
        time.sleep(REQUEST_DELAY_SECONDS)
        if resp is not None and cmdi_marker in resp.text:
            hits.append(
                {
                    "kind": "command-injection-candidate",
                    "param": name,
                    "url": str(resp.url),
                    "severity": "critical",
                    "evidence": (
                        f"GET {resp.url} -> parameter '{name}' echoed marker '{cmdi_marker}' back verbatim "
                        "after appending a single benign shell command-separator probe "
                        f"('; echo {cmdi_marker} #'). Only a no-op `echo` was ever attempted -- verify "
                        "manually before treating as confirmed, and never escalate to a more impactful "
                        "command without the program's explicit go-ahead."
                    ),
                }
            )

        crlf_marker = f"bbhcrlf{secrets.token_hex(4)}"
        crlf_url = _replace_param(parts, params, i, f"{value}\r\nX-{crlf_marker}: 1")
        try:
            resp = client.get(crlf_url, timeout=15, follow_redirects=True)
        except httpx.HTTPError:
            resp = None
        time.sleep(REQUEST_DELAY_SECONDS)
        if resp is not None and f"x-{crlf_marker}".lower() in {h.lower() for h in resp.headers}:
            hits.append(
                {
                    "kind": "crlf-header-injection-candidate",
                    "param": name,
                    "url": str(resp.url),
                    "severity": "high",
                    "evidence": (
                        f"GET {resp.url} -> parameter '{name}' with a CRLF sequence (\\r\\n) followed by "
                        f"'X-{crlf_marker}: 1' appended caused that header to appear as a real response "
                        "header, not just reflected in the body. Detection-only -- no attempt was made to "
                        "inject Set-Cookie, split the response, or chain into XSS; verify manually before "
                        "treating as confirmed."
                    ),
                }
            )

    return hits


def _check_shellshock(client: httpx.Client, host: str) -> list[dict]:
    """One GET to `/` with a crafted `User-Agent` -- the classic
    CVE-2014-6271 (Shellshock) test string, `() { :; }; echo <marker>`.
    Same benign-echo-only philosophy as `_check_injection_signals`'s
    command-injection probe: if a CGI/mod_cgi-backed endpoint passes
    that header into a vulnerable bash, bash executes everything after
    the function definition, so a no-op `echo` of a random marker is
    enough to detect it without running anything that reads, writes, or
    changes state. This one request necessarily overrides the program's
    required User-Agent (see recon/passive.py's `_request_headers`) --
    the malicious string IS the User-Agent for this specific, single,
    well-known CVE-detection probe; the random marker embedded in it is
    still traceable in server logs to this run. Returns a hit dict in a
    list (for a uniform call-site shape with the per-param checks
    above), or [] if nothing fired or the request failed."""
    marker = f"BBHSHOCK{secrets.token_hex(4)}"
    try:
        resp = client.get(
            f"https://{host}/",
            headers={"User-Agent": f"() {{ :; }}; echo {marker}"},
            timeout=15,
            follow_redirects=True,
        )
    except httpx.HTTPError:
        return []
    if marker not in resp.text:
        return []
    return [
        {
            "kind": "shellshock-candidate",
            "url": str(resp.url),
            "severity": "critical",
            "evidence": (
                f"GET {resp.url} with User-Agent '() {{ :; }}; echo {marker}' (CVE-2014-6271 test string) "
                f"echoed marker '{marker}' back in the response body -- consistent with a CGI/mod_cgi-backed "
                "endpoint passing that header into a vulnerable bash. Only a no-op `echo` was ever "
                "attempted -- verify manually before treating as confirmed, and never escalate to a more "
                "impactful command without the program's explicit go-ahead."
            ),
        }
    ]


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


def run_nuclei_cve_scan(
    host: str, cve_ids: list[str], rules: RulesOfEngagement, *, timeout: float = NUCLEI_RUN_TIMEOUT_SECONDS
) -> list[dict] | None:
    """Run nuclei restricted to specific CVE template IDs against one
    host, to actively confirm the weak NVD-keyword matches passive recon
    produced. nuclei's CVE templates are keyed by the CVE id, so `-id
    CVE-2021-44228,...` selects exactly those -- turning a 'maybe this
    version is affected' keyword guess into an actually-fired check. Same
    conservative 1 req/s, single-connection pacing as run_nuclei_scan.
    Returns None if nuclei isn't installed or the run errors (="skip"),
    an empty list for 'ran, nothing fired'."""
    binary = _tool_path("nuclei")
    if not binary or not cve_ids:
        return None
    headers = _request_headers(rules)
    header_args = []
    for key, value in headers.items():
        header_args += ["-H", f"{key}: {value}"]
    try:
        proc = subprocess.run(
            [
                binary, "-jsonl", "-silent",
                "-id", ",".join(sorted(set(cve_ids))),
                "-rate-limit", str(NUCLEI_RATE_LIMIT_PER_SECOND),
                "-bulk-size", "1", "-c", "1", "-timeout", "15",
            ]
            + header_args,
            input=f"https://{host}",
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    results: list[dict] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if line:
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


def _seed_base_names(program: Program) -> list[str]:
    """The organizational-ish label from each in-scope URL/WILDCARD
    seed (e.g. "example" from "example.com", "www.example.com", or
    "*.example.com") -- input for cloud_storage.py's bucket-name
    guessing, deliberately derived only from what the program itself
    already lists as in scope, never an invented/unrelated name."""
    names: list[str] = []
    for asset in program.in_scope:
        if asset.asset_type not in (AssetType.URL, AssetType.WILDCARD):
            continue
        host = _extract_host(asset.identifier)
        if not host:
            continue
        label = host.lower()
        if label.startswith("www."):
            label = label[4:]
        parts = label.split(".")
        base = parts[0] if len(parts) <= 2 else parts[-2]
        if base and base not in names:
            names.append(base)
    return names


def run_active_checks(
    program: Program,
    recon_result: ReconResult | None = None,
    *,
    injection: bool = False,
    nuclei: bool = False,
    cloud_buckets: bool = False,
) -> list[Finding]:
    """`injection=True` additionally runs the reflected-XSS/SQL-error/
    NoSQL-error/command-injection/CRLF-header-injection signature checks
    (see module docstring) against Wayback-discovered param URLs from
    `recon_result`, plus one Shellshock (CVE-2014-6271) User-Agent probe
    per selected host regardless of `recon_result`. `nuclei=True` additionally runs the
    curated nuclei template set (see `run_nuclei_scan`) against the same
    selected hosts, skipped silently if the binary isn't installed.
    `cloud_buckets=True` additionally checks a small set of S3/GCS/
    Azure bucket-name variations derived from the program's own in-scope
    domains for a publicly-listable cloud storage bucket (see
    testing/cloud_storage.py) -- every finding from this one lands at
    "info" severity with an explicit ownership-verification caveat,
    since a same-named bucket can genuinely belong to an unrelated third
    party. All three are gated by the exact same
    `permits(ACTIVE_LOW_IMPACT)` check as everything else here -- none
    is a separate or higher permission tier, just a separate opt-in
    since each is a qualitatively different request shape worth a
    deliberate choice to include."""
    if not program.rules.permits(TestType.ACTIVE_LOW_IMPACT):
        raise RuntimeError(
            f"{program.key}: active testing blocked by rules.permits() -- run `bbhunter review-rules` "
            "and `bbhunter approve-active` first if this program's policy actually allows it"
        )

    headers = _request_headers(program.rules)
    hosts = _select_hosts(program, recon_result)
    host_set = set(hosts)

    fingerprints = recon_result.fingerprints if recon_result else {}

    findings: list[Finding] = []
    with httpx.Client(headers=headers) as client:
        for host in hosts:
            for hit in _check_host(client, host, fingerprints.get(host)):
                # A single path (most often "/", for the header/rate-limit/data-exposure
                # checks) can now produce more than one distinct hit, so the title is
                # folded into the id too -- otherwise two hits sharing a path would
                # collide and upsert_finding would silently overwrite one with the other.
                title_digest = hashlib.sha256(hit["title"].encode()).hexdigest()[:8]
                findings.append(
                    Finding(
                        id=f"{program.key}:{host}:{hit['path']}:{title_digest}",
                        program_key=program.key,
                        asset=host,
                        title=hit["title"],
                        vuln_class="exposure" if hit["severity"] != "info" else "hardening",
                        test_type=TestType.ACTIVE_LOW_IMPACT,
                        evidence=(
                            f"GET {hit['url']} -> HTTP {hit['status_code']}. Path: {hit['path']}."
                            + (f" {hit['detail']}" if hit.get("detail") else "")
                        ),
                        status=FindingStatus.CANDIDATE,
                        notes=f"severity guess: {hit['severity']} -- verify manually before drafting a PoC",
                    )
                )

        if injection:
            for host in hosts:
                for hit in _check_shellshock(client, host):
                    digest = hashlib.sha256(f"{host}:{hit['kind']}".encode()).hexdigest()[:12]
                    findings.append(
                        Finding(
                            id=f"{program.key}:{digest}",
                            program_key=program.key,
                            asset=host,
                            title=hit["kind"],
                            vuln_class=hit["kind"],
                            test_type=TestType.ACTIVE_LOW_IMPACT,
                            evidence=hit["evidence"],
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

    if cloud_buckets:
        for base_name in _seed_base_names(program):
            for hit in check_cloud_buckets_for_name(base_name):
                digest = hashlib.sha256(f"{base_name}:{hit['kind']}:{hit['evidence']}".encode()).hexdigest()[:12]
                findings.append(
                    Finding(
                        id=f"{program.key}:cloud:{digest}",
                        program_key=program.key,
                        asset=base_name,
                        title=hit["kind"].replace("-", " "),
                        vuln_class=hit["kind"],
                        test_type=TestType.ACTIVE_LOW_IMPACT,
                        evidence=hit["evidence"],
                        status=FindingStatus.CANDIDATE,
                        notes=f"severity guess: {hit['severity']} -- verify manually before drafting a PoC",
                    )
                )

    return findings
