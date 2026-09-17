"""Phase 2: passive recon. Everything here is TestType.PASSIVE_RECON,
which `RulesOfEngagement.permits()` always allows regardless of
confidence (see models.py) -- it's the guardrail floor, not something
gated per-program like active testing will be in Phase 3.

Subdomain discovery merges three sources, none of which send a request
to the target itself: certificate-transparency (crt.sh), the `subfinder`
binary (projectdiscovery -- itself just a fan-out over ~30 passive OSINT
sources: crt.sh, DNS aggregators, etc, never a direct probe of the
target), and archive.org's Wayback CDX API (also surfaces historic URLs
with query strings, saved as `ReconResult.param_urls` -- the input set
for testing/active.py's opt-in, still-gated injection-signature checks).
CVE keyword search against NVD is likewise third-party-only. `subfinder`
is optional: if the binary isn't installed, that source is silently
skipped (see README for `go install` instructions) and everything else
still works.

Fingerprinting is the one step that sends requests to the target itself
-- one plain GET per discovered host, optionally enriched by the
`httpx` binary (projectdiscovery's HTTP toolkit, not to be confused with
the `httpx` Python HTTP client this module already imports -- located by
absolute path, see `_tool_path`) for tech-stack detection, which is why
this module is deliberately conservative: capped number of hosts per
asset, rate-limited, and self-identifying via User-Agent so a program's
security team can recognize the traffic. If a program's rules specify a
required User-Agent or header (RulesOfEngagement.required_user_agent /
required_request_header, as Intigriti exposes structurally), that is
used instead of the default and is a hard requirement, not a suggestion.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from datetime import datetime
from urllib.parse import urlparse

import httpx

from bbhunter.models import AssetType, Finding, FindingStatus, Program, ReconResult, RulesOfEngagement, TestType

CRTSH_URL = "https://crt.sh/"
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
WAYBACK_CDX_URL = "https://web.archive.org/cdx/search/cdx"
DEFAULT_USER_AGENT = os.environ.get("BBHUNTER_USER_AGENT", "bbhunter-recon/0.1 (personal security research tool)")

MAX_SUBDOMAINS_PER_SEED = 25
MAX_PARAM_URLS_PER_SEED = 200
FINGERPRINT_DELAY_SECONDS = 1.0
NVD_DELAY_SECONDS = 6.0  # unauthenticated NVD rate limit is 5 requests / 30s
CRTSH_DELAY_SECONDS = 0.5  # crt.sh is a free public service, not the target -- still worth not hammering
SUBFINDER_TIMEOUT_SECONDS = 30  # live-tested 2026-09-17: unauthenticated subfinder against a real domain can take
                                 # several minutes across its ~30 sources with no API keys configured -- 30s here
                                 # (vs. subfinder's own 60s default) trades some source coverage for keeping a
                                 # full multi-seed `bbhunter recon` run from taking hours on a large program
WAYBACK_DELAY_SECONDS = 0.5  # archive.org is a free public service, not the target


def _tool_path(name: str) -> str | None:
    """Locate an external recon binary. Checks `~/go/bin` first -- where
    `go install` puts every projectdiscovery tool this module uses --
    then falls back to PATH. The order matters: the Python `httpx`
    package (already a project dependency) installs its own `httpx`
    command into this project's venv, which `shutil.which` would
    otherwise find first and which is not the projectdiscovery tool
    `httpx_tech_detect` expects (confirmed live -- it's a non-functional
    stub without its optional [cli] extras installed, so this isn't
    hypothetical). Checking `~/go/bin` first sidesteps that collision
    for all three tools this module shells out to, without needing to
    special-case `httpx` by name. Returns None if the tool genuinely
    isn't installed anywhere; every caller treats that as "skip this
    source", never as an error."""
    go_bin = os.path.expanduser(f"~/go/bin/{name}")
    if os.path.isfile(go_bin):
        return go_bin
    return shutil.which(name)


def _extract_host(identifier: str) -> str | None:
    identifier = identifier.strip()
    if not identifier:
        return None
    host = urlparse(identifier).hostname if "://" in identifier else identifier.split("/")[0].split(":")[0]
    if not host:
        return None
    return host.lstrip("*.") or None


def crtsh_subdomains(domain: str, *, timeout: float = 30) -> tuple[set[str], bool]:
    """Returns (discovered_names, succeeded). `succeeded=False` means the
    query itself errored (timeout, crt.sh rate-limiting, bad JSON) --
    distinct from a successful query that legitimately found nothing, so
    callers can tell "no subdomains" apart from "we don't actually know"
    instead of silently treating both the same way."""
    try:
        resp = httpx.get(
            CRTSH_URL,
            params={"q": f"%.{domain}", "output": "json"},
            timeout=timeout,
            headers={"User-Agent": DEFAULT_USER_AGENT},
        )
        resp.raise_for_status()
        entries = resp.json()
    except (httpx.HTTPError, ValueError):
        return set(), False

    names: set[str] = set()
    for entry in entries:
        for name in entry.get("name_value", "").split("\n"):
            name = name.strip().lstrip("*.").lower()
            if name and name.endswith(domain):
                names.add(name)
    return names, True


def subfinder_subdomains(domain: str, *, timeout: float = SUBFINDER_TIMEOUT_SECONDS) -> tuple[set[str], bool]:
    """Shells out to the `subfinder` binary in its default passive mode
    (no active flags like `-active`/DNS-bruteforce are ever passed) --
    every one of its ~30 sources is itself a third-party OSINT lookup,
    never a direct request to `domain`. Returns `(names, succeeded)` on
    the same contract as `crtsh_subdomains`: `succeeded=False` means the
    binary is missing or the run errored/timed out, not "found
    nothing"."""
    binary = _tool_path("subfinder")
    if not binary:
        return set(), False
    try:
        proc = subprocess.run(
            [binary, "-d", domain, "-silent", "-timeout", str(int(timeout))],
            capture_output=True,
            text=True,
            timeout=timeout + 30,
        )
    except (subprocess.SubprocessError, OSError):
        return set(), False
    names = {line.strip().lower() for line in proc.stdout.splitlines() if line.strip()}
    # subfinder can exit non-zero for a partial run (one source timed out)
    # while still printing good results on stdout -- only treat it as a
    # hard failure if we got nothing at all back.
    if proc.returncode != 0 and not names:
        return set(), False
    return {n for n in names if n.endswith(domain)}, True


def _wayback_cdx_query(params: dict, *, timeout: float) -> list[list[str]] | None:
    try:
        resp = httpx.get(
            WAYBACK_CDX_URL,
            params=params,
            timeout=timeout,
            headers={"User-Agent": DEFAULT_USER_AGENT},
        )
        resp.raise_for_status()
        rows = resp.json()
    except (httpx.HTTPError, ValueError):
        return None
    return rows[1:] if rows else []  # first row is the field-name header, not data


def wayback_subdomains(domain: str, *, timeout: float = 30) -> tuple[set[str], bool]:
    """Archive.org's CDX API, queried for anything ever crawled under
    `*.domain/*`. Never sends a request to the target -- archive.org
    only. Same (names, succeeded) contract as crtsh_subdomains.

    `limit` is capped well below what the CDX API allows: live-tested
    2026-09-17 against a heavily-archived real domain (a news site), an
    unbounded query took several minutes to fully transfer -- `timeout`
    is httpx's per-read timeout, not a hard wall-clock cap, so a slowly-
    trickling large response can outlast it without ever triggering a
    ReadTimeout. Bounding the response size directly is what actually
    keeps this fast."""
    rows = _wayback_cdx_query(
        {"url": f"*.{domain}/*", "output": "json", "fl": "original", "collapse": "urlkey", "limit": 3000},
        timeout=timeout,
    )
    if rows is None:
        return set(), False
    names: set[str] = set()
    for row in rows:
        host = _extract_host(row[0]) if row else None
        if host and host.endswith(domain):
            names.add(host)
    return names, True


def wayback_param_urls(domain: str, *, timeout: float = 30, limit: int = MAX_PARAM_URLS_PER_SEED) -> list[str]:
    """Historic URLs under `domain` that Wayback recorded with a query
    string -- the candidate set testing/active.py's opt-in
    injection-signature checks draw from, since those checks need a
    real parameter name to probe rather than guessing one. Archive.org
    only, never the target. Best-effort: returns [] on any failure
    rather than raising, since this is optional enrichment, not a
    required recon step."""
    rows = _wayback_cdx_query(
        {
            "url": f"*.{domain}/*",
            "output": "json",
            "fl": "original",
            "collapse": "urlkey",
            "filter": "original:.*\\?.+=.+",
            "limit": limit,
        },
        timeout=timeout,
    )
    if not rows:
        return []
    seen: set[str] = set()
    urls: list[str] = []
    for row in rows:
        url = row[0] if row else None
        if url and url not in seen:
            seen.add(url)
            urls.append(url)
    return urls


def httpx_tech_detect(host: str, rules: RulesOfEngagement, *, timeout: float = 15) -> dict | None:
    """Optional enrichment over `fingerprint_host` using the `httpx`
    binary (projectdiscovery) for its tech-stack signature database --
    far broader than this module's own Server/X-Powered-By header check.
    Still exactly one request to the host (httpx defaults to following
    the same probe budget), same required User-Agent/header contract as
    the plain-GET path. Returns None if the binary isn't installed or
    the run fails -- callers must fall back to `fingerprint_host`
    alone, never treat this as required."""
    binary = _tool_path("httpx")
    if not binary:
        return None
    headers = _request_headers(rules)
    header_args = []
    for key, value in headers.items():
        header_args += ["-H", f"{key}: {value}"]
    try:
        proc = subprocess.run(
            [binary, "-u", host, "-silent", "-json", "-tech-detect", "-title", "-timeout", str(int(timeout))]
            + header_args,
            capture_output=True,
            text=True,
            timeout=timeout + 15,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    line = next((l for l in proc.stdout.splitlines() if l.strip()), None)
    if not line:
        return None
    try:
        data = json.loads(line)
    except ValueError:
        return None
    return {
        "status_code": data.get("status_code"),
        "server": data.get("webserver"),
        "powered_by": None,  # httpx's JSON output doesn't surface X-Powered-By directly; tech[] covers this instead
        "title": data.get("title"),
        "tech": data.get("tech") or [],
        "final_url": data.get("url"),
    }


def _tech_banner_candidates(tech: list[str]) -> list[str]:
    """httpx's `tech` entries look like "Apache:2.4.41" (colon-separated)
    when it has version data -- reshape those into the "Name/x.y" form
    `_versioned_banner`'s regex expects (same shape as a Server header),
    so CVE-keyword search can also key off tech-stack detections, not
    just the Server/X-Powered-By headers. Entries with no version
    (e.g. plain "Cloudflare") are dropped, same as a bare Server header
    would be."""
    candidates = []
    for entry in tech:
        name, _, version = entry.partition(":")
        if name and version:
            candidates.append(f"{name}/{version}")
    return candidates


def _request_headers(rules: RulesOfEngagement) -> dict[str, str]:
    headers = {"User-Agent": rules.required_user_agent or DEFAULT_USER_AGENT}
    header_spec = rules.required_request_header
    if header_spec and ":" in header_spec:
        key, _, value = header_spec.partition(":")
        headers[key.strip()] = value.strip()
    return headers


def fingerprint_host(host: str, rules: RulesOfEngagement, *, timeout: float = 15) -> dict | None:
    headers = _request_headers(rules)
    for scheme in ("https", "http"):
        try:
            resp = httpx.get(f"{scheme}://{host}", headers=headers, timeout=timeout, follow_redirects=True)
        except httpx.HTTPError:
            continue
        return {
            "status_code": resp.status_code,
            "server": resp.headers.get("server"),
            "powered_by": resp.headers.get("x-powered-by"),
            "final_url": str(resp.url),
        }
    return None


def fingerprint(host: str, rules: RulesOfEngagement, *, timeout: float = 15) -> dict | None:
    """One request per host, same as `fingerprint_host` alone -- when the
    `httpx` binary is installed this uses it directly (its tech-detect
    signature database is far broader than the plain Server/
    X-Powered-By header check), rather than doing both and doubling the
    request count against the target. Falls back to `fingerprint_host`
    when the binary isn't present or its run fails."""
    enriched = httpx_tech_detect(host, rules, timeout=timeout)
    if enriched is not None:
        return enriched
    return fingerprint_host(host, rules, timeout=timeout)


_VERSION_RE = re.compile(r"([A-Za-z][\w.+-]*)/(\d+(?:\.\d+)+[\w.+-]*)")


def _versioned_banner(*headers: str | None) -> str | None:
    """Extract a "Product version" string worth CVE-searching, e.g.
    "Apache 2.4.41" from a "Server: Apache/2.4.41" header. Returns None
    for bare product names with no version, or a lone major-version digit
    with no dotted minor/patch component at all (e.g. plain "Apache" or
    "Undertow/1") -- keyword-searching either of those against NVD
    produces years of unrelated CVEs and is worse than no signal at all.
    Requires at least "x.y" -- see _cve_applies_to_version for the
    second-layer check against the actual affected version ranges."""
    for header in headers:
        if not header:
            continue
        m = _VERSION_RE.search(header)
        if m:
            return f"{m.group(1)} {m.group(2)}"
    return None


def _parse_version_tuple(version: str) -> tuple[int, ...]:
    """Leading dotted-numeric prefix only, e.g. '2.4.62' -> (2, 4, 62),
    '1.4.17.Final' -> (1, 4, 17). Empty tuple if nothing numeric leads
    it -- callers must treat that as "can't compare", not "version 0"."""
    m = re.match(r"^(\d+(?:\.\d+)*)", version.strip())
    if not m:
        return ()
    return tuple(int(part) for part in m.group(1).split("."))


def _version_affected_by_cpe_match(version: tuple[int, ...], cpe_match: dict) -> bool | None:
    """True/False if this cpeMatch entry's version constraints let us
    decide whether `version` falls inside it, or None if there isn't
    enough information to tell (e.g. a bare wildcard criteria with no
    range bounds) -- callers must treat None as "can't rule this out",
    never as either a match or a non-match."""
    start_inc = cpe_match.get("versionStartIncluding")
    start_exc = cpe_match.get("versionStartExcluding")
    end_inc = cpe_match.get("versionEndIncluding")
    end_exc = cpe_match.get("versionEndExcluding")

    if any((start_inc, start_exc, end_inc, end_exc)):
        if start_inc and version < _parse_version_tuple(start_inc):
            return False
        if start_exc and version <= _parse_version_tuple(start_exc):
            return False
        if end_inc and version > _parse_version_tuple(end_inc):
            return False
        if end_exc and version >= _parse_version_tuple(end_exc):
            return False
        return True

    # No range bounds -- the criteria CPE string itself may pin an exact
    # version instead, e.g. "cpe:2.3:a:apache:http_server:2.4.61:*:...".
    parts = cpe_match.get("criteria", "").split(":")
    if len(parts) > 5 and parts[5] not in ("*", "-", ""):
        exact = _parse_version_tuple(parts[5])
        if exact:
            return version == exact

    return None


def _cve_applies_to_version(configurations: list, version: tuple[int, ...]) -> bool:
    """Whether a CVE's own NVD-published version data is consistent with
    `version` being affected. Deliberately asymmetric: this only ever
    narrows false positives, never manufactures a false negative from
    ambiguous data. Returns True (keep it as a candidate) unless we can
    positively evaluate every "vulnerable" cpeMatch entry and every one
    of them excludes our version -- any single indeterminate entry, or
    the total absence of configuration data, means "stay permissive"."""
    if not version or not configurations:
        return True

    determined_any = False
    for config in configurations:
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if not cpe_match.get("vulnerable"):
                    continue
                verdict = _version_affected_by_cpe_match(version, cpe_match)
                if verdict is None:
                    continue
                determined_any = True
                if verdict:
                    return True
    return not determined_any


def nvd_search(keyword: str, *, timeout: float = 30) -> list[dict]:
    try:
        resp = httpx.get(
            NVD_CVE_URL,
            params={"keywordSearch": keyword, "resultsPerPage": 5},
            timeout=timeout,
            headers={"User-Agent": DEFAULT_USER_AGENT},
        )
        resp.raise_for_status()
        data = resp.json()
    except (httpx.HTTPError, ValueError):
        return []

    results = []
    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        descriptions = cve.get("descriptions") or []
        summary = next((d.get("value") for d in descriptions if d.get("lang") == "en"), None)
        if cve.get("id"):
            results.append({
                "id": cve["id"],
                "summary": summary or "",
                "configurations": cve.get("configurations") or [],
            })
    return results


def run_passive_recon(
    program: Program, *, max_subdomains_per_seed: int = MAX_SUBDOMAINS_PER_SEED
) -> tuple[ReconResult, list[Finding]]:
    """`max_subdomains_per_seed` only narrows *breadth* (how many
    crt.sh-discovered subdomains get fingerprinted per seed, 0 meaning
    "just the seed hosts themselves") -- it never touches per-request
    pacing against the target (FINGERPRINT_DELAY_SECONDS), which is
    calibrated to programs' own stated rate-limit requirements (e.g.
    Visa's policy: "rate limit any... testing to 1 request per second or
    longer") and must never be reduced to make a run finish faster."""
    if not program.rules.permits(TestType.PASSIVE_RECON):
        # Should be unreachable -- passive recon is always in the default
        # allowed set -- but fail loudly rather than silently proceed if
        # that invariant is ever broken.
        raise RuntimeError(f"{program.key}: passive recon blocked by rules.permits(), refusing to proceed")

    subdomains_by_seed: dict[str, list[str]] = {}
    fingerprints: dict[str, dict] = {}
    crtsh_failures: list[str] = []
    subfinder_failures: list[str] = []
    wayback_failures: list[str] = []
    param_urls_by_seed: dict[str, list[str]] = {}
    findings: list[Finding] = []
    nvd_cache: dict[str, list[dict]] = {}

    recon_assets = [a for a in program.in_scope if a.asset_type in (AssetType.URL, AssetType.WILDCARD)]
    seeds_processed = 0

    try:
        for asset in recon_assets:
            host = _extract_host(asset.identifier)
            if not host:
                seeds_processed += 1
                continue

            discovered, crtsh_ok = crtsh_subdomains(host)
            time.sleep(CRTSH_DELAY_SECONDS)
            if not crtsh_ok:
                crtsh_failures.append(host)

            subfinder_names, subfinder_ok = subfinder_subdomains(host)
            if not subfinder_ok:
                subfinder_failures.append(host)
            discovered |= subfinder_names

            wayback_names, wayback_ok = wayback_subdomains(host)
            time.sleep(WAYBACK_DELAY_SECONDS)
            if not wayback_ok:
                wayback_failures.append(host)
            discovered |= wayback_names

            subdomains_by_seed[host] = sorted(discovered)

            param_urls = wayback_param_urls(host)
            time.sleep(WAYBACK_DELAY_SECONDS)
            if param_urls:
                param_urls_by_seed[host] = param_urls

            hosts_to_fingerprint = [host] + sorted(discovered)[:max_subdomains_per_seed]
            for target_host in hosts_to_fingerprint:
                if target_host in fingerprints:
                    continue
                fp = fingerprint(target_host, program.rules)
                time.sleep(FINGERPRINT_DELAY_SECONDS)
                if not fp:
                    continue
                fingerprints[target_host] = fp

                banners = []
                header_banner = _versioned_banner(fp.get("server"), fp.get("powered_by"))
                if header_banner:
                    banners.append(header_banner)
                banners += _tech_banner_candidates(fp.get("tech") or [])

                matched_cve_ids: set[str] = set()
                for banner in banners:
                    if banner not in nvd_cache:
                        nvd_cache[banner] = nvd_search(banner)
                        time.sleep(NVD_DELAY_SECONDS)

                    detected_version = _parse_version_tuple(banner.rsplit(" ", 1)[-1])
                    for cve in nvd_cache[banner]:
                        if cve["id"] in matched_cve_ids:
                            continue  # same CVE already matched via another banner on this host
                        if not _cve_applies_to_version(cve.get("configurations", []), detected_version):
                            continue  # NVD's own published version range rules this exact version out
                        matched_cve_ids.add(cve["id"])
                        findings.append(
                            Finding(
                                id=f"{program.key}:{target_host}:{cve['id']}",
                                program_key=program.key,
                                asset=target_host,
                                title=f"Keyword CVE match: {cve['id']} against banner '{banner}'",
                                vuln_class="version-cve-keyword-match",
                                test_type=TestType.VERSION_CVE_MATCH,
                                evidence=(
                                    f"Host {target_host} returned a banner identifying '{banner}'. "
                                    f"NVD keyword search for that string surfaced {cve['id']}: {cve['summary'][:400]}. "
                                    "This is a coarse keyword match, not a confirmed vulnerable version -- verify the "
                                    "actual product/version before treating as a real finding."
                                ),
                                status=FindingStatus.CANDIDATE,
                            )
                        )
            seeds_processed += 1
    except KeyboardInterrupt:
        # Stopping mid-run (Ctrl-C, or `kill -INT`/`pkill -INT` against a
        # backgrounded run) should save everything gathered so far rather
        # than discard it -- the caller still gets a normal ReconResult
        # back, just with seeds_processed < len(recon_assets) so it knows
        # this program wasn't fully covered and may be worth re-running.
        pass

    result = ReconResult(
        program_key=program.key,
        subdomains=subdomains_by_seed,
        fingerprints=fingerprints,
        crtsh_failures=crtsh_failures,
        subfinder_failures=subfinder_failures,
        wayback_failures=wayback_failures,
        param_urls=param_urls_by_seed,
        seeds_total=len(recon_assets),
        seeds_processed=seeds_processed,
        last_run=datetime.utcnow(),
    )
    return result, findings
