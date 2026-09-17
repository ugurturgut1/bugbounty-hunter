"""Phase 2: passive recon. Everything here is TestType.PASSIVE_RECON,
which `RulesOfEngagement.permits()` always allows regardless of
confidence (see models.py) -- it's the guardrail floor, not something
gated per-program like active testing will be in Phase 3.

Two of the three steps never touch the target at all (certificate
transparency lookup, CVE keyword search against NVD's public database).
The third -- fingerprinting -- sends one plain GET request per discovered
host, which is why this module is deliberately conservative: capped
number of hosts per asset, rate-limited, and self-identifying via
User-Agent so a program's security team can recognize the traffic. If a
program's rules specify a required User-Agent or header
(RulesOfEngagement.required_user_agent / required_request_header, as
Intigriti exposes structurally), that is used instead of the default and
is a hard requirement, not a suggestion.
"""
from __future__ import annotations

import os
import re
import time
from datetime import datetime
from urllib.parse import urlparse

import httpx

from bbhunter.models import AssetType, Finding, FindingStatus, Program, ReconResult, RulesOfEngagement, TestType

CRTSH_URL = "https://crt.sh/"
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_USER_AGENT = os.environ.get("BBHUNTER_USER_AGENT", "bbhunter-recon/0.1 (personal security research tool)")

MAX_SUBDOMAINS_PER_SEED = 25
FINGERPRINT_DELAY_SECONDS = 1.0
NVD_DELAY_SECONDS = 6.0  # unauthenticated NVD rate limit is 5 requests / 30s
CRTSH_DELAY_SECONDS = 0.5  # crt.sh is a free public service, not the target -- still worth not hammering


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


def run_passive_recon(program: Program) -> tuple[ReconResult, list[Finding]]:
    if not program.rules.permits(TestType.PASSIVE_RECON):
        # Should be unreachable -- passive recon is always in the default
        # allowed set -- but fail loudly rather than silently proceed if
        # that invariant is ever broken.
        raise RuntimeError(f"{program.key}: passive recon blocked by rules.permits(), refusing to proceed")

    subdomains_by_seed: dict[str, list[str]] = {}
    fingerprints: dict[str, dict] = {}
    crtsh_failures: list[str] = []
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
            subdomains_by_seed[host] = sorted(discovered)
            if not crtsh_ok:
                crtsh_failures.append(host)

            hosts_to_fingerprint = [host] + sorted(discovered)[:MAX_SUBDOMAINS_PER_SEED]
            for target_host in hosts_to_fingerprint:
                if target_host in fingerprints:
                    continue
                fp = fingerprint_host(target_host, program.rules)
                time.sleep(FINGERPRINT_DELAY_SECONDS)
                if not fp:
                    continue
                fingerprints[target_host] = fp

                banner = _versioned_banner(fp.get("server"), fp.get("powered_by"))
                if not banner:
                    continue  # no version number to search on -- bare product names produce useless noise
                if banner not in nvd_cache:
                    nvd_cache[banner] = nvd_search(banner)
                    time.sleep(NVD_DELAY_SECONDS)

                detected_version = _parse_version_tuple(banner.rsplit(" ", 1)[-1])
                for cve in nvd_cache[banner]:
                    if not _cve_applies_to_version(cve.get("configurations", []), detected_version):
                        continue  # NVD's own published version range rules this exact version out
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
        seeds_total=len(recon_assets),
        seeds_processed=seeds_processed,
        last_run=datetime.utcnow(),
    )
    return result, findings
