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


def _extract_host(identifier: str) -> str | None:
    identifier = identifier.strip()
    if not identifier:
        return None
    host = urlparse(identifier).hostname if "://" in identifier else identifier.split("/")[0].split(":")[0]
    if not host:
        return None
    return host.lstrip("*.") or None


def crtsh_subdomains(domain: str, *, timeout: float = 30) -> set[str]:
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
        return set()

    names: set[str] = set()
    for entry in entries:
        for name in entry.get("name_value", "").split("\n"):
            name = name.strip().lstrip("*.").lower()
            if name and name.endswith(domain):
                names.add(name)
    return names


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


_VERSION_RE = re.compile(r"([A-Za-z][\w.+-]*)/([0-9][\w.+-]*)")


def _versioned_banner(*headers: str | None) -> str | None:
    """Extract a "Product version" string worth CVE-searching, e.g.
    "Apache 2.4.41" from a "Server: Apache/2.4.41" header. Returns None
    for bare product names with no version (e.g. plain "Apache") --
    keyword-searching those against NVD produces years of unrelated CVEs
    and is worse than no signal at all."""
    for header in headers:
        if not header:
            continue
        m = _VERSION_RE.search(header)
        if m:
            return f"{m.group(1)} {m.group(2)}"
    return None


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
            results.append({"id": cve["id"], "summary": summary or ""})
    return results


def run_passive_recon(program: Program) -> tuple[ReconResult, list[Finding]]:
    if not program.rules.permits(TestType.PASSIVE_RECON):
        # Should be unreachable -- passive recon is always in the default
        # allowed set -- but fail loudly rather than silently proceed if
        # that invariant is ever broken.
        raise RuntimeError(f"{program.key}: passive recon blocked by rules.permits(), refusing to proceed")

    subdomains_by_seed: dict[str, list[str]] = {}
    fingerprints: dict[str, dict] = {}
    findings: list[Finding] = []
    nvd_cache: dict[str, list[dict]] = {}

    recon_assets = [a for a in program.in_scope if a.asset_type in (AssetType.URL, AssetType.WILDCARD)]

    for asset in recon_assets:
        host = _extract_host(asset.identifier)
        if not host:
            continue

        discovered = crtsh_subdomains(host)
        subdomains_by_seed[host] = sorted(discovered)

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
            for cve in nvd_cache[banner]:
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

    result = ReconResult(
        program_key=program.key,
        subdomains=subdomains_by_seed,
        fingerprints=fingerprints,
        last_run=datetime.utcnow(),
    )
    return result, findings
