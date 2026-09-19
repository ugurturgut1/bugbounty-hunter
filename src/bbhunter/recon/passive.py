"""Phase 2: passive recon. Everything here is TestType.PASSIVE_RECON,
which `RulesOfEngagement.permits()` always allows regardless of
confidence (see models.py) -- it's the guardrail floor, not something
gated per-program like active testing will be in Phase 3.

Subdomain discovery merges five sources, none of which send a request to
the target itself: certificate-transparency via crt.sh and, as a second
independent CT-log source, SSLMate's Certspotter API
(`certspotter_subdomains` -- unauthenticated tier is capped at 10
requests/hour per Certspotter's own `x-ratelimit-limit` header, so on a
program with many seeds this source runs out mid-run; that's treated the
same as any other source hitting its limit, `succeeded=False` and
silently move on, never a hard failure of the whole run), the
`subfinder` binary (projectdiscovery -- itself just a fan-out over ~30
passive OSINT sources: crt.sh, DNS aggregators, etc, never a direct
probe of the target), a fifth source `assetfinder` (tomnomnom,
`--subs-only`, heavy overlap with subfinder but an independent source
list), and archive.org's Wayback CDX API (also surfaces historic URLs
with query strings, saved as `ReconResult.param_urls` -- the input set
for testing/active.py's opt-in, still-gated injection-signature checks).
CVE keyword search against NVD is likewise third-party-only.
`subfinder`/`assetfinder` are optional: if a binary isn't installed,
that source is silently skipped (see README for `go install`
instructions) and everything else still works.

Before fingerprinting, discovered subdomains are filtered through
`dnsx_resolve` (the `dnsx` binary, also optional) -- public DNS queries
only, never touching the target's HTTP surface -- so
`max_subdomains_per_seed`'s cap is spent on hosts that actually resolve
rather than a stale crt.sh/Wayback entry. Falls back to the unfiltered
set if `dnsx` isn't installed.

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

**Scope (Guardrail 1)**: fingerprinting -- and everything downstream of
it that also touches the target (TLS handshake, dangling-CNAME check,
JS harvesting, robots.txt/security.txt) -- only ever expands past the
exact seed host when that seed's `AssetType` is `WILDCARD`. A plain
`URL`-type seed only ever gets its own exact host fingerprinted, even
when crt.sh/Certspotter/subfinder/assetfinder/Wayback surface a sibling
subdomain under the same parent domain -- that subdomain isn't in scope
just because it was discovered, mirroring exactly how
`testing/active.py`'s `_select_hosts` already gates active testing.

Each fingerprinted host also gets one raw TLS handshake to port 443 (via
the `openssl` binary, see `tls_cert_info`) to read its certificate --
the same information any browser already reads on every visit, no
application-layer request sent, no validation against a trust store of
our own (so self-signed certs are observed, not rejected). Findings from
this (`tls_findings`: expired/soon-expiring, self-signed, weak SHA-1
signature, hostname not covered by the cert's SAN) land as
TestType.PASSIVE_RECON, same floor as everything else here.

Per seed host, `recon/dns_hygiene.py` also runs SPF/DMARC/DKIM
email-spoofing misconfig checks (public DNS lookups only, same request
class as crt.sh/Wayback), and every fingerprinted host gets a
dangling-CNAME check -- run BEFORE the HTTP fingerprint attempt, since a
truly dangling target often never responds to HTTP at all, which would
otherwise skip it entirely.

Per seed host, `recon/js_harvest.py` also fetches the page and every
`<script src>` it links (public static content any visitor already
receives) to scan for hardcoded secrets, exposed source maps, and
internal-looking API paths referenced in the JS -- see that module's
docstring for exactly what and why.

Per seed host, `recon/github_dork.py` optionally searches GitHub's
public code-search API for the domain alongside a real secret-shaped
pattern -- classic "GitHub recon" dorking, entirely third-party (never
touches the target), skipped silently unless a free GitHub personal
access token is configured (`GITHUB_API_TOKEN`, see .env.example).

Per seed host, `recon/well_known.py` also fetches /robots.txt and
/security.txt (RFC 9116 -- /.well-known/security.txt first, falling
back to the legacy path) -- both are files a host publishes specifically
to be read by any crawler/researcher, same request class as the plain
GET `fingerprint()` already makes. See that module's docstring.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Callable
from urllib.parse import urlparse

import httpx

from bbhunter.config import GitHubCreds
from bbhunter.models import AssetType, Finding, FindingStatus, Program, ReconResult, RulesOfEngagement, TestType
from bbhunter.recon.dns_hygiene import check_dangling_cname, check_dkim, check_dmarc, check_spf
from bbhunter.recon.github_dork import GITHUB_SEARCH_DELAY_SECONDS, scan_github_results_for_secrets, search_domain_mentions
from bbhunter.recon.js_harvest import (
    check_source_map_exposed,
    extract_script_urls,
    fetch_text_capped,
    find_source_map_url,
    scan_js_internal_paths,
    scan_js_secrets,
)
from bbhunter.recon.well_known import check_robots_txt, check_security_txt

CRTSH_URL = "https://crt.sh/"
CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances"
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
WAYBACK_CDX_URL = "https://web.archive.org/cdx/search/cdx"
DEFAULT_USER_AGENT = os.environ.get("BBHUNTER_USER_AGENT", "bbhunter-recon/0.1 (personal security research tool)")

MAX_SUBDOMAINS_PER_SEED = 25
MAX_PARAM_URLS_PER_SEED = 200
FINGERPRINT_DELAY_SECONDS = 1.0
NVD_DELAY_SECONDS = 6.0  # unauthenticated NVD rate limit is 5 requests / 30s
SUBFINDER_TIMEOUT_SECONDS = 15  # trimmed from 30 2026-09-18 -- live-tested 2026-09-17: unauthenticated
                                 # subfinder against a real domain can take several minutes across its ~30
                                 # sources with no API keys configured; 15s (vs. subfinder's own 60s
                                 # default) trades more source coverage for a multi-seed `bbhunter recon`
                                 # run staying in the tens-of-minutes range on a medium/large program
                                 # instead of hours -- still returns whatever sources answered in time,
                                 # never treated as a hard failure unless nothing came back at all
# CRTSH_DELAY_SECONDS/CERTSPOTTER_DELAY_SECONDS/WAYBACK_DELAY_SECONDS/DNS_DELAY_SECONDS were individual
# per-call courtesy sleeps, replaced 2026-09-20 by PARALLEL_OSINT_DELAY_SECONDS below once those calls
# started running concurrently instead of serially (see run_passive_recon) -- removed rather than left
# as dead constants.
PARALLEL_OSINT_DELAY_SECONDS = 0.5  # single combined courtesy pause after the whole parallel OSINT
                                     # batch below (crt.sh/Certspotter/subfinder/assetfinder/Wayback x2/
                                     # SPF/DMARC/DKIM), replacing what used to be 4 separate sequential
                                     # sleeps -- every one of those calls hits a third-party service or a
                                     # public DNS resolver, never the target itself (same reasoning the
                                     # module docstring already gives for why none of them need the
                                     # target's own rate limit respected), so running them concurrently
                                     # collapses their sum into their max without touching
                                     # FINGERPRINT_DELAY_SECONDS or anything else that actually paces
                                     # requests to the target -- that stays untouched, still fully serial,
                                     # below in the per-host fingerprinting loop.
RECON_EXECUTOR_MAX_WORKERS = 12  # shared thread pool for every target-untouched, parallelizable batch
                                  # below: per-seed OSINT gathering (crtsh + certspotter + subfinder +
                                  # assetfinder + wayback_subdomains + wayback_param_urls + spf + dmarc +
                                  # dkim, 9 tasks) and, separately, dangling-CNAME pre-resolution across
                                  # every host_to_fingerprint (DNS-only, see check_dangling_cname's own
                                  # docstring) -- the two batches never run concurrently with each other
                                  # (each is awaited via .result() before the next phase starts), so one
                                  # pool sized for the larger of the two is enough


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


def crtsh_subdomains(domain: str, *, timeout: float = 15) -> tuple[set[str], bool]:
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


def certspotter_subdomains(domain: str, *, timeout: float = 15) -> tuple[set[str], bool]:
    """SSLMate's Certspotter CT-log API -- a second, independent
    certificate-transparency source alongside crt.sh (see
    docs/EXTERNAL_RESOURCES.md). Never touches the target. Same
    (names, succeeded) contract as crtsh_subdomains: `succeeded=False`
    covers both a request error and the unauthenticated tier's own
    10-requests/hour rate limit being exhausted (a 4xx from
    `raise_for_status()`, caught below) -- either way this is "we don't
    know", not "found nothing", so crt.sh staying the primary CT source
    matters more here than usual."""
    try:
        resp = httpx.get(
            CERTSPOTTER_URL,
            params={"domain": domain, "include_subdomains": "true", "expand": "dns_names"},
            timeout=timeout,
            headers={"User-Agent": DEFAULT_USER_AGENT},
        )
        resp.raise_for_status()
        entries = resp.json()
    except (httpx.HTTPError, ValueError):
        return set(), False

    names: set[str] = set()
    for entry in entries:
        for name in entry.get("dns_names", []):
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
            timeout=timeout + 10,
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


def assetfinder_subdomains(domain: str, *, timeout: float = 15) -> tuple[set[str], bool]:
    """Shells out to the `assetfinder` binary (tomnomnom) with
    `--subs-only` -- restricts output to actual subdomains of `domain`,
    never the unrelated "related root domains" assetfinder can also
    surface without that flag (those would be a scope violation to
    silently start treating as in-scope). A fourth passive subdomain
    source alongside crt.sh/Certspotter/subfinder/Wayback -- heavy
    overlap with subfinder in practice, but a different, independent
    source list, so worth the one extra optional binary. Same
    (names, succeeded) contract and silent-skip-if-missing behavior as
    every other optional source here."""
    binary = _tool_path("assetfinder")
    if not binary:
        return set(), False
    try:
        proc = subprocess.run(
            [binary, "--subs-only", domain],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (subprocess.SubprocessError, OSError):
        return set(), False
    names = {line.strip().lower() for line in proc.stdout.splitlines() if line.strip()}
    if proc.returncode != 0 and not names:
        return set(), False
    return {n for n in names if n.endswith(domain)}, True


def dnsx_resolve(hosts: set[str], *, timeout: float = 15) -> set[str] | None:
    """Filters `hosts` down to the ones that actually resolve, via the
    `dnsx` binary (projectdiscovery) in silent mode -- public DNS
    queries only, never touches the target's own HTTP surface, same
    request class as recon/dns_hygiene.py's lookups. Used to keep
    `max_subdomains_per_seed`'s fingerprinting budget from being spent
    on a crt.sh/Certspotter/subfinder/assetfinder/Wayback entry that no
    longer resolves (a stale cert, an expired Wayback snapshot) ahead of
    a live one. Returns None -- not "resolved nothing" -- if the binary
    isn't installed or the run fails; callers must fall back to the
    unfiltered set in that case, never silently drop every host just
    because dnsx wasn't available."""
    if not hosts:
        return set()
    binary = _tool_path("dnsx")
    if not binary:
        return None
    try:
        proc = subprocess.run(
            [binary, "-silent"],
            input="\n".join(sorted(hosts)),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    resolved = {line.strip().lower() for line in proc.stdout.splitlines() if line.strip()}
    if proc.returncode != 0 and not resolved:
        return None
    return resolved & hosts


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


def wayback_subdomains(domain: str, *, timeout: float = 15) -> tuple[set[str], bool]:
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


def wayback_param_urls(domain: str, *, timeout: float = 15, limit: int = MAX_PARAM_URLS_PER_SEED) -> list[str]:
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


def httpx_tech_detect(host: str, rules: RulesOfEngagement, *, timeout: float = 8) -> dict | None:
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
            timeout=timeout + 8,
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


TLS_CERT_TIMEOUT_SECONDS = 5  # trimmed from 10 2026-09-18 -- a real handshake completes in well under a
                              # second; this only bounds how long a per-host attempt can hang against an
                              # unresponsive port, which multiplies fast across dozens of subdomains
TLS_CERT_SOON_EXPIRING_DAYS = 14

_CERT_END_MARKER = "-----END CERTIFICATE-----"
_VERIFY_CODE_RE = re.compile(r"Verify return code:\s*(\d+)\s*\(([^)]*)\)")
_NOT_AFTER_RE = re.compile(r"notAfter=(.+)")
_SUBJECT_RE = re.compile(r"^subject=(.+)$", re.MULTILINE)
_SIGNATURE_ALGO_RE = re.compile(r"Signature Algorithm:\s*(\S+)")
_SAN_DNS_RE = re.compile(r"DNS:([^,\s]+)")
# openssl verify return codes for a self-signed leaf/chain -- see `verify(1)`:
# 18 = self signed certificate, 19 = self signed certificate in certificate chain
_SELF_SIGNED_VERIFY_CODES = {18, 19}


def tls_cert_info(host: str, *, timeout: float = TLS_CERT_TIMEOUT_SECONDS) -> dict | None:
    """One raw TLS handshake to `host:443` via the `openssl` binary --
    reads the certificate any browser visiting this host already reads
    on every connection, sends no application-layer request at all (no
    HTTP GET happens here), and never validates against a trust store
    of our own (so a self-signed cert is observed, not rejected). Same
    request class as `fingerprint`'s plain GET: read-only, single
    connection, no interaction beyond what establishing TLS requires.
    Returns None if `openssl` isn't installed, the connection/handshake
    fails, or no certificate was presented -- callers must treat that as
    "no signal", never as "found nothing wrong"."""
    binary = shutil.which("openssl")
    if not binary:
        return None

    try:
        s_client = subprocess.run(
            [binary, "s_client", "-connect", f"{host}:443", "-servername", host],
            input=b"", capture_output=True, timeout=timeout,
        )
    except (subprocess.SubprocessError, OSError):
        return None

    combined = s_client.stdout.decode(errors="ignore") + "\n" + s_client.stderr.decode(errors="ignore")
    if _CERT_END_MARKER not in combined:
        return None
    pem = combined[combined.index("-----BEGIN CERTIFICATE-----"): combined.index(_CERT_END_MARKER) + len(_CERT_END_MARKER)]

    verify_code = None
    verify_text = None
    verify_match = _VERIFY_CODE_RE.search(combined)
    if verify_match:
        verify_code = int(verify_match.group(1))
        verify_text = verify_match.group(2)

    try:
        x509_out = subprocess.run(
            [binary, "x509", "-noout", "-enddate", "-subject", "-ext", "subjectAltName", "-text"],
            input=pem.encode(), capture_output=True, timeout=timeout,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    x509_text = x509_out.stdout.decode(errors="ignore")

    not_after = None
    m = _NOT_AFTER_RE.search(x509_text)
    if m:
        not_after = m.group(1).strip()
    subject = None
    m = _SUBJECT_RE.search(x509_text)
    if m:
        subject = m.group(1).strip()
    signature_algorithm = None
    m = _SIGNATURE_ALGO_RE.search(x509_text)
    if m:
        signature_algorithm = m.group(1)
    san_dns_names = _SAN_DNS_RE.findall(x509_text)

    return {
        "not_after": not_after,
        "subject": subject,
        "signature_algorithm": signature_algorithm,
        "san_dns_names": san_dns_names,
        "verify_code": verify_code,
        "verify_text": verify_text,
    }


def _parse_openssl_not_after(not_after: str) -> datetime | None:
    try:
        return datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
    except ValueError:
        return None


def _hostname_covered_by_san(host: str, san_dns_names: list[str]) -> bool:
    """Deliberately permissive wildcard match -- a false negative here
    (silently skipping a real SAN mismatch) is worse than a false
    positive on an unusual-but-legitimate CDN/multi-tenant cert setup,
    consistent with this project's general stack/signature-matching
    philosophy elsewhere."""
    host_lower = host.lower()
    for name in san_dns_names:
        name_lower = name.lower()
        if name_lower == host_lower:
            return True
        if name_lower.startswith("*.") and host_lower.endswith(name_lower[1:]):
            return True
    return False


def tls_findings(host: str, info: dict) -> list[dict]:
    """Turns `tls_cert_info`'s raw output into hit dicts (title/severity/
    evidence), same shape testing/active.py's checks already use. Every
    check here is read-only interpretation of a certificate that was
    already fetched -- no additional connection."""
    hits: list[dict] = []

    if info.get("verify_code") in _SELF_SIGNED_VERIFY_CODES:
        hits.append({
            "kind": "tls-self-signed-cert",
            "severity": "low",
            "evidence": (
                f"TLS handshake to {host}:443 presented a self-signed certificate "
                f"(openssl verify: {info.get('verify_text')}). Could be a forgotten dev/staging cert "
                "left reachable on a production host, or an intentional internal setup -- verify context "
                "before reporting."
            ),
        })

    not_after = info.get("not_after")
    if not_after:
        expiry = _parse_openssl_not_after(not_after)
        if expiry:
            days_left = (expiry - datetime.utcnow()).total_seconds() / 86400
            if days_left < 0:
                hits.append({
                    "kind": "tls-cert-expired",
                    "severity": "medium",
                    "evidence": f"TLS certificate for {host} expired on {not_after} ({abs(days_left):.0f} day(s) ago).",
                })
            elif days_left <= TLS_CERT_SOON_EXPIRING_DAYS:
                hits.append({
                    "kind": "tls-cert-expiring-soon",
                    "severity": "info",
                    "evidence": f"TLS certificate for {host} expires {not_after} (in {days_left:.0f} day(s)).",
                })

    sig_algo = info.get("signature_algorithm") or ""
    if "sha1" in sig_algo.lower():
        hits.append({
            "kind": "tls-weak-signature-algorithm",
            "severity": "low",
            "evidence": f"TLS certificate for {host} is signed with {sig_algo}, deprecated and rejected by modern browsers/clients.",
        })

    san_dns_names = info.get("san_dns_names") or []
    if san_dns_names and not _hostname_covered_by_san(host, san_dns_names):
        hits.append({
            "kind": "tls-hostname-not-in-san",
            "severity": "info",
            "evidence": (
                f"TLS certificate presented for {host} doesn't appear to cover it in its Subject "
                f"Alternative Names ({', '.join(san_dns_names[:10])}). Heuristic wildcard match only -- "
                "verify manually before reporting, shared/CDN certs are common and often legitimate."
            ),
        })

    return hits


def fingerprint_host(host: str, rules: RulesOfEngagement, *, timeout: float = 8) -> dict | None:
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


def fingerprint(host: str, rules: RulesOfEngagement, *, timeout: float = 8) -> dict | None:
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


def _harvest_js_for_host(host: str, rules: RulesOfEngagement) -> list[dict]:
    """One page GET to find `<script src>` tags, then one GET per linked
    JS file (capped, see js_harvest.MAX_JS_FILES_PER_PAGE) -- same
    request class as the plain-GET fingerprint request, just reading
    public static assets a normal page load already triggers. Returns
    [] on any failure to fetch the page itself."""
    headers = _request_headers(rules)
    try:
        resp = httpx.get(f"https://{host}", headers=headers, timeout=8, follow_redirects=True)
    except httpx.HTTPError:
        return []
    if resp.status_code != 200:
        return []

    hits: list[dict] = []
    internal_paths: set[str] = set()
    for js_url in extract_script_urls(str(resp.url), resp.text):
        js_text = fetch_text_capped(js_url)
        time.sleep(FINGERPRINT_DELAY_SECONDS)
        if not js_text:
            continue

        hits.extend(scan_js_secrets(js_url, js_text))
        internal_paths.update(scan_js_internal_paths(js_text))

        map_url = find_source_map_url(js_url, js_text)
        if map_url:
            map_hit = check_source_map_exposed(map_url)
            time.sleep(FINGERPRINT_DELAY_SECONDS)
            if map_hit:
                hits.append(map_hit)

    if internal_paths:
        sample = ", ".join(sorted(internal_paths)[:10])
        hits.append({
            "kind": "js-referenced-internal-api-paths",
            "severity": "info",
            "evidence": (
                f"Public JS on {host} references {len(internal_paths)} internal-looking API path(s), "
                f"e.g.: {sample}. Worth manually exploring for endpoints not otherwise discovered."
            ),
        })

    return hits


def _check_well_known_for_host(host: str, rules: RulesOfEngagement) -> list[dict]:
    """One GET to /robots.txt and up to two GETs for security.txt
    (`.well-known/` then the legacy path) -- see recon/well_known.py.
    Same required-User-Agent/header contract as every other request this
    module makes against the target."""
    headers = _request_headers(rules)
    return check_robots_txt(host, headers) + check_security_txt(host, headers)


def run_passive_recon(
    program: Program,
    *,
    max_subdomains_per_seed: int = MAX_SUBDOMAINS_PER_SEED,
    on_progress: Callable[[str], None] | None = None,
) -> tuple[ReconResult, list[Finding]]:
    """`max_subdomains_per_seed` only narrows *breadth* (how many
    crt.sh-discovered subdomains get fingerprinted per seed, 0 meaning
    "just the seed hosts themselves") -- it never touches per-request
    pacing against the target (FINGERPRINT_DELAY_SECONDS), which is
    calibrated to programs' own stated rate-limit requirements (e.g.
    Visa's policy: "rate limit any... testing to 1 request per second or
    longer") and must never be reduced to make a run finish faster.

    `on_progress`, if given, is called with a short human-readable status
    string at each meaningful checkpoint (per-seed substeps, each host
    fingerprinted, and an end-of-seed line with a heuristic ETA). The ETA
    is deliberately simple: average duration of seeds completed so far,
    times seeds remaining -- seeds vary a lot in how many subdomains they
    expand to, so this is a rough estimate, not a precise one, and it
    only becomes meaningful after the first seed or two complete. Never
    raises on its own account -- a broken callback would abort a real
    recon run over what's just a progress display."""
    def _report(msg: str) -> None:
        if on_progress is None:
            return
        try:
            on_progress(msg)
        except Exception:
            pass

    if not program.rules.permits(TestType.PASSIVE_RECON):
        # Should be unreachable -- passive recon is always in the default
        # allowed set -- but fail loudly rather than silently proceed if
        # that invariant is ever broken.
        raise RuntimeError(f"{program.key}: passive recon blocked by rules.permits(), refusing to proceed")

    subdomains_by_seed: dict[str, list[str]] = {}
    fingerprints: dict[str, dict] = {}
    crtsh_failures: list[str] = []
    certspotter_failures: list[str] = []
    subfinder_failures: list[str] = []
    assetfinder_failures: list[str] = []
    wayback_failures: list[str] = []
    param_urls_by_seed: dict[str, list[str]] = {}
    findings: list[Finding] = []
    nvd_cache: dict[str, list[dict]] = {}
    github_creds = GitHubCreds()

    recon_assets = [a for a in program.in_scope if a.asset_type in (AssetType.URL, AssetType.WILDCARD)]
    seeds_total = len(recon_assets)
    seeds_processed = 0
    seed_durations: list[float] = []

    # Shared across every seed -- see RECON_EXECUTOR_MAX_WORKERS. Not a context manager here
    # (the seed loop's existing KeyboardInterrupt handling below would otherwise need re-indenting
    # under a `with` block) -- shut down explicitly in `finally` instead, `wait=False` so an
    # interrupt-triggered shutdown doesn't itself block on still-running (target-untouched) futures.
    executor = ThreadPoolExecutor(max_workers=RECON_EXECUTOR_MAX_WORKERS)
    try:
        for seed_index, asset in enumerate(recon_assets, start=1):
            seed_start = time.monotonic()
            host = _extract_host(asset.identifier)
            if not host:
                seeds_processed += 1
                continue

            _report(
                f"[{seed_index}/{seeds_total}] {host}: gathering crt.sh/Certspotter/subfinder/"
                "assetfinder/Wayback subdomains + Wayback param URLs + DNS hygiene (SPF/DMARC/DKIM) "
                "(parallel, third-party services only -- never the target itself)..."
            )
            email_domain = host[4:] if host.lower().startswith("www.") else host
            crtsh_future = executor.submit(crtsh_subdomains, host)
            certspotter_future = executor.submit(certspotter_subdomains, host)
            subfinder_future = executor.submit(subfinder_subdomains, host)
            assetfinder_future = executor.submit(assetfinder_subdomains, host)
            wayback_future = executor.submit(wayback_subdomains, host)
            wayback_param_future = executor.submit(wayback_param_urls, host)
            spf_future = executor.submit(check_spf, email_domain)
            dmarc_future = executor.submit(check_dmarc, email_domain)
            dkim_future = executor.submit(check_dkim, email_domain)

            discovered, crtsh_ok = crtsh_future.result()
            if not crtsh_ok:
                crtsh_failures.append(host)

            certspotter_names, certspotter_ok = certspotter_future.result()
            if not certspotter_ok:
                certspotter_failures.append(host)
            discovered |= certspotter_names

            subfinder_names, subfinder_ok = subfinder_future.result()
            if not subfinder_ok:
                subfinder_failures.append(host)
            discovered |= subfinder_names

            assetfinder_names, assetfinder_ok = assetfinder_future.result()
            if not assetfinder_ok:
                assetfinder_failures.append(host)
            discovered |= assetfinder_names

            wayback_names, wayback_ok = wayback_future.result()
            if not wayback_ok:
                wayback_failures.append(host)
            discovered |= wayback_names

            subdomains_by_seed[host] = sorted(discovered)
            _report(f"[{seed_index}/{seeds_total}] {host}: {len(discovered)} subdomain(s) found")

            for hit in [*spf_future.result(), *dmarc_future.result(), *dkim_future.result()]:
                findings.append(
                    Finding(
                        id=f"{program.key}:{email_domain}:{hit['kind']}",
                        program_key=program.key,
                        asset=email_domain,
                        title=hit["kind"].replace("-", " "),
                        vuln_class=hit["kind"],
                        test_type=TestType.PASSIVE_RECON,
                        evidence=hit["evidence"],
                        status=FindingStatus.CANDIDATE,
                        notes=f"severity guess: {hit['severity']} -- verify manually before drafting a PoC",
                    )
                )

            param_urls = wayback_param_future.result()
            if param_urls:
                param_urls_by_seed[host] = param_urls

            time.sleep(PARALLEL_OSINT_DELAY_SECONDS)

            _report(f"[{seed_index}/{seeds_total}] {host}: JS harvesting...")
            for hit in _harvest_js_for_host(host, program.rules):
                digest = hashlib.sha256(f"{host}:{hit['kind']}:{hit['evidence']}".encode()).hexdigest()[:12]
                findings.append(
                    Finding(
                        id=f"{program.key}:{host}:{digest}",
                        program_key=program.key,
                        asset=host,
                        title=hit["kind"].replace("-", " "),
                        vuln_class=hit["kind"],
                        test_type=TestType.PASSIVE_RECON,
                        evidence=hit["evidence"],
                        status=FindingStatus.CANDIDATE,
                        notes=f"severity guess: {hit['severity']} -- verify manually before drafting a PoC",
                    )
                )

            _report(f"[{seed_index}/{seeds_total}] {host}: robots.txt / security.txt...")
            for hit in _check_well_known_for_host(host, program.rules):
                digest = hashlib.sha256(f"{host}:{hit['kind']}:{hit['evidence']}".encode()).hexdigest()[:12]
                findings.append(
                    Finding(
                        id=f"{program.key}:{host}:{digest}",
                        program_key=program.key,
                        asset=host,
                        title=hit["kind"].replace("-", " "),
                        vuln_class=hit["kind"],
                        test_type=TestType.PASSIVE_RECON,
                        evidence=hit["evidence"],
                        status=FindingStatus.CANDIDATE,
                        notes=f"severity guess: {hit['severity']} -- verify manually before drafting a PoC",
                    )
                )

            if github_creds.configured:
                _report(f"[{seed_index}/{seeds_total}] {host}: GitHub code search...")
                github_items = search_domain_mentions(email_domain, github_creds)
                time.sleep(GITHUB_SEARCH_DELAY_SECONDS)
                for hit in scan_github_results_for_secrets(email_domain, github_items):
                    digest = hashlib.sha256(f"{email_domain}:{hit['kind']}:{hit['evidence']}".encode()).hexdigest()[:12]
                    findings.append(
                        Finding(
                            id=f"{program.key}:{email_domain}:{digest}",
                            program_key=program.key,
                            asset=email_domain,
                            title=hit["kind"].replace("-", " "),
                            vuln_class=hit["kind"],
                            test_type=TestType.PASSIVE_RECON,
                            evidence=hit["evidence"],
                            status=FindingStatus.CANDIDATE,
                            notes=f"severity guess: {hit['severity']} -- verify manually before drafting a PoC",
                        )
                    )

            # Guardrail 1: a plain URL seed licenses testing exactly that host, never a sibling
            # subdomain just because crt.sh/Certspotter/Wayback/etc. happened to surface one --
            # only a WILDCARD-type seed actually covers its subdomains. This must gate the live
            # fingerprint/TLS/dangling-CNAME requests below the same way testing/active.py's
            # _select_hosts already gates active testing -- found missing here 2026-09-20 after a
            # live recon run against a plain-URL-scoped program sent a real request to an
            # undeclared subdomain (origin-<seed>-shaped host discovered via crt.sh).
            if asset.asset_type == AssetType.WILDCARD:
                _report(f"[{seed_index}/{seeds_total}] {host}: resolving discovered subdomains...")
                resolvable = dnsx_resolve(discovered)
                discovered_for_fingerprint = resolvable if resolvable is not None else discovered
                hosts_to_fingerprint = [host] + sorted(discovered_for_fingerprint)[:max_subdomains_per_seed]
            else:
                hosts_to_fingerprint = [host]

            _report(
                f"[{seed_index}/{seeds_total}] {host}: dangling-CNAME check "
                f"({len(hosts_to_fingerprint)} host(s), parallel, DNS-only)..."
            )
            cname_futures = {th: executor.submit(check_dangling_cname, th) for th in hosts_to_fingerprint}
            cname_hits = {th: fut.result() for th, fut in cname_futures.items()}
            time.sleep(PARALLEL_OSINT_DELAY_SECONDS)

            for host_index, target_host in enumerate(hosts_to_fingerprint, start=1):
                if target_host in fingerprints:
                    continue

                _report(
                    f"[{seed_index}/{seeds_total}] {host}: fingerprinting "
                    f"{host_index}/{len(hosts_to_fingerprint)} ({target_host})..."
                )
                cname_hit = cname_hits.get(target_host)
                if cname_hit:
                    findings.append(
                        Finding(
                            id=f"{program.key}:{target_host}:{cname_hit['kind']}",
                            program_key=program.key,
                            asset=target_host,
                            title=cname_hit["kind"].replace("-", " "),
                            vuln_class=cname_hit["kind"],
                            test_type=TestType.PASSIVE_RECON,
                            evidence=cname_hit["evidence"],
                            status=FindingStatus.CANDIDATE,
                            notes=f"severity guess: {cname_hit['severity']} -- verify manually before drafting a PoC",
                        )
                    )

                fp = fingerprint(target_host, program.rules)
                time.sleep(FINGERPRINT_DELAY_SECONDS)
                if not fp:
                    continue
                fingerprints[target_host] = fp

                # Only worth attempting if we already know this host actually served something
                # over HTTPS -- a host that fell back to plain HTTP (or only ever answered HTTP)
                # is a guaranteed TLS_CERT_TIMEOUT_SECONDS-long wasted attempt otherwise, and that
                # cost multiplies fast across dozens of subdomains.
                tls_info = None
                if (fp.get("final_url") or "").startswith("https://"):
                    tls_info = tls_cert_info(target_host)
                    time.sleep(FINGERPRINT_DELAY_SECONDS)
                if tls_info:
                    fp["tls"] = tls_info
                    for hit in tls_findings(target_host, tls_info):
                        findings.append(
                            Finding(
                                id=f"{program.key}:{target_host}:{hit['kind']}",
                                program_key=program.key,
                                asset=target_host,
                                title=hit["kind"].replace("-", " "),
                                vuln_class=hit["kind"],
                                test_type=TestType.PASSIVE_RECON,
                                evidence=hit["evidence"],
                                status=FindingStatus.CANDIDATE,
                                notes=f"severity guess: {hit['severity']} -- verify manually before drafting a PoC",
                            )
                        )

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
            seed_durations.append(time.monotonic() - seed_start)
            seeds_remaining = seeds_total - seeds_processed
            if seeds_remaining > 0:
                avg_seed_seconds = sum(seed_durations) / len(seed_durations)
                eta_minutes = avg_seed_seconds * seeds_remaining / 60
                _report(
                    f"[{seed_index}/{seeds_total}] {host}: done in {seed_durations[-1]:.0f}s -- "
                    f"heuristic est. {eta_minutes:.1f} min remaining ({seeds_remaining} seed(s) left, "
                    f"avg {avg_seed_seconds:.0f}s/seed so far)"
                )
            else:
                _report(f"[{seed_index}/{seeds_total}] {host}: done in {seed_durations[-1]:.0f}s -- last seed")
    except KeyboardInterrupt:
        # Stopping mid-run (Ctrl-C, or `kill -INT`/`pkill -INT` against a
        # backgrounded run) should save everything gathered so far rather
        # than discard it -- the caller still gets a normal ReconResult
        # back, just with seeds_processed < len(recon_assets) so it knows
        # this program wasn't fully covered and may be worth re-running.
        pass
    finally:
        executor.shutdown(wait=False, cancel_futures=True)

    result = ReconResult(
        program_key=program.key,
        subdomains=subdomains_by_seed,
        fingerprints=fingerprints,
        crtsh_failures=crtsh_failures,
        certspotter_failures=certspotter_failures,
        subfinder_failures=subfinder_failures,
        assetfinder_failures=assetfinder_failures,
        wayback_failures=wayback_failures,
        param_urls=param_urls_by_seed,
        seeds_total=len(recon_assets),
        seeds_processed=seeds_processed,
        last_run=datetime.utcnow(),
    )
    return result, findings
