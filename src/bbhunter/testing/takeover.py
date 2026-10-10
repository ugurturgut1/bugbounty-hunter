"""Active subdomain-takeover confirmation. recon/dns_hygiene.py already
flags the *passive* precursor (a CNAME to an NXDOMAIN target); this adds
the HTTP-level confirmation that catches the larger class where the
CNAME target *does* resolve but points at an unclaimed resource on a
third-party service (GitHub Pages, S3, Heroku, ...). One GET per host;
if the response body carries a known "this resource is unclaimed"
fingerprint for such a service, that subdomain is likely claimable.

Read-only (a single GET to an in-scope host), gated by
RulesOfEngagement.permits(TestType.ACTIVE_LOW_IMPACT) like every active
check. Detection only -- it never attempts to actually claim/register
anything; the finding tells the human to verify and claim-test manually.

Fingerprints are a conservative subset of the community
can-i-take-over-xyz list -- the strings are distinctive enough that a
match is a strong signal, but still 'candidate', never confirmed.
"""
from __future__ import annotations

import hashlib

import dns.resolver
import httpx

from bbhunter.models import Finding, FindingStatus, Program, TestType
from bbhunter.safety import assert_active_allowed, is_in_scope

# CNAME targets of Google-hosted custom-domain services (Blogger, Sites,
# Workspace). A dangling CNAME here serving Google's "no site configured" 404
# is stale DNS, but -- unlike the claimable services below -- it is generally
# NOT takeoverable: Blogger needs a security CNAME and Workspace needs domain-
# ownership verification an attacker can't satisfy (per can-i-take-over-xyz).
# So this is flagged LOW/informational, for the human to verify, not a
# high-severity takeover.
_GOOGLE_GHS_TARGETS = ("ghs.google.com", "ghs.googlehosted.com")


def _cname_target(host: str) -> str | None:
    """Return the host's CNAME target (lowercased, no trailing dot), or None."""
    try:
        ans = dns.resolver.resolve(host, "CNAME")
    except Exception:
        return None
    return str(ans[0].target).rstrip(".").lower() if ans else None

# service label -> distinctive body substrings that mean "unclaimed here"
TAKEOVER_FINGERPRINTS: dict[str, tuple[str, ...]] = {
    "GitHub Pages": ("There isn't a GitHub Pages site here.", "For root URLs (like http://example.com/) you must provide an index.html file"),
    "AWS S3": ("NoSuchBucket", "The specified bucket does not exist"),
    "Heroku": ("No such app", "herokucdn.com/error-pages/no-such-app.html"),
    "Fastly": ("Fastly error: unknown domain",),
    "Shopify": ("Sorry, this shop is currently unavailable",),
    "Surge.sh": ("project not found",),
    "Bitbucket": ("Repository not found",),
    "Pantheon": ("The gods are wise, but do not know of the site which you seek",),
    "Tumblr": ("Whatever you were looking for doesn't currently exist at this address.",),
    "Zendesk": ("Help Center Closed",),
    "Cargo Collective": ("If you're moving your domain away from Cargo",),
    "Webflow": ("The page you are looking for doesn't exist or has been moved",),
}


def check_takeover(host: str, *, timeout: float = 15) -> dict | None:
    """One GET. Returns a hit dict if the body matches a known unclaimed
    -service fingerprint, else None (including on any HTTP error -- that's
    'inconclusive', not 'vulnerable'). Also flags a dangling CNAME to a
    Google-hosted service (ghs) separately, at low severity."""
    # Google ghs dangling CNAME: check DNS first, since these hosts often serve
    # no HTTPS at all (the unconfigured domain has no cert), so the https GET
    # below would just error out and miss them.
    cname = _cname_target(host)
    if cname and any(cname == t or cname.endswith("." + t) for t in _GOOGLE_GHS_TARGETS):
        for scheme in ("https", "http"):
            try:
                r = httpx.get(f"{scheme}://{host}/", timeout=timeout, follow_redirects=False)
            except httpx.HTTPError:
                continue
            if r.status_code == 404:
                return {
                    "service": "Google (ghs)",
                    "severity": "low",
                    "evidence": (
                        f"{host} is CNAME'd to {cname} (Google-hosted) and serves Google's "
                        f"'no site configured' 404 ({scheme}). This is a dangling/stale DNS record. "
                        "Per can-i-take-over-xyz, ghs/Blogger/Workspace mappings are generally NOT "
                        "claimable without domain-ownership verification, so this is usually informational "
                        "(a record to remove), not a takeover -- verify claimability before rating higher."
                    ),
                }
    try:
        resp = httpx.get(f"https://{host}/", timeout=timeout, follow_redirects=True)
    except httpx.HTTPError:
        return None
    body = resp.text
    for service, signatures in TAKEOVER_FINGERPRINTS.items():
        if any(sig in body for sig in signatures):
            return {
                "service": service,
                "severity": "high",
                "evidence": (
                    f"GET https://{host}/ -> HTTP {resp.status_code} returned {service}'s "
                    "'unclaimed resource' page, which is the classic subdomain-takeover signal: the DNS "
                    "record still points at a resource that no longer exists on that service and may be "
                    "claimable. Verify ownership and attempt a controlled claim-test manually before "
                    "drafting a PoC -- never claim a resource you can't immediately release."
                ),
            }
    return None


def run_takeover_check(program: Program, hosts: list[str], *, delay: float = 1.5) -> list[Finding]:
    assert_active_allowed()
    if not program.rules.permits(TestType.ACTIVE_LOW_IMPACT):
        raise RuntimeError(
            f"{program.key}: takeover check blocked by rules.permits() -- run `bbhunter review-rules` "
            "and `bbhunter approve-active` first if this program's policy actually allows it"
        )
    hosts = [h for h in hosts if is_in_scope(program, h)]  # defense-in-depth: never probe off-scope
    import time

    findings: list[Finding] = []
    for i, host in enumerate(hosts):
        if i:
            time.sleep(delay)
        hit = check_takeover(host)
        if not hit:
            continue
        digest = hashlib.sha256(host.encode()).hexdigest()[:12]
        findings.append(
            Finding(
                id=f"{program.key}:takeover:{digest}",
                program_key=program.key,
                asset=host,
                title=f"Possible subdomain takeover ({hit['service']})",
                vuln_class="subdomain-takeover",
                test_type=TestType.ACTIVE_LOW_IMPACT,
                evidence=hit["evidence"],
                status=FindingStatus.CANDIDATE,
                notes=f"severity guess: {hit['severity']} -- verify manually before drafting a PoC",
            )
        )
    return findings
