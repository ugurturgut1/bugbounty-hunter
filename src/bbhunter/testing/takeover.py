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

import httpx

from bbhunter.models import Finding, FindingStatus, Program, TestType

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
    'inconclusive', not 'vulnerable')."""
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
    if not program.rules.permits(TestType.ACTIVE_LOW_IMPACT):
        raise RuntimeError(
            f"{program.key}: takeover check blocked by rules.permits() -- run `bbhunter review-rules` "
            "and `bbhunter approve-active` first if this program's policy actually allows it"
        )
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
