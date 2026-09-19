"""Passive checks against the small set of well-known, publicly-meant-to-be-
read files a host serves at fixed, conventional paths: robots.txt and
security.txt (RFC 9116). Each is one GET to a path any web crawler or
security researcher is expected to request -- same request class as
fingerprint()'s plain GET, so everything here lands as TestType.PASSIVE_RECON,
no approval needed.

Both checks are drawn from docs/EXTERNAL_RESOURCES.md's mapping of
EdOverflow's bugbounty-cheatsheet recon notes onto this project: robots.txt
Disallow entries are a classic source of unlinked-but-real paths worth
exploring manually, and security.txt/RFC 9116 (whose author is also
EdOverflow) exists specifically to standardize where a program publishes its
own disclosure contact/policy -- reading it here is simply following that
published channel, never contacting the program itself.

robots.txt Disallow paths are aggregated into one informational finding per
host (same "worth manually exploring" pattern as js_harvest.py's internal-
API-path aggregation) -- a Disallow entry discloses that a path exists, not
that anything sensitive lives there. security.txt is surfaced only as an
informational contact/policy summary, never as something needing a fix.
"""
from __future__ import annotations

import re

import httpx

WELL_KNOWN_FETCH_TIMEOUT_SECONDS = 8
MAX_DISALLOW_PATHS_REPORTED = 25

_DISALLOW_RE = re.compile(r"(?im)^\s*Disallow:\s*(\S+)")
_CONTACT_RE = re.compile(r"(?im)^\s*Contact:\s*\S+")


def _get(url: str, headers: dict[str, str], *, timeout: float) -> httpx.Response | None:
    try:
        resp = httpx.get(url, headers=headers, timeout=timeout, follow_redirects=True)
    except httpx.HTTPError:
        return None
    return resp if resp.status_code == 200 else None


def check_robots_txt(
    host: str, headers: dict[str, str], *, timeout: float = WELL_KNOWN_FETCH_TIMEOUT_SECONDS
) -> list[dict]:
    """One GET to /robots.txt. Disallow paths are aggregated into a single
    informational finding (not one per path, to avoid finding spam) -- a
    human should look at the short list themselves. Returns [] if
    robots.txt isn't served, or is served but lists no Disallow entries --
    both are common and not themselves a finding."""
    resp = _get(f"https://{host}/robots.txt", headers, timeout=timeout)
    if resp is None:
        return []
    paths = sorted(set(_DISALLOW_RE.findall(resp.text)))[:MAX_DISALLOW_PATHS_REPORTED]
    if not paths:
        return []
    sample = ", ".join(paths[:10])
    return [{
        "kind": "robots-txt-disallowed-paths",
        "severity": "info",
        "evidence": (
            f"{host}/robots.txt lists {len(paths)} Disallow path(s), e.g.: {sample}. Worth exploring "
            "manually -- a Disallow entry only asks crawlers not to index a path, it doesn't mean the "
            "path is actually access-controlled."
        ),
    }]


def check_security_txt(
    host: str, headers: dict[str, str], *, timeout: float = WELL_KNOWN_FETCH_TIMEOUT_SECONDS
) -> list[dict]:
    """RFC 9116: tries /.well-known/security.txt first (the standardized
    location) and falls back to the legacy /security.txt. Purely
    informational -- records that a disclosure policy/contact exists (or
    doesn't), never treated as a vulnerability. Only fires when the file
    actually contains a Contact: line, to avoid matching an unrelated 200
    (e.g. a custom 404 page) that happens to serve something at that path."""
    resp = _get(f"https://{host}/.well-known/security.txt", headers, timeout=timeout)
    source = ".well-known/security.txt"
    if resp is None:
        resp = _get(f"https://{host}/security.txt", headers, timeout=timeout)
        source = "security.txt"
    if resp is None or not _CONTACT_RE.search(resp.text):
        return []
    contact_line = next((l.strip() for l in resp.text.splitlines() if l.strip().lower().startswith("contact:")), "")
    return [{
        "kind": "security-txt-present",
        "severity": "info",
        "evidence": (
            f"{host} publishes {source} (RFC 9116) with {contact_line}. Not a vulnerability -- kept for "
            "reference (correct disclosure channel) when drafting a report."
        ),
    }]
