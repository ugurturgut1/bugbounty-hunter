"""Phase 3: active testing, deliberately scoped to read-only misconfig and
exposed-file checks -- no injection payloads, no state-changing requests.
Only runs when RulesOfEngagement.permits(TestType.ACTIVE_LOW_IMPACT) is
True, which requires an explicit recorded human decision (see cli.py
`review-rules` / `approve-active`) -- never something this module or any
heuristic can unlock on its own.

Every check is a single GET to a well-known path. Findings are gated
behind a soft-404 baseline: many sites return HTTP 200 with a generic
page for ANY path, and naively flagging "status == 200" on those would
be pure noise. We fetch one random nonexistent path first and only flag
a candidate if its response is both 200, meaningfully different in size
from that baseline, AND its body matches a signature specific to the
file we're checking for.
"""
from __future__ import annotations

import secrets
import time

import httpx

from bbhunter.models import AssetType, Finding, FindingStatus, Program, TestType
from bbhunter.recon.passive import _extract_host, _request_headers

REQUEST_DELAY_SECONDS = 1.5
MAX_HOSTS_PER_PROGRAM = 15

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


def run_active_checks(program: Program) -> list[Finding]:
    if not program.rules.permits(TestType.ACTIVE_LOW_IMPACT):
        raise RuntimeError(
            f"{program.key}: active testing blocked by rules.permits() -- run `bbhunter review-rules` "
            "and `bbhunter approve-active` first if this program's policy actually allows it"
        )

    headers = _request_headers(program.rules)

    hosts: list[str] = []
    for asset in program.in_scope:
        if asset.asset_type not in (AssetType.URL, AssetType.WILDCARD):
            continue
        host = _extract_host(asset.identifier)
        if host and host not in hosts:
            hosts.append(host)
    hosts = hosts[:MAX_HOSTS_PER_PROGRAM]

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

    return findings
