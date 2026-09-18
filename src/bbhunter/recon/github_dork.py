"""Optional passive GitHub code-search recon: looks for public repos
mentioning the target's domain and scans the matched code snippets for
real secret-shaped patterns (the same `bbhunter.secret_patterns` used by
testing/ai_safety.py and recon/js_harvest.py). Fully passive -- every
request goes to GitHub's own public API, never touches the target's
infrastructure -- classic "GitHub recon" dorking technique, catches
leaked credentials/internal URLs that never touch the target's own
infra at all.

GitHub's code-search endpoint requires an authenticated token even for
public repos (a free personal access token with NO scopes checked
works, since this only ever calls a public read-only search endpoint),
so this source is optional and skips silently -- same graceful-
degradation pattern as subfinder/nuclei/openssl -- when
`GitHubCreds.configured` is False.

Deliberately conservative: one search query per seed domain (never one
per discovered subdomain), a capped result count, and a Finding is only
ever produced when a real secret-shaped pattern actually matches a
returned code snippet -- "a public repo mentions this domain" on its
own is far too common (client SDKs, tutorials, the company's own public
docs) to be a useful signal by itself.
"""
from __future__ import annotations

from bbhunter.config import GitHubCreds
from bbhunter.secret_patterns import SECRET_PATTERNS

import httpx

GITHUB_SEARCH_URL = "https://api.github.com/search/code"
GITHUB_SEARCH_TIMEOUT_SECONDS = 15
GITHUB_SEARCH_DELAY_SECONDS = 6.0  # GitHub code search: 10 req/min authenticated -- stay well under
MAX_RESULTS_SCANNED = 10


def search_domain_mentions(domain: str, creds: GitHubCreds, *, timeout: float = GITHUB_SEARCH_TIMEOUT_SECONDS) -> list[dict]:
    """One code-search query for `"<domain>"`. Returns [] (not an error)
    if no token is configured, the request fails, or nothing matched --
    callers must treat [] as "no signal", never as "confirmed clean"."""
    if not creds.configured:
        return []

    headers = {
        "Authorization": f"Bearer {creds.token}",
        "Accept": "application/vnd.github.v3.text-match+json",
        "User-Agent": "bbhunter-recon/0.1 (personal security research tool)",
    }
    try:
        resp = httpx.get(
            GITHUB_SEARCH_URL,
            params={"q": f'"{domain}"', "per_page": MAX_RESULTS_SCANNED},
            headers=headers,
            timeout=timeout,
        )
        resp.raise_for_status()
        data = resp.json()
    except (httpx.HTTPError, ValueError):
        return []

    return (data.get("items") or [])[:MAX_RESULTS_SCANNED]


def scan_github_results_for_secrets(domain: str, items: list[dict]) -> list[dict]:
    hits: list[dict] = []
    for item in items:
        repo_full_name = (item.get("repository") or {}).get("full_name", "unknown/unknown")
        html_url = item.get("html_url", "")
        for text_match in item.get("text_matches") or []:
            fragment = text_match.get("fragment", "")
            for pattern in SECRET_PATTERNS:
                if pattern.search(fragment):
                    hits.append({
                        "kind": "github-leaked-secret-candidate",
                        "severity": "high",
                        "evidence": (
                            f"Public GitHub repo {repo_full_name} mentions '{domain}' in code that also "
                            f"matches a real secret-shaped pattern ({pattern.pattern}): {html_url}. "
                            "The actual matched value is deliberately not included here -- open the file "
                            "yourself, verify, and rotate any real credential this turns out to be."
                        ),
                    })
                    break  # one hit per matched fragment is enough signal, don't multiply per-pattern
    return hits
