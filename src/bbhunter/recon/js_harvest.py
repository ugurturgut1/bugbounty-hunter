"""Passive JS harvesting + secret scanning. A `<script src>` linked from
a page recon already fetched is public static content served to any
visitor -- fetching and reading it is the same request class as the
plain GET `fingerprint()` already makes against the page itself, so
everything here lands as TestType.PASSIVE_RECON, no approval needed.

Three things are checked per JS file:
1. Hardcoded secrets (`bbhunter.secret_patterns.SECRET_PATTERNS` -- the
   same real secret-shaped patterns testing/ai_safety.py uses, not just
   keyword matching). The evidence never includes the actual matched
   substring, only which pattern matched -- this project doesn't persist
   real credential material into its own state DB.
2. Exposed source maps (`//# sourceMappingURL=...` comment, then one
   follow-up GET to confirm the map is actually publicly served and
   looks like real source-map JSON) -- a source map routinely leaks
   original unminified source, comments, and internal file paths that
   the minified bundle itself doesn't.
3. Referenced internal-looking API paths (absolute paths matching
   `/api/...`-shaped strings) -- aggregated per host as a single
   informational finding (not one per path, to avoid finding spam),
   input for a human to manually explore further.

Every fetch is a single GET, byte-capped via streaming so a
multi-hundred-MB bundle can't be fully downloaded, and the whole scan is
capped at a handful of JS files per page to keep this from ballooning a
single host's request count.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

import httpx
from bs4 import BeautifulSoup

from bbhunter.secret_patterns import SECRET_PATTERNS

MAX_JS_FILES_PER_PAGE = 8
JS_FETCH_TIMEOUT_SECONDS = 8  # trimmed from 15 2026-09-18 -- charged per linked JS file (up to 8), a
                              # dead/unreachable CDN link at the old timeout could cost 2 minutes on its own
JS_FETCH_MAX_BYTES = 2_000_000  # ~2MB -- enough for basically any real bundle's meaningful content
SOURCE_MAP_FETCH_TIMEOUT_SECONDS = 8

_SOURCE_MAP_COMMENT_RE = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)")
_INTERNAL_PATH_RE = re.compile(r'["\'](/api/[a-zA-Z0-9_\-/{}.]{2,80})["\']')
MAX_INTERNAL_PATHS_REPORTED = 15


def extract_script_urls(base_url: str, html: str) -> list[str]:
    """Absolute URLs for every `<script src>` on the page, deduped,
    capped at MAX_JS_FILES_PER_PAGE. Includes third-party-hosted scripts
    too (e.g. a CDN) -- a leaked secret doesn't stop mattering just
    because the JS itself is served from a different host."""
    soup = BeautifulSoup(html, "html.parser")
    urls: list[str] = []
    for tag in soup.find_all("script", src=True):
        src = tag.get("src")
        if not src:
            continue
        absolute = urljoin(base_url, src)
        if absolute not in urls:
            urls.append(absolute)
        if len(urls) >= MAX_JS_FILES_PER_PAGE:
            break
    return urls


def fetch_text_capped(url: str, *, max_bytes: int = JS_FETCH_MAX_BYTES, timeout: float = JS_FETCH_TIMEOUT_SECONDS) -> str | None:
    """One GET, read as a stream and stop after `max_bytes` rather than
    fully downloading an arbitrarily large response. Returns None on any
    request failure -- callers must treat that as "no signal", never as
    "found nothing"."""
    try:
        with httpx.stream("GET", url, timeout=timeout, follow_redirects=True) as resp:
            if resp.status_code != 200:
                return None
            chunks: list[bytes] = []
            total = 0
            for chunk in resp.iter_bytes():
                chunks.append(chunk)
                total += len(chunk)
                if total >= max_bytes:
                    break
            return b"".join(chunks).decode(errors="ignore")
    except httpx.HTTPError:
        return None


def scan_js_secrets(js_url: str, js_text: str) -> list[dict]:
    hits: list[dict] = []
    for pattern in SECRET_PATTERNS:
        if pattern.search(js_text):
            hits.append({
                "kind": "js-embedded-secret",
                "severity": "critical",
                "evidence": (
                    f"Publicly-served JS at {js_url} contains a match for a real secret-shaped pattern "
                    f"({pattern.pattern}). The actual matched value is deliberately not included here -- "
                    "fetch the file yourself, verify, and rotate any real credential this turns out to be."
                ),
            })
    return hits


def find_source_map_url(js_url: str, js_text: str) -> str | None:
    # The sourceMappingURL comment is conventionally the last line -- searching the
    # whole text is still cheap for anything under JS_FETCH_MAX_BYTES and avoids
    # missing it on a bundle that appends trailing metadata after the comment.
    match = _SOURCE_MAP_COMMENT_RE.search(js_text)
    if not match:
        return None
    return urljoin(js_url, match.group(1))


def check_source_map_exposed(map_url: str, *, timeout: float = SOURCE_MAP_FETCH_TIMEOUT_SECONDS) -> dict | None:
    try:
        resp = httpx.get(map_url, timeout=timeout, follow_redirects=True)
    except httpx.HTTPError:
        return None
    if resp.status_code != 200:
        return None
    body = resp.text
    if '"sources"' not in body or '"mappings"' not in body:
        return None
    return {
        "kind": "exposed-source-map",
        "severity": "medium",
        "evidence": (
            f"Source map {map_url} is publicly accessible and looks like real source-map JSON "
            "('sources'/'mappings' keys present). Source maps routinely leak original unminified "
            "source, developer comments, and internal file paths not present in the shipped bundle."
        ),
    }


def scan_js_internal_paths(js_text: str) -> list[str]:
    return sorted(set(_INTERNAL_PATH_RE.findall(js_text)))[:MAX_INTERNAL_PATHS_REPORTED]
