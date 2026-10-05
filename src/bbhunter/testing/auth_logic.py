"""Two more human-session-driven auth checks, same safe paradigm as
testing/idor.py: the human supplies a real session they control, each
check is read-only and single-request, and everything is gated by
RulesOfEngagement.permits(TestType.ACTIVE_LOW_IMPACT).

- check_token_leak: does a resource leak the caller's own auth token
  somewhere a third party could read it -- echoed into the response
  body, or carried in a redirect's URL/Location (where it lands in
  browser history, Referer headers, and proxy logs)? The token value is
  the human's own; we only look for *where it ends up*, never transmit
  anything new.
- check_session_valid: after the human logs out of a session out-of-band,
  does that now-"dead" session still return an authenticated response?
  One GET; a non-denied 200 means the server didn't actually invalidate
  it (broken session management). The logout itself is the human's
  action, never this tool's -- we only observe whether the old session
  still works.
"""
from __future__ import annotations

import hashlib

import httpx

from bbhunter.models import Finding, FindingStatus, Program, TestType
from bbhunter.safety import assert_active_allowed, assert_in_scope

# Reused denial heuristic -- a response that looks like a login wall or an
# explicit deny is NOT the resource being served.
_DENIAL_SIGNATURES = (
    "not authorized",
    "unauthorized",
    "forbidden",
    "access denied",
    "permission denied",
    "please log in",
    "please sign in",
    "log in to continue",
    "sign in to continue",
)


def _looks_denied(status_code: int, body_lower: str) -> bool:
    if status_code in (401, 403):
        return True
    return any(sig in body_lower for sig in _DENIAL_SIGNATURES)


def check_token_leak(
    url: str, headers: dict[str, str], token_value: str, *, timeout: float = 15
) -> dict | None:
    """One GET. Flags a leak if `token_value` (the caller's own auth
    token/session) appears in the final URL after redirects, in a
    redirect-chain Location header, or reflected in the response body."""
    if not token_value:
        return None
    try:
        resp = httpx.get(url, headers=headers, timeout=timeout, follow_redirects=True)
    except httpx.HTTPError:
        return None

    where: list[str] = []
    if token_value in str(resp.url):
        where.append("final URL after redirect")
    for r in resp.history:
        if token_value in r.headers.get("location", ""):
            where.append("a redirect Location header")
            break
    if token_value in resp.text:
        where.append("the response body")
    if not where:
        return None
    return {
        "kind": "auth-token-leak",
        "severity": "medium",
        "evidence": (
            f"GET {url}: the supplied auth token value appears in {', '.join(sorted(set(where)))}. "
            "A token in a URL/Location leaks via browser history, Referer, and proxy/server logs; "
            "reflected in the body it may be exposed to other scripts. Verify the token is genuinely "
            "sensitive (not a public CSRF token) and reaches a third party before drafting a PoC."
        ),
    }


def check_session_valid(url: str, headers: dict[str, str], *, timeout: float = 15) -> dict | None:
    """One GET with a session the human has already logged out of
    out-of-band. A non-denied 200 means the session is still alive ->
    broken session invalidation. Returns None if it's properly dead
    (denied/redirected to login) -- the expected, non-vulnerable outcome."""
    try:
        resp = httpx.get(url, headers=headers, timeout=timeout, follow_redirects=True)
    except httpx.HTTPError:
        return None
    if resp.status_code != 200 or _looks_denied(resp.status_code, resp.text.lower()):
        return None
    return {
        "kind": "session-not-invalidated",
        "severity": "medium",
        "evidence": (
            f"GET {url} returned HTTP 200 (non-denial body) using a session that was logged out "
            "out-of-band before this request -- the server did not invalidate it server-side. "
            "Confirm the logout actually completed and that this is the same session token before "
            "drafting a PoC."
        ),
    }


def _finding(program: Program, url: str, hit: dict, note: str | None) -> Finding:
    digest = hashlib.sha256(f"{hit['kind']}:{url}".encode()).hexdigest()[:12]
    evidence = hit["evidence"]
    if note:
        evidence = f"{evidence} Context: {note}"
    return Finding(
        id=f"{program.key}:{hit['kind']}:{digest}",
        program_key=program.key,
        asset=url,
        title=f"{hit['kind']} candidate",
        vuln_class=hit["kind"],
        test_type=TestType.ACTIVE_LOW_IMPACT,
        evidence=evidence,
        status=FindingStatus.CANDIDATE,
        notes=f"severity guess: {hit['severity']} -- verify manually before drafting a PoC",
    )


def _require_active(program: Program, url: str | None = None) -> None:
    assert_active_allowed()
    if not program.rules.permits(TestType.ACTIVE_LOW_IMPACT):
        raise RuntimeError(
            f"{program.key}: blocked by rules.permits() -- run `bbhunter review-rules` and "
            "`bbhunter approve-active` first if this program's policy actually allows it"
        )
    if url is not None:
        assert_in_scope(program, url)


def run_token_leak_check(
    program: Program, url: str, headers: dict[str, str], token_value: str, *, note: str | None = None
) -> list[Finding]:
    _require_active(program, url)
    hit = check_token_leak(url, headers, token_value)
    return [_finding(program, url, hit, note)] if hit else []


def run_session_valid_check(
    program: Program, url: str, headers: dict[str, str], *, note: str | None = None
) -> list[Finding]:
    _require_active(program, url)
    hit = check_session_valid(url, headers)
    return [_finding(program, url, hit, note)] if hit else []
