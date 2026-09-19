"""TestType.CREDENTIAL_TESTING -- tests a small, explicit,
human-supplied credential list against a login endpoint. This is
deliberately NOT an open-ended wordlist/username-list brute force
(that's `hydra`'s job, and this project doesn't wrap it) -- login/
credential brute-forcing is one of the most commonly explicitly
prohibited techniques across bug bounty programs and risks locking out
real user accounts, a denial of service to actual users rather than
just the target company (see cli.py's `_RISK_WARNINGS` for the full
warning shown before this tier can even be approved).

`MAX_CREDENTIALS_PER_RUN` is a hard cap, enforced in code, not just
documentation: this function refuses to run against more than a small
handful of credential pairs. Every credential pair must come from the
user themselves (their own test account, or one the program explicitly
provided) -- this module never generates, guesses, or expands a
wordlist on its own.

Stops immediately the moment a response matches a lockout/rate-limit
signature (`LOCKOUT_SIGNATURES`), rather than continuing through the
rest of the (already small) list -- continuing past that signal is
exactly the harm this category exists to avoid.

Success detection is unavoidably weaker/more heuristic here than
elsewhere in this project: whether a login succeeded is inherently
app-specific. If the caller can supply a known "logged in" string
(`success_signature`), that's used directly; otherwise this falls back
to "the response shape differs from every failed attempt's shape,
without matching a known failure signature" -- a real heuristic, not a
strong signal, documented honestly rather than overclaiming."""
from __future__ import annotations

import hashlib
import time

import httpx

from bbhunter.models import Finding, FindingStatus, Program, RulesOfEngagement, TestType
from bbhunter.recon.passive import _extract_host, _request_headers

MAX_CREDENTIALS_PER_RUN = 10  # hard cap -- credential TESTING, not a brute-force engine
CREDENTIAL_TEST_DELAY_SECONDS = 2.0  # slower than every other check in this project, deliberately
CREDENTIAL_TEST_TIMEOUT_SECONDS = 15

LOCKOUT_SIGNATURES = (
    "account locked", "account is locked", "too many attempts", "too many failed",
    "temporarily locked", "try again later", "rate limit", "rate-limited",
    "suspicious activity", "temporarily suspended",
)


def test_credentials(
    login_url: str,
    username_field: str,
    password_field: str,
    credentials: list[tuple[str, str]],
    rules: RulesOfEngagement,
    *,
    success_signature: str | None = None,
    failure_signature: str | None = None,
    timeout: float = CREDENTIAL_TEST_TIMEOUT_SECONDS,
) -> list[dict]:
    """POSTs each `(username, password)` pair in `credentials` to
    `login_url`, one at a time, `CREDENTIAL_TEST_DELAY_SECONDS` apart.
    Raises `ValueError` (never silently truncates) if `credentials` is
    larger than `MAX_CREDENTIALS_PER_RUN`. Returns a list of hit dicts;
    stops early (returning whatever was already found) the moment a
    lockout/rate-limit signature is observed in a response."""
    if len(credentials) > MAX_CREDENTIALS_PER_RUN:
        raise ValueError(
            f"refusing to test {len(credentials)} credential pair(s) -- capped at "
            f"{MAX_CREDENTIALS_PER_RUN}. This is bounded credential testing, not a wordlist brute "
            "force; a larger list needs a manual, human-supervised session outside this tool."
        )

    headers = _request_headers(rules)
    hits: list[dict] = []
    seen_failure_shapes: set[tuple[int, int]] = set()

    with httpx.Client(headers=headers, timeout=timeout, follow_redirects=True) as client:
        for username, password in credentials:
            try:
                resp = client.post(login_url, data={username_field: username, password_field: password})
            except httpx.HTTPError:
                time.sleep(CREDENTIAL_TEST_DELAY_SECONDS)
                continue

            body_lower = resp.text.lower()
            if any(sig in body_lower for sig in LOCKOUT_SIGNATURES):
                hits.append(
                    {
                        "kind": "credential-testing-stopped-lockout-signal",
                        "severity": "info",
                        "evidence": (
                            f"POST {login_url} (username '{username}') triggered a lockout/rate-limit "
                            "signature in the response -- stopped immediately, no further credentials "
                            "were tried. Report this to the program if it wasn't expected."
                        ),
                    }
                )
                break

            shape = (resp.status_code, len(resp.content))
            is_hit = False
            if success_signature:
                is_hit = success_signature.lower() in body_lower
            elif seen_failure_shapes and shape not in seen_failure_shapes:
                is_hit = not (failure_signature and failure_signature.lower() in body_lower)

            if is_hit:
                hits.append(
                    {
                        "kind": "credential-testing-possible-success",
                        "username": username,
                        "severity": "critical",
                        "evidence": (
                            f"POST {login_url} (username '{username}') produced a response "
                            f"(HTTP {resp.status_code}, {len(resp.content)} bytes) that looks like a "
                            "successful login. Signature-based/heuristic -- login-success detection is "
                            "inherently app-specific, verify manually before treating as confirmed."
                        ),
                    }
                )
            else:
                seen_failure_shapes.add(shape)

            time.sleep(CREDENTIAL_TEST_DELAY_SECONDS)

    return hits


def run_credential_test(
    program: Program,
    login_url: str,
    username_field: str,
    password_field: str,
    credentials: list[tuple[str, str]],
    *,
    success_signature: str | None = None,
    failure_signature: str | None = None,
) -> list[Finding]:
    """`bbhunter test-credentials` entry point. Requires
    `permits(TestType.CREDENTIAL_TESTING)`."""
    if not program.rules.permits(TestType.CREDENTIAL_TESTING):
        raise RuntimeError(
            f"{program.key}: credential testing blocked by rules.permits() -- run `bbhunter review-rules` "
            "and `bbhunter approve-active --test-type credential_testing --i-understand-the-risk` first"
        )

    hits = test_credentials(
        login_url, username_field, password_field, credentials, program.rules,
        success_signature=success_signature, failure_signature=failure_signature,
    )
    findings: list[Finding] = []
    for hit in hits:
        digest = hashlib.sha256(f"{login_url}:{hit['kind']}:{hit.get('username', '')}".encode()).hexdigest()[:12]
        findings.append(
            Finding(
                id=f"{program.key}:{digest}",
                program_key=program.key,
                asset=_extract_host(login_url) or login_url,
                title=hit["kind"].replace("-", " "),
                vuln_class=hit["kind"],
                test_type=TestType.CREDENTIAL_TESTING,
                evidence=hit["evidence"],
                status=FindingStatus.CANDIDATE,
                notes=f"severity guess: {hit['severity']} -- verify manually before drafting a PoC",
            )
        )
    return findings
