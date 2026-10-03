"""Opt-in authenticated-session-diffing checks for OWASP API Top 10
2023's two access-control categories: API1 Broken Object Level
Authorization (BOLA, the API-specific generalization of "IDOR") and
API5 Broken Function Level Authorization (BFLA -- the same defect, but
against an administrative/privileged function or endpoint rather than a
data object). Mechanically identical technique, different target shape,
kept as one module since a BFLA finding is just a BOLA finding pointed
at `/admin/...` instead of `/orders/123`.

Unlike every other check in this package, this is inherently
manual-input-driven: both are app-specific by nature (there's no generic
path/signature to scan for the way there is for an exposed .env file),
so they can't be automated the way the rest of this module is -- they
need a human to supply two real identities and a URL known to belong to
(or be accessible by) one of them.

The technique: fetch the same exact URL once authenticated as the
confirmed owner/authorized identity (confirms the URL is real and
accessible at all -- the baseline) and once authenticated as a second,
unrelated (and for BFLA, lower-privileged) identity. If the second
identity also gets a non-denied 200 response of similar shape to the
first's, that's a real access-control signal: two requests total, no
enumeration, no guessing IDs, no follow-through past detection.

Gated by the same RulesOfEngagement.permits(TestType.ACTIVE_LOW_IMPACT)
check as the rest of this module -- this class of probing via two
already-authenticated sessions is the same "safe probes, no data
modification" class as everything else here, not a new tier. Both
identities' credentials always come from the human running this, never
anything this tool invents, guesses, or brute-forces on its own.
"""
from __future__ import annotations

import hashlib
import time

import httpx

from bbhunter.models import Finding, FindingStatus, Program, TestType

# Spacing between successive URLs in a batch run. A batch tests many
# human-curated URLs in one go, so -- unlike a one-off single-URL check --
# the aggregate request rate matters: paired with the per-check
# inter-request delay below, this keeps a batch comfortably under a
# 1-request/second program cap (the strictest we've seen, e.g. gener8).
BATCH_URL_DELAY_SECONDS = 1.5
# Spacing between the two requests of a single access-diff. Default 0.0
# preserves the original single-URL behavior (and its tests); batch runs
# pass 1.0 so no two requests ever land inside the same second.
BATCH_INTER_REQUEST_DELAY_SECONDS = 1.0

# Response signatures suggesting a request was actually denied/redirected
# to a login page rather than genuinely served the resource -- checked on
# BOTH requests. If the owner's own "baseline" request matches one of
# these, the baseline itself is invalid (can't conclude anything), and if
# the second identity's request matches one, that's the expected/correct
# "properly denied" behavior, not a finding.
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
    "you do not have permission",
    "you don't have permission",
)


def _looks_denied(status_code: int, body_lower: str) -> bool:
    if status_code in (401, 403):
        return True
    return any(sig in body_lower for sig in _DENIAL_SIGNATURES)


def _check_access_diff(
    url: str,
    owner_headers: dict[str, str],
    other_headers: dict[str, str],
    *,
    kind: str,
    subject_label: str,
    timeout: float = 15,
    request_delay: float = 0.0,
) -> dict | None:
    """Exactly two GET requests: one as the confirmed owner/authorized
    identity (the baseline), one as a different, unrelated identity.
    Returns a hit dict only if both succeeded (200, not a denial-looking
    body) and the second response is similar in size to the first -- a
    meaningfully different size likely means a different/generic page
    (e.g. a redirect target), not the same thing actually being served
    to the wrong identity. Returns None on any HTTP error, a failed
    baseline, or a properly-denied second request -- all of those are
    "no finding," not an error condition to surface. `subject_label`
    only affects the wording of the returned evidence string (e.g.
    "resource" for BOLA vs. "function/endpoint" for BFLA)."""
    try:
        owner_resp = httpx.get(url, headers=owner_headers, timeout=timeout, follow_redirects=True)
    except httpx.HTTPError:
        return None
    if owner_resp.status_code != 200 or _looks_denied(owner_resp.status_code, owner_resp.text.lower()):
        return None  # can't establish "the owner/authorized identity can access this" -- baseline invalid

    if request_delay:
        time.sleep(request_delay)
    try:
        other_resp = httpx.get(url, headers=other_headers, timeout=timeout, follow_redirects=True)
    except httpx.HTTPError:
        return None
    if other_resp.status_code != 200:
        return None
    other_body_lower = other_resp.text.lower()
    if _looks_denied(other_resp.status_code, other_body_lower):
        return None  # correctly denied -- the expected, non-vulnerable outcome

    owner_size = len(owner_resp.content)
    other_size = len(other_resp.content)
    size_diff = abs(other_size - owner_size)
    if size_diff > max(64, owner_size * 0.2):
        return None  # meaningfully different response shape -- likely not the same thing being served

    return {
        "kind": kind,
        "severity": "high",
        "evidence": (
            f"GET {url} succeeded (HTTP 200, non-denial body) both as the confirmed owner/authorized "
            f"identity ({owner_size} bytes) and as a second, unrelated identity ({other_size} bytes, "
            f"{size_diff} bytes different) -- the second identity's request wasn't denied and "
            f"returned a response of similar shape to the first's. Detection-only, single request "
            f"pair -- verify manually that the response actually reveals the {subject_label} before "
            "treating this as confirmed, and check whether this generalizes further."
        ),
    }


def check_idor(
    url: str,
    owner_headers: dict[str, str],
    other_headers: dict[str, str],
    *,
    timeout: float = 15,
    request_delay: float = 0.0,
) -> dict | None:
    """OWASP API1:2023 Broken Object Level Authorization (BOLA), the
    generalized/API-focused name for what's colloquially called IDOR.
    See `_check_access_diff` for the mechanism."""
    return _check_access_diff(
        url, owner_headers, other_headers, kind="idor-candidate", subject_label="owner's data",
        timeout=timeout, request_delay=request_delay,
    )


def check_bfla(
    url: str,
    authorized_headers: dict[str, str],
    other_headers: dict[str, str],
    *,
    timeout: float = 15,
    request_delay: float = 0.0,
) -> dict | None:
    """OWASP API5:2023 Broken Function Level Authorization: the same
    access-diffing technique as `check_idor`, pointed at an
    administrative or privileged function/endpoint (e.g.
    `/admin/users`, `/api/internal/export`) rather than a data object,
    with a lower-privileged `other_headers` identity in place of an
    unrelated one. See `_check_access_diff` for the mechanism."""
    return _check_access_diff(
        url,
        authorized_headers,
        other_headers,
        kind="bfla-candidate",
        subject_label="privileged function's output",
        timeout=timeout,
        request_delay=request_delay,
    )


def run_idor_check(
    program: Program,
    url: str,
    owner_headers: dict[str, str],
    other_headers: dict[str, str],
    *,
    owner_note: str | None = None,
    request_delay: float = 0.0,
) -> list[Finding]:
    if not program.rules.permits(TestType.ACTIVE_LOW_IMPACT):
        raise RuntimeError(
            f"{program.key}: IDOR check blocked by rules.permits() -- run `bbhunter review-rules` "
            "and `bbhunter approve-active` first if this program's policy actually allows it"
        )

    hit = check_idor(url, owner_headers, other_headers, request_delay=request_delay)
    if not hit:
        return []

    digest = hashlib.sha256(url.encode()).hexdigest()[:12]
    evidence = hit["evidence"]
    if owner_note:
        evidence = f"{evidence} Owner context: {owner_note}"
    return [
        Finding(
            id=f"{program.key}:idor:{digest}",
            program_key=program.key,
            asset=url,
            title="BOLA/IDOR candidate: resource accessible to a second, unrelated identity",
            vuln_class=hit["kind"],
            test_type=TestType.ACTIVE_LOW_IMPACT,
            evidence=evidence,
            status=FindingStatus.CANDIDATE,
            notes=f"severity guess: {hit['severity']} -- verify manually before drafting a PoC",
        )
    ]


def run_bfla_check(
    program: Program,
    url: str,
    authorized_headers: dict[str, str],
    other_headers: dict[str, str],
    *,
    authorized_note: str | None = None,
    request_delay: float = 0.0,
) -> list[Finding]:
    if not program.rules.permits(TestType.ACTIVE_LOW_IMPACT):
        raise RuntimeError(
            f"{program.key}: BFLA check blocked by rules.permits() -- run `bbhunter review-rules` "
            "and `bbhunter approve-active` first if this program's policy actually allows it"
        )

    hit = check_bfla(url, authorized_headers, other_headers, request_delay=request_delay)
    if not hit:
        return []

    digest = hashlib.sha256(url.encode()).hexdigest()[:12]
    evidence = hit["evidence"]
    if authorized_note:
        evidence = f"{evidence} Authorized-identity context: {authorized_note}"
    return [
        Finding(
            id=f"{program.key}:bfla:{digest}",
            program_key=program.key,
            asset=url,
            title="BFLA candidate: privileged function accessible to a lower-privileged identity",
            vuln_class=hit["kind"],
            test_type=TestType.ACTIVE_LOW_IMPACT,
            evidence=evidence,
            status=FindingStatus.CANDIDATE,
            notes=f"severity guess: {hit['severity']} -- verify manually before drafting a PoC",
        )
    ]


def run_idor_batch(
    program: Program,
    urls: list[str],
    owner_headers: dict[str, str],
    other_headers: dict[str, str],
    *,
    owner_note: str | None = None,
) -> list[Finding]:
    """Run the same two-request BOLA/IDOR access-diff across many
    human-curated owner-URLs in one gated run. Each URL is still the
    identical safe check (two requests, no enumeration, no ID guessing);
    this only saves re-invoking the command per URL. Every request is
    spaced >=1s from the next (BATCH_INTER_REQUEST_DELAY_SECONDS within a
    pair, BATCH_URL_DELAY_SECONDS between URLs) so a whole batch stays
    under a 1-RPS program cap. The caller supplies both sessions and the
    URL list -- nothing here is discovered, invented, or enumerated."""
    findings: list[Finding] = []
    for i, url in enumerate(urls):
        if i:
            time.sleep(BATCH_URL_DELAY_SECONDS)
        findings.extend(
            run_idor_check(
                program, url, owner_headers, other_headers,
                owner_note=owner_note, request_delay=BATCH_INTER_REQUEST_DELAY_SECONDS,
            )
        )
    return findings


def run_bfla_batch(
    program: Program,
    urls: list[str],
    authorized_headers: dict[str, str],
    other_headers: dict[str, str],
    *,
    authorized_note: str | None = None,
) -> list[Finding]:
    """Batch sibling of `run_bfla_check` -- same mechanism and pacing as
    `run_idor_batch`, pointed at privileged function/endpoint URLs."""
    findings: list[Finding] = []
    for i, url in enumerate(urls):
        if i:
            time.sleep(BATCH_URL_DELAY_SECONDS)
        findings.extend(
            run_bfla_check(
                program, url, authorized_headers, other_headers,
                authorized_note=authorized_note, request_delay=BATCH_INTER_REQUEST_DELAY_SECONDS,
            )
        )
    return findings
