"""Noise/dedup triage: before you spend time drafting a PoC, flag the
candidate findings a program's own policy already says it won't accept --
the classic low-value classes (missing SPF/DMARC, missing security
headers, rate-limit observations, ...) that mature programs explicitly
exclude, plus anything whose asset is in the program's out-of-scope
list. These aren't deleted (they might still matter on another program);
they're just labelled so you don't burn reputation reporting a known
non-issue.

Heuristic and deliberately conservative: a flag means "the policy text
mentions excluding this class -- check before reporting", not "definitely
invalid". It never promotes or hides a finding on its own.
"""
from __future__ import annotations

from bbhunter.models import Finding, Program

# finding vuln_class/title keyword -> policy phrases that would exclude it.
# If any phrase appears in the program's policy text, a matching candidate
# is flagged as likely-out-of-scope.
_EXCLUSION_MAP: dict[str, tuple[str, ...]] = {
    "dmarc": ("dmarc", "spf", "dkim", "email spoof", "spf/dkim"),
    "spf": ("spf", "dmarc", "dkim", "email spoof"),
    "security header": ("security header", "missing header", "x-frame-options", "clickjack",
                         "content security policy", "content-security-policy", "httponly", "secure flag"),
    "content-security-policy": ("content security policy", "content-security-policy", "security header", "clickjack"),
    "rate-limit": ("rate limit", "rate-limit", "rate limiting", "brute force"),
    "rate limit": ("rate limit", "rate-limit", "rate limiting"),
    "source map": ("source map", "sourcemap", "source-map"),
    "robots": ("directory listing", "robots.txt", "content/directory enumeration"),
    "self-xss": ("self-xss", "self xss"),
    "clickjack": ("clickjack", "x-frame-options", "ui redress"),
}


def _asset_out_of_scope(program: Program, asset: str) -> str | None:
    for oos in program.out_of_scope:
        ident = oos.identifier.lstrip("*.").lower()
        if ident and ident in asset.lower():
            return oos.identifier
    return None


def flag_known_issues(program: Program, findings: list[Finding]) -> list[tuple[Finding, str]]:
    """Return (finding, reason) for every candidate the policy likely
    excludes -- an out-of-scope asset, or a class the policy text names as
    excluded. Findings with no match are omitted (they're the ones worth a
    real look)."""
    policy = (program.raw_policy_text or "").lower()
    flagged: list[tuple[Finding, str]] = []
    for f in findings:
        oos_asset = _asset_out_of_scope(program, f.asset)
        if oos_asset:
            flagged.append((f, f"asset is out of scope ({oos_asset})"))
            continue
        hay = f"{f.vuln_class} {f.title}".lower()
        for keyword, phrases in _EXCLUSION_MAP.items():
            if keyword in hay and any(p in policy for p in phrases):
                hit = next(p for p in phrases if p in policy)
                flagged.append((f, f"policy excludes this class (mentions {hit!r})"))
                break
    return flagged
