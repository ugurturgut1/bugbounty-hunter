"""Turns a program's free-text policy into a conservative RulesOfEngagement.

Default posture: if the policy doesn't CLEARLY say something is allowed,
treat it as not allowed. This is a keyword-heuristic first pass, not a
substitute for reading the policy yourself. Every program's `confidence`
should be manually bumped to "high" by you (or a reviewed LLM pass) before
anything beyond passive recon is ever run against it.
"""
from __future__ import annotations

import re

from bbhunter.models import RulesOfEngagement, TestType

_DISALLOW_PATTERNS = [
    r"no automated (scanning|scanners|tools)",
    r"do not (use|run) automated",
    r"denial of service",
    r"\bdos\b",
    r"social engineering",
    r"phishing",
    r"physical (security|access|attacks?)",
    r"no (brute[- ]?force|credential stuffing)",
    r"do not (test|attack) third[- ]party",
    r"spam",
    r"no destructive",
]

_ACTIVE_ALLOW_PATTERNS = [
    r"automated scanners? (are|is) (allowed|permitted|welcome)",
    r"automated (testing|tools) (are|is)? ?(allowed|permitted)",
]

_SAFE_HARBOR_PATTERNS = [r"safe harbor"]
_AUTH_REQUIRED_PATTERNS = [r"request(ing)? (written )?(authorization|permission)", r"prior written consent"]


def _find_any(patterns: list[str], text: str) -> list[str]:
    hits = []
    for p in patterns:
        m = re.search(p, text, re.IGNORECASE)
        if m:
            hits.append(m.group(0))
    return hits


def derive_rules(raw_policy_text: str | None) -> RulesOfEngagement:
    if not raw_policy_text or not raw_policy_text.strip():
        return RulesOfEngagement(
            allowed_test_types={TestType.PASSIVE_RECON},
            confidence="low",
            raw_notes="No policy text available; defaulting to passive-only.",
        )

    text = raw_policy_text
    disallowed_hits = _find_any(_DISALLOW_PATTERNS, text)
    active_allow_hits = _find_any(_ACTIVE_ALLOW_PATTERNS, text)
    safe_harbor_hits = _find_any(_SAFE_HARBOR_PATTERNS, text)
    auth_required_hits = _find_any(_AUTH_REQUIRED_PATTERNS, text)

    allowed: set[TestType] = {TestType.PASSIVE_RECON, TestType.VERSION_CVE_MATCH}

    automated_scanners_allowed: bool | None = None
    if active_allow_hits:
        automated_scanners_allowed = True
        allowed.add(TestType.ACTIVE_LOW_IMPACT)
    if any("automated" in h.lower() for h in disallowed_hits):
        automated_scanners_allowed = False
        allowed.discard(TestType.ACTIVE_LOW_IMPACT)

    # Confidence is only "high" when the text is long enough to have been
    # meaningfully parsed AND we found at least one explicit, unambiguous
    # signal either way. Silence is not permission.
    has_signal = bool(disallowed_hits or active_allow_hits)
    confidence = "medium" if (has_signal and len(text) > 200) else "low"

    rules = RulesOfEngagement(
        allowed_test_types=allowed if confidence != "low" else {TestType.PASSIVE_RECON},
        explicitly_disallowed_techniques=disallowed_hits,
        automated_scanners_allowed=automated_scanners_allowed,
        safe_harbor=bool(safe_harbor_hits) or None,
        requires_authorization_request=bool(auth_required_hits),
        confidence=confidence,
        raw_notes=(
            f"heuristic pass: {len(disallowed_hits)} disallow signal(s), "
            f"{len(active_allow_hits)} active-allow signal(s)"
        ),
    )
    return rules
