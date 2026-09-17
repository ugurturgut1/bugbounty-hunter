"""Ranks synced programs by expected report/CVE-credit value per unit of
recon time, so a human can pick a handful of programs worth actually
spending hours on instead of working through the list in sync order.

Score is deliberately a *rough* ROI proxy, not a real EV model -- there's
no ground truth to fit it against. It exists to surface a short list for
a human to sanity-check, not to be trusted blindly.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field

from bbhunter.models import AssetType, Program

# Real-world calibration point: hackerone:watsons via intigriti (93 seed
# hosts, some crt.sh failures/rate-limiting) took "~30+ minutes" in
# practice (see project notes) -- about 19s/seed, and that run had
# unusually many crt.sh failures inflating it. 20s/seed is a deliberately
# round, slightly conservative per-seed estimate for planning purposes,
# not a measured average -- it will be wrong in both directions.
SECONDS_PER_RECON_SEED = 20.0

# Phrases pulled from real program policies (e.g. Visa's) that explicitly
# exclude exactly what Phase 2's CVE-keyword-match technique produces --
# "banner grabbing"/fingerprinting findings, or N-day vulnerabilities in
# third-party software. A hit here doesn't zero out a program's value
# (Phase 3's exposed-file/misconfig checks are a different vuln class and
# usually still eligible) but it means the passive-recon pass alone is
# unlikely to produce anything payable.
CVE_MATCH_DISCOUNT_PHRASES = [
    "banner grabbing",
    "banner-grabbing",
    "known n-day",
    "n-day vulnerabilit",
    "zero-day only",
    "vulnerabilities in third-party software",
]


@dataclass
class PriorityScore:
    program_key: str
    name: str
    score: float
    est_recon_minutes: float
    eligible_seeds: int
    offers_bounties: bool
    already_reconned: bool
    active_testing_ready: bool
    cve_match_discounted: bool
    reasons: list[str] = field(default_factory=list)


def _eligible_seed_count(program: Program) -> int:
    return sum(1 for a in program.in_scope if a.asset_type in (AssetType.URL, AssetType.WILDCARD))


def _cve_match_discounted(program: Program) -> bool:
    text = (program.raw_policy_text or "").lower()
    return any(phrase in text for phrase in CVE_MATCH_DISCOUNT_PHRASES)


def score_program(program: Program, *, already_reconned: bool) -> PriorityScore | None:
    """Returns None for programs with nothing for recon to do (no
    URL/wildcard scope) -- there's nothing to rank."""
    eligible_seeds = _eligible_seed_count(program)
    if eligible_seeds == 0:
        return None

    est_minutes = (eligible_seeds * SECONDS_PER_RECON_SEED) / 60
    reasons: list[str] = []

    # More seeds = more attack surface = more chances of a real finding,
    # but with sharply diminishing returns (a 200-asset scope isn't 200x
    # more promising than a 1-asset one) -- log growth models that.
    # Dividing by sqrt(time) rather than time itself means recon cost is
    # a soft penalty, not a hard divisor: a plain value/time ratio lets a
    # 1-seed, ~20s program dominate purely because it's fast, regardless
    # of how little surface it actually has to find anything in.
    surface = math.log2(eligible_seeds + 1)
    time_penalty = math.sqrt(max(est_minutes, 1 / 60))

    value = 3.0 if program.offers_bounties else 1.0
    reasons.append("pays bounties (3x)" if program.offers_bounties else "VDP only, no bounty (1x baseline)")

    discounted = _cve_match_discounted(program)
    if discounted:
        value *= 0.6
        reasons.append("policy excludes banner-grabbing/N-day findings -- Phase 2 CVE-match discounted 0.6x")

    active_ready = program.rules.human_reviewed and program.rules.confidence == "high"
    if active_ready:
        value *= 1.3
        reasons.append("active testing already approved -- Phase 3 exposed-file checks unlocked (1.3x)")

    if program.rules.safe_harbor:
        value *= 1.1
        reasons.append("explicit safe harbor (1.1x)")

    if already_reconned:
        value *= 0.2
        reasons.append("already reconned once -- mostly marginal value now (0.2x)")

    score = value * surface / time_penalty

    return PriorityScore(
        program_key=program.key,
        name=program.name,
        score=score,
        est_recon_minutes=est_minutes,
        eligible_seeds=eligible_seeds,
        offers_bounties=program.offers_bounties,
        already_reconned=already_reconned,
        active_testing_ready=active_ready,
        cve_match_discounted=discounted,
        reasons=reasons,
    )


def prioritize(programs: list[Program], reconned_keys: set[str]) -> list[PriorityScore]:
    scored = [score_program(p, already_reconned=p.key in reconned_keys) for p in programs]
    ranked = [s for s in scored if s is not None]
    ranked.sort(key=lambda s: s.score, reverse=True)
    return ranked
