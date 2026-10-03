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
    is_fresh: bool = False
    recently_expanded: bool = False
    reasons: list[str] = field(default_factory=list)


def _eligible_seed_count(program: Program) -> int:
    return sum(1 for a in program.in_scope if a.asset_type in (AssetType.URL, AssetType.WILDCARD))


def _cve_match_discounted(program: Program) -> bool:
    text = (program.raw_policy_text or "").lower()
    return any(phrase in text for phrase in CVE_MATCH_DISCOUNT_PHRASES)


def outcome_multiplier(stat: dict | None) -> tuple[float, str | None]:
    """Turn a program's historical submission outcomes into a score
    multiplier: reward programs that have actually resolved/paid your
    reports, penalize ones where everything so far closed
    duplicate/informative. None/empty history is neutral (1.0)."""
    if not stat:
        return 1.0, None
    resolved = stat.get("resolved", 0)
    paid = stat.get("bounty_total", 0.0)
    noise = stat.get("duplicate", 0) + stat.get("informative", 0)
    if resolved or paid:
        mult = min(2.0, 1.0 + 0.4 * resolved + (0.3 if paid else 0.0))
        return mult, f"proven: {resolved} resolved, {paid:.0f} paid ({mult:.1f}x)"
    if noise:
        return 0.5, f"only dupes/informative so far ({noise}) (0.5x)"
    return 1.0, None


def score_program(
    program: Program, *, already_reconned: bool, is_fresh: bool = False, recently_expanded: bool = False,
    outcome: dict | None = None,
) -> PriorityScore | None:
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

    # Freshness: brand-new programs and freshly-expanded scope are the
    # least picked-over by other researchers -- where first-blood bugs and
    # CVE-worthy findings actually come from, so they get the biggest
    # boosts here.
    if is_fresh:
        value *= 1.6
        reasons.append("newly-added program -- likely less picked-over (1.6x)")
    if recently_expanded:
        value *= 1.4
        reasons.append("scope recently expanded -- fresh attack surface (1.4x)")

    # Learned signal: weight by what this program has actually done with
    # your past reports (resolved/paid vs. closed dupe/informative).
    out_mult, out_reason = outcome_multiplier(outcome)
    if out_reason:
        value *= out_mult
        reasons.append(out_reason)

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
        is_fresh=is_fresh,
        recently_expanded=recently_expanded,
        reasons=reasons,
    )


def prioritize(
    programs: list[Program],
    reconned_keys: set[str],
    fresh_keys: set[str] | None = None,
    expanded_keys: set[str] | None = None,
    outcome_stats: dict[str, dict] | None = None,
) -> list[PriorityScore]:
    fresh_keys = fresh_keys or set()
    expanded_keys = expanded_keys or set()
    outcome_stats = outcome_stats or {}
    scored = [
        score_program(
            p,
            already_reconned=p.key in reconned_keys,
            is_fresh=p.key in fresh_keys,
            recently_expanded=p.key in expanded_keys,
            outcome=outcome_stats.get(p.key),
        )
        for p in programs
    ]
    ranked = [s for s in scored if s is not None]
    ranked.sort(key=lambda s: s.score, reverse=True)
    return ranked
