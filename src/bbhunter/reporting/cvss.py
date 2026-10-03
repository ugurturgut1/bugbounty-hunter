"""CVSS v3.1 base-score calculator. A researcher-set severity is a guess;
a CVSS vector is a defensible, triager-recognized number. This takes a
Base-metric vector string and returns (score, severity rating) using the
official v3.1 formula (spec section 7.1), so `draft-report` can derive
severity from a vector instead of a hunch.

Base metrics only -- Temporal/Environmental are out of scope here (they
rarely belong in an initial report). Unknown/invalid vectors raise
ValueError rather than silently scoring wrong.
"""
from __future__ import annotations

import math

# metric -> value -> weight (v3.1 spec table)
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
# PR depends on Scope: (unchanged, changed)
_PR = {"N": (0.85, 0.85), "L": (0.62, 0.68), "H": (0.27, 0.50)}
_REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def parse_vector(vector: str) -> dict[str, str]:
    """Parse 'AV:N/AC:L/...' (optionally prefixed 'CVSS:3.1/') into a
    {metric: value} dict, validating that every required Base metric is
    present and known."""
    parts = [p for p in vector.strip().split("/") if p]
    metrics: dict[str, str] = {}
    for p in parts:
        if p.upper().startswith("CVSS:"):
            continue
        if ":" not in p:
            raise ValueError(f"malformed metric {p!r} (expected 'KEY:VALUE')")
        k, v = p.split(":", 1)
        metrics[k.upper()] = v.upper()
    missing = [m for m in _REQUIRED if m not in metrics]
    if missing:
        raise ValueError(f"missing required Base metric(s): {', '.join(missing)}")
    return metrics


def _roundup(x: float) -> float:
    """Official CVSS 3.1 Roundup: smallest one-decimal number >= x,
    avoiding binary-float artifacts (spec appendix)."""
    i = round(x * 100000)
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def base_score(vector: str) -> float:
    m = parse_vector(vector)
    scope_changed = m["S"] == "C"
    try:
        iss = 1 - (1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]])
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss
        exploitability = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * _PR[m["PR"]][1 if scope_changed else 0] * _UI[m["UI"]]
    except KeyError as e:
        raise ValueError(f"unknown metric value: {e}") from e
    if impact <= 0:
        return 0.0
    raw = 1.08 * (impact + exploitability) if scope_changed else impact + exploitability
    return _roundup(min(raw, 10.0))


def severity_rating(score: float) -> str:
    """v3.1 qualitative rating band."""
    if score == 0.0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def score_and_rating(vector: str) -> tuple[float, str]:
    s = base_score(vector)
    return s, severity_rating(s)
