"""Dedup candidate findings against a program's already-public disclosed
reports, so you don't submit (and burn reputation on) something the
program has already seen and closed. Disclosures are stored per program
as a small JSON list under DATA_DIR/disclosures/<slug>.json -- populate
it from the program's Hacktivity/disclosure feed (manually via
`add-disclosure`, or a future fetcher writing the same file).

Matching is deliberately conservative: a flag means "this looks like an
already-public report -- check before submitting", via an exact
vuln_class match or high title-word overlap on the same asset. It never
hides or deletes a finding.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from bbhunter.config import DATA_DIR
from bbhunter.models import Finding

DISCLOSURE_DIR = DATA_DIR / "disclosures"
DISCLOSURE_DIR.mkdir(parents=True, exist_ok=True)

_STOPWORDS = {"the", "a", "an", "in", "on", "of", "to", "via", "and", "or", "for",
              "with", "is", "are", "at", "by", "candidate", "possible", "finding"}
_TITLE_OVERLAP_THRESHOLD = 0.5


def _slug(program_key: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "_", program_key).strip("_")


def _path(program_key: str) -> Path:
    return DISCLOSURE_DIR / f"{_slug(program_key)}.json"


def load_disclosures(program_key: str) -> list[dict]:
    """Return the stored disclosed reports for a program (list of
    {title, vuln_class?}), or [] if none recorded / unreadable."""
    p = _path(program_key)
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text())
    except (OSError, ValueError):
        return []
    return data if isinstance(data, list) else []


def add_disclosure(program_key: str, title: str, vuln_class: str | None = None) -> int:
    """Append one disclosed report to the store; returns the new total."""
    items = load_disclosures(program_key)
    items.append({"title": title, "vuln_class": vuln_class or ""})
    _path(program_key).write_text(json.dumps(items, indent=2))
    return len(items)


def _title_tokens(title: str) -> set[str]:
    words = re.findall(r"[a-z0-9]+", title.lower())
    return {w for w in words if w not in _STOPWORDS and len(w) > 2}


def _overlap(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def match_disclosures(findings: list[Finding], disclosures: list[dict]) -> list[tuple[Finding, str]]:
    """Return (finding, reason) for each finding that looks like an
    already-public disclosure -- same vuln_class, or title-word overlap
    >= threshold. Findings with no match are omitted."""
    flagged: list[tuple[Finding, str]] = []
    disc = [(d.get("title", ""), (d.get("vuln_class") or "").lower(), _title_tokens(d.get("title", ""))) for d in disclosures]
    for f in findings:
        ftoks = _title_tokens(f.title)
        fclass = f.vuln_class.lower()
        for dtitle, dclass, dtoks in disc:
            if dclass and dclass == fclass:
                flagged.append((f, f"same vuln_class as disclosed report {dtitle!r}"))
                break
            ov = _overlap(ftoks, dtoks)
            if ov >= _TITLE_OVERLAP_THRESHOLD:
                flagged.append((f, f"title ~{int(ov*100)}% overlap with disclosed report {dtitle!r}"))
                break
    return flagged
