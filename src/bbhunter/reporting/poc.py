"""Phase 4, step 1: PoC drafting.

Deliberately does NOT generate exploit code or attempt to weaponize a
Finding -- it only assembles a structured markdown template from what the
automation already observed (the Finding's `evidence` field) and leaves
the actual reproduction narrative, verification, and impact assessment as
explicit TODOs for a human. Nothing downstream (`draft_report`) reads
this file's TODOs as if they were filled in; the approval gate in
`approve-poc` is where a human confirms they actually did the work.

One piece of head-start reference IS included automatically, never
generated: `_technique_notes_for` best-effort-matches the Finding's
`vuln_class` against a section heading in `docs/VULN_TECHNIQUE_NOTES.md`
and embeds that section's real text verbatim, so whoever's about to
write the reproduction steps below has the relevant manual-verification
notes right there instead of a blank page. This is reference material to
work from, not a substitute for actually reproducing the finding -- it
never claims anything about this specific finding, only general
technique for the vuln class.
"""
from __future__ import annotations

import re
from pathlib import Path

from bbhunter.config import DATA_DIR
from bbhunter.models import Finding, FindingStatus, Program

POC_DIR = DATA_DIR / "pocs"
POC_DIR.mkdir(parents=True, exist_ok=True)

VULN_TECHNIQUE_NOTES_PATH = Path(__file__).resolve().parents[3] / "docs" / "VULN_TECHNIQUE_NOTES.md"

# vuln_class substring (checked lowercase, first match wins) -> the exact "## " heading it maps to
# in docs/VULN_TECHNIQUE_NOTES.md. Deliberately not exhaustive -- classes with no real notes there
# (IDOR, cloud buckets, TLS findings, etc.) just get no technique-notes section, not a fabricated one.
_TECHNIQUE_NOTE_KEYWORDS: list[tuple[str, str]] = [
    ("shellshock", "RCE"),
    ("command-injection", "RCE"),
    ("crlf", "CRLF / HTTP response splitting"),
    ("sql-injection", "SQL injection"),
    ("sql-error", "SQL injection"),
    ("nosql-error", "SQL injection"),
    ("xss", "XSS"),
    ("ssrf", "SSRF"),
    ("xxe", "XXE"),
    ("ssti", "Template injection (SSTI)"),
    ("redirect", "Open redirect"),
]


def _technique_notes_for(vuln_class: str) -> tuple[str, str] | None:
    """Returns `(heading, body)` for the `docs/VULN_TECHNIQUE_NOTES.md`
    section matching `vuln_class`, or `None` if nothing matches or the
    file can't be read -- callers must treat `None` as "no notes to
    include," never an error."""
    vuln_class_lower = vuln_class.lower()
    heading = next((h for kw, h in _TECHNIQUE_NOTE_KEYWORDS if kw in vuln_class_lower), None)
    if not heading:
        return None
    try:
        text = VULN_TECHNIQUE_NOTES_PATH.read_text(encoding="utf-8")
    except OSError:
        return None
    match = re.search(rf"^## {re.escape(heading)}\n(.*?)(?=^## |\Z)", text, re.DOTALL | re.MULTILINE)
    if not match:
        return None
    return heading, match.group(1).strip()


def _slug(finding_id: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "_", finding_id).strip("_")


def poc_path_for(finding_id: str) -> Path:
    return POC_DIR / f"{_slug(finding_id)}.md"


def _extract_section(markdown: str, heading: str) -> str:
    pattern = rf"^## {re.escape(heading)}\s*\n(.*?)(?=\n## |\Z)"
    m = re.search(pattern, markdown, re.DOTALL | re.MULTILINE)
    if not m:
        return "(section not found in PoC file)"
    body = m.group(1)
    body = re.sub(r"<!--.*?-->", "", body, flags=re.DOTALL)
    return body.strip() or "(empty)"


def poc_has_unfilled_todos(poc_path: str) -> bool:
    """True if the PoC markdown at `poc_path`'s Reproduction steps or
    Impact section still contains a literal `TODO`. The single source of
    truth for this check -- `approve_poc_cmd` (cli.py) enforces it BEFORE
    a finding can become `POC_APPROVED` at all, and `draft_report`
    enforces it again independently before drafting a report, so a
    still-templated PoC can never slip past either gate no matter which
    path something takes to get there."""
    text = Path(poc_path).read_text(encoding="utf-8")
    steps = _extract_section(text, "Reproduction steps")
    impact = _extract_section(text, "Impact")
    return "TODO" in steps or "TODO" in impact


def draft_poc(finding: Finding, program: Program) -> Finding:
    if finding.status != FindingStatus.CANDIDATE:
        raise RuntimeError(
            f"{finding.id}: can only draft a PoC from status=candidate (currently {finding.status.value})"
        )

    notes_match = _technique_notes_for(finding.vuln_class)
    technique_section = (
        f"\n## Technique notes ({notes_match[0]}, from docs/VULN_TECHNIQUE_NOTES.md)\n\n"
        f"{notes_match[1]}\n\n"
        "_Reference for how to approach reproduction/verification for this vuln class -- not a claim "
        "about this specific finding._\n"
        if notes_match
        else ""
    )

    path = poc_path_for(finding.id)
    path.write_text(
        f"""# PoC: {finding.title}

- **Finding ID:** {finding.id}
- **Program:** {program.name} ({program.key})
- **Asset:** {finding.asset}
- **Test type:** {finding.test_type.value}
- **Vuln class:** {finding.vuln_class}

## What the automation observed

{finding.evidence}

{f"Automation notes: {finding.notes}" if finding.notes else ""}
{technique_section}
## Reproduction steps

<!-- TODO (human): verify the finding above yourself and write the exact,
minimal steps to reproduce it. Do not approve this PoC until you have
personally reproduced it -- the automation's evidence is a lead, not a
confirmed vulnerability. -->

1. TODO

## Impact

<!-- TODO (human): what can an attacker actually do with this? Be
concrete and specific to this program's assets -- this text is reused
verbatim as the basis for the disclosure report's Impact section. -->

TODO

## Suggested severity

<!-- TODO (human): none | low | medium | high | critical -->

TODO

## Supporting material

<!-- attach screenshots, request/response captures, etc. here or link to
files alongside this one -->
""",
        encoding="utf-8",
    )

    finding.poc_path = str(path)
    finding.status = FindingStatus.POC_DRAFTED
    return finding
